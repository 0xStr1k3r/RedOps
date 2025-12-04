package validation

import (
	"context"
	"fmt"

	"github.com/redops/redops/internal/project"
)

// ValidateFinding runs every validator matching the finding title and records
// each run. The finding is promoted to validated when at least one validator
// confirms. Failed runs never demote: they may be transient, so the operator
// decides via the findings workflow. Returns results + promoted flag.
func ValidateFinding(ctx context.Context, st *project.Store, projectID, findingID, actor string, opts Options) ([]Result, bool, error) {
	f, err := st.GetFinding(projectID, findingID)
	if err != nil {
		return nil, false, err
	}
	sc, err := st.LoadScope(projectID)
	if err != nil {
		return nil, false, fmt.Errorf("cannot validate: project has no valid scope (%v)", err)
	}
	// Scope gate before any connection: the finding host must still be in scope.
	host, _, err := splitTarget(f.Target)
	if err != nil {
		return nil, false, err
	}
	if err := sc.Enforce(host); err != nil {
		_ = st.AppendAudit(projectID, actor, "validation.denied", f.Target, err.Error())
		return nil, false, err
	}
	matched := MatchAll(f.Title)
	if len(matched) == 0 {
		return nil, false, fmt.Errorf("no validator applies to %q", f.Title)
	}
	var results []Result
	confirmed := false
	for _, v := range matched {
		res, err := v.Run(ctx, sc, f.Target, opts)
		if err != nil {
			res = Result{Validator: v.Name(), Confirmed: false, Detail: "error: " + err.Error()}
		}
		results = append(results, res)
		_ = st.RecordValidationRun(projectID, f.ID, v.Name(), res.Confirmed, res.Detail, actor)
		if res.Confirmed {
			confirmed = true
		}
	}
	if confirmed && (f.Confidence == "observed" || f.Confidence == "potential") {
		if _, err := st.UpdateFinding(projectID, f.ID, "", "validated", ""); err != nil {
			return results, false, err
		}
		_ = st.AppendAudit(projectID, actor, "validation.confirmed", f.Target, f.Title)
		return results, true, nil
	}
	_ = st.AppendAudit(projectID, actor, "validation.unconfirmed", f.Target, f.Title)
	return results, false, nil
}
