package findings

import (
	"fmt"

	"github.com/0xStr1k3r/RedOps/internal/project"
)

// RaiseFromEnumResults loads all enum results for a project, runs the rule
// catalog, and persists new findings (dedupe: re-runs add nothing).
// Returns the number of newly created findings.
func RaiseFromEnumResults(st *project.Store, projectID, actor string) (int, error) {
	if _, err := st.GetProject(projectID); err != nil {
		return 0, err
	}
	results, err := st.ListEnumResults(projectID)
	if err != nil {
		return 0, err
	}
	var obs []Observation
	for _, r := range results {
		target := fmt.Sprintf("%s:%d", r.HostIP, r.Port)
		for _, o := range r.Observations {
			obs = append(obs, Observation{
				Target: target, Kind: o.Kind, Detail: o.Detail,
				TechniqueID: o.TechniqueID, Source: r.Module,
			})
		}
	}
	drafts := Raise(projectID, obs)
	raised := 0
	for _, d := range drafts {
		key := DedupeKey(d.Target, d.Title, d.Evidence)
		saved, err := st.CreateFinding(projectID, project.FindingRow{
			Title: d.Title, Description: d.Description, Severity: d.Severity,
			Confidence: d.Confidence, Target: d.Target, Evidence: d.Evidence,
			Source: d.Source, CWE: d.CWE, CVE: d.CVE, TechniqueID: d.TechniqueID,
			Remediation: d.Remediation, Status: d.Status,
		}, key)
		if err != nil {
			// Duplicate keys are skipped silently (idempotent re-raise).
			continue
		}
		if saved {
			raised++
		}
	}
	if raised > 0 {
		_ = st.AppendAudit(projectID, actor, "findings.raise", "", fmt.Sprintf("%d new", raised))
	}
	return raised, nil
}
