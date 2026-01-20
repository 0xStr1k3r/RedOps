package scenarios

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redops/redops/internal/attack"
	"github.com/redops/redops/internal/enumeration"
	"github.com/redops/redops/internal/evidence"
	"github.com/redops/redops/internal/findings"
	"github.com/redops/redops/internal/project"
	"github.com/redops/redops/internal/recon"
	"github.com/redops/redops/internal/scope"
	"github.com/redops/redops/internal/validation"
)

// StepResult records one executed step.
type StepResult struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Technique string `json:"technique,omitempty"`
	Success   bool   `json:"success"`
	Detail    string `json:"detail"`
}

// Run executes a scenario synchronously against one in-scope target.
// Callers needing HTTP-friendly behavior wrap this in a goroutine and poll
// the scenario_runs row (see the API layer).
func Run(ctx context.Context, st *project.Store, projectID, target, actor, scenarioName string) ([]StepResult, error) {
	sc, err := Get(scenarioName)
	if err != nil {
		return nil, err
	}
	scope, err := st.LoadScope(projectID)
	if err != nil {
		return nil, fmt.Errorf("cannot run scenario: project has no valid scope (%v)", err)
	}
	if err := scope.Enforce(target); err != nil {
		_ = st.AppendAudit(projectID, actor, "scenario.denied", target, err.Error())
		return nil, err
	}
	var results []StepResult
	for _, step := range sc.Steps {
		res := runStep(ctx, st, projectID, target, actor, step)
		results = append(results, res)
		msg := fmt.Sprintf("scenario %s step %s: %s [detect: %s]", scenarioName, step.Name, res.Detail, step.Detection)
		_ = st.AppendAudit(projectID, actor, "scenario.step", target, msg)
		if !res.Success {
			// Fail-open to later platform steps would hide breakage; stop instead.
			// Recon/enum steps failing means later steps have nothing to work on.
			if step.Kind == KindRecon || step.Kind == KindEnum {
				break
			}
		}
	}
	raw, _ := json.Marshal(results)
	ev := evidence.New(projectID, actor, target, "scenario."+scenarioName, "scenario "+scenarioName+" on "+target, string(raw), "")
	_, _ = st.RecordEvidence(projectID, toEvidenceRow(ev))
	return results, nil
}

func runStep(ctx context.Context, st *project.Store, projectID, target, actor string, step Step) StepResult {
	timeout := step.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, timeout)
	defer cancel()

	ok := func(detail string) StepResult {
		return StepResult{Name: step.Name, Kind: step.Kind, Technique: step.Technique, Success: true, Detail: detail}
	}
	fail := func(err error) StepResult {
		return StepResult{Name: step.Name, Kind: step.Kind, Technique: step.Technique, Success: false, Detail: err.Error()}
	}

	switch step.Kind {
	case KindRecon:
		tool := step.Tool
		if tool == "" {
			tool = "nmap"
		}
		job, err := recon.Enqueue(ctx, st, projectID, tool, target, actor)
		if err != nil {
			return fail(err)
		}
		if err := recon.RunJob(ctx, st, job, recon.Options{Profile: "fast", Timeout: timeout}); err != nil {
			return fail(err)
		}
		return ok(fmt.Sprintf("%s on %s done", tool, target))
	case KindEnum:
		svcs, err := st.ListServices(projectID)
		if err != nil {
			return fail(err)
		}
		var mine []project.Service
		for _, s := range svcs {
			if belongsToTarget(s, target) {
				mine = append(mine, s)
			}
		}
		if len(mine) == 0 {
			return ok("no discovered services for target; nothing to enumerate")
		}
		// An explicit module only runs on services it handles (e.g. the
		// web scenario skips SSH ports instead of force-probing them).
		if step.Tool != "" {
			mod, err := enumeration.Get(step.Tool)
			if err != nil {
				return fail(err)
			}
			var matched []project.Service
			for _, s := range mine {
				if mod.Handles(enumeration.ServiceRef{HostIP: s.HostIP, Port: s.Port, Name: s.Name}) {
					matched = append(matched, s)
				}
			}
			if len(matched) == 0 {
				return ok(fmt.Sprintf("no %s services discovered; nothing to enumerate", step.Tool))
			}
			mine = matched
		}
		if len(mine) > 10 {
			mine = mine[:10]
		}
		done, failed := 0, 0
		for _, s := range mine {
			mod := step.Tool // "" = auto-match
			job, err := enumeration.Enqueue(ctx, st, projectID, s.HostIP, s.Port, mod, actor)
			if err != nil {
				failed++
				continue
			}
			if err := enumeration.RunJob(ctx, st, job, enumeration.Options{}); err != nil {
				failed++
				continue
			}
			done++
		}
		if done == 0 {
			return fail(fmt.Errorf("%d services, all enumerations failed", failed))
		}
		return ok(fmt.Sprintf("enumerated %d services (%d failed)", done, failed))
	case KindRaise:
		n, err := findings.RaiseFromEnumResults(st, projectID, actor)
		if err != nil {
			return fail(err)
		}
		return ok(fmt.Sprintf("raised %d findings", n))
	case KindValidate:
		rows, err := st.ListFindings(projectID, project.FindingFilter{Status: "open"})
		if err != nil {
			return fail(err)
		}
		confirmed := 0
		for _, f := range rows {
			if !strings.HasPrefix(f.Target, targetHost(target)) {
				continue
			}
			_, promoted, err := validation.ValidateFinding(ctx, st, projectID, f.ID, actor, validation.Options{})
			if err == nil && promoted {
				confirmed++
			}
		}
		return ok(fmt.Sprintf("validated %d findings", confirmed))
	case KindPaths:
		n, err := attack.Generate(ctx, st, projectID, actor, attack.Options{})
		if err != nil {
			return fail(err)
		}
		return ok(fmt.Sprintf("generated %d attack paths", n))
	default:
		return fail(fmt.Errorf("unknown step kind %q", step.Kind))
	}
}

// belongsToTarget links a discovered service to the scenario target via real
// CIDR/IP math: exact match, or the service host falls inside the target range.
func belongsToTarget(s project.Service, target string) bool {
	if s.HostIP == target {
		return true
	}
	typ, norm, err := scope.Classify(target)
	if err != nil {
		return false
	}
	if typ != scope.TypeCIDR {
		return false
	}
	ok, _ := scope.ParseEntries([]string{norm})
	if ok == nil {
		return false
	}
	allowed, _ := ok.ContainsTarget(s.HostIP)
	return allowed
}

// targetHost strips an optional :port for finding-target prefix matching.
func targetHost(target string) string {
	if i := strings.LastIndex(target, ":"); i > 0 && !strings.Contains(target, "/") {
		return target[:i]
	}
	return target
}

func toEvidenceRow(ev *evidence.Evidence) project.EvidenceRow {
	return project.EvidenceRow{
		ID: ev.ID, ProjectID: ev.ProjectID, Timestamp: ev.Timestamp,
		Operator: ev.Operator, Target: ev.Target, Action: ev.Action,
		Command: ev.Command, OutputRef: ev.OutputRef, Technique: ev.Technique,
		FindingID: ev.FindingID,
	}
}
