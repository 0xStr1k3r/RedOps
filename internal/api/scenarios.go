package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/0xStr1k3r/RedOps/internal/auth"
	"github.com/0xStr1k3r/RedOps/internal/project"
	"github.com/0xStr1k3r/RedOps/internal/scenarios"
)

func handleListScenarios(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, scenarios.Catalog())
	}
}

func handleRunScenario(cfg Config) http.HandlerFunc {
	type req struct {
		Target string `json:"target"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !can(r, auth.RoleOperator) {
			writeErr(w, 403, "operator role required")
			return
		}
		var in req
		if err := decodeJSON(r, &in); err != nil || strings.TrimSpace(in.Target) == "" {
			writeErr(w, 400, "field 'target' required")
			return
		}
		name := chi.URLParam(r, "name")
		if _, err := scenarios.Get(name); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		pid := chi.URLParam(r, "id")
		// Fast scope pre-check for an immediate 403 (runner re-checks too).
		if sc, err := cfg.Store.LoadScope(pid); err != nil {
			writeErr(w, 403, fmt.Sprintf("cannot run scenario: project has no valid scope (%v)", err))
			return
		} else if err := sc.Enforce(in.Target); err != nil {
			_ = cfg.Store.AppendAudit(pid, actor(r), "scenario.denied", in.Target, err.Error())
			writeErr(w, 403, err.Error())
			return
		}
		run, err := cfg.Store.CreateScenarioRun(pid, name, strings.TrimSpace(in.Target), actor(r))
		if err != nil {
			writeErr(w, 404, err.Error())
			return
		}
		// Background execution: scans can exceed the HTTP timeout.
		go executeScenario(cfg.Store, run)
		writeJSON(w, 202, run)
	}
}

// executeScenario runs the playbook and lands the terminal state.
func executeScenario(st *project.Store, run *project.ScenarioRun) {
	_ = st.StartScenarioRun(run.ID)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	results, err := scenarios.Run(ctx, st, run.ProjectID, run.Target, run.CreatedBy, run.Scenario)
	if err != nil {
		_ = st.FinishScenarioRun(run.ID, project.JobFailed, "", err.Error())
		return
	}
	raw, _ := json.Marshal(results)
	done := 0
	for _, res := range results {
		if res.Success {
			done++
		}
	}
	_ = st.FinishScenarioRun(run.ID, project.JobDone, fmt.Sprintf("%d/%d steps ok: %s", done, len(results), string(raw)), "")
}

func handleListScenarioRuns(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := cfg.Store.ListScenarioRuns(chi.URLParam(r, "id"))
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		if list == nil {
			writeJSON(w, 200, []any{})
			return
		}
		writeJSON(w, 200, list)
	}
}

func handleGetScenarioRun(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		run, err := cfg.Store.GetScenarioRun(chi.URLParam(r, "id"), chi.URLParam(r, "runID"))
		if err != nil {
			writeErr(w, 404, "scenario run not found")
			return
		}
		writeJSON(w, 200, run)
	}
}
