package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/redops/redops/internal/auth"
	"github.com/redops/redops/internal/findings"
	"github.com/redops/redops/internal/project"
)

func handleCreateFinding(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !can(r, auth.RoleOperator) {
			writeErr(w, 403, "operator role required")
			return
		}
		var in findings.Finding
		if err := decodeJSON(r, &in); err != nil {
			writeErr(w, 400, "invalid JSON: "+err.Error())
			return
		}
		in.Normalize()
		if err := in.Validate(); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		pid := chi.URLParam(r, "id")
		ok, err := cfg.Store.CreateFinding(pid, project.FindingRow{
			Title: in.Title, Description: in.Description, Severity: in.Severity,
			Confidence: in.Confidence, Target: in.Target, Evidence: in.Evidence,
			Source: in.Source, CWE: in.CWE, CVE: in.CVE, TechniqueID: in.TechniqueID,
			Remediation: in.Remediation, Status: in.Status,
		}, project.ManualDedupeKey())
		if err != nil || !ok {
			writeErr(w, 400, "create failed")
			return
		}
		_ = cfg.Store.AppendAudit(pid, actor(r), "finding.create", in.Target, in.Title)
		writeJSON(w, 201, map[string]string{"status": "created"})
	}
}

func handleListFindings(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		list, err := cfg.Store.ListFindings(chi.URLParam(r, "id"), project.FindingFilter{
			Severity: q.Get("severity"), Status: q.Get("status"), Target: q.Get("target"),
		})
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		if list == nil {
			list = []project.FindingRow{}
		}
		writeJSON(w, 200, list)
	}
}

func handleGetFinding(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f, err := cfg.Store.GetFinding(chi.URLParam(r, "id"), chi.URLParam(r, "fid"))
		if err != nil {
			writeErr(w, 404, "finding not found")
			return
		}
		writeJSON(w, 200, f)
	}
}

func handlePatchFinding(cfg Config) http.HandlerFunc {
	type req struct {
		Status     string `json:"status"`
		Confidence string `json:"confidence"`
		Severity   string `json:"severity"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !can(r, auth.RoleOperator) {
			writeErr(w, 403, "operator role required")
			return
		}
		var in req
		if err := decodeJSON(r, &in); err != nil {
			writeErr(w, 400, "invalid JSON")
			return
		}
		f, err := cfg.Store.UpdateFinding(chi.URLParam(r, "id"), chi.URLParam(r, "fid"), in.Status, in.Confidence, in.Severity)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				writeErr(w, 404, "finding not found")
				return
			}
			writeErr(w, 400, err.Error())
			return
		}
		_ = cfg.Store.AppendAudit(chi.URLParam(r, "id"), actor(r), "finding.update", f.Target, f.Status)
		writeJSON(w, 200, f)
	}
}

func handleRaiseFindings(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !can(r, auth.RoleOperator) {
			writeErr(w, 403, "operator role required")
			return
		}
		n, err := findings.RaiseFromEnumResults(cfg.Store, chi.URLParam(r, "id"), actor(r))
		if err != nil {
			writeErr(w, 404, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"raised": n})
	}
}
