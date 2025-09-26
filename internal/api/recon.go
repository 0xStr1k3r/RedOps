package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/redops/redops/internal/auth"
	"github.com/redops/redops/internal/project"
	"github.com/redops/redops/internal/recon"
)

func handleEnqueueRecon(cfg Config) http.HandlerFunc {
	type req struct {
		Tool   string `json:"tool"`
		Target string `json:"target"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !can(r, auth.RoleOperator) {
			writeErr(w, 403, "operator role required")
			return
		}
		var in req
		if err := decodeJSON(r, &in); err != nil || strings.TrimSpace(in.Tool) == "" || strings.TrimSpace(in.Target) == "" {
			writeErr(w, 400, "fields 'tool' and 'target' required")
			return
		}
		job, err := recon.Enqueue(r.Context(), cfg.Store, chi.URLParam(r, "id"), in.Tool, in.Target, actor(r))
		if err != nil {
			if strings.Contains(err.Error(), "scope denied") || strings.Contains(err.Error(), "no valid scope") {
				_ = cfg.Store.AppendAudit(chi.URLParam(r, "id"), actor(r), "recon.denied", in.Target, err.Error())
				writeErr(w, 403, err.Error())
				return
			}
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 202, job)
	}
}

func handleListRecon(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := cfg.Store.ListReconJobs(chi.URLParam(r, "id"))
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		if list == nil {
			list = []project.ReconJob{}
		}
		writeJSON(w, 200, list)
	}
}

func handleGetRecon(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		j, err := cfg.Store.GetReconJob(chi.URLParam(r, "id"), chi.URLParam(r, "jobID"))
		if err != nil {
			writeErr(w, 404, "job not found")
			return
		}
		writeJSON(w, 200, j)
	}
}

func handleListHosts(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := cfg.Store.ListHosts(chi.URLParam(r, "id"))
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		if list == nil {
			list = []project.Host{}
		}
		writeJSON(w, 200, list)
	}
}

func handleListServices(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := cfg.Store.ListServices(chi.URLParam(r, "id"))
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		if list == nil {
			list = []project.Service{}
		}
		writeJSON(w, 200, list)
	}
}

func handleAssets(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hosts, _ := cfg.Store.ListHosts(chi.URLParam(r, "id"))
		services, _ := cfg.Store.ListServices(chi.URLParam(r, "id"))
		if hosts == nil {
			hosts = []project.Host{}
		}
		if services == nil {
			services = []project.Service{}
		}
		writeJSON(w, 200, map[string]any{"hosts": hosts, "services": services})
	}
}
