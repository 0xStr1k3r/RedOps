package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/redops/redops/internal/auth"
	"github.com/redops/redops/internal/enumeration"
	"github.com/redops/redops/internal/project"
)

func handleEnqueueEnum(cfg Config) http.HandlerFunc {
	type req struct {
		Host   string `json:"host"`
		Port   int    `json:"port"`
		Module string `json:"module"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !can(r, auth.RoleOperator) {
			writeErr(w, 403, "operator role required")
			return
		}
		var in req
		if err := decodeJSON(r, &in); err != nil || strings.TrimSpace(in.Host) == "" || in.Port == 0 {
			writeErr(w, 400, "fields 'host' and 'port' required")
			return
		}
		job, err := enumeration.Enqueue(r.Context(), cfg.Store, chi.URLParam(r, "id"), in.Host, in.Port, in.Module, actor(r))
		if err != nil {
			if strings.Contains(err.Error(), "scope denied") || strings.Contains(err.Error(), "no valid scope") {
				_ = cfg.Store.AppendAudit(chi.URLParam(r, "id"), actor(r), "enum.denied", in.Host, err.Error())
				writeErr(w, 403, err.Error())
				return
			}
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 202, job)
	}
}

func handleListEnum(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := cfg.Store.ListEnumJobs(chi.URLParam(r, "id"))
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		if list == nil {
			list = []project.EnumJob{}
		}
		writeJSON(w, 200, list)
	}
}

func handleGetEnum(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		j, err := cfg.Store.GetEnumJob(chi.URLParam(r, "id"), chi.URLParam(r, "jobID"))
		if err != nil {
			writeErr(w, 404, "job not found")
			return
		}
		writeJSON(w, 200, j)
	}
}

func handleListEnumResults(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := cfg.Store.ListEnumResults(chi.URLParam(r, "id"))
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		if list == nil {
			list = []project.EnumResult{}
		}
		writeJSON(w, 200, list)
	}
}
