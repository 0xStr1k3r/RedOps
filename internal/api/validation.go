package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/0xStr1k3r/RedOps/internal/auth"
	"github.com/0xStr1k3r/RedOps/internal/validation"
)

func handleListValidators(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type item struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			AppliesTo   []string `json:"-"`
		}
		var out []map[string]string
		for _, name := range validation.List() {
			v, _ := validation.Get(name)
			out = append(out, map[string]string{"name": v.Name(), "description": v.Description()})
		}
		if out == nil {
			out = []map[string]string{}
		}
		writeJSON(w, 200, out)
	}
}

func handleValidateFinding(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !can(r, auth.RoleOperator) {
			writeErr(w, 403, "operator role required")
			return
		}
		results, promoted, err := validation.ValidateFinding(r.Context(), cfg.Store, chi.URLParam(r, "id"), chi.URLParam(r, "fid"), actor(r), validation.Options{})
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"results": results, "promoted": promoted})
	}
}

func handleListValidationRuns(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		runs, err := cfg.Store.ListValidationRuns(chi.URLParam(r, "id"), chi.URLParam(r, "fid"))
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		if runs == nil {
			writeJSON(w, 200, []any{})
			return
		}
		writeJSON(w, 200, runs)
	}
}
