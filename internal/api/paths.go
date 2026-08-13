package api

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/0xStr1k3r/RedOps/internal/attack"
	"github.com/0xStr1k3r/RedOps/internal/auth"
)

func handleGeneratePaths(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !can(r, auth.RoleOperator) {
			writeErr(w, 403, "operator role required")
			return
		}
		n, err := attack.Generate(r.Context(), cfg.Store, chi.URLParam(r, "id"), actor(r), attack.Options{})
		if err != nil {
			writeErr(w, 404, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"generated": n})
	}
}

func handleListPaths(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		minRisk, _ := strconv.Atoi(r.URL.Query().Get("min_risk"))
		list, err := cfg.Store.ListAttackPaths(chi.URLParam(r, "id"), minRisk)
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

func handleGetPath(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := cfg.Store.GetAttackPath(chi.URLParam(r, "id"), chi.URLParam(r, "pathID"))
		if err != nil {
			writeErr(w, 404, "attack path not found")
			return
		}
		writeJSON(w, 200, p)
	}
}

func handleConfirmPath(cfg Config) http.HandlerFunc {
	type req struct {
		Confidence string `json:"confidence"`
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
		p, err := cfg.Store.ConfirmAttackPath(chi.URLParam(r, "id"), chi.URLParam(r, "pathID"), in.Confidence, actor(r))
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 200, p)
	}
}
