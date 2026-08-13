package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/0xStr1k3r/RedOps/internal/mitre"
)

func handleMitreTactics(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, mitre.Tactics)
	}
}

func handleMitreTechniques(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tactic := r.URL.Query().Get("tactic")
		if tactic == "" {
			writeJSON(w, 200, mitre.Techniques)
			return
		}
		writeJSON(w, 200, mitre.TechniquesByTactic(tactic))
	}
}

func handleProjectTechniques(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cov, err := mitre.ProjectCoverage(cfg.Store, chi.URLParam(r, "id"))
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		writeJSON(w, 200, cov)
	}
}
