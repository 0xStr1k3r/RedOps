package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/0xStr1k3r/RedOps/internal/insights"
	"github.com/0xStr1k3r/RedOps/internal/mitre"
)

func handleInsights(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := insights.Compute(cfg.Store, chi.URLParam(r, "id"))
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

func handleLayer(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		l, err := mitre.ToLayer(cfg.Store, chi.URLParam(r, "id"))
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=redops-layer.json")
		writeJSON(w, 200, l)
	}
}
