package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func handleListEvidence(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := cfg.Store.ListEvidence(chi.URLParam(r, "id"))
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

func handleGetEvidence(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		e, err := cfg.Store.GetEvidence(chi.URLParam(r, "id"), chi.URLParam(r, "eid"))
		if err != nil {
			writeErr(w, 404, "evidence not found")
			return
		}
		writeJSON(w, 200, e)
	}
}

func handleVerifyChain(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := cfg.Store.VerifyEvidenceChain(chi.URLParam(r, "id"))
		writeJSON(w, 200, status)
	}
}
