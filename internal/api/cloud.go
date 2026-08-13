package api

import (
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/0xStr1k3r/RedOps/internal/auth"
	"github.com/0xStr1k3r/RedOps/internal/cloud"
)

func handleCloudImport(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !can(r, auth.RoleOperator) {
			writeErr(w, 403, "operator role required")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			writeErr(w, 400, "body too large (max 1MB)")
			return
		}
		if _, err := cloud.ParseImport(raw); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		pid := chi.URLParam(r, "id")
		if err := cfg.Store.SaveCloudImport(pid, string(raw), actor(r)); err != nil {
			writeErr(w, 404, err.Error())
			return
		}
		writeJSON(w, 200, map[string]string{"status": "imported"})
	}
}

func handleCloudAssets(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		doc, err := cfg.Store.GetCloudImport(chi.URLParam(r, "id"))
		if err != nil || doc == "" {
			writeErr(w, 404, "no cloud import for project")
			return
		}
		g, err := cloud.ToGraphFromDocument(doc)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"nodes": g.Nodes, "edges": g.Edges, "stats": g.Stats()})
	}
}

func handleCloudPaths(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		doc, err := cfg.Store.GetCloudImport(chi.URLParam(r, "id"))
		if err != nil || doc == "" {
			writeErr(w, 404, "no cloud import for project")
			return
		}
		imp, err := cloud.ParseImport([]byte(doc))
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		paths := cloud.FindPaths(imp)
		if paths == nil {
			paths = []cloud.Path{}
		}
		writeJSON(w, 200, paths)
	}
}
