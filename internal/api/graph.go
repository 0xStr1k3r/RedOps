package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/redops/redops/internal/attackgraph"
	"github.com/redops/redops/internal/auth"
)

func handleGraphJSON(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g, err := attackgraph.Build(cfg.Store, chi.URLParam(r, "id"))
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		writeJSON(w, 200, map[string]any{"nodes": g.Nodes, "edges": g.Edges, "stats": g.Stats()})
	}
}

func handleGraphCypher(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g, err := attackgraph.Build(cfg.Store, chi.URLParam(r, "id"))
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(attackgraph.ToCypher(g)))
	}
}

func handleGraphSync(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !can(r, auth.RoleOperator) {
			writeErr(w, 403, "operator role required")
			return
		}
		g, err := attackgraph.Build(cfg.Store, chi.URLParam(r, "id"))
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		uri, user, pass := attackgraph.ConfigFromEnv()
		if uri == "" {
			writeErr(w, 501, "neo4j not configured (set REDOPS_NEO4J_URI/USER/PASS)")
			return
		}
		if err := attackgraph.Sync(r.Context(), uri, user, pass, g); err != nil {
			if strings.Contains(err.Error(), "unreachable") {
				writeErr(w, 502, err.Error())
				return
			}
			writeErr(w, 500, err.Error())
			return
		}
		_ = cfg.Store.AppendAudit(chi.URLParam(r, "id"), actor(r), "graph.sync", uri, "ok")
		writeJSON(w, 200, map[string]any{"synced_nodes": len(g.Nodes), "synced_edges": len(g.Edges)})
	}
}
