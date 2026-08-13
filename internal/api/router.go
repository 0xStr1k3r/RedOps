package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/0xStr1k3r/RedOps/internal/auth"
	"github.com/0xStr1k3r/RedOps/internal/project"
)

// Config wires the HTTP layer.
type Config struct {
	Store     *project.Store
	JWTSecret string
	TokenTTL  time.Duration
}

// NewRouter builds the RedOps REST API. See docs/api.md.
func NewRouter(cfg Config) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP, middleware.Recoverer)
	r.Use(middleware.Timeout(15 * time.Second))

	r.Get("/healthz", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok", "service": "redops-api"})
	})
	mountGUI(r)

	r.Route("/api/v1", func(r chi.Router) {
		authLimit := newRateLimiter(10, time.Minute)
		r.Post("/auth/register", limitAuth(authLimit, handleRegister(cfg)))
		r.Post("/auth/login", limitAuth(authLimit, handleLogin(cfg)))
		// Static ATT&CK reference is public; per-project coverage needs auth.
		r.Get("/mitre/tactics", handleMitreTactics(cfg))
		r.Get("/mitre/techniques", handleMitreTechniques(cfg))

		r.Group(func(r chi.Router) {
			r.Use(requireAuth(cfg))
			r.Post("/projects", handleCreateProject(cfg))
			r.Get("/projects", handleListProjects(cfg))
			r.Get("/projects/{id}", handleGetProject(cfg))
			r.Post("/projects/{id}/scope", handleAddScope(cfg))
			r.Get("/projects/{id}/scope", handleListScope(cfg))
			r.Post("/projects/{id}/targets", handleAddTarget(cfg))
			r.Get("/projects/{id}/targets", handleListTargets(cfg))
			r.Get("/projects/{id}/timeline", handleTimeline(cfg))
			r.Post("/projects/{id}/recon", handleEnqueueRecon(cfg))
			r.Get("/projects/{id}/recon", handleListRecon(cfg))
			r.Get("/projects/{id}/recon/{jobID}", handleGetRecon(cfg))
			r.Get("/projects/{id}/hosts", handleListHosts(cfg))
			r.Get("/projects/{id}/services", handleListServices(cfg))
			r.Get("/projects/{id}/assets", handleAssets(cfg))
			r.Post("/projects/{id}/enumerate", handleEnqueueEnum(cfg))
			r.Get("/projects/{id}/enumerate", handleListEnum(cfg))
			r.Get("/projects/{id}/enumerate/{jobID}", handleGetEnum(cfg))
			r.Get("/projects/{id}/enum-results", handleListEnumResults(cfg))
			r.Post("/projects/{id}/findings", handleCreateFinding(cfg))
			r.Get("/projects/{id}/findings", handleListFindings(cfg))
			r.Get("/projects/{id}/findings/{fid}", handleGetFinding(cfg))
			r.Patch("/projects/{id}/findings/{fid}", handlePatchFinding(cfg))
			r.Post("/projects/{id}/findings/raise", handleRaiseFindings(cfg))
			r.Get("/projects/{id}/techniques", handleProjectTechniques(cfg))
			r.Get("/projects/{id}/graph", handleGraphJSON(cfg))
			r.Get("/projects/{id}/graph/cypher", handleGraphCypher(cfg))
			r.Post("/projects/{id}/graph/sync", handleGraphSync(cfg))
			r.Post("/projects/{id}/attack-paths/generate", handleGeneratePaths(cfg))
			r.Get("/projects/{id}/attack-paths", handleListPaths(cfg))
			r.Get("/projects/{id}/attack-paths/{pathID}", handleGetPath(cfg))
			r.Post("/projects/{id}/attack-paths/{pathID}/confirm", handleConfirmPath(cfg))
			r.Get("/validators", handleListValidators(cfg))
			r.Post("/projects/{id}/findings/{fid}/validate", handleValidateFinding(cfg))
			r.Get("/projects/{id}/findings/{fid}/validations", handleListValidationRuns(cfg))
			r.Get("/scenarios", handleListScenarios(cfg))
			r.Post("/projects/{id}/scenarios/{name}/run", handleRunScenario(cfg))
			r.Get("/projects/{id}/scenarios/runs", handleListScenarioRuns(cfg))
			r.Get("/projects/{id}/scenarios/runs/{runID}", handleGetScenarioRun(cfg))
			r.Get("/projects/{id}/evidence", handleListEvidence(cfg))
			r.Get("/projects/{id}/evidence/{eid}", handleGetEvidence(cfg))
			r.Get("/projects/{id}/evidence/verify", handleVerifyChain(cfg))
			r.Post("/projects/{id}/cloud/import", handleCloudImport(cfg))
			r.Get("/projects/{id}/cloud/assets", handleCloudAssets(cfg))
			r.Get("/projects/{id}/cloud/paths", handleCloudPaths(cfg))
			r.Get("/projects/{id}/insights", handleInsights(cfg))
			r.Get("/projects/{id}/techniques/layer", handleLayer(cfg))
			r.Post("/projects/{id}/report", handleReport(cfg))
		})
	})
	return r
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decodeJSON(req *http.Request, v any) error {
	defer req.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, req.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// --- auth handlers ---

func handleRegister(cfg Config) http.HandlerFunc {
	type req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in req
		if err := decodeJSON(r, &in); err != nil {
			writeErr(w, 400, "invalid JSON: "+err.Error())
			return
		}
		in.Username = strings.TrimSpace(in.Username)
		if in.Username == "" || len(in.Password) < 8 {
			writeErr(w, 400, "username required and password >= 8 chars")
			return
		}
		role := strings.ToLower(strings.TrimSpace(in.Role))
		n, _ := cfg.Store.CountUsers()
		if n == 0 {
			// First user bootstraps as admin regardless of requested role.
			role = auth.RoleAdmin
		} else {
			var err error
			role, err = auth.NormalizeRole(role)
			if err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			// Only admins may create operator/admin accounts after bootstrap.
			claims, _ := claimsFrom(r)
			if claims == nil || claims.Role != auth.RoleAdmin {
				role = auth.RoleViewer
			}
		}
		hash, err := auth.HashPassword(in.Password)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		id := newID()
		if err := cfg.Store.CreateUser(id, in.Username, hash, role, time.Now()); err != nil {
			writeErr(w, 409, "username already exists")
			return
		}
		_ = cfg.Store.AppendAudit("", in.Username, "auth.register", "", role)
		writeJSON(w, 201, map[string]string{"id": id, "username": in.Username, "role": role})
	}
}

func handleLogin(cfg Config) http.HandlerFunc {
	type req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in req
		if err := decodeJSON(r, &in); err != nil {
			writeErr(w, 400, "invalid JSON")
			return
		}
		id, hash, role, err := cfg.Store.GetUserByUsername(strings.TrimSpace(in.Username))
		if err != nil || !auth.VerifyPassword(hash, in.Password) {
			writeErr(w, 401, "invalid credentials")
			return
		}
		tok, err := auth.Issue(cfg.JWTSecret, id, strings.TrimSpace(in.Username), role, cfg.TokenTTL)
		if err != nil {
			writeErr(w, 500, "token issuance failed")
			return
		}
		_ = cfg.Store.AppendAudit("", in.Username, "auth.login", "", "ok")
		writeJSON(w, 200, map[string]string{"token": tok, "role": role})
	}
}

// --- project handlers ---

func handleCreateProject(cfg Config) http.HandlerFunc {
	type req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
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
		p, err := cfg.Store.CreateProject(in.Name, in.Description)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		_ = cfg.Store.AppendAudit(p.ID, actor(r), "project.create", p.Name, "ok")
		writeJSON(w, 201, p)
	}
}

func handleListProjects(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := cfg.Store.ListProjects()
		if err != nil {
			writeErr(w, 500, "list failed")
			return
		}
		if list == nil {
			list = []project.Project{}
		}
		writeJSON(w, 200, list)
	}
}

func handleGetProject(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := cfg.Store.GetProject(chi.URLParam(r, "id"))
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		writeJSON(w, 200, p)
	}
}

func handleAddScope(cfg Config) http.HandlerFunc {
	type req struct {
		Value string `json:"value"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !can(r, auth.RoleOperator) {
			writeErr(w, 403, "operator role required")
			return
		}
		var in req
		if err := decodeJSON(r, &in); err != nil || strings.TrimSpace(in.Value) == "" {
			writeErr(w, 400, "field 'value' required (CIDR, IP, or domain)")
			return
		}
		e, err := cfg.Store.AddScopeEntry(chi.URLParam(r, "id"), in.Value)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		_ = cfg.Store.AppendAudit(e.ProjectID, actor(r), "scope.add", e.Value, "ok")
		writeJSON(w, 201, e)
	}
}

func handleListScope(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := cfg.Store.ListScopes(chi.URLParam(r, "id"))
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		if list == nil {
			list = []project.ScopeEntry{}
		}
		writeJSON(w, 200, list)
	}
}

func handleAddTarget(cfg Config) http.HandlerFunc {
	type req struct {
		Value string `json:"value"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !can(r, auth.RoleOperator) {
			writeErr(w, 403, "operator role required")
			return
		}
		var in req
		if err := decodeJSON(r, &in); err != nil || strings.TrimSpace(in.Value) == "" {
			writeErr(w, 400, "field 'value' required")
			return
		}
		t, err := cfg.Store.AddTarget(chi.URLParam(r, "id"), in.Value, actor(r))
		if err != nil {
			// Scope denials are 403 to distinguish from bad input.
			if strings.Contains(err.Error(), "scope denied") || strings.Contains(err.Error(), "no valid scope") {
				_ = cfg.Store.AppendAudit(chi.URLParam(r, "id"), actor(r), "target.denied", in.Value, err.Error())
				writeErr(w, 403, err.Error())
				return
			}
			writeErr(w, 400, err.Error())
			return
		}
		_ = cfg.Store.AppendAudit(t.ProjectID, actor(r), "target.add", t.Value, "ok")
		writeJSON(w, 201, t)
	}
}

func handleListTargets(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := cfg.Store.ListTargets(chi.URLParam(r, "id"))
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		if list == nil {
			list = []project.Target{}
		}
		writeJSON(w, 200, list)
	}
}

func handleTimeline(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := cfg.Store.ListTimeline(chi.URLParam(r, "id"))
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		if list == nil {
			list = []project.TimelineEvent{}
		}
		writeJSON(w, 200, list)
	}
}
