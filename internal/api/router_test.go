package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/redops/redops/internal/project"
)

func testRouter(t *testing.T) (http.Handler, *project.Store) {
	t.Helper()
	st, err := project.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h := NewRouter(Config{Store: st, JWTSecret: "test-secret-32-bytes-minimum-abcdef", TokenTTL: time.Hour})
	return h, st
}

func doReq(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func registerLogin(t *testing.T, h http.Handler, user, pass string) string {
	t.Helper()
	rr := doReq(h, "POST", "/api/v1/auth/register", "", `{"username":"`+user+`","password":"`+pass+`"}`)
	if rr.Code != 201 {
		t.Fatalf("register %s: %d %s", user, rr.Code, rr.Body.String())
	}
	rr = doReq(h, "POST", "/api/v1/auth/login", "", `{"username":"`+user+`","password":"`+pass+`"}`)
	if rr.Code != 200 {
		t.Fatalf("login %s: %d %s", user, rr.Code, rr.Body.String())
	}
	var out map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["token"] == "" {
		t.Fatal("no token returned")
	}
	return out["token"]
}

func TestScopeEnforcementEndToEnd(t *testing.T) {
	h, _ := testRouter(t)
	tok := registerLogin(t, h, "alice", "password-123")

	rr := doReq(h, "POST", "/api/v1/projects", tok, `{"name":"acme","description":"lab"}`)
	if rr.Code != 201 {
		t.Fatalf("create project: %d %s", rr.Code, rr.Body.String())
	}
	var p map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	id := p["id"].(string)

	// Target before scope must be denied (403).
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/targets", tok, `{"value":"10.10.10.10"}`)
	if rr.Code != 403 {
		t.Fatalf("expected 403 pre-scope, got %d %s", rr.Code, rr.Body.String())
	}

	// Add scope, then in-scope target succeeds.
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/scope", tok, `{"value":"10.10.10.0/24"}`)
	if rr.Code != 201 {
		t.Fatalf("add scope: %d %s", rr.Code, rr.Body.String())
	}
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/targets", tok, `{"value":"10.10.10.10"}`)
	if rr.Code != 201 {
		t.Fatalf("in-scope target: %d %s", rr.Code, rr.Body.String())
	}
	// Out-of-scope must be 403 and audited.
	for _, bad := range []string{"8.8.8.8", "192.168.1.10", "example.com"} {
		rr = doReq(h, "POST", "/api/v1/projects/"+id+"/targets", tok, `{"value":"`+bad+`"}`)
		if rr.Code != 403 {
			t.Fatalf("expected 403 for %s, got %d %s", bad, rr.Code, rr.Body.String())
		}
	}
	// Viewer cannot create projects.
	tok2 := registerLogin(t, h, "bob", "password-123")
	rr = doReq(h, "POST", "/api/v1/projects", tok2, `{"name":"evil"}`)
	if rr.Code != 403 {
		t.Fatalf("viewer create must be 403, got %d", rr.Code)
	}
}

func TestAuthRequired(t *testing.T) {
	h, _ := testRouter(t)
	rr := doReq(h, "GET", "/api/v1/projects", "", "")
	if rr.Code != 401 {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}
