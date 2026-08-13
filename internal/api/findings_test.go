package api

import (
	"encoding/json"
	"testing"

	"github.com/0xStr1k3r/RedOps/internal/project"
)

func TestFindingsFlow(t *testing.T) {
	h, st := testRouter(t)
	tok := registerLogin(t, h, "alice", "password-123")

	rr := doReq(h, "POST", "/api/v1/projects", tok, `{"name":"acme"}`)
	var p map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	id := p["id"].(string)

	// Manual create + validation.
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/findings", tok, `{"title":"","target":"x"}`)
	if rr.Code != 400 {
		t.Fatalf("empty title must be 400, got %d", rr.Code)
	}
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/findings", tok, `{"title":"Weak TLS","severity":"high","confidence":"observed","target":"10.0.0.1:443","cwe":"CWE-327"}`)
	if rr.Code != 201 {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/findings?severity=high", tok, "")
	var list []map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Fatalf("filter: %s", rr.Body.String())
	}
	fid := list[0]["id"].(string)

	// Patch workflow.
	rr = doReq(h, "PATCH", "/api/v1/projects/"+id+"/findings/"+fid, tok, `{"status":"acknowledged","confidence":"validated"}`)
	if rr.Code != 200 {
		t.Fatalf("patch: %d %s", rr.Code, rr.Body.String())
	}
	rr = doReq(h, "PATCH", "/api/v1/projects/"+id+"/findings/"+fid, tok, `{"status":"bogus"}`)
	if rr.Code != 400 {
		t.Fatalf("bad status must be 400, got %d", rr.Code)
	}

	// Auto-raise from seeded enum results (idempotent).
	_ = st.SaveEnumResult(id, "job1", "10.0.0.1", 80, "http", "test", []project.EnumObservation{
		{Kind: "http-robots", Detail: "/robots.txt present", TechniqueID: "T1594"},
		{Kind: "http-missing-header", Detail: "missing Content-Security-Policy", TechniqueID: "T1046"},
	})
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/findings/raise", tok, ``)
	if rr.Code != 200 {
		t.Fatalf("raise: %d %s", rr.Code, rr.Body.String())
	}
	var raised map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &raised)
	if raised["raised"].(float64) != 2 {
		t.Fatalf("expected 2 raised, got %v", raised)
	}
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/findings/raise", tok, ``)
	_ = json.Unmarshal(rr.Body.Bytes(), &raised)
	if raised["raised"].(float64) != 0 {
		t.Fatalf("re-raise must be idempotent, got %v", raised)
	}
	// Viewer cannot write.
	tok2 := registerLogin(t, h, "bob", "password-123")
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/findings", tok2, `{"title":"x","target":"y"}`)
	if rr.Code != 403 {
		t.Fatalf("viewer write must be 403, got %d", rr.Code)
	}
}
