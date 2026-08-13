package api

import (
	"encoding/json"
	"testing"

	"github.com/0xStr1k3r/RedOps/internal/project"
)

func TestMitreEndpoints(t *testing.T) {
	h, st := testRouter(t)

	// Public reference endpoints need no token.
	rr := doReq(h, "GET", "/api/v1/mitre/tactics", "", "")
	if rr.Code != 200 {
		t.Fatalf("tactics: %d", rr.Code)
	}
	var tactics []map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &tactics)
	if len(tactics) != 14 {
		t.Fatalf("expected 14 tactics, got %d", len(tactics))
	}
	rr = doReq(h, "GET", "/api/v1/mitre/techniques?tactic=Discovery", "", "")
	var techs []map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &techs)
	if len(techs) < 5 {
		t.Fatalf("discovery techniques: %d", len(techs))
	}

	// Project coverage behind auth.
	tok := registerLogin(t, h, "alice", "password-123")
	rr = doReq(h, "POST", "/api/v1/projects", tok, `{"name":"acme"}`)
	var p map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	id := p["id"].(string)
	_, _ = st.CreateFinding(id, project.FindingRow{Title: "CSP", Severity: "low", Target: "h:80", TechniqueID: "T1046"}, "k1")

	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/techniques", tok, "")
	if rr.Code != 200 {
		t.Fatalf("coverage: %d %s", rr.Code, rr.Body.String())
	}
	var cov map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &cov)
	if cov["seen"].(float64) != 1 {
		t.Fatalf("coverage: %v", cov)
	}
	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/techniques", "", "")
	if rr.Code != 401 {
		t.Fatalf("coverage without token must be 401, got %d", rr.Code)
	}
}
