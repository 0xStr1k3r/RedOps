package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xStr1k3r/RedOps/internal/project"
)

func TestGraphEndpoints(t *testing.T) {
	h, st := testRouter(t)
	tok := registerLogin(t, h, "alice", "password-123")

	rr := doReq(h, "POST", "/api/v1/projects", tok, `{"name":"acme"}`)
	var p map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	id := p["id"].(string)
	_, _ = st.AddScopeEntry(id, "10.10.10.0/24")
	_, _ = st.AddTarget(id, "10.10.10.10", "alice")
	_ = st.UpsertHost(id, "10.10.10.10", "", "", "nmap")
	_ = st.UpsertService(id, "10.10.10.10", 80, "tcp", "open", "http", "nginx", "1.24")
	_, _ = st.CreateFinding(id, project.FindingRow{Title: "R", Severity: "info", Target: "10.10.10.10:80", TechniqueID: "T1594"}, "k1")

	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/graph", tok, "")
	if rr.Code != 200 {
		t.Fatalf("graph: %d", rr.Code)
	}
	var g map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &g)
	if len(g["nodes"].([]any)) != 6 || len(g["edges"].([]any)) != 6 {
		t.Fatalf("graph nodes/edges: %v stats %v", len(g["nodes"].([]any)), g["stats"])
	}

	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/graph/cypher", tok, "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "MERGE (n:Host") {
		t.Fatalf("cypher: %d %s", rr.Code, rr.Body.String()[:200])
	}

	// Unconfigured Neo4j → 501, not 500.
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/graph/sync", tok, ``)
	if rr.Code != 501 {
		t.Fatalf("sync unconfigured must be 501, got %d %s", rr.Code, rr.Body.String())
	}
	rr = doReq(h, "GET", "/api/v1/projects/nope/graph", tok, "")
	if rr.Code != 404 {
		t.Fatalf("unknown project must be 404, got %d", rr.Code)
	}
}
