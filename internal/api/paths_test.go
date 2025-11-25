package api

import (
	"encoding/json"
	"testing"

	"github.com/redops/redops/internal/project"
)

func TestPathsFlow(t *testing.T) {
	h, st := testRouter(t)
	tok := registerLogin(t, h, "alice", "password-123")

	rr := doReq(h, "POST", "/api/v1/projects", tok, `{"name":"acme"}`)
	var p map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	id := p["id"].(string)
	_, _ = st.AddScopeEntry(id, "10.10.10.0/24")
	_, _ = st.AddTarget(id, "10.10.10.10", "alice")
	_ = st.UpsertHost(id, "10.10.10.10", "", "", "nmap")
	_ = st.UpsertService(id, "10.10.10.10", 443, "tcp", "open", "https", "", "")
	_, _ = st.CreateFinding(id, project.FindingRow{Title: "Weak TLS", Severity: "high", Target: "10.10.10.10:443", TechniqueID: "T1046"}, "k1")

	// Empty before generate.
	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/attack-paths", tok, "")
	var empty []any
	_ = json.Unmarshal(rr.Body.Bytes(), &empty)
	if len(empty) != 0 {
		t.Fatalf("expected no paths, got %v", len(empty))
	}

	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/attack-paths/generate", tok, ``)
	var gen map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &gen)
	if gen["generated"].(float64) == 0 {
		t.Fatal("expected paths generated")
	}

	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/attack-paths?min_risk=75", tok, "")
	var list []map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if len(list) == 0 {
		t.Fatal("expected high-risk paths")
	}
	if list[0]["confidence"] != "observed" {
		t.Fatalf("engine confidence must be observed, got %v", list[0]["confidence"])
	}
	pid := list[0]["id"].(string)

	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/attack-paths/"+pid, tok, "")
	if rr.Code != 200 {
		t.Fatalf("get path: %d", rr.Code)
	}
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/attack-paths/"+pid+"/confirm", tok, `{"confidence":"validated"}`)
	if rr.Code != 200 {
		t.Fatalf("confirm: %d %s", rr.Code, rr.Body.String())
	}
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/attack-paths/"+pid+"/confirm", tok, `{"confidence":"observed"}`)
	if rr.Code != 400 {
		t.Fatalf("downgrade via confirm must be 400, got %d", rr.Code)
	}
	// Viewer cannot generate.
	tok2 := registerLogin(t, h, "bob", "password-123")
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/attack-paths/generate", tok2, ``)
	if rr.Code != 403 {
		t.Fatalf("viewer generate must be 403, got %d", rr.Code)
	}
}
