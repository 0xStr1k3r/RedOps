package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/0xStr1k3r/RedOps/internal/project"
)

func TestEvidenceFlow(t *testing.T) {
	h, st := testRouter(t)
	tok := registerLogin(t, h, "alice", "password-123")

	rr := doReq(h, "POST", "/api/v1/projects", tok, `{"name":"acme"}`)
	var p map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	id := p["id"].(string)

	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/evidence/verify", tok, "")
	var v map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &v)
	if v["ok"] != true || v["checked"].(float64) != 0 {
		t.Fatalf("empty chain: %s", rr.Body.String())
	}

	_, _ = st.RecordEvidence(id, project.EvidenceRow{
		ID: uuid.NewString(), ProjectID: id, Timestamp: time.Now().UTC(),
		Operator: "alice", Target: "10.0.0.1", Action: "recon.nmap",
	})
	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/evidence", tok, "")
	var list []map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Fatalf("expected 1 record, got %s", rr.Body.String())
	}
	eid := list[0]["id"].(string)
	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/evidence/"+eid, tok, "")
	if rr.Code != 200 {
		t.Fatalf("get evidence: %d", rr.Code)
	}
	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/evidence/nope", tok, "")
	if rr.Code != 404 {
		t.Fatalf("missing evidence must be 404, got %d", rr.Code)
	}
	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/evidence/verify", tok, "")
	_ = json.Unmarshal(rr.Body.Bytes(), &v)
	if v["ok"] != true || v["checked"].(float64) != 1 {
		t.Fatalf("chain: %s", rr.Body.String())
	}
}
