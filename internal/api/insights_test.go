package api

import (
	"encoding/json"
	"testing"

	"github.com/redops/redops/internal/project"
)

func TestInsightsAndLayer(t *testing.T) {
	h, st := testRouter(t)
	tok := registerLogin(t, h, "alice", "password-123")

	rr := doReq(h, "POST", "/api/v1/projects", tok, `{"name":"acme"}`)
	var p map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	id := p["id"].(string)

	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/insights", tok, "")
	var insights []map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &insights)
	if len(insights) == 0 || insights[0]["link"] == "" {
		t.Fatalf("insights: %s", rr.Body.String())
	}

	_, _ = st.CreateFinding(id, project.FindingRow{Title: "CSP", Severity: "low", Target: "h:80", TechniqueID: "T1046"}, "k1")
	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/techniques/layer", tok, "")
	var layer map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &layer)
	if layer["domain"] != "enterprise-attack" {
		t.Fatalf("layer: %v", layer)
	}
	techs := layer["techniques"].([]any)
	if len(techs) != 1 || techs[0].(map[string]any)["techniqueID"] != "T1046" {
		t.Fatalf("layer techniques: %v", techs)
	}
	rr = doReq(h, "GET", "/api/v1/projects/nope/insights", tok, "")
	if rr.Code != 404 {
		t.Fatalf("unknown project must be 404, got %d", rr.Code)
	}
}
