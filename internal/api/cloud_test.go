package api

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCloudFlow(t *testing.T) {
	h, _ := testRouter(t)
	tok := registerLogin(t, h, "alice", "password-123")

	rr := doReq(h, "POST", "/api/v1/projects", tok, `{"name":"acme"}`)
	var p map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	id := p["id"].(string)

	// No import yet → 404s.
	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/cloud/paths", tok, "")
	if rr.Code != 404 {
		t.Fatalf("expected 404 pre-import, got %d", rr.Code)
	}
	// Invalid import → 400.
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/cloud/import", tok, `{"users":[{"name":"u","policies":["Missing"]}]}`)
	if rr.Code != 400 {
		t.Fatalf("bad import must be 400, got %d %s", rr.Code, rr.Body.String())
	}
	data, err := os.ReadFile("../../lab/cloud-iam-example.json")
	if err != nil {
		t.Fatal(err)
	}
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/cloud/import", tok, string(data))
	if rr.Code != 200 {
		t.Fatalf("import: %d %s", rr.Code, rr.Body.String())
	}
	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/cloud/paths", tok, "")
	var paths []map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &paths)
	if len(paths) != 2 {
		t.Fatalf("paths: %s", rr.Body.String())
	}
	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/cloud/assets", tok, "")
	var assets map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &assets)
	if assets["stats"].(map[string]any)["Role"].(float64) != 3 {
		t.Fatalf("assets: %v", assets["stats"])
	}
	// Unified graph now includes cloud nodes.
	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/graph", tok, "")
	var g map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &g)
	if g["stats"].(map[string]any)["User"] == nil {
		t.Fatalf("graph missing cloud users: %v", g["stats"])
	}
	// Viewer cannot import.
	tok2 := registerLogin(t, h, "bob", "password-123")
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/cloud/import", tok2, string(data))
	if rr.Code != 403 {
		t.Fatalf("viewer import must be 403, got %d", rr.Code)
	}
}
