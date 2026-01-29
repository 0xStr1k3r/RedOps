package api

import (
	"encoding/json"
	"testing"
	"time"
)

func TestScenarioFlow(t *testing.T) {
	h, _ := testRouter(t)
	tok := registerLogin(t, h, "alice", "password-123")

	rr := doReq(h, "GET", "/api/v1/scenarios", tok, "")
	var catalog []map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &catalog)
	if len(catalog) != 2 {
		t.Fatalf("catalog: %s", rr.Body.String())
	}

	rr = doReq(h, "POST", "/api/v1/projects", tok, `{"name":"acme"}`)
	var p map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	id := p["id"].(string)

	// Unknown scenario → 400; out-of-scope → 403.
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/scenarios/nope/run", tok, `{"target":"10.0.0.1"}`)
	if rr.Code != 400 {
		t.Fatalf("unknown scenario must be 400, got %d", rr.Code)
	}
	_ = doReq(h, "POST", "/api/v1/projects/"+id+"/scope", tok, `{"value":"10.10.10.0/24"}`)
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/scenarios/web-to-admin/run", tok, `{"target":"8.8.8.8"}`)
	if rr.Code != 403 {
		t.Fatalf("out-of-scope run must be 403, got %d", rr.Code)
	}

	// Launch against in-scope target (nmap missing in CI → run fails
	// gracefully in background; the API contract is 202 + pollable row).
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/scenarios/web-to-admin/run", tok, `{"target":"10.10.10.10"}`)
	if rr.Code != 202 {
		t.Fatalf("run must be 202, got %d %s", rr.Code, rr.Body.String())
	}
	var run map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &run)
	rid := run["id"].(string)

	// Poll until terminal (background goroutine shares the test DB).
	deadline := time.Now().Add(30 * time.Second)
	for {
		rr = doReq(h, "GET", "/api/v1/projects/"+id+"/scenarios/runs/"+rid, tok, "")
		var got map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &got)
		if got["status"] == "done" || got["status"] == "failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("run never finished: %v", got["status"])
		}
		time.Sleep(200 * time.Millisecond)
	}
	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/scenarios/runs", tok, "")
	var runs []map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &runs)
	if len(runs) != 1 {
		t.Fatalf("runs: %s", rr.Body.String())
	}
	// Viewer cannot launch.
	tok2 := registerLogin(t, h, "bob", "password-123")
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/scenarios/web-to-admin/run", tok2, `{"target":"10.10.10.10"}`)
	if rr.Code != 403 {
		t.Fatalf("viewer run must be 403, got %d", rr.Code)
	}
}
