package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/0xStr1k3r/RedOps/internal/project"
)

func TestReconEnqueueGate(t *testing.T) {
	h, _ := testRouter(t)
	tok := registerLogin(t, h, "alice", "password-123")

	rr := doReq(h, "POST", "/api/v1/projects", tok, `{"name":"acme"}`)
	var p map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	id := p["id"].(string)

	// No scope: recon must be 403.
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/recon", tok, `{"tool":"nmap","target":"10.10.10.10"}`)
	if rr.Code != 403 {
		t.Fatalf("expected 403 pre-scope, got %d %s", rr.Code, rr.Body.String())
	}
	_ = doReq(h, "POST", "/api/v1/projects/"+id+"/scope", tok, `{"value":"10.10.10.0/24"}`)

	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/recon", tok, `{"tool":"nmap","target":"10.10.10.10"}`)
	if rr.Code != 202 {
		t.Fatalf("enqueue: %d %s", rr.Code, rr.Body.String())
	}
	var job map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &job)

	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/recon", tok, `{"tool":"nmap","target":"8.8.8.8"}`)
	if rr.Code != 403 {
		t.Fatalf("out-of-scope recon must be 403, got %d", rr.Code)
	}
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/recon", tok, `{"tool":"evil","target":"10.10.10.10"}`)
	if rr.Code != 400 {
		t.Fatalf("unknown tool must be 400, got %d", rr.Code)
	}
	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/recon", tok, "")
	if rr.Code != 200 {
		t.Fatalf("list recon: %d", rr.Code)
	}
	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/assets", tok, "")
	if rr.Code != 200 {
		t.Fatalf("assets: %d", rr.Code)
	}
	_ = project.JobQueued
	_ = time.Now
}
