package api

import (
	"encoding/json"
	"testing"
)

func TestEnumGate(t *testing.T) {
	h, _ := testRouter(t)
	tok := registerLogin(t, h, "alice", "password-123")

	rr := doReq(h, "POST", "/api/v1/projects", tok, `{"name":"acme"}`)
	var p map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	id := p["id"].(string)

	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/enumerate", tok, `{"host":"10.10.10.10","port":80}`)
	if rr.Code != 403 {
		t.Fatalf("expected 403 pre-scope, got %d %s", rr.Code, rr.Body.String())
	}
	_ = doReq(h, "POST", "/api/v1/projects/"+id+"/scope", tok, `{"value":"10.10.10.0/24"}`)

	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/enumerate", tok, `{"host":"10.10.10.10","port":80}`)
	if rr.Code != 202 {
		t.Fatalf("enqueue: %d %s", rr.Code, rr.Body.String())
	}
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/enumerate", tok, `{"host":"8.8.8.8","port":80}`)
	if rr.Code != 403 {
		t.Fatalf("out-of-scope must be 403, got %d", rr.Code)
	}
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/enumerate", tok, `{"host":"10.10.10.10","port":80,"module":"evil"}`)
	if rr.Code != 400 {
		t.Fatalf("unknown module must be 400, got %d", rr.Code)
	}
	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/enum-results", tok, "")
	if rr.Code != 200 {
		t.Fatalf("enum-results: %d", rr.Code)
	}
}
