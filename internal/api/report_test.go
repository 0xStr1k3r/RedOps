package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReportFlow(t *testing.T) {
	h, _ := testRouter(t)
	tok := registerLogin(t, h, "alice", "password-123")

	rr := doReq(h, "POST", "/api/v1/projects", tok, `{"name":"acme"}`)
	var p map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	id := p["id"].(string)

	for _, format := range []string{"markdown", "html", "pdf"} {
		rr = doReq(h, "POST", "/api/v1/projects/"+id+"/report?format="+format, tok, ``)
		if rr.Code != 200 {
			t.Fatalf("%s: %d %s", format, rr.Code, rr.Body.String()[:100])
		}
	}
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/report?format=markdown", tok, ``)
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "text/markdown") {
		t.Fatalf("content type: %s", ct)
	}
	if !strings.Contains(rr.Body.String(), "# RedOps Assessment Report") {
		t.Fatal("markdown body wrong")
	}
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/report?format=pdf", tok, ``)
	if ct := rr.Header().Get("Content-Type"); ct != "application/pdf" {
		t.Fatalf("pdf content type: %s", ct)
	}
	if !strings.HasPrefix(rr.Body.String(), "%PDF") {
		t.Fatal("pdf body wrong")
	}
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/report?format=docx", tok, ``)
	if rr.Code != 400 {
		t.Fatalf("bad format must be 400, got %d", rr.Code)
	}
	rr = doReq(h, "POST", "/api/v1/projects/nope/report", tok, ``)
	if rr.Code != 404 {
		t.Fatalf("unknown project must be 404, got %d", rr.Code)
	}
	// Viewers can read reports (read-only role).
	tok2 := registerLogin(t, h, "bob", "password-123")
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/report?format=html", tok2, ``)
	if rr.Code != 200 {
		t.Fatalf("viewer report must be 200, got %d", rr.Code)
	}
}
