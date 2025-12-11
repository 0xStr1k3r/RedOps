package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/redops/redops/internal/project"
)

func TestValidationFlow(t *testing.T) {
	h, st := testRouter(t)
	tok := registerLogin(t, h, "alice", "password-123")

	rr := doReq(h, "GET", "/api/v1/validators", tok, "")
	if rr.Code != 200 {
		t.Fatalf("validators: %d", rr.Code)
	}
	var validators []map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &validators)
	if len(validators) != 6 {
		t.Fatalf("expected 6 validators, got %d", len(validators))
	}

	rr = doReq(h, "POST", "/api/v1/projects", tok, `{"name":"acme"}`)
	var p map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	id := p["id"].(string)
	_, _ = st.AddScopeEntry(id, "127.0.0.0/8")

	// Live local HTTP server as the validation target.
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "User-agent: *\n")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	hostport := srv.Listener.Addr().String()

	_, _ = st.CreateFinding(id, project.FindingRow{Title: "Exposed robots.txt", Severity: "info", Target: hostport, TechniqueID: "T1594"}, "k1")
	rows, _ := st.ListFindings(id, project.FindingFilter{})

	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/findings/"+rows[0].ID+"/validate", tok, ``)
	if rr.Code != 200 {
		t.Fatalf("validate: %d %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["promoted"] != true {
		t.Fatalf("expected promotion, got %v", out)
	}
	after, _ := st.GetFinding(id, rows[0].ID)
	if after.Confidence != "validated" {
		t.Fatalf("confidence: %s", after.Confidence)
	}

	rr = doReq(h, "GET", "/api/v1/projects/"+id+"/findings/"+rows[0].ID+"/validations", tok, "")
	var runs []map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &runs)
	if len(runs) != 1 {
		t.Fatalf("runs: %s", rr.Body.String())
	}

	// Viewer cannot validate.
	tok2 := registerLogin(t, h, "bob", "password-123")
	rr = doReq(h, "POST", "/api/v1/projects/"+id+"/findings/"+rows[0].ID+"/validate", tok2, ``)
	if rr.Code != 403 {
		t.Fatalf("viewer validate must be 403, got %d", rr.Code)
	}
}
