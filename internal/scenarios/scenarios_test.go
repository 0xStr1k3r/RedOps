package scenarios

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/redops/redops/internal/project"
)

func TestCatalogValid(t *testing.T) {
	knownTools := map[string]bool{"nmap": true, "httpx": true, "dnsx": true, "subfinder": true, "": true}
	knownKinds := map[string]bool{KindRecon: true, KindEnum: true, KindRaise: true, KindValidate: true, KindPaths: true}
	for _, sc := range Catalog() {
		if len(sc.Steps) == 0 {
			t.Fatalf("%s has no steps", sc.Name)
		}
		for _, step := range sc.Steps {
			if !knownKinds[step.Kind] {
				t.Errorf("%s step %s: bad kind %q", sc.Name, step.Name, step.Kind)
			}
			if step.Kind == KindRecon && !knownTools[step.Tool] {
				t.Errorf("%s step %s: bad tool %q", sc.Name, step.Name, step.Tool)
			}
		}
	}
	if _, err := Get("nope"); err == nil {
		t.Fatal("unknown scenario must error")
	}
}

func TestRunDeniedOutOfScope(t *testing.T) {
	st, err := project.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p, _ := st.CreateProject("acme", "")
	_, _ = st.AddScopeEntry(p.ID, "10.10.10.0/24")
	if _, err := Run(context.Background(), st, p.ID, "8.8.8.8", "alice", "web-to-admin"); err == nil {
		t.Fatal("out-of-scope scenario must fail before any step")
	}
	runs, _ := st.ListScenarioRuns(p.ID)
	if len(runs) != 0 {
		t.Fatal("denied run must not create a row")
	}
}

// TestPlatformSteps runs the enum→raise→validate→paths chain (the same
// functions Run uses) against a local HTTP server with seeded inventory.
func TestPlatformSteps(t *testing.T) {
	st, err := project.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p, _ := st.CreateProject("acme", "")
	_, _ = st.AddScopeEntry(p.ID, "127.0.0.0/8")

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24")
		w.Write([]byte("<html><head><title>Admin Console</title></head></html>"))
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("User-agent: *\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	hostport := strings.TrimPrefix(srv.URL, "http://")
	host, portStr, _ := strings.Cut(hostport, ":")
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	_ = st.UpsertHost(p.ID, host, "", "", "test")
	_ = st.UpsertService(p.ID, host, port, "tcp", "open", "http", "nginx", "1.24")

	ctx := context.Background()
	enumRes := runStep(ctx, st, p.ID, host, "alice", Step{Name: "web-enumeration", Kind: KindEnum, Tool: "http"})
	if !enumRes.Success {
		t.Fatalf("enum step: %s", enumRes.Detail)
	}
	raiseRes := runStep(ctx, st, p.ID, host, "alice", Step{Name: "finding-triage", Kind: KindRaise})
	if !raiseRes.Success || !strings.Contains(raiseRes.Detail, "raised") {
		t.Fatalf("raise step: %+v", raiseRes)
	}
	valRes := runStep(ctx, st, p.ID, hostport, "alice", Step{Name: "finding-validation", Kind: KindValidate})
	if !valRes.Success {
		t.Fatalf("validate step: %+v", valRes)
	}
	pathsRes := runStep(ctx, st, p.ID, host, "alice", Step{Name: "path-analysis", Kind: KindPaths})
	if !pathsRes.Success {
		t.Fatalf("paths step: %+v", pathsRes)
	}
	// Findings were raised and at least the robots one validated.
	rows, _ := st.ListFindings(p.ID, project.FindingFilter{})
	if len(rows) == 0 {
		t.Fatal("expected findings from the chain")
	}
}
