package recon

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/0xStr1k3r/RedOps/internal/project"
	"github.com/0xStr1k3r/RedOps/internal/scope"
)

func testStore(t *testing.T) *project.Store {
	t.Helper()
	st, err := project.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestRegistry(t *testing.T) {
	for _, n := range []string{"nmap", "httpx", "dnsx", "subfinder"} {
		if _, err := Get(n); err != nil {
			t.Fatalf("tool %s missing: %v", n, err)
		}
	}
	if _, err := Get("nope"); err == nil {
		t.Fatal("unknown tool must error")
	}
}

func TestEnqueueScopeGate(t *testing.T) {
	st := testStore(t)
	p, _ := st.CreateProject("acme", "")
	if _, err := Enqueue(context.Background(), st, p.ID, "nmap", "10.10.10.10", "alice"); err == nil {
		t.Fatal("no scope yet must fail")
	}
	if _, err := st.AddScopeEntry(p.ID, "10.10.10.0/24"); err != nil {
		t.Fatal(err)
	}
	j, err := Enqueue(context.Background(), st, p.ID, "nmap", "10.10.10.10", "alice")
	if err != nil || j.Status != project.JobQueued {
		t.Fatalf("in-scope enqueue failed: %v", j)
	}
	if _, err := Enqueue(context.Background(), st, p.ID, "nmap", "8.8.8.8", "alice"); err == nil {
		t.Fatal("out-of-scope must fail")
	} else if !strings.Contains(err.Error(), "scope denied") {
		t.Fatalf("expected scope denied, got %v", err)
	}
	// Wrong capability: dnsx needs a domain.
	if _, err := Enqueue(context.Background(), st, p.ID, "dnsx", "10.10.10.10", "alice"); err == nil {
		t.Fatal("dnsx on IP must fail")
	}
}

func TestValidateOptions(t *testing.T) {
	if err := ValidateOptions(Options{Ports: "80,443"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOptions(Options{Ports: "80; rm -rf /"}); err == nil {
		t.Fatal("injection ports must fail")
	}
	if err := ValidateOptions(Options{Profile: "evil"}); err == nil {
		t.Fatal("bad profile must fail")
	}
}

// fakeTool lets RunJob be tested without binaries.
type fakeTool struct{ out []byte }

func (f fakeTool) Name() string                  { return "faketool" }
func (f fakeTool) Binary() string                { return "faketool" }
func (f fakeTool) Description() string           { return "test" }
func (f fakeTool) Supports(scope.EntryType) bool { return true }
func (f fakeTool) Execute(context.Context, *scope.Scope, string, Options) ([]byte, error) {
	return f.out, nil
}
func (f fakeTool) Parse(output []byte) (Result, error) {
	if string(output) == "two" {
		return Result{
			Hosts:    []Host{{IP: "10.10.10.10", Hostname: "web01.lab"}},
			Services: []Service{{HostIP: "10.10.10.10", Port: 80, Protocol: "tcp", State: "open", Name: "http"}},
			Summary:  "1 hosts, 1 services",
		}, nil
	}
	return Result{Summary: "empty"}, nil
}

func TestRunJobSavesAssets(t *testing.T) {
	Register(fakeTool{out: []byte("two")})
	// allowlist lives in project package; bypass Enqueue and insert directly.
	st := testStore(t)
	p, _ := st.CreateProject("acme", "")
	_, _ = st.AddScopeEntry(p.ID, "10.10.10.0/24")
	j := &project.ReconJob{ID: "j1", ProjectID: p.ID, Tool: "faketool", Target: "10.10.10.10", Status: project.JobQueued, CreatedBy: "alice"}
	// Insert job row manually via Enqueue with nmap then rewrite tool for the test.
	nj, err := st.EnqueueReconJob(p.ID, "nmap", "10.10.10.10", "alice")
	if err != nil {
		t.Fatal(err)
	}
	nj.Tool = "faketool"
	nj.Target = "10.10.10.10"
	_ = j
	if err := RunJob(context.Background(), st, nj, Options{}); err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	hosts, _ := st.ListHosts(p.ID)
	if len(hosts) != 1 || hosts[0].IP != "10.10.10.10" {
		t.Fatalf("hosts not saved: %+v", hosts)
	}
	svcs, _ := st.ListServices(p.ID)
	if len(svcs) != 1 || svcs[0].Port != 80 {
		t.Fatalf("services not saved: %+v", svcs)
	}
	got, _ := st.GetReconJob(p.ID, nj.ID)
	if got.Status != project.JobDone {
		t.Fatalf("job not done: %+v", got)
	}
}

func TestNmapParseTestdata(t *testing.T) {
	tool, _ := Get("nmap")
	data, err := os.ReadFile("../../pkg/nmap/testdata/scan.xml")
	if err != nil {
		t.Skip("no testdata")
	}
	res, err := tool.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 1 || len(res.Services) != 2 {
		t.Fatalf("unexpected %+v", res)
	}
}
