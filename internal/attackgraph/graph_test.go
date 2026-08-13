package attackgraph

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0xStr1k3r/RedOps/internal/project"
)

func seedStore(t *testing.T) (*project.Store, string) {
	t.Helper()
	st, err := project.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	p, _ := st.CreateProject("acme", "")
	_, _ = st.AddScopeEntry(p.ID, "10.10.10.0/24")
	_, _ = st.AddTarget(p.ID, "10.10.10.10", "alice")
	_ = st.UpsertHost(p.ID, "10.10.10.10", "web01.lab", "Linux", "nmap")
	_ = st.UpsertService(p.ID, "10.10.10.10", 80, "tcp", "open", "http", "nginx", "1.24")
	_ = st.SaveEnumResult(p.ID, "j1", "10.10.10.10", 80, "http", "s", []project.EnumObservation{
		{Kind: "http-robots", Detail: "robots", TechniqueID: "T1594"},
	})
	_, _ = st.CreateFinding(p.ID, project.FindingRow{Title: "Robots", Severity: "info", Target: "10.10.10.10:80", TechniqueID: "T1594"}, "k1")
	_, _ = st.CreateFinding(p.ID, project.FindingRow{Title: "Orphan", Severity: "low", Target: "unknown"}, "k2")
	return st, p.ID
}

func TestBuild(t *testing.T) {
	st, pid := seedStore(t)
	g, err := Build(st, pid)
	if err != nil {
		t.Fatal(err)
	}
	stats := g.Stats()
	if stats[KindHost] != 1 || stats[KindService] != 1 || stats[KindFinding] != 2 || stats[KindTechnique] != 1 || stats[KindTarget] != 1 {
		t.Fatalf("stats %+v", stats)
	}
	// Every edge has a reason; finding attaches to service; orphan to project.
	types := map[string]int{}
	for _, e := range g.Edges {
		if e.Reason == "" {
			t.Fatalf("edge without reason %+v", e)
		}
		types[e.Type]++
	}
	if types[EdgeRuns] != 1 || types[EdgeHasFinding] != 2 || types[EdgeMapsTo] != 1 || types[EdgeMatches] != 1 {
		t.Fatalf("edges %+v", types)
	}
	if _, err := Build(st, "nope"); err == nil {
		t.Fatal("unknown project must fail")
	}
}

func TestExports(t *testing.T) {
	st, pid := seedStore(t)
	g, _ := Build(st, pid)
	cy := ToCypher(g)
	for _, want := range []string{"MERGE (n:Host", "MERGE (n:Service", "MERGE (a)-[r:RUNS", "MERGE (a)-[r:MAPS_TO", "reason:"} {
		if !strings.Contains(cy, want) {
			t.Errorf("cypher missing %q", want)
		}
	}
	dot := ToDOT(g)
	if !strings.Contains(dot, "digraph redops") || !strings.Contains(dot, "T1594") {
		t.Errorf("dot looks wrong:\n%s", dot)
	}
}

func TestSyncValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Sync(ctx, "", "", "", &Graph{}); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("empty URI must report unconfigured, got %v", err)
	}
	bad := &Graph{Nodes: []Node{{ID: "x", Kind: "Evil"}}}
	if err := Sync(ctx, "bolt://127.0.0.1:1", "u", "p", bad); err == nil || !strings.Contains(err.Error(), "unknown node kind") {
		t.Fatalf("unknown kind must be rejected pre-connection, got %v", err)
	}
}
