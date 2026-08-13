package attack

import (
	"testing"

	"github.com/0xStr1k3r/RedOps/internal/attackgraph"
	"github.com/0xStr1k3r/RedOps/internal/project"
)

func graphFixture() *attackgraph.Graph {
	n := func(id, kind string, props map[string]string) attackgraph.Node {
		return attackgraph.Node{ID: id, Kind: kind, Labels: []string{kind}, Props: props}
	}
	e := func(from, to, typ string) attackgraph.Edge {
		return attackgraph.Edge{From: from, To: to, Type: typ, Reason: "test"}
	}
	return &attackgraph.Graph{
		Nodes: []attackgraph.Node{
			n("project:p", "Project", map[string]string{"name": "acme"}),
			n("target:10.0.0.1", "Target", map[string]string{"value": "10.0.0.1"}),
			n("host:10.0.0.1", "Host", map[string]string{"ip": "10.0.0.1"}),
			n("svc:10.0.0.1:80/tcp", "Service", map[string]string{"host": "10.0.0.1", "port": "80"}),
			n("finding:f1", "Finding", map[string]string{"title": "Weak TLS", "severity": "high"}),
			n("technique:T1046", "Technique", map[string]string{"technique_id": "T1046"}),
			n("finding:f2", "Finding", map[string]string{"title": "Robots", "severity": "info"}),
		},
		Edges: []attackgraph.Edge{
			e("project:p", "target:10.0.0.1", "HAS_TARGET"),
			e("target:10.0.0.1", "host:10.0.0.1", "MATCHES"),
			e("project:p", "host:10.0.0.1", "HAS_HOST"),
			e("host:10.0.0.1", "svc:10.0.0.1:80/tcp", "RUNS"),
			e("svc:10.0.0.1:80/tcp", "finding:f1", "HAS_FINDING"),
			e("finding:f1", "technique:T1046", "MAPS_TO"),
			e("svc:10.0.0.1:80/tcp", "finding:f2", "HAS_FINDING"),
		},
	}
}

func TestFindPaths(t *testing.T) {
	paths := FindPaths(graphFixture(), nil, "p", Options{})
	if len(paths) == 0 {
		t.Fatal("expected paths")
	}
	// Top path must be the high-severity chain to the technique.
	top := paths[0]
	if top.Risk < 75 || top.Confidence != ConfObserved {
		t.Fatalf("top path risk/confidence: %+v", top)
	}
	if len(top.Techniques) != 1 || top.Techniques[0] != "T1046" {
		t.Fatalf("techniques: %+v", top)
	}
	if len(top.RequiredPrivileges) != 1 {
		t.Fatalf("privileges: %+v", top)
	}
	// Engine never emits validated/confirmed.
	for _, p := range paths {
		if p.Confidence == ConfValidated || p.Confidence == ConfConfirmed {
			t.Fatalf("engine must not emit %s", p.Confidence)
		}
	}
	// Sorted by risk desc.
	for i := 1; i < len(paths); i++ {
		if paths[i].Risk > paths[i-1].Risk {
			t.Fatal("paths not sorted by risk")
		}
	}
}

func TestScore(t *testing.T) {
	if Score("critical", 3, 2) != 100 {
		t.Fatal("critical caps at 100")
	}
	if Score("high", 1, 3) != 80 {
		t.Fatalf("high+1tech = 80, got %d", Score("high", 1, 3))
	}
	if Score("info", 0, 10) != 0 {
		t.Fatalf("long info path floors at 0, got %d", Score("info", 0, 10))
	}
}

func TestGeneratePersists(t *testing.T) {
	st, err := project.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p, _ := st.CreateProject("acme", "")
	_, _ = st.AddScopeEntry(p.ID, "10.10.10.0/24")
	_, _ = st.AddTarget(p.ID, "10.10.10.10", "alice")
	_ = st.UpsertHost(p.ID, "10.10.10.10", "", "", "nmap")
	_ = st.UpsertService(p.ID, "10.10.10.10", 443, "tcp", "open", "https", "", "")
	_, _ = st.CreateFinding(p.ID, project.FindingRow{Title: "Weak TLS", Severity: "high", Target: "10.10.10.10:443", TechniqueID: "T1046"}, "k1")

	n, err := Generate(t.Context(), st, p.ID, "alice", Options{})
	if err != nil || n == 0 {
		t.Fatalf("generate: %d %v", n, err)
	}
	list, _ := st.ListAttackPaths(p.ID, 0)
	if len(list) == 0 || list[0].Risk < 75 {
		t.Fatalf("stored paths: %+v", list)
	}
	// Regenerate is replace, not append (fresh IDs each run).
	n2, _ := Generate(t.Context(), st, p.ID, "alice", Options{})
	list2, _ := st.ListAttackPaths(p.ID, 0)
	if n2 != n || len(list2) != len(list) {
		t.Fatalf("regenerate must replace: %d/%d vs %d/%d", n, len(list), n2, len(list2))
	}
	// Confirm workflow: operator promotion only.
	if _, err := st.ConfirmAttackPath(p.ID, list2[0].ID, "bogus", "alice"); err == nil {
		t.Fatal("bad confidence must fail")
	}
	confirmed, err := st.ConfirmAttackPath(p.ID, list2[0].ID, "validated", "alice")
	if err != nil || confirmed.Confidence != "validated" {
		t.Fatalf("confirm: %+v %v", confirmed, err)
	}
}
