package insights

import (
	"testing"

	"github.com/0xStr1k3r/RedOps/internal/project"
)

func TestEmptyProject(t *testing.T) {
	st, _ := project.Open(":memory:")
	defer st.Close()
	p, _ := st.CreateProject("acme", "")
	got, err := Compute(st, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Level != LevelWarn {
		t.Fatalf("empty project should warn about scope: %+v", got)
	}
	if _, err := Compute(st, "nope"); err == nil {
		t.Fatal("unknown project must fail")
	}
}

func TestPrioritization(t *testing.T) {
	st, _ := project.Open(":memory:")
	defer st.Close()
	p, _ := st.CreateProject("acme", "")
	_, _ = st.AddScopeEntry(p.ID, "10.10.10.0/24")
	_, _ = st.AddTarget(p.ID, "10.10.10.10", "alice")
	_ = st.UpsertHost(p.ID, "10.10.10.10", "", "", "nmap")
	_ = st.UpsertService(p.ID, "10.10.10.10", 443, "tcp", "open", "https", "", "")
	_, _ = st.CreateFinding(p.ID, project.FindingRow{Title: "Weak TLS", Severity: "critical", Target: "h:443", TechniqueID: "T1046"}, "k1")
	_, _ = st.CreateFinding(p.ID, project.FindingRow{Title: "CSP", Severity: "low", Target: "h:80"}, "k2")

	got, err := Compute(st, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || got[0].Level != LevelCritical {
		t.Fatalf("critical first: %+v", got)
	}
	levels := map[string]bool{}
	for _, in := range got {
		levels[in.Level] = true
		if in.Link == "" || in.Link[0] != '#' {
			t.Fatalf("insight needs GUI link: %+v", in)
		}
	}
	if !levels[LevelWarn] || !levels[LevelInfo] {
		t.Fatalf("expected warn+info present: %+v", got)
	}
}
