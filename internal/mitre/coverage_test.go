package mitre

import (
	"testing"

	"github.com/0xStr1k3r/RedOps/internal/project"
)

func TestMatrixIntegrity(t *testing.T) {
	if len(Tactics) != 14 {
		t.Fatalf("expected 14 tactics, got %d", len(Tactics))
	}
	seen := map[string]bool{}
	tacticNames := map[string]bool{}
	for _, tac := range Tactics {
		tacticNames[tac.Name] = true
	}
	for _, tech := range Techniques {
		if seen[tech.ID] {
			t.Fatalf("duplicate technique %s", tech.ID)
		}
		seen[tech.ID] = true
		if !tacticNames[tech.Tactic] {
			t.Fatalf("technique %s references unknown tactic %q", tech.ID, tech.Tactic)
		}
	}
	if _, ok := Lookup("T1046"); !ok {
		t.Fatal("T1046 must resolve")
	}
	if len(TechniquesByTactic("Discovery")) < 5 {
		t.Fatal("Discovery should have several techniques")
	}
}

func TestProjectCoverage(t *testing.T) {
	st, err := project.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p, _ := st.CreateProject("acme", "")
	_, _ = st.AddScopeEntry(p.ID, "10.10.10.0/24")
	if _, err := st.CreateFinding(p.ID, project.FindingRow{Title: "CSP", Severity: "low", Target: "h:80", TechniqueID: "T1046"}, "k1"); err != nil {
		t.Fatal(err)
	}
	_ = st.SaveEnumResult(p.ID, "j1", "10.10.10.10", 80, "http", "s", []project.EnumObservation{
		{Kind: "http-robots", Detail: "r", TechniqueID: "T1594"},
		{Kind: "http-robots", Detail: "r2", TechniqueID: "T1594"},
	})
	j, _ := st.EnqueueReconJob(p.ID, "nmap", "10.10.10.10", "alice")
	_ = st.FinishReconJob(j.ID, project.JobDone, "1 hosts", "")

	cov, err := ProjectCoverage(st, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Total < 50 || cov.Seen != 2 {
		t.Fatalf("coverage seen=%d total=%d", cov.Seen, cov.Total)
	}
	// T1594 must show count 2 with findings 0; T1046 merges finding + recon evidence.
	var t1046, t1594 *TechniqueHit
	for _, tac := range cov.Tactics {
		for i, h := range tac.Techniques {
			if h.ID == "T1046" {
				t1046 = &tac.Techniques[i]
			}
			if h.ID == "T1594" {
				t1594 = &tac.Techniques[i]
			}
		}
	}
	if t1046 == nil || t1046.Findings != 1 {
		t.Fatalf("T1046: %+v", t1046)
	}
	if t1594 == nil || t1594.Count != 2 {
		t.Fatalf("T1594: %+v", t1594)
	}
	if _, err := ProjectCoverage(st, "nope"); err == nil {
		t.Fatal("unknown project must fail")
	}
}
