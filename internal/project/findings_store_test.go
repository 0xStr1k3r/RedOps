package project

import "testing"

func openFindingsTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestFindingCRUD(t *testing.T) {
	s := openFindingsTest(t)
	p, _ := s.CreateProject("acme", "")
	ok, err := s.CreateFinding(p.ID, FindingRow{Title: "Missing CSP", Severity: "low", Target: "10.0.0.1:80"}, "k1")
	if err != nil || !ok {
		t.Fatalf("create: %v %v", ok, err)
	}
	// Same key: idempotent no-op.
	ok, err = s.CreateFinding(p.ID, FindingRow{Title: "Missing CSP", Severity: "low", Target: "10.0.0.1:80"}, "k1")
	if err != nil || ok {
		t.Fatalf("dedupe: %v %v", ok, err)
	}
	if _, err := s.CreateFinding(p.ID, FindingRow{Title: "", Target: "x"}, "k2"); err == nil {
		t.Fatal("empty title must fail")
	}
	list, _ := s.ListFindings(p.ID, FindingFilter{})
	if len(list) != 1 || list[0].Status != "open" || list[0].Confidence != "observed" {
		t.Fatalf("list: %+v", list)
	}
	low, _ := s.ListFindings(p.ID, FindingFilter{Severity: "low"})
	if len(low) != 1 {
		t.Fatal("severity filter failed")
	}
	high, _ := s.ListFindings(p.ID, FindingFilter{Severity: "high"})
	if len(high) != 0 {
		t.Fatal("severity filter leaked")
	}
	upd, err := s.UpdateFinding(p.ID, list[0].ID, "acknowledged", "validated", "")
	if err != nil || upd.Status != "acknowledged" || upd.Confidence != "validated" {
		t.Fatalf("update: %+v %v", upd, err)
	}
	if _, err := s.UpdateFinding(p.ID, list[0].ID, "bogus", "", ""); err == nil {
		t.Fatal("bad status must fail")
	}
	if _, err := s.GetFinding(p.ID, "nope"); err == nil {
		t.Fatal("missing finding must 404-style error")
	}
}
