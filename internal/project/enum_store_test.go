package project

import "testing"

func openEnumTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestEnumJobLifecycle(t *testing.T) {
	s := openEnumTest(t)
	p, _ := s.CreateProject("acme", "")
	j, err := s.EnqueueEnumJob(p.ID, "10.10.10.10", 80, "http", "alice")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.ClaimNextEnumJob()
	if err != nil || claimed == nil || claimed.ID != j.ID {
		t.Fatalf("claim failed: %v %+v", err, claimed)
	}
	obs := []EnumObservation{{Kind: "http-title", Detail: "Lab", TechniqueID: "T1046"}}
	if err := s.SaveEnumResult(p.ID, j.ID, "10.10.10.10", 80, "http", "1 observations", obs); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishEnumJob(j.ID, JobDone, "done", ""); err != nil {
		t.Fatal(err)
	}
	results, err := s.ListEnumResults(p.ID)
	if err != nil || len(results) != 1 || results[0].Observations[0].Detail != "Lab" {
		t.Fatalf("results: %+v %v", results, err)
	}
	if empty, _ := s.ClaimNextEnumJob(); empty != nil {
		t.Fatal("queue should be empty")
	}
}
