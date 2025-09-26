package project

import "testing"

func openReconTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestReconJobLifecycle(t *testing.T) {
	s := openReconTest(t)
	p, _ := s.CreateProject("acme", "")
	if _, err := s.AddScopeEntry(p.ID, "10.10.10.0/24"); err != nil {
		t.Fatal(err)
	}
	j, err := s.EnqueueReconJob(p.ID, "nmap", "10.10.10.10", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnqueueReconJob(p.ID, "nmap", "8.8.8.8", "alice"); err == nil {
		t.Fatal("out-of-scope must fail")
	}
	if _, err := s.EnqueueReconJob(p.ID, "evil", "10.10.10.10", "alice"); err == nil {
		t.Fatal("unknown tool must fail")
	}
	claimed, err := s.ClaimNextJob()
	if err != nil || claimed == nil || claimed.ID != j.ID {
		t.Fatalf("claim failed: %v %+v", err, claimed)
	}
	if err := s.FinishReconJob(j.ID, JobDone, "1 hosts", ""); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetReconJob(p.ID, j.ID)
	if got.Status != JobDone {
		t.Fatalf("expected done, got %s", got.Status)
	}
	if empty, _ := s.ClaimNextJob(); empty != nil {
		t.Fatal("queue should be empty")
	}
}

func TestAssetUpsert(t *testing.T) {
	s := openReconTest(t)
	p, _ := s.CreateProject("acme", "")
	_ = s.UpsertHost(p.ID, "10.10.10.10", "web01.lab", "Linux", "nmap")
	_ = s.UpsertHost(p.ID, "10.10.10.10", "web01.lab", "Linux 5.X", "httpx")
	_ = s.UpsertService(p.ID, "10.10.10.10", 80, "tcp", "open", "http", "nginx", "1.24")
	_ = s.UpsertService(p.ID, "10.10.10.10", 80, "tcp", "open", "http", "nginx", "1.25")
	hosts, _ := s.ListHosts(p.ID)
	if len(hosts) != 1 || hosts[0].OS != "Linux 5.X" {
		t.Fatalf("host upsert failed: %+v", hosts)
	}
	svcs, _ := s.ListServices(p.ID)
	if len(svcs) != 1 || svcs[0].Version != "1.25" {
		t.Fatalf("service upsert failed: %+v", svcs)
	}
}
