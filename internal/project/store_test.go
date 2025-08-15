package project

import "testing"

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestProjectTargetScopeEnforcement(t *testing.T) {
	s := openTest(t)
	p, err := s.CreateProject("acme", "internal pentest")
	if err != nil {
		t.Fatal(err)
	}
	// No scope yet: target add must fail.
	if _, err := s.AddTarget(p.ID, "10.10.10.10", "tester"); err == nil {
		t.Fatal("target without scope must fail")
	}
	if _, err := s.AddScopeEntry(p.ID, "10.10.10.0/24"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddTarget(p.ID, "10.10.10.10", "tester"); err != nil {
		t.Fatalf("in-scope target rejected: %v", err)
	}
	if _, err := s.AddTarget(p.ID, "8.8.8.8", "tester"); err == nil {
		t.Fatal("out-of-scope target must be rejected")
	}
	if _, err := s.AddTarget(p.ID, "example.com", "tester"); err == nil {
		t.Fatal("domain outside scope must be rejected")
	}
	targets, err := s.ListTargets(p.ID)
	if err != nil || len(targets) != 1 {
		t.Fatalf("expected 1 target, got %v %v", targets, err)
	}
	timeline, err := s.ListTimeline(p.ID)
	if err != nil || len(timeline) < 3 {
		t.Fatalf("expected timeline events, got %v %v", timeline, err)
	}
}

func TestInvalidScopeRejected(t *testing.T) {
	s := openTest(t)
	p, _ := s.CreateProject("x", "")
	if _, err := s.AddScopeEntry(p.ID, "not-a-scope!!!"); err == nil {
		t.Fatal("invalid scope must be rejected")
	}
}
