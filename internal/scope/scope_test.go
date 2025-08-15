package scope

import "testing"

func mustParse(t *testing.T, entries []string) *Scope {
	t.Helper()
	s, err := ParseEntries(entries)
	if err != nil {
		t.Fatalf("ParseEntries(%v) error: %v", entries, err)
	}
	return s
}

func TestAllowsInScopeIP(t *testing.T) {
	s := mustParse(t, []string{"10.10.10.0/24"})
	ok, _ := s.ContainsTarget("10.10.10.10")
	if !ok {
		t.Fatal("expected 10.10.10.10 to be allowed")
	}
}

func TestDeniesOutOfScope(t *testing.T) {
	s := mustParse(t, []string{"10.10.10.0/24"})
	for _, target := range []string{"8.8.8.8", "192.168.1.10", "10.10.11.1"} {
		if ok, reason := s.ContainsTarget(target); ok {
			t.Fatalf("expected %s to be denied, got allowed (%s)", target, reason)
		}
		if err := s.Enforce(target); err == nil {
			t.Fatalf("expected Enforce(%s) to error", target)
		}
	}
}

func TestDeniesDomainUnlessExplicit(t *testing.T) {
	s := mustParse(t, []string{"10.10.10.0/24"})
	if ok, _ := s.ContainsTarget("example.com"); ok {
		t.Fatal("domain must not be allowed by IP-only scope")
	}
	s2 := mustParse(t, []string{"10.10.10.0/24", "example.com"})
	if ok, _ := s2.ContainsTarget("example.com"); !ok {
		t.Fatal("explicit domain should be allowed")
	}
	if ok, _ := s2.ContainsTarget("evil.com"); ok {
		t.Fatal("non-listed domain must be denied")
	}
}

func TestCIDRSubset(t *testing.T) {
	s := mustParse(t, []string{"10.10.0.0/16"})
	if ok, _ := s.ContainsTarget("10.10.10.0/24"); !ok {
		t.Fatal("subset CIDR should be allowed")
	}
	if ok, _ := s.ContainsTarget("10.11.0.0/16"); ok {
		t.Fatal("non-subset CIDR must be denied")
	}
}

func TestSingleIPScope(t *testing.T) {
	s := mustParse(t, []string{"10.10.10.10"})
	if ok, _ := s.ContainsTarget("10.10.10.10"); !ok {
		t.Fatal("exact IP should be allowed")
	}
	if ok, _ := s.ContainsTarget("10.10.10.11"); ok {
		t.Fatal("other IP must be denied")
	}
}

func TestInvalidEntries(t *testing.T) {
	for _, e := range []string{"", "999.999.999.999", "10.0.0.0/99", "http://example.com/x"} {
		if _, _, err := Classify(e); err == nil {
			t.Fatalf("expected Classify(%q) to fail", e)
		}
	}
	if _, err := ParseEntries(nil); err == nil {
		t.Fatal("empty scope must fail")
	}
}
