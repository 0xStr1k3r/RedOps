package auth

import "testing"

func TestHashAndVerify(t *testing.T) {
	h, err := HashPassword("correct-horse-123")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(h, "correct-horse-123") {
		t.Fatal("valid password did not verify")
	}
	if VerifyPassword(h, "wrong-password") {
		t.Fatal("wrong password verified")
	}
}

func TestRejectShortPassword(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("expected short password to be rejected")
	}
}

func TestIssueParseRoundTrip(t *testing.T) {
	tok, err := Issue("test-secret-32-bytes-minimum-xxxx", "u1", "alice", RoleOperator, 3600000000000)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse("test-secret-32-bytes-minimum-xxxx", tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Username != "alice" || c.Role != RoleOperator {
		t.Fatalf("unexpected claims %+v", c)
	}
}

func TestRejectWrongSecret(t *testing.T) {
	tok, _ := Issue("secret-a-abcdefghijklmnopqrstuvwxyz", "u1", "alice", RoleViewer, 3600000000000)
	if _, err := Parse("secret-b-abcdefghijklmnopqrstuvwxyz", tok); err == nil {
		t.Fatal("wrong secret must fail")
	}
}

func TestRBACOrdering(t *testing.T) {
	if !CanAct(RoleAdmin, RoleViewer) || !CanAct(RoleAdmin, RoleOperator) {
		t.Fatal("admin should satisfy all")
	}
	if CanAct(RoleViewer, RoleOperator) {
		t.Fatal("viewer must not satisfy operator")
	}
	if !CanAct(RoleOperator, RoleViewer) {
		t.Fatal("operator should satisfy viewer")
	}
}
