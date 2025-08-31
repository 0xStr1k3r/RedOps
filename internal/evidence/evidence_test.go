package evidence

import "testing"

func TestHashVerify(t *testing.T) {
	e := New("p1", "alice", "10.10.10.10", "http-enum", "httpx -u http://10.10.10.10", "out-1", "T1046")
	if !e.Verify() {
		t.Fatal("fresh evidence must verify")
	}
	e.Command = "tampered"
	if e.Verify() {
		t.Fatal("tampered evidence must not verify")
	}
}
