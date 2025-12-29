package project

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func openEvidenceTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestEvidenceChain(t *testing.T) {
	s := openEvidenceTest(t)
	p, _ := s.CreateProject("acme", "")
	if got := s.VerifyEvidenceChain(p.ID); !got.OK || got.Checked != 0 {
		t.Fatalf("empty chain must verify: %+v", got)
	}
	for i, action := range []string{"recon.nmap", "enum.http", "validation.http-robots"} {
		_, err := s.RecordEvidence(p.ID, EvidenceRow{
			ID: uuid.NewString(), ProjectID: p.ID, Timestamp: time.Now().UTC(),
			Operator: "alice", Target: "10.0.0.1", Action: action,
		})
		if err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	list, _ := s.ListEvidence(p.ID)
	if len(list) != 3 {
		t.Fatalf("expected 3, got %d", len(list))
	}
	if list[0].PrevHash != "" || list[1].PrevHash != list[0].Hash || list[2].PrevHash != list[1].Hash {
		t.Fatal("chain links broken")
	}
	if got := s.VerifyEvidenceChain(p.ID); !got.OK || got.Checked != 3 {
		t.Fatalf("chain must verify: %+v", got)
	}
	// Tamper with one record: verification must pinpoint it.
	_, err := s.db.Exec(`UPDATE evidence SET output_ref='tampered' WHERE id=?`, list[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	got := s.VerifyEvidenceChain(p.ID)
	if got.OK || got.BrokenAt != list[1].ID {
		t.Fatalf("tamper must break at record 2: %+v", got)
	}
	if _, err := s.GetEvidence(p.ID, list[0].ID); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := s.GetEvidence(p.ID, "nope"); err == nil {
		t.Fatal("missing record must error")
	}
}
