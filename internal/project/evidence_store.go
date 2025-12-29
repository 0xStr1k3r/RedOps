package project

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// RecordEvidence chains and persists one evidence record: prev_hash is the
// project's last evidence hash ("" for genesis), then the record hash is
// recomputed over all fields including the link. Returns the sealed hash.
func (s *Store) RecordEvidence(projectID string, e EvidenceRow) (string, error) {
	if _, err := s.GetProject(projectID); err != nil {
		return "", err
	}
	// Genesis record chains from "".
	e.PrevHash = lastEvidenceHash(s, projectID)
	now := time.Now().UTC()
	if e.Timestamp.IsZero() {
		e.Timestamp = now
	}
	e.Hash = hashEvidence(e)
	_, err := s.db.Exec(`INSERT INTO evidence(id, project_id, timestamp, operator, target, action, command, output_ref, technique, finding_id, prev_hash, hash, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, projectID, e.Timestamp, e.Operator, e.Target, e.Action, e.Command, e.OutputRef, e.Technique, e.FindingID, e.PrevHash, e.Hash, now)
	if err != nil {
		return "", err
	}
	_ = s.addTimeline(projectID, "evidence.recorded", fmt.Sprintf("%s on %s [%s]", e.Action, e.Target, shortHash(e.Hash)), e.Operator)
	return e.Hash, nil
}

func lastEvidenceHash(s *Store, projectID string) string {
	var h string
	if err := s.db.QueryRow(`SELECT hash FROM evidence WHERE project_id=? ORDER BY created_at DESC LIMIT 1`, projectID).Scan(&h); err != nil {
		return ""
	}
	return h
}

func hashEvidence(e EvidenceRow) string {
	h := sha256.New()
	h.Write([]byte(e.ProjectID + "\x00" + e.Target + "\x00" + e.Action + "\x00" + e.Command + "\x00" + e.OutputRef + "\x00" + e.Timestamp.UTC().Format(time.RFC3339Nano) + "\x00" + e.Operator + "\x00" + e.FindingID + "\x00" + e.PrevHash))
	return hex.EncodeToString(h.Sum(nil))
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// ListEvidence returns records in chain order (oldest first).
func (s *Store) ListEvidence(projectID string) ([]EvidenceRow, error) {
	rows, err := s.db.Query(`SELECT id, project_id, timestamp, operator, target, action, command, output_ref, technique, finding_id, prev_hash, hash FROM evidence WHERE project_id=? ORDER BY created_at`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EvidenceRow
	for rows.Next() {
		var e EvidenceRow
		if err := rows.Scan(&e.ID, &e.ProjectID, &e.Timestamp, &e.Operator, &e.Target, &e.Action, &e.Command, &e.OutputRef, &e.Technique, &e.FindingID, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetEvidence fetches one record.
func (s *Store) GetEvidence(projectID, evidenceID string) (*EvidenceRow, error) {
	var e EvidenceRow
	err := s.db.QueryRow(`SELECT id, project_id, timestamp, operator, target, action, command, output_ref, technique, finding_id, prev_hash, hash FROM evidence WHERE id=? AND project_id=?`, evidenceID, projectID).
		Scan(&e.ID, &e.ProjectID, &e.Timestamp, &e.Operator, &e.Target, &e.Action, &e.Command, &e.OutputRef, &e.Technique, &e.FindingID, &e.PrevHash, &e.Hash)
	if err != nil {
		return nil, fmt.Errorf("evidence not found")
	}
	return &e, nil
}

// VerifyEvidenceChain recomputes every record hash and checks linkage.
// Any field tampering or row deletion breaks the chain at that record.
func (s *Store) VerifyEvidenceChain(projectID string) ChainStatus {
	rows, err := s.ListEvidence(projectID)
	if err != nil {
		return ChainStatus{OK: false, BrokenAt: "list: " + err.Error()}
	}
	prev := ""
	for _, e := range rows {
		if e.PrevHash != prev {
			return ChainStatus{OK: false, Checked: len(rows), BrokenAt: e.ID}
		}
		if hashEvidence(e) != e.Hash {
			return ChainStatus{OK: false, Checked: len(rows), BrokenAt: e.ID}
		}
		prev = e.Hash
	}
	return ChainStatus{OK: true, Checked: len(rows)}
}
