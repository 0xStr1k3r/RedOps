package project

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CreateFinding inserts a finding with a dedupe key. Returns (false, nil)
// when the key already exists (idempotent re-raise).
func (s *Store) CreateFinding(projectID string, f FindingRow, dedupeKey string) (bool, error) {
	if _, err := s.GetProject(projectID); err != nil {
		return false, err
	}
	f.Title = strings.TrimSpace(f.Title)
	f.Target = strings.TrimSpace(f.Target)
	if f.Title == "" || f.Target == "" {
		return false, fmt.Errorf("title and target required")
	}
	f.Severity = strings.ToLower(strings.TrimSpace(f.Severity))
	f.Confidence = strings.ToLower(strings.TrimSpace(f.Confidence))
	f.Status = strings.ToLower(strings.TrimSpace(f.Status))
	if f.Status == "" {
		f.Status = "open"
	}
	if f.Confidence == "" {
		f.Confidence = "observed"
	}
	now := time.Now().UTC()
	res, err := s.db.Exec(`INSERT INTO findings(id, project_id, title, description, severity, confidence, target, evidence, source, cwe, cve, technique_id, remediation, status, dedupe_key, created_at, updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(project_id, dedupe_key) DO NOTHING`,
		uuid.NewString(), projectID, f.Title, f.Description, f.Severity, f.Confidence, f.Target, f.Evidence, f.Source, f.CWE, f.CVE, f.TechniqueID, f.Remediation, f.Status, dedupeKey, now, now)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil
	}
	_ = s.addTimeline(projectID, "finding.created", fmt.Sprintf("[%s] %s (%s)", f.Severity, f.Title, f.Target), "")
	return true, nil
}

// ManualDedupeKey gives operator-created findings a unique key (no dedupe).
func ManualDedupeKey() string { return uuid.NewString() }

func scanFindingRow(row *sql.Rows, f *FindingRow) error {
	return row.Scan(&f.ID, &f.ProjectID, &f.Title, &f.Description, &f.Severity, &f.Confidence,
		&f.Target, &f.Evidence, &f.Source, &f.CWE, &f.CVE, &f.TechniqueID, &f.Remediation,
		&f.Status, &f.CreatedAt, &f.UpdatedAt)
}

const findingCols = `id, project_id, title, description, severity, confidence, target, evidence, source, cwe, cve, technique_id, remediation, status, created_at, updated_at`

// GetFinding fetches one finding within a project.
func (s *Store) GetFinding(projectID, findingID string) (*FindingRow, error) {
	var f FindingRow
	err := s.db.QueryRow(`SELECT `+findingCols+` FROM findings WHERE id=? AND project_id=?`, findingID, projectID).
		Scan(&f.ID, &f.ProjectID, &f.Title, &f.Description, &f.Severity, &f.Confidence,
			&f.Target, &f.Evidence, &f.Source, &f.CWE, &f.CVE, &f.TechniqueID, &f.Remediation,
			&f.Status, &f.CreatedAt, &f.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("finding not found")
	}
	return &f, err
}

// ListFindings returns findings with optional filters, newest last.
func (s *Store) ListFindings(projectID string, flt FindingFilter) ([]FindingRow, error) {
	q := `SELECT ` + findingCols + ` FROM findings WHERE project_id=?`
	args := []any{projectID}
	if flt.Severity != "" {
		q += ` AND severity=?`
		args = append(args, strings.ToLower(flt.Severity))
	}
	if flt.Status != "" {
		q += ` AND status=?`
		args = append(args, strings.ToLower(flt.Status))
	}
	if flt.Target != "" {
		q += ` AND target=?`
		args = append(args, flt.Target)
	}
	q += ` ORDER BY created_at`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingRow
	for rows.Next() {
		var f FindingRow
		if err := scanFindingRow(rows, &f); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// FindingPatch carries operator workflow updates. Empty = no change;
// Severity/Confidence validated when set.
func (s *Store) UpdateFinding(projectID, findingID string, status, confidence, severity string) (*FindingRow, error) {
	f, err := s.GetFinding(projectID, findingID)
	if err != nil {
		return nil, err
	}
	if status != "" {
		switch strings.ToLower(status) {
		case "open", "acknowledged", "resolved", "false_positive":
			f.Status = strings.ToLower(status)
		default:
			return nil, fmt.Errorf("invalid status %q", status)
		}
	}
	if confidence != "" {
		switch strings.ToLower(confidence) {
		case "observed", "potential", "validated", "confirmed":
			f.Confidence = strings.ToLower(confidence)
		default:
			return nil, fmt.Errorf("invalid confidence %q", confidence)
		}
	}
	if severity != "" {
		switch strings.ToLower(severity) {
		case "info", "low", "medium", "high", "critical":
			f.Severity = strings.ToLower(severity)
		default:
			return nil, fmt.Errorf("invalid severity %q", severity)
		}
	}
	_, err = s.db.Exec(`UPDATE findings SET status=?, confidence=?, severity=?, updated_at=? WHERE id=? AND project_id=?`,
		f.Status, f.Confidence, f.Severity, time.Now().UTC(), findingID, projectID)
	if err != nil {
		return nil, err
	}
	return s.GetFinding(projectID, findingID)
}
