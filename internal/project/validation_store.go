package project

import (
	"time"

	"github.com/google/uuid"
)

// RecordValidationRun appends an immutable evidence row for one validator run.
func (s *Store) RecordValidationRun(projectID, findingID, validator string, success bool, detail, actor string) error {
	_, err := s.db.Exec(`INSERT INTO validation_runs(id, project_id, finding_id, validator, success, detail, actor, created_at) VALUES(?,?,?,?,?,?,?,?)`,
		uuid.NewString(), projectID, findingID, validator, success, detail, actor, time.Now().UTC())
	if err != nil {
		return err
	}
	kind := "validation.failed"
	if success {
		kind = "validation.confirmed"
	}
	return s.addTimeline(projectID, kind, validator+" on finding "+findingID+": "+detail, actor)
}

// ListValidationRuns returns runs for a finding, newest last.
func (s *Store) ListValidationRuns(projectID, findingID string) ([]ValidationRun, error) {
	rows, err := s.db.Query(`SELECT id, project_id, finding_id, validator, success, detail, actor, created_at FROM validation_runs WHERE project_id=? AND finding_id=? ORDER BY created_at`, projectID, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ValidationRun
	for rows.Next() {
		var r ValidationRun
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.FindingID, &r.Validator, &r.Success, &r.Detail, &r.Actor, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
