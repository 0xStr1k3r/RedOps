package project

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// CreateScenarioRun inserts a queued run. Scope is checked by the caller
// (scenarios.Run); the API pre-checks too for a fast 403.
func (s *Store) CreateScenarioRun(projectID, scenario, target, createdBy string) (*ScenarioRun, error) {
	if _, err := s.GetProject(projectID); err != nil {
		return nil, err
	}
	run := &ScenarioRun{ID: uuid.NewString(), ProjectID: projectID, Scenario: scenario, Target: target, Status: JobQueued, CreatedBy: createdBy, CreatedAt: time.Now().UTC()}
	_, err := s.db.Exec(`INSERT INTO scenario_runs(id, project_id, scenario, target, status, created_by, created_at) VALUES(?,?,?,?,?,?,?)`,
		run.ID, run.ProjectID, run.Scenario, run.Target, run.Status, run.CreatedBy, run.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = s.addTimeline(projectID, "scenario.queued", fmt.Sprintf("%s queued on %s", scenario, target), createdBy)
	return run, nil
}

func (s *Store) GetScenarioRun(projectID, runID string) (*ScenarioRun, error) {
	var r ScenarioRun
	var finished sql.NullTime
	err := s.db.QueryRow(`SELECT id, project_id, scenario, target, status, output_ref, error, created_by, created_at, finished_at FROM scenario_runs WHERE id=? AND project_id=?`, runID, projectID).
		Scan(&r.ID, &r.ProjectID, &r.Scenario, &r.Target, &r.Status, &r.OutputRef, &r.Error, &r.CreatedBy, &r.CreatedAt, &finished)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("scenario run not found")
	}
	if err != nil {
		return nil, err
	}
	if finished.Valid {
		r.FinishedAt = &finished.Time
	}
	return &r, nil
}

func (s *Store) ListScenarioRuns(projectID string) ([]ScenarioRun, error) {
	rows, err := s.db.Query(`SELECT id, project_id, scenario, target, status, output_ref, error, created_by, created_at, finished_at FROM scenario_runs WHERE project_id=? ORDER BY created_at`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScenarioRun
	for rows.Next() {
		var r ScenarioRun
		var finished sql.NullTime
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.Scenario, &r.Target, &r.Status, &r.OutputRef, &r.Error, &r.CreatedBy, &r.CreatedAt, &finished); err != nil {
			return nil, err
		}
		if finished.Valid {
			r.FinishedAt = &finished.Time
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// StartScenarioRun marks running (background worker claim).
func (s *Store) StartScenarioRun(runID string) error {
	_, err := s.db.Exec(`UPDATE scenario_runs SET status='running' WHERE id=? AND status='queued'`, runID)
	return err
}

// FinishScenarioRun records the terminal state with a step summary.
func (s *Store) FinishScenarioRun(runID, status, outputRef, errMsg string) error {
	if status != JobDone && status != JobFailed {
		return fmt.Errorf("invalid terminal status %q", status)
	}
	_, err := s.db.Exec(`UPDATE scenario_runs SET status=?, output_ref=?, error=?, finished_at=? WHERE id=?`, status, outputRef, errMsg, time.Now().UTC(), runID)
	return err
}
