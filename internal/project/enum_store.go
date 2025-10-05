package project

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// EnqueueEnumJob queues a service enumeration. Callers (enumeration.Enqueue)
// already scope-checked the host; the worker re-checks at execution.
func (s *Store) EnqueueEnumJob(projectID, hostIP string, port int, module, createdBy string) (*EnumJob, error) {
	if _, err := s.GetProject(projectID); err != nil {
		return nil, err
	}
	job := &EnumJob{ID: uuid.NewString(), ProjectID: projectID, HostIP: hostIP, Port: port, Module: module, Status: JobQueued, CreatedBy: createdBy, CreatedAt: time.Now().UTC()}
	_, err := s.db.Exec(`INSERT INTO enum_jobs(id, project_id, host_ip, port, module, status, created_by, created_at) VALUES(?,?,?,?,?,?,?,?)`,
		job.ID, job.ProjectID, job.HostIP, job.Port, job.Module, job.Status, job.CreatedBy, job.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = s.addTimeline(projectID, "enum.queued", fmt.Sprintf("%s queued on %s:%d", module, hostIP, port), createdBy)
	return job, nil
}

func (s *Store) GetEnumJob(projectID, jobID string) (*EnumJob, error) {
	var j EnumJob
	var finished sql.NullTime
	err := s.db.QueryRow(`SELECT id, project_id, host_ip, port, module, status, output_ref, error, created_by, created_at, finished_at FROM enum_jobs WHERE id=? AND project_id=?`, jobID, projectID).
		Scan(&j.ID, &j.ProjectID, &j.HostIP, &j.Port, &j.Module, &j.Status, &j.OutputRef, &j.Error, &j.CreatedBy, &j.CreatedAt, &finished)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("job not found")
	}
	if err != nil {
		return nil, err
	}
	if finished.Valid {
		j.FinishedAt = &finished.Time
	}
	return &j, nil
}

func (s *Store) ListEnumJobs(projectID string) ([]EnumJob, error) {
	rows, err := s.db.Query(`SELECT id, project_id, host_ip, port, module, status, output_ref, error, created_by, created_at, finished_at FROM enum_jobs WHERE project_id=? ORDER BY created_at`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnumJob
	for rows.Next() {
		var j EnumJob
		var finished sql.NullTime
		if err := rows.Scan(&j.ID, &j.ProjectID, &j.HostIP, &j.Port, &j.Module, &j.Status, &j.OutputRef, &j.Error, &j.CreatedBy, &j.CreatedAt, &finished); err != nil {
			return nil, err
		}
		if finished.Valid {
			j.FinishedAt = &finished.Time
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// ClaimNextEnumJob atomically moves one queued enum job to running.
func (s *Store) ClaimNextEnumJob() (*EnumJob, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var j EnumJob
	var finished sql.NullTime
	err = tx.QueryRow(`SELECT id, project_id, host_ip, port, module, status, output_ref, error, created_by, created_at, finished_at FROM enum_jobs WHERE status='queued' ORDER BY created_at LIMIT 1`).Scan(
		&j.ID, &j.ProjectID, &j.HostIP, &j.Port, &j.Module, &j.Status, &j.OutputRef, &j.Error, &j.CreatedBy, &j.CreatedAt, &finished)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE enum_jobs SET status='running' WHERE id=? AND status='queued'`, j.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	j.Status = JobRunning
	return &j, nil
}

func (s *Store) FinishEnumJob(jobID, status, outputRef, errMsg string) error {
	if status != JobDone && status != JobFailed {
		return fmt.Errorf("invalid terminal status %q", status)
	}
	_, err := s.db.Exec(`UPDATE enum_jobs SET status=?, output_ref=?, error=?, finished_at=? WHERE id=?`, status, outputRef, errMsg, time.Now().UTC(), jobID)
	return err
}

// SaveEnumResult persists observations as JSON. Observations use the local
// EnumObservation shape; the enumeration package converts field-by-field.
func (s *Store) SaveEnumResult(projectID, jobID, hostIP string, port int, module, summary string, observations []EnumObservation) error {
	raw, err := json.Marshal(observations)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO enum_results(id, project_id, job_id, host_ip, port, module, summary, observations_json, created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		uuid.NewString(), projectID, jobID, hostIP, port, module, summary, string(raw), time.Now().UTC())
	if err != nil {
		return err
	}
	return s.addTimeline(projectID, "enum.done", fmt.Sprintf("%s on %s:%d: %s", module, hostIP, port, summary), "")
}

func (s *Store) ListEnumResults(projectID string) ([]EnumResult, error) {
	rows, err := s.db.Query(`SELECT id, project_id, job_id, host_ip, port, module, summary, observations_json, created_at FROM enum_results WHERE project_id=? ORDER BY created_at`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnumResult
	for rows.Next() {
		var r EnumResult
		var raw string
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.JobID, &r.HostIP, &r.Port, &r.Module, &r.Summary, &raw, &r.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(raw), &r.Observations)
		out = append(out, r)
	}
	return out, rows.Err()
}
