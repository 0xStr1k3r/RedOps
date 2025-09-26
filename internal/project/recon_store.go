package project

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// EnqueueReconJob validates tool + scope, then queues a job.
// Scope denials surface as "scope denied ..." so the API can return 403.
func (s *Store) EnqueueReconJob(projectID, tool, target, createdBy string) (*ReconJob, error) {
	if _, err := s.GetProject(projectID); err != nil {
		return nil, err
	}
	tool = strings.ToLower(strings.TrimSpace(tool))
	if !AllowedReconTools[tool] {
		return nil, fmt.Errorf("unknown tool %q (allowed: nmap, httpx, dnsx, subfinder)", tool)
	}
	sc, err := s.LoadScope(projectID)
	if err != nil {
		return nil, fmt.Errorf("cannot run recon: project has no valid scope yet (%v)", err)
	}
	if err := sc.Enforce(target); err != nil {
		return nil, err
	}
	if strings.HasPrefix(strings.TrimSpace(target), "-") {
		return nil, fmt.Errorf("invalid target %q", target)
	}
	job := &ReconJob{
		ID: projectID[:8] + "-" + uuid.NewString()[:8],
		ProjectID: projectID, Tool: tool, Target: strings.TrimSpace(target),
		Status: JobQueued, CreatedBy: createdBy, CreatedAt: time.Now().UTC(),
	}
	job.ID = uuid.NewString()
	_, err = s.db.Exec(`INSERT INTO recon_jobs(id, project_id, tool, target, status, created_by, created_at) VALUES(?,?,?,?,?,?,?)`,
		job.ID, job.ProjectID, job.Tool, job.Target, job.Status, job.CreatedBy, job.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = s.addTimeline(projectID, "recon.queued", fmt.Sprintf("%s queued on %s", tool, job.Target), createdBy)
	_ = s.AppendAudit(projectID, createdBy, "recon.enqueue", job.Target, tool)
	return job, nil
}

func scanJob(row *sql.Row, j *ReconJob) error {
	var finished sql.NullTime
	err := row.Scan(&j.ID, &j.ProjectID, &j.Tool, &j.Target, &j.Status, &j.OutputRef, &j.Error, &j.CreatedBy, &j.CreatedAt, &finished)
	if finished.Valid {
		j.FinishedAt = &finished.Time
	}
	return err
}

// GetReconJob fetches one job, ensuring it belongs to the project.
func (s *Store) GetReconJob(projectID, jobID string) (*ReconJob, error) {
	var j ReconJob
	err := scanJob(s.db.QueryRow(`SELECT id, project_id, tool, target, status, output_ref, error, created_by, created_at, finished_at FROM recon_jobs WHERE id=? AND project_id=?`, jobID, projectID), &j)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("job not found")
	}
	return &j, err
}

// ListReconJobs returns jobs newest-last (creation order).
func (s *Store) ListReconJobs(projectID string) ([]ReconJob, error) {
	rows, err := s.db.Query(`SELECT id, project_id, tool, target, status, output_ref, error, created_by, created_at, finished_at FROM recon_jobs WHERE project_id=? ORDER BY created_at`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReconJob
	for rows.Next() {
		var j ReconJob
		var finished sql.NullTime
		if err := rows.Scan(&j.ID, &j.ProjectID, &j.Tool, &j.Target, &j.Status, &j.OutputRef, &j.Error, &j.CreatedBy, &j.CreatedAt, &finished); err != nil {
			return nil, err
		}
		if finished.Valid {
			j.FinishedAt = &finished.Time
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// ClaimNextJob atomically moves one queued job to running. Returns nil when empty.
func (s *Store) ClaimNextJob() (*ReconJob, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var j ReconJob
	var finished sql.NullTime
	err = tx.QueryRow(`SELECT id, project_id, tool, target, status, output_ref, error, created_by, created_at, finished_at FROM recon_jobs WHERE status='queued' ORDER BY created_at LIMIT 1`).Scan(
		&j.ID, &j.ProjectID, &j.Tool, &j.Target, &j.Status, &j.OutputRef, &j.Error, &j.CreatedBy, &j.CreatedAt, &finished)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE recon_jobs SET status='running' WHERE id=? AND status='queued'`, j.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	j.Status = JobRunning
	return &j, nil
}

// FinishReconJob marks done/failed with optional output summary + error.
func (s *Store) FinishReconJob(jobID, status, outputRef, errMsg string) error {
	if status != JobDone && status != JobFailed {
		return fmt.Errorf("invalid terminal status %q", status)
	}
	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE recon_jobs SET status=?, output_ref=?, error=?, finished_at=? WHERE id=?`, status, outputRef, errMsg, now, jobID)
	return err
}

// UpsertHost inserts or updates a discovered host.
func (s *Store) UpsertHost(projectID, ip, hostname, os, source string) error {
	_, err := s.db.Exec(`INSERT INTO hosts(id, project_id, ip, hostname, os, source, created_at) VALUES(?,?,?,?,?,?,?)
ON CONFLICT(project_id, ip) DO UPDATE SET hostname=excluded.hostname, os=excluded.os, source=excluded.source`,
		uuid.NewString(), projectID, ip, hostname, os, source, time.Now().UTC())
	return err
}

// UpsertService inserts or updates a discovered service.
func (s *Store) UpsertService(projectID, hostIP string, port int, protocol, state, name, product, version string) error {
	if protocol == "" {
		protocol = "tcp"
	}
	_, err := s.db.Exec(`INSERT INTO services(id, project_id, host_ip, port, protocol, state, name, product, version, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(project_id, host_ip, port, protocol) DO UPDATE SET state=excluded.state, name=excluded.name, product=excluded.product, version=excluded.version`,
		uuid.NewString(), projectID, hostIP, port, protocol, state, name, product, version, time.Now().UTC())
	return err
}

func (s *Store) ListHosts(projectID string) ([]Host, error) {
	rows, err := s.db.Query(`SELECT id, project_id, ip, hostname, os, source, created_at FROM hosts WHERE project_id=? ORDER BY ip`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		var h Host
		if err := rows.Scan(&h.ID, &h.ProjectID, &h.IP, &h.Hostname, &h.OS, &h.Source, &h.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) ListServices(projectID string) ([]Service, error) {
	rows, err := s.db.Query(`SELECT id, project_id, host_ip, port, protocol, state, name, product, version, created_at FROM services WHERE project_id=? ORDER BY host_ip, port`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Service
	for rows.Next() {
		var sv Service
		if err := rows.Scan(&sv.ID, &sv.ProjectID, &sv.HostIP, &sv.Port, &sv.Protocol, &sv.State, &sv.Name, &sv.Product, &sv.Version, &sv.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sv)
	}
	return out, rows.Err()
}
