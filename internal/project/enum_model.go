package project

import "time"

// EnumJob is one scope-checked service enumeration task.
type EnumJob struct {
	ID         string     `json:"id"`
	ProjectID  string     `json:"project_id"`
	HostIP     string     `json:"host_ip"`
	Port       int        `json:"port"`
	Module     string     `json:"module"`
	Status     string     `json:"status"`
	OutputRef  string     `json:"output_ref,omitempty"`
	Error      string     `json:"error,omitempty"`
	CreatedBy  string     `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// EnumObservation mirrors enumeration.Observation without importing that
// package (project must stay importable from enumeration, not vice versa).
type EnumObservation struct {
	Kind        string `json:"kind"`
	Detail      string `json:"detail"`
	TechniqueID string `json:"technique_id"`
}

// EnumResult is the persisted observation set from a finished job.
type EnumResult struct {
	ID           string            `json:"id"`
	ProjectID    string            `json:"project_id"`
	JobID        string            `json:"job_id"`
	HostIP       string            `json:"host_ip"`
	Port         int               `json:"port"`
	Module       string            `json:"module"`
	Summary      string            `json:"summary"`
	Observations []EnumObservation `json:"observations"`
	CreatedAt    time.Time         `json:"created_at"`
}
