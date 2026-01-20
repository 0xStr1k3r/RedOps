package project

import "time"

// ScenarioRun tracks one playbook execution (async: queued → running → done|failed).
type ScenarioRun struct {
	ID         string     `json:"id"`
	ProjectID  string     `json:"project_id"`
	Scenario   string     `json:"scenario"`
	Target     string     `json:"target"`
	Status     string     `json:"status"`
	OutputRef  string     `json:"output_ref,omitempty"`
	Error      string     `json:"error,omitempty"`
	CreatedBy  string     `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}
