package project

import "time"

// ValidationRun is one recorded validator execution against a finding.
type ValidationRun struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	FindingID string    `json:"finding_id"`
	Validator string    `json:"validator"`
	Success   bool      `json:"success"`
	Detail    string    `json:"detail"`
	Actor     string    `json:"actor"`
	CreatedAt time.Time `json:"created_at"`
}
