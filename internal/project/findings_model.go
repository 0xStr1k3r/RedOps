package project

import (
	"time"
)

// FindingRow mirrors findings.Finding for storage (project must not import
// the findings package; the findings service converts field-by-field).
type FindingRow struct {
	ID          string    `json:"id"`
	ProjectID   string    `json:"project_id"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Severity    string    `json:"severity"`
	Confidence  string    `json:"confidence"`
	Target      string    `json:"target"`
	Evidence    string    `json:"evidence,omitempty"`
	Source      string    `json:"source,omitempty"`
	CWE         string    `json:"cwe,omitempty"`
	CVE         string    `json:"cve,omitempty"`
	TechniqueID string    `json:"attack_technique,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// FindingFilter narrows ListFindings. Empty fields match all.
type FindingFilter struct {
	Severity string
	Status   string
	Target   string
}
