package findings

import (
	"fmt"
	"strings"
	"time"
)

// Severity levels, ordered.
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Confidence in a finding: observed < potential < validated < confirmed.
const (
	ConfObserved  = "observed"
	ConfPotential = "potential"
	ConfValidated = "validated"
	ConfConfirmed = "confirmed"
)

// Lifecycle status, orthogonal to confidence.
const (
	StatusOpen          = "open"
	StatusAcknowledged  = "acknowledged"
	StatusResolved      = "resolved"
	StatusFalsePositive = "false_positive"
)

// Finding is the normalized object for everything discovered.
// Phase 1 defines the schema; engines populate it in later phases.
type Finding struct {
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
	Status      string    `json:"status,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

var severities = map[string]bool{
	SeverityInfo: true, SeverityLow: true, SeverityMedium: true, SeverityHigh: true, SeverityCritical: true,
}

var confidences = map[string]bool{
	ConfObserved: true, ConfPotential: true, ConfValidated: true, ConfConfirmed: true,
}

var statuses = map[string]bool{
	StatusOpen: true, StatusAcknowledged: true, StatusResolved: true, StatusFalsePositive: true,
}

// Validate checks required fields and enums.
func (f *Finding) Validate() error {
	if strings.TrimSpace(f.Title) == "" {
		return fmt.Errorf("title required")
	}
	if strings.TrimSpace(f.Target) == "" {
		return fmt.Errorf("target required")
	}
	if !severities[strings.ToLower(f.Severity)] {
		return fmt.Errorf("invalid severity %q", f.Severity)
	}
	if !confidences[strings.ToLower(f.Confidence)] {
		return fmt.Errorf("invalid confidence %q", f.Confidence)
	}
	if f.Status != "" && !statuses[strings.ToLower(f.Status)] {
		return fmt.Errorf("invalid status %q", f.Status)
	}
	return nil
}

// Normalize lowercases enums and defaults empty status to open.
func (f *Finding) Normalize() {
	f.Severity = strings.ToLower(strings.TrimSpace(f.Severity))
	f.Confidence = strings.ToLower(strings.TrimSpace(f.Confidence))
	f.Status = strings.ToLower(strings.TrimSpace(f.Status))
	if f.Status == "" {
		f.Status = StatusOpen
	}
	if f.Confidence == "" {
		f.Confidence = ConfObserved
	}
}
