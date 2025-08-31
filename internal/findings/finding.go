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
	Timestamp   time.Time `json:"timestamp"`
}

var severities = map[string]bool{
	SeverityInfo: true, SeverityLow: true, SeverityMedium: true, SeverityHigh: true, SeverityCritical: true,
}

var confidences = map[string]bool{
	ConfObserved: true, ConfPotential: true, ConfValidated: true, ConfConfirmed: true,
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
	return nil
}
