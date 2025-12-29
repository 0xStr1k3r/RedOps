package project

import "time"

// EvidenceRow mirrors evidence.Evidence for storage (project must not import
// the evidence package; services convert field-by-field).
type EvidenceRow struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	Timestamp time.Time `json:"timestamp"`
	Operator  string    `json:"operator"`
	Target    string    `json:"target"`
	Action    string    `json:"action"`
	Command   string    `json:"command,omitempty"`
	OutputRef string    `json:"output_ref,omitempty"`
	Technique string    `json:"technique,omitempty"`
	FindingID string    `json:"finding_id,omitempty"`
	PrevHash  string    `json:"prev_hash,omitempty"`
	Hash      string    `json:"hash"`
}

// ChainStatus is the result of VerifyEvidenceChain.
type ChainStatus struct {
	OK       bool   `json:"ok"`
	Checked  int    `json:"checked"`
	BrokenAt string `json:"broken_at,omitempty"`
}
