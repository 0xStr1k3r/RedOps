package project

import "time"

// Project is one authorized assessment.
type Project struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// ScopeEntry is one authorized scope value (cidr/ip/domain).
type ScopeEntry struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	Value     string    `json:"value"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
}

// Target is a host/range submitted for assessment. Always scope-checked on insert.
type Target struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	Value     string    `json:"value"`
	Type      string    `json:"type"`
	AddedBy   string    `json:"added_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// TimelineEvent backs the assessment timeline (Phase 1: project/target/auth events).
type TimelineEvent struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	Timestamp time.Time `json:"timestamp"`
	Kind      string    `json:"kind"`
	Message   string    `json:"message"`
	Actor     string    `json:"actor,omitempty"`
}

// AuditRecord is an append-only log of security-relevant actions.
type AuditRecord struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id,omitempty"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target,omitempty"`
	Result    string    `json:"result,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
