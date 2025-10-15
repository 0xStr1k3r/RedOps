package project

import "time"

// Recon job lifecycle: queued -> running -> done | failed.
const (
	JobQueued  = "queued"
	JobRunning = "running"
	JobDone    = "done"
	JobFailed  = "failed"
)

// AllowedReconTools is the Phase-2 allowlist. The recon registry must match.
// Kept here (not imported from recon) to avoid an import cycle.
var AllowedReconTools = map[string]bool{
	"nmap": true, "httpx": true, "dnsx": true, "subfinder": true,
}

// ReconJob is one scope-checked tool execution.
type ReconJob struct {
	ID         string     `json:"id"`
	ProjectID  string     `json:"project_id"`
	Tool       string     `json:"tool"`
	Target     string     `json:"target"`
	Status     string     `json:"status"`
	OutputRef  string     `json:"output_ref,omitempty"`
	Error      string     `json:"error,omitempty"`
	CreatedBy  string     `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// Host is a discovered asset.
type Host struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname,omitempty"`
	OS        string    `json:"os,omitempty"`
	Source    string    `json:"source,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Service is one open port on a host.
type Service struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	HostIP    string    `json:"host_ip"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"`
	State     string    `json:"state,omitempty"`
	Name      string    `json:"name,omitempty"`
	Product   string    `json:"product,omitempty"`
	Version   string    `json:"version,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
