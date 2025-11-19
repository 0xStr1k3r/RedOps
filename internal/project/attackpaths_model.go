package project

import "time"

// StoredPath is a persisted attack path (nodes as JSON).
type StoredPath struct {
	ID         string    `json:"id"`
	ProjectID  string    `json:"project_id"`
	NodesJSON  string    `json:"nodes"`
	Length     int       `json:"length"`
	Risk       int       `json:"risk"`
	Confidence string    `json:"confidence"`
	Techniques string    `json:"techniques"`
	Objective  string    `json:"objective"`
	Privileges string    `json:"required_privileges"`
	CreatedAt  time.Time `json:"created_at"`
}
