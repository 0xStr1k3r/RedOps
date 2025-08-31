package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
)

// Evidence is an integrity-protected record of one operator action.
// Hash = SHA256(project|target|action|command|output|timestamp|operator).
type Evidence struct {
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
	Hash      string    `json:"hash"`
}

// New builds an evidence object and computes its hash.
func New(projectID, operator, target, action, command, outputRef, technique string) *Evidence {
	e := &Evidence{
		ID:        uuid.NewString(),
		ProjectID: projectID,
		Timestamp: time.Now().UTC(),
		Operator:  operator,
		Target:    target,
		Action:    action,
		Command:   command,
		OutputRef: outputRef,
		Technique: technique,
	}
	e.Hash = e.compute()
	return e
}

func (e *Evidence) compute() string {
	h := sha256.New()
	h.Write([]byte(e.ProjectID + "\x00" + e.Target + "\x00" + e.Action + "\x00" + e.Command + "\x00" + e.OutputRef + "\x00" + e.Timestamp.UTC().Format(time.RFC3339Nano) + "\x00" + e.Operator))
	return hex.EncodeToString(h.Sum(nil))
}

// Verify recomputes the hash and reports integrity.
func (e *Evidence) Verify() bool { return e.compute() == e.Hash }
