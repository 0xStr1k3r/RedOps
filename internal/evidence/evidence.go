package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
)

// Evidence is an integrity-protected record of one operator action.
// Hash = SHA256(project|target|action|command|output|timestamp|operator|finding|prev).
// PrevHash links each record to the previous one in its project, forming a
// tamper-evident chain verified by project.VerifyEvidenceChain.
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
	PrevHash  string    `json:"prev_hash,omitempty"`
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
	h.Write([]byte(e.ProjectID + "\x00" + e.Target + "\x00" + e.Action + "\x00" + e.Command + "\x00" + e.OutputRef + "\x00" + e.Timestamp.UTC().Format(time.RFC3339Nano) + "\x00" + e.Operator + "\x00" + e.FindingID + "\x00" + e.PrevHash))
	return hex.EncodeToString(h.Sum(nil))
}

// Verify recomputes the hash and reports integrity.
func (e *Evidence) Verify() bool { return e.compute() == e.Hash }

// Seal binds the record to a finding and chains it after prevHash,
// recomputing the hash. The store calls this with the project's last hash.
func (e *Evidence) Seal(findingID, prevHash string) {
	e.FindingID = findingID
	e.PrevHash = prevHash
	e.Hash = e.compute()
}
