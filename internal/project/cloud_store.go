package project

import (
	"fmt"
	"time"
)

// SaveCloudImport validates nothing itself (callers parse first) and stores
// the raw document with replace semantics. One import per project.
func (s *Store) SaveCloudImport(projectID, document, actor string) error {
	if _, err := s.GetProject(projectID); err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err := s.db.Exec(`INSERT INTO cloud_imports(project_id, document, created_at, updated_at) VALUES(?,?,?,?)
ON CONFLICT(project_id) DO UPDATE SET document=excluded.document, updated_at=excluded.updated_at`,
		projectID, document, now, now)
	if err != nil {
		return err
	}
	_ = s.addTimeline(projectID, "cloud.imported", fmt.Sprintf("IAM import stored (%d bytes)", len(document)), actor)
	_ = s.AppendAudit(projectID, actor, "cloud.import", "", fmt.Sprintf("%d bytes", len(document)))
	return nil
}

// GetCloudImport returns the raw document or "" when none exists.
func (s *Store) GetCloudImport(projectID string) (string, error) {
	var doc string
	err := s.db.QueryRow(`SELECT document FROM cloud_imports WHERE project_id=?`, projectID).Scan(&doc)
	if err != nil {
		return "", nil
	}
	return doc, nil
}
