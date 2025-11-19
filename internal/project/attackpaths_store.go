package project

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// ReplaceAttackPaths atomically swaps a project's paths (regenerate semantics).
func (s *Store) ReplaceAttackPaths(projectID string, paths []StoredPath) error {
	if _, err := s.GetProject(projectID); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM attack_paths WHERE project_id=?`, projectID); err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, p := range paths {
		if _, err := tx.Exec(`INSERT INTO attack_paths(id, project_id, nodes_json, length, risk, confidence, techniques, objective, privileges, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			p.ID, projectID, p.NodesJSON, p.Length, p.Risk, p.Confidence, p.Techniques, p.Objective, p.Privileges, now); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	_ = s.addTimeline(projectID, "attackpaths.generated", fmt.Sprintf("%d attack paths generated", len(paths)), "")
	return nil
}

// ListAttackPaths returns paths sorted by risk desc, then length asc.
func (s *Store) ListAttackPaths(projectID string, minRisk int) ([]StoredPath, error) {
	rows, err := s.db.Query(`SELECT id, project_id, nodes_json, length, risk, confidence, techniques, objective, privileges, created_at FROM attack_paths WHERE project_id=? AND risk>=? ORDER BY risk DESC, length ASC`, projectID, minRisk)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredPath
	for rows.Next() {
		var p StoredPath
		if err := rows.Scan(&p.ID, &p.ProjectID, &p.NodesJSON, &p.Length, &p.Risk, &p.Confidence, &p.Techniques, &p.Objective, &p.Privileges, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetAttackPath fetches one path within a project.
func (s *Store) GetAttackPath(projectID, pathID string) (*StoredPath, error) {
	var p StoredPath
	err := s.db.QueryRow(`SELECT id, project_id, nodes_json, length, risk, confidence, techniques, objective, privileges, created_at FROM attack_paths WHERE id=? AND project_id=?`, pathID, projectID).
		Scan(&p.ID, &p.ProjectID, &p.NodesJSON, &p.Length, &p.Risk, &p.Confidence, &p.Techniques, &p.Objective, &p.Privileges, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("attack path not found")
	}
	return &p, err
}

// ConfirmAttackPath lets an operator promote confidence after verification.
// Only upgrades to validated/confirmed are allowed here; downgrades use the
// findings workflow. The engine itself never writes these states.
func (s *Store) ConfirmAttackPath(projectID, pathID, confidence, actor string) (*StoredPath, error) {
	switch strings.ToLower(confidence) {
	case "validated", "confirmed":
	default:
		return nil, fmt.Errorf("can only confirm to validated|confirmed (got %q)", confidence)
	}
	res, err := s.db.Exec(`UPDATE attack_paths SET confidence=? WHERE id=? AND project_id=?`, strings.ToLower(confidence), pathID, projectID)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, fmt.Errorf("attack path not found")
	}
	_ = s.AppendAudit(projectID, actor, "attackpath.confirm", pathID, confidence)
	return s.GetAttackPath(projectID, pathID)
}
