package project

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redops/redops/internal/scope"
	_ "modernc.org/sqlite"
)

// Store is a SQLite-backed repository for Phase 1 entities.
// Schema is forward-compatible with the Postgres migration (same table/column names).
type Store struct {
	db *sql.DB
}

// Open creates/opens the SQLite file and applies the schema.
// Use ":memory:" for tests.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	schema := `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS scopes (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  value TEXT NOT NULL,
  type TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  UNIQUE(project_id, value)
);
CREATE TABLE IF NOT EXISTS targets (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  value TEXT NOT NULL,
  type TEXT NOT NULL,
  added_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL,
  UNIQUE(project_id, value)
);
CREATE TABLE IF NOT EXISTS timeline (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  timestamp TIMESTAMP NOT NULL,
  kind TEXT NOT NULL,
  message TEXT NOT NULL,
  actor TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  result TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scopes_project ON scopes(project_id);
CREATE INDEX IF NOT EXISTS idx_targets_project ON targets(project_id);
CREATE INDEX IF NOT EXISTS idx_timeline_project ON timeline(project_id, timestamp);
CREATE TABLE IF NOT EXISTS recon_jobs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  tool TEXT NOT NULL,
  target TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  output_ref TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL,
  finished_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS hosts (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  ip TEXT NOT NULL,
  hostname TEXT NOT NULL DEFAULT '',
  os TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL,
  UNIQUE(project_id, ip)
);
CREATE TABLE IF NOT EXISTS services (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  host_ip TEXT NOT NULL,
  port INTEGER NOT NULL,
  protocol TEXT NOT NULL DEFAULT 'tcp',
  state TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '',
  product TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL,
  UNIQUE(project_id, host_ip, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_jobs_project ON recon_jobs(project_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_hosts_project ON hosts(project_id);
CREATE INDEX IF NOT EXISTS idx_services_project ON services(project_id, host_ip);
CREATE TABLE IF NOT EXISTS enum_jobs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  host_ip TEXT NOT NULL,
  port INTEGER NOT NULL,
  module TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  output_ref TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL,
  finished_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS enum_results (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  job_id TEXT NOT NULL,
  host_ip TEXT NOT NULL,
  port INTEGER NOT NULL,
  module TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  observations_json TEXT NOT NULL DEFAULT '[]',
  created_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enumjobs_project ON enum_jobs(project_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_enumresults_project ON enum_results(project_id, host_ip, port);
`
	_, err := s.db.Exec(schema)
	return err
}

// --- Users (used by API layer; hashing lives in auth package) ---

func (s *Store) CreateUser(id, username, passHash, role string, now time.Time) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username required")
	}
	_, err := s.db.Exec(`INSERT INTO users(id, username, password_hash, role, created_at) VALUES(?,?,?,?,?)`,
		id, username, passHash, role, now.UTC())
	return err
}

func (s *Store) GetUserByUsername(username string) (id, passHash, role string, err error) {
	err = s.db.QueryRow(`SELECT id, password_hash, role FROM users WHERE username=?`, username).Scan(&id, &passHash, &role)
	return
}

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// --- Projects ---

func (s *Store) CreateProject(name, description string) (*Project, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return nil, fmt.Errorf("project name must be 1-100 chars")
	}
	p := &Project{ID: uuid.NewString(), Name: name, Description: description, CreatedAt: time.Now().UTC()}
	_, err := s.db.Exec(`INSERT INTO projects(id, name, description, created_at) VALUES(?,?,?,?)`,
		p.ID, p.Name, p.Description, p.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = s.addTimeline(p.ID, "project.created", "Project created: "+name, "")
	return p, nil
}

func (s *Store) ListProjects() ([]Project, error) {
	rows, err := s.db.Query(`SELECT id, name, description, created_at FROM projects ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetProject(id string) (*Project, error) {
	var p Project
	err := s.db.QueryRow(`SELECT id, name, description, created_at FROM projects WHERE id=?`, id).
		Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("project not found")
	}
	return &p, err
}

// --- Scope ---

func (s *Store) AddScopeEntry(projectID, rawValue string) (*ScopeEntry, error) {
	if _, err := s.GetProject(projectID); err != nil {
		return nil, err
	}
	typ, norm, err := scope.Classify(rawValue)
	if err != nil {
		return nil, err
	}
	e := &ScopeEntry{ID: uuid.NewString(), ProjectID: projectID, Value: norm, Type: string(typ), CreatedAt: time.Now().UTC()}
	_, err = s.db.Exec(`INSERT INTO scopes(id, project_id, value, type, created_at) VALUES(?,?,?,?,?)`,
		e.ID, e.ProjectID, e.Value, e.Type, e.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = s.addTimeline(projectID, "scope.added", "Scope added: "+norm, "")
	return e, nil
}

func (s *Store) ListScopes(projectID string) ([]ScopeEntry, error) {
	rows, err := s.db.Query(`SELECT id, project_id, value, type, created_at FROM scopes WHERE project_id=? ORDER BY created_at`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScopeEntry
	for rows.Next() {
		var e ScopeEntry
		if err := rows.Scan(&e.ID, &e.ProjectID, &e.Value, &e.Type, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// LoadScope builds the enforceable scope for a project.
func (s *Store) LoadScope(projectID string) (*scope.Scope, error) {
	entries, err := s.ListScopes(projectID)
	if err != nil {
		return nil, err
	}
	raw := make([]string, 0, len(entries))
	for _, e := range entries {
		raw = append(raw, e.Value)
	}
	return scope.ParseEntries(raw)
}

// --- Targets (scope-enforced) ---

func (s *Store) AddTarget(projectID, rawValue, addedBy string) (*Target, error) {
	if _, err := s.GetProject(projectID); err != nil {
		return nil, err
	}
	sc, err := s.LoadScope(projectID)
	if err != nil {
		return nil, fmt.Errorf("cannot add target: project has no valid scope yet (%v)", err)
	}
	if err := sc.Enforce(rawValue); err != nil {
		return nil, err
	}
	typ, norm, err := scope.Classify(rawValue)
	if err != nil {
		return nil, err
	}
	t := &Target{ID: uuid.NewString(), ProjectID: projectID, Value: norm, Type: string(typ), AddedBy: addedBy, CreatedAt: time.Now().UTC()}
	_, err = s.db.Exec(`INSERT INTO targets(id, project_id, value, type, added_by, created_at) VALUES(?,?,?,?,?,?)`,
		t.ID, t.ProjectID, t.Value, t.Type, t.AddedBy, t.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = s.addTimeline(projectID, "target.added", "Target added: "+norm, addedBy)
	return t, nil
}

func (s *Store) ListTargets(projectID string) ([]Target, error) {
	rows, err := s.db.Query(`SELECT id, project_id, value, type, added_by, created_at FROM targets WHERE project_id=? ORDER BY created_at`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.ID, &t.ProjectID, &t.Value, &t.Type, &t.AddedBy, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// --- Timeline + audit ---

func (s *Store) addTimeline(projectID, kind, message, actor string) error {
	_, err := s.db.Exec(`INSERT INTO timeline(id, project_id, timestamp, kind, message, actor) VALUES(?,?,?,?,?,?)`,
		uuid.NewString(), projectID, time.Now().UTC(), kind, message, actor)
	return err
}

func (s *Store) ListTimeline(projectID string) ([]TimelineEvent, error) {
	rows, err := s.db.Query(`SELECT id, project_id, timestamp, kind, message, actor FROM timeline WHERE project_id=? ORDER BY timestamp`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TimelineEvent
	for rows.Next() {
		var e TimelineEvent
		if err := rows.Scan(&e.ID, &e.ProjectID, &e.Timestamp, &e.Kind, &e.Message, &e.Actor); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) AppendAudit(projectID, actor, action, target, result string) error {
	_, err := s.db.Exec(`INSERT INTO audit_log(id, project_id, actor, action, target, result, created_at) VALUES(?,?,?,?,?,?,?)`,
		uuid.NewString(), projectID, actor, action, target, result, time.Now().UTC())
	return err
}
