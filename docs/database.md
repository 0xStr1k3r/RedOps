# Database — Phase 1 (SQLite, Postgres-compatible)

```sql
users(id TEXT PK, username UNIQUE, password_hash, role, created_at)
projects(id TEXT PK, name UNIQUE, description, created_at)
scopes(id PK, project_id FK CASCADE, value, type, created_at, UNIQUE(project_id,value))
targets(id PK, project_id FK CASCADE, value, type, added_by, created_at, UNIQUE(project_id,value))
timeline(id PK, project_id FK CASCADE, timestamp, kind, message, actor)
audit_log(id PK, project_id, actor, action, target, result, created_at)
```

`type` ∈ `cidr|ip|domain` (from `scope.Classify`).

## Postgres migration (Phase 6)

- Same DDL with `TEXT` → `TEXT`, `TIMESTAMP` → `TIMESTAMPTZ`, add `ON DELETE CASCADE`.
- New tables: `hosts, services, findings, credentials, techniques, evidence, operations, reports`.
- Neo4j mirrors relations: `(:Host)-[:RUNS]->(:Service)`, `(:Service)-[:HAS_FINDING]->(:Finding)`,
  `(:Finding)-[:MAPS_TO]->(:Technique)`, `(:User)-[:MEMBER_OF]->(:Group)`.
- Swap driver in `project.Open`; `sql.DB` API unchanged.

## Indexes

`idx_scopes_project, idx_targets_project, idx_timeline_project(project_id,timestamp)`.
