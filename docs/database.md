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
`idx_jobs_project(project_id,status,created_at)`, `idx_hosts_project`, `idx_services_project(host_id)`.

## Phase-2 tables

```sql
recon_jobs(id PK, project_id FK CASCADE, tool, target, status, output_ref, error, created_by, created_at, finished_at)
hosts(id PK, project_id FK CASCADE, ip, hostname, os, source, created_at, UNIQUE(project_id,ip))
services(id PK, project_id FK CASCADE, host_ip, port, protocol, state, name, product, version, created_at, UNIQUE(project_id,host_ip,port,protocol))
enum_jobs(id PK, project_id FK CASCADE, host_ip, port, module, status, output_ref, error, created_by, created_at, finished_at)
enum_results(id PK, project_id FK CASCADE, job_id, host_ip, port, module, summary, observations_json, created_at)
findings(id PK, project_id FK CASCADE, title, description, severity, confidence, target, evidence, source, cwe, cve, technique_id, remediation, status, dedupe_key UNIQUE per project, created_at, updated_at)
attack_paths(id PK, project_id FK CASCADE, nodes_json, length, risk, confidence, techniques, objective, privileges, created_at)
validation_runs(id PK, project_id FK CASCADE, finding_id, validator, success, detail, actor, created_at)
```
