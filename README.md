# RedOps — Red-Team Attack Path & Adversary Emulation Platform

> **Authorized assessments only.** RedOps enforces project scope on every target.
> Out-of-scope targets are refused (HTTP 403 / CLI error) and audit-logged.
> See [SECURITY.md](SECURITY.md).

Modular red-team platform: project → scope → targets → recon → enumeration →
findings → MITRE ATT&CK → attack graph → validation (lab-only) → evidence →
timeline → report.

## Status: Phase 6 — Attack graph (implemented)

- Go REST API (`chi`), JWT auth, RBAC (`admin > operator > viewer`)
- Project / scope / target management with **scope enforcement**
- Recon: `Tool` adapters (nmap, httpx, dnsx, subfinder), SQLite job queue,
  worker daemon, hosts/services inventory — every run scope-gated twice
- Enumeration: `http`, `ssh-banner`, `dns`, `tcp-banner` read-only modules,
  enum queue + results store — see `docs/enumeration.md`
- Findings: deterministic rule engine (observations → severity/CWE/ATT&CK),
  deduped store, status/confidence workflow — see `docs/findings.md`
- MITRE: embedded matrix (101 techniques), per-project tactic coverage — see `docs/mitre.md`
- Graph: offline-first attack graph (JSON/Cypher/DOT) + Neo4j MERGE sync — see `docs/attackgraph.md`
- SQLite store (Postgres-compatible schema, see `docs/database.md`)
- Timeline + audit log, evidence hashing (SHA-256)
- Nmap/httpx/dnsx parsers, finding schema, MITRE subset
- CLI (`redops`), server (`redops-api`), worker (`redops-worker`)
- CI: tests, vet, gosec, Trivy

## Quick start (no Docker needed)

```bash
# 1. Build
make build

# 2. Start API (needs 32+ char secret)
export REDOPS_JWT_SECRET=$(openssl rand -hex 32)
export REDOPS_DB=redops.db
./bin/redops-api &
# or: go run ./cmd/server

# 3. Register first user (becomes admin), login
curl -s -X POST localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password-123"}'

TOKEN=$(curl -s -X POST localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password-123"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# 4. Project + scope + targets
PID=$(curl -s -X POST localhost:8080/api/v1/projects \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"acme","description":"lab pentest"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")

curl -s -X POST localhost:8080/api/v1/projects/$PID/scope \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"value":"10.10.10.0/24"}'

curl -s -X POST localhost:8080/api/v1/projects/$PID/targets \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"value":"10.10.10.10"}'   # 200/201

curl -s -X POST localhost:8080/api/v1/projects/$PID/targets \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"value":"8.8.8.8"}'       # 403 scope denied
```

CLI equivalent (same DB file, no server):

```bash
./bin/redops --db redops.db project create acme --scope 10.10.10.0/24
./bin/redops --db redops.db target add acme 10.10.10.10
./bin/redops --db redops.db target add acme 8.8.8.8   # denied
./bin/redops --db redops.db status acme
```

## Recon (Phase 2)

```bash
# Inline (no worker needed):
./bin/redops --db redops.db recon run acme --tool nmap --target 10.10.10.10 --profile fast
./bin/redops --db redops.db assets acme

# Queued (worker processes):
./bin/redops --db redops.db recon run acme --tool nmap --target 10.10.10.10 --async
REDOPS_DB=redops.db ./bin/redops-worker            # polls queue
REDOPS_DB=redops.db REDOPS_WORKER_ONCE=1 ./bin/redops-worker  # single pass
```

API:

```bash
curl -X POST localhost:8080/api/v1/projects/$PID/recon \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"tool":"nmap","target":"10.10.10.10"}'   # 202, or 403 out-of-scope
curl localhost:8080/api/v1/projects/$PID/assets -H "Authorization: Bearer $TOKEN"
```

## Enumeration (Phase 3, read-only)

```bash
./bin/redops --db redops.db enum run acme --host 10.10.10.10 --port 80
./bin/redops --db redops.db enum run acme --host 10.10.10.10 --port 22 --module ssh-banner
./bin/redops --db redops.db enum results acme
```

Details per module (observations, ATT&CK mapping, safety limits): `docs/enumeration.md`.

## Findings (Phase 4)

```bash
./bin/redops --db redops.db findings raise acme
./bin/redops --db redops.db findings list acme --severity low --status open
./bin/redops --db redops.db findings update acme <id> --status acknowledged --confidence validated
```

Rule catalog + severity rubric: `docs/findings.md`.

## MITRE ATT&CK (Phase 5)

```bash
./bin/redops --db redops.db mitre tactics
./bin/redops --db redops.db mitre techniques --tactic Discovery
./bin/redops --db redops.db mitre coverage acme
```

## Attack graph (Phase 6, offline-first)

```bash
./bin/redops --db redops.db graph show acme --format cypher
export REDOPS_NEO4J_URI=bolt://127.0.0.1:7687 REDOPS_NEO4J_USER=neo4j REDOPS_NEO4J_PASS=...
./bin/redops --db redops.db graph sync acme
```

## Layout

```text
cmd/server  REST API entrypoint
cmd/cli     operator CLI (cobra)
cmd/worker  Phase-2 job consumer (stub)
internal/scope       CIDR/IP/domain enforcement (tested)
internal/auth        Argon2id + JWT + RBAC (tested)
internal/project     SQLite store: projects/scopes/targets/timeline/audit (tested)
internal/api         chi router + handlers (tested end-to-end)
internal/evidence    SHA-256 evidence objects
internal/findings    normalized finding schema
internal/mitre       embedded ATT&CK subset + observation mapping
pkg/nmap             nmap -oX parser
docs/                architecture, api, database, roadmap, threat-model
lab/                 docker lab (Phase 2+ targets)
deployments/         compose for Postgres/Neo4j/Redis (Phase 6)
```

## API

See [docs/api.md](docs/api.md). Summary:

```text
POST /api/v1/auth/register  POST /api/v1/auth/login
POST /api/v1/projects       GET /api/v1/projects  GET /api/v1/projects/{id}
POST /api/v1/projects/{id}/scope   GET /api/v1/projects/{id}/scope
POST /api/v1/projects/{id}/targets GET /api/v1/projects/{id}/targets
GET  /api/v1/projects/{id}/timeline
GET  /healthz
```

## Roadmap

Phases 2–12 in [docs/roadmap.md](docs/roadmap.md). Next: Phase 2 Recon
(tool adapters for nmap/httpx/dnsx behind scope enforcement + job queue).

## Lab safety

Phase 1 ships **no tool execution, no exploits**. Validation modules
(Phase 8) will run only against `lab/` containers. Never point RedOps
at systems you are not authorized to test.
