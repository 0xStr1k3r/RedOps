# API — Phase 1

Base: `http://localhost:8080`. All `/api/v1` except register/login need
`Authorization: Bearer <jwt>`.

## Auth

```http
POST /api/v1/auth/register  {"username":"alice","password":"...","role":"viewer"}
→ 201 {"id","username","role"}   # first user forced admin

POST /api/v1/auth/login  {"username":"alice","password":"..."}
→ 200 {"token","role"}
```

## Projects

```http
POST /api/v1/projects  {"name":"acme","description":"lab"}
→ 201 Project   # operator+

GET /api/v1/projects → 200 [Project]
GET /api/v1/projects/{id} → 200 Project | 404
```

## Scope

```http
POST /api/v1/projects/{id}/scope  {"value":"10.10.10.0/24"}
→ 201 ScopeEntry | 400 invalid   # operator+

GET /api/v1/projects/{id}/scope → 200 [ScopeEntry]
```

Values: CIDR (`10.10.0.0/16`), IP (`10.0.0.5`), domain (`web01.lab`).

## Targets (scope-enforced)

```http
POST /api/v1/projects/{id}/targets  {"value":"10.10.10.10"}
→ 201 Target | 403 scope denied | 400 invalid   # operator+

GET /api/v1/projects/{id}/targets → 200 [Target]
GET /api/v1/projects/{id}/timeline → 200 [TimelineEvent]
```

## Recon (Phase 2, scope-gated)

```http
POST /api/v1/projects/{id}/recon  {"tool":"nmap","target":"10.10.10.10"}
→ 202 ReconJob | 403 scope denied | 400 unknown tool   # operator+

GET /api/v1/projects/{id}/recon → 200 [ReconJob]
GET /api/v1/projects/{id}/recon/{jobID} → 200 ReconJob | 404
GET /api/v1/projects/{id}/hosts → 200 [Host]
GET /api/v1/projects/{id}/services → 200 [Service]
GET /api/v1/projects/{id}/assets → 200 {"hosts":[],"services":[]}
GET /healthz → 200 {"status":"ok"}
```

Tools: `nmap` (IP/CIDR), `httpx` (IP/domain), `dnsx`/`subfinder` (domain).
Jobs run via `redops-worker` (polls queue, re-enforces scope at execution).
Missing binaries fail the job with an install hint, never the server.

## Enumeration (Phase 3, read-only)

```http
POST /api/v1/projects/{id}/enumerate  {"host":"10.10.10.10","port":80,"module":"http"}
→ 202 EnumJob | 403 scope denied | 400 unknown module   # operator+, module optional (auto-match)

GET /api/v1/projects/{id}/enumerate → 200 [EnumJob]
GET /api/v1/projects/{id}/enumerate/{jobID} → 200 EnumJob | 404
GET /api/v1/projects/{id}/enum-results → 200 [EnumResult]
```

Modules: `http`, `ssh-banner`, `dns`, `tcp-banner` (fallback).
Full per-module docs: `docs/enumeration.md`.

## Findings (Phase 4)

```http
POST /api/v1/projects/{id}/findings  {"title":"...","severity":"high","confidence":"observed","target":"10.0.0.1:443"}
→ 201 | 400 invalid   # operator+

GET /api/v1/projects/{id}/findings?severity=high&status=open → 200 [Finding]
GET /api/v1/projects/{id}/findings/{fid} → 200 Finding | 404
PATCH /api/v1/projects/{id}/findings/{fid}  {"status":"acknowledged","confidence":"validated"}
→ 200 Finding | 400 invalid | 404   # operator+

POST /api/v1/projects/{id}/findings/raise → 200 {"raised": N}   # operator+, idempotent
```

Rule catalog + severity rubric: `docs/findings.md`.

## MITRE ATT&CK (Phase 5)

```http
GET /api/v1/mitre/tactics → 200 [Tactic]                    # public
GET /api/v1/mitre/techniques[?tactic=Discovery] → 200 [Technique]  # public
GET /api/v1/projects/{id}/techniques → 200 Coverage          # auth
```

Matrix + coverage model: `docs/mitre.md`.

## Attack graph (Phase 6, offline-first)

```http
GET /api/v1/projects/{id}/graph → 200 {nodes, edges, stats}   # auth
GET /api/v1/projects/{id}/graph/cypher → 200 text/plain        # auth
POST /api/v1/projects/{id}/graph/sync → 200 {synced_nodes, synced_edges}  # operator+
  → 501 neo4j unconfigured | 502 neo4j unreachable
```

Model + Cypher recipes: `docs/attackgraph.md`.

## Attack paths (Phase 7, observed facts only)

```http
POST /api/v1/projects/{id}/attack-paths/generate → 200 {generated}  # operator+
GET /api/v1/projects/{id}/attack-paths[?min_risk=50] → 200 [Path]
GET /api/v1/projects/{id}/attack-paths/{pathID} → 200 Path | 404
POST /api/v1/projects/{id}/attack-paths/{pathID}/confirm {"confidence":"validated"}
→ 200 Path | 400   # operator+, upgrades only
```

Algorithm + scoring: `docs/attackpaths.md`.

## Validation (Phase 8, read-only)

```http
GET /api/v1/validators → 200 [{name, description}]   # auth
POST /api/v1/projects/{id}/findings/{fid}/validate → 200 {results, promoted}  # operator+
GET /api/v1/projects/{id}/findings/{fid}/validations → 200 [ValidationRun]
```

Validator catalog + safety rules: `docs/validation.md`.

## Evidence (Phase 9, hash-chained)

```http
GET /api/v1/projects/{id}/evidence → 200 [Evidence]   # auth
GET /api/v1/projects/{id}/evidence/{eid} → 200 Evidence | 404
GET /api/v1/projects/{id}/evidence/verify → 200 {ok, checked, broken_at?}
```

Ledger + chain design: `docs/evidence.md`.

## Reporting (Phase 10, on-demand)

```http
POST /api/v1/projects/{id}/report?format=markdown|html|pdf → 200 file  # any role
```

Renderers + sections: `docs/reporting.md`.

## Scenarios (Phase 11, read-only playbooks)

```http
GET /api/v1/scenarios → 200 [Scenario]   # auth
POST /api/v1/projects/{id}/scenarios/{name}/run {"target":"10.10.10.10"} → 202 Run  # operator+
GET /api/v1/projects/{id}/scenarios/runs → 200 [Run]
GET /api/v1/projects/{id}/scenarios/runs/{runID} → 200 Run | 404
```

Playbooks + detection hooks: `docs/scenarios.md`.

## Errors

```json
{"error":"scope denied for \"8.8.8.8\": IP 8.8.8.8 is outside authorized scope"}
```

- 400 malformed JSON / bad field / invalid scope syntax
- 401 missing/expired token, bad credentials
- 403 valid auth but forbidden (out-of-scope, viewer write)
- 404 unknown project
- 409 duplicate (username, project name, scope/target value)
