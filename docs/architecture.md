# Architecture — RedOps Phase 1

```text
CLI (cobra) ──┐
              ├─→ project.Store (SQLite) ← scope.Scope.Enforce
API (chi)  ───┘         │ timeline + audit_log
                        │
Recon: API/CLI enqueue → recon_jobs → worker claims → Tool.Execute
       (scope re-checked) → Parse → hosts/services upsert → evidence hash
Enum:  API/CLI enqueue → enum_jobs → worker claims → Module.Enumerate
       (scope re-checked, read-only) → enum_results → evidence hash
Findings: enum_results → rule catalog → findings (deduplicated)
       + manual operator findings → status/confidence workflow
ATT&CK: findings + enum observations + recon jobs → per-tactic coverage
Graph:  store → in-memory graph → JSON/Cypher/DOT, optional Neo4j MERGE sync
Paths:  BFS entry→finding(+technique) → risk score → observed/potential,
        operator confirm to validated/confirmed
Validation: finding → matching read-only validator → confirm → validated
Evidence: every op → hash-chained record (prev_hash link) → verify endpoint
Report:  aggregate all stores → Markdown / HTML / PDF on demand
```

## Request path (Phase 1)

```text
User → Bearer JWT → requireAuth → RBAC (operator for writes)
 → project exists? → scope.LoadScope → scope.Enforce(target)
 → insert → timeline + audit → JSON
```

Scope denials return **403** with reason (`outside authorized scope`,
`not fully within`, `explicit entry required`) and are audit-logged as
`target.denied`. This distinction matters: 400 = malformed, 403 = forbidden.

## Storage

SQLite now, Postgres later. Table names/columns are identical so the
migration is `pgloader` + driver swap. See `docs/database.md`.

Phase-2 tables: `recon_jobs` (queued→running→done|failed queue),
`hosts` + `services` (upserted asset inventory per project).

## Auth

- Argon2id hash string `argon2id$v=19$m=..,t=..,p=..$salt$hash`
- JWT `uid, sub, role, iat, exp`, HS256, 12h TTL
- Roles numeric: viewer=1, operator=2, admin=3; `CanAct(role, required)`

## Evidence / timeline

`evidence.New()` hashes canonical fields with SHA-256. Timeline rows are
written on project/scope/target events; the API exposes them read-only.
Full operation evidence (command/output capture) attaches in Phase 2+.

## What Phase 1 does NOT do

No sockets, no subprocesses, no scanning. `pkg/nmap` only **parses** XML.

## Phase 2 recon safety

- One choke point: `recon.runBinary` — scope re-enforced, `LookPath`,
  `exec.CommandContext` with timeout, argv only (never a shell), output capped.
- Adapters declare `Supports()` per target type; mismatches rejected before spawn.
- Ports/profile inputs validated (`^[0-9,\- ]+$`, canned profiles only).
- Missing binaries → job `failed` with install hint; worker keeps polling.
