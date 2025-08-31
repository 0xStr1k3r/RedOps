# Architecture — RedOps Phase 1

```text
CLI (cobra) ──┐
              ├─→ project.Store (SQLite) ← scope.Scope.Enforce
API (chi)  ───┘         │ timeline + audit_log
                        │
Future: recon/enumeration/validation workers → findings → mitre → Neo4j graph
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
Execution adapters arrive in Phase 2 behind the same `Enforce()` gate.
