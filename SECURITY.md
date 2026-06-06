# SECURITY.md — RedOps authorized-use and security model

## 1. Authorized use only

RedOps is for **systems you own or are explicitly authorized to test**
(lab, CTF, contracted assessment). Pointing it at third-party infrastructure
without written authorization may be illegal. The maintainers accept no
liability for misuse.

Lab targets live in `lab/`. Public releases contain **no exploits, no C2,
no payloads, no persistence, no EDR bypass**.

## 2. Threat model (this repo)

| Threat | Mitigation (Phase 1) |
|---|---|
| Operator scans out-of-scope host | `internal/scope` CIDR/IP/domain enforcement on every `AddTarget`; API returns 403 + audit `target.denied` |
| Credential stuffing on login | 10 req/min/IP on auth endpoints, 429 + Retry-After (`api/ratelimit.go`) |
| Cloud-metadata SSRF via fetchers | `scope.IsBlockedHost` enforced in http enum, all validators, httpx, dns |
| Arbitrary shell via tool params | **No tool execution in Phase 1.** Phase 2+ uses allowlisted adapters (`Tool` interface), never `sh -c $input` |
| Credential theft (DB leak) | Argon2id (`m=64MB,t=2,p=2`), never plaintext; JWT HS256, 12h TTL, secret from env |
| Privilege escalation in app | RBAC `admin > operator > viewer`; viewers read-only; first user bootstraps admin |
| Evidence tampering | SHA-256 over `(project,target,action,command,output,ts,operator)`; `Verify()` |
| Silent abuse | Append-only `audit_log` + per-project `timeline` |
| Weak passwords | Min 8 chars, max 256; registration rate-limit by reverse proxy (compose) |
| Token theft | Short TTL, `Authorization: Bearer` only, no cookies; rotate `REDOPS_JWT_SECRET` |

## 3. Scope enforcement rules

- Scope entries: `10.10.10.0/24`, `10.0.0.5`, `web01.lab`.
- Targets must be **fully contained**: IP within prefix, CIDR subset of a scope prefix, domain exact-match.
- Domains never inherit from IP scope; each domain needs an explicit entry.
- Invalid values (`999.1.1.1`, `10.0.0.0/99`, URLs) are rejected, not normalized.
- Enforcement point: `scope.Scope.Enforce()` called in `project.Store.AddTarget`
  **and** in the API handler before insert. Future recon/enumeration workers
  must call it again before spawning any tool.

## 4. Secrets

- `REDOPS_JWT_SECRET`: ≥32 chars, from env or vault. Never commit.
- DB file (`redops.db`) and `.redops-secret` are created mode `0600`.
- Neo4j password via `NEO4J_AUTH`/`REDOPS_NEO4J_PASS` env only; the Browser (7474) is never exposed beyond localhost in the provided compose.
- Postgres/Redis passwords (Phase 6 compose) come from `.env`, not git.
- Compose binds API + Neo4j ports to `127.0.0.1`; expose deliberately or not at all.

## 5. Security review

Full audit (auth, scope/SSRF, exec, SQL, XSS, transport, crypto, deps):
[docs/security-review.md](docs/security-review.md) — govulncheck 0 reachable,
gosec 0 issues. Re-run before every release (last re-run: 2026-08-26).

## 6. Reporting vulnerabilities in RedOps

Open a GitHub issue with `security` label or email maintainers. Include:
repro steps, scope config, logs (redact secrets). Do not publish exploits
against live deployments.

## 6. What we deliberately do NOT ship

C2, malware, AV/EDR evasion, obfuscation, persistence, credential dumping
binaries. Adversary emulation (Phase 11) is **simulation + detection
validation in `lab/` only**.
