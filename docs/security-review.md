# Security review — full-project audit

Method: manual code audit of every package (auth, scope, exec, SQL, output
encoding, secrets, network) + `govulncheck` (dependencies) + `gosec`
(static analysis) + live verification. Toolchain raised to Go 1.26.8 during
this review to clear all stdlib findings.

Results: **govulncheck 0 reachable · gosec 0 issues · go vet clean · 19 test
packages green.**

## A. Authentication & session

| # | Area | Verdict |
|---|---|---|
| A1 | Password hashing: Argon2id m=64MB/t=2/p=2, random 16 B salt, constant-time compare (`internal/auth/auth.go`) | PASS |
| A2 | JWT pinned to HS256 server-side; `Parse` rejects other algos, expiry enforced (`auth.Parse`) | PASS |
| A3 | No default credentials: first registered user bootstraps admin; later users viewer-only (`api/router.go`) | PASS (by design) |
| A4 | Login errors generic (`invalid credentials`); no timing oracle (hash verify dominates) | PASS |
| A5 | Brute force: **fixed** — 10 req/min/IP on register+login, 429 + Retry-After (`api/ratelimit.go`, tested) | FIXED |
| A6 | Secret handling: flag → env → 0600 auto-file; never logged; rotation = logout-all | PASS |
| A7 | Tokens in browser localStorage (SPA requirement); XSS mitigated by output-encoding audit (F1) | ACCEPTED (documented) |

## B. Scope enforcement & SSRF

| # | Area | Verdict |
|---|---|---|
| B1 | `scope.Classify` rejects URLs, flags (`-x`), bad octets, single-label abuse; CIDR targets must be subsets (`internal/scope`) | PASS |
| B2 | Every intake re-enforced: targets, recon/enum jobs, validators, scenario steps | PASS |
| B3 | Cloud-metadata SSRF: **fixed** — `IsBlockedHost` (169.254.169.254, 100.100.100.100, GCE metadata names, `@` tricks) enforced in http enum, all validators, httpx adapter, dns module (`scope/guard.go`, tested) | FIXED |
| B4 | Recon (nmap banners) intentionally exempt: stores no page bodies; operator-explicit scans | ACCEPTED (documented) |

## C. Command execution

| # | Area | Verdict |
|---|---|---|
| C1 | Single choke point `recon.runBinary`: LookPath allowlist, argv-only (no shell), stdin closed, context timeout, 5 MB output cap | PASS (`#nosec G204` justified) |
| C2 | Ports regex `^[0-9,\- ]+$`, canned profiles only; targets re-classified before spawn | PASS |
| C3 | No other `exec`/`sh`/`system` calls in the tree (grep-verified) | PASS |

## D. Data layer

| # | Area | Verdict |
|---|---|---|
| D1 | All SQL parameterized; only constant column-list concatenation (`project/*_store.go`) | PASS |
| D2 | DB file chmod 0600 on open (hashes + audit inside) — **fixed** (`project.Open`) | FIXED |
| D3 | Dedupe keys SHA-256; evidence chain SHA-256 with linkage verification | PASS |
| D4 | Unhandled `db.Close` error in `Open` failure path — **fixed** (`_ =`) | FIXED |

## E. Output encoding / XSS

| # | Area | Verdict |
|---|---|---|
| E1 | HTML report: `html/template` auto-escaping; hostile-title test (`<b>XSS?</b>`) | PASS |
| E2 | GUI: `esc()` on all finding/timeline/evidence/graph values; sources are internal constants | PASS (audited) |
| E3 | API is JSON-only (`application/json`); Markdown/PDF are downloads, not rendered | PASS |
| E4 | Cypher export escapes quotes; labels/types from allowlisted constants only | PASS |

## F. Network & transport

| # | Area | Verdict |
|---|---|---|
| F1 | HTTP servers now use explicit timeouts (header/read/write/idle) — **fixed** (`cmd/server`, `redops serve`) | FIXED |
| F2 | Request body caps (1 MB JSON, 1 MB cloud import); response caps (512 KB pages, 5 MB tool output) | PASS |
| F3 | Compose binds API + Neo4j to `127.0.0.1` — **fixed** (was all-interfaces) | FIXED |
| F4 | No TLS by default: terminate at reverse proxy (documented in `docs/usage.md` §7); HSTS out of scope without TLS | ACCEPTED |
| F5 | No CORS headers: same-origin GUI; cross-origin API use stays blocked by default | PASS |
| F6 | CSRF N/A: Bearer tokens, no cookies | PASS |

## G. Cryptography notes

| # | Area | Verdict |
|---|---|---|
| G1 | `InsecureSkipVerify` in 3 lab fetch paths — intentional (lab metadata, no creds sent), annotated `#nosec G402` | ACCEPTED (documented) |
| G2 | `uint32(len(hash))` conversion — decoded 32 B length, annotated `#nosec G115` | ACCEPTED |
| G3 | Report files now 0600 (findings are sensitive) — **fixed** | FIXED |
| G4 | `~/.redops-secret`/JWT secret file 0600 at creation | PASS |

## H. Dependencies

- `govulncheck ./...`: **0 reachable** (1 unreachable in a required module — no call path, no action). During review the stdlib showed 24 findings against go1.26.0 → toolchain upgraded to **go1.26.8**, rescan clean.
- `gosec ./...`: **0 issues** after 4 code fixes + 7 justified `#nosec` annotations (each carries its reason inline).

## Residual recommendations (not vulnerabilities)

1. Front with TLS-terminating reverse proxy + WAF rate limits for multi-user exposure.
2. Rotate `REDOPS_JWT_SECRET` on personnel changes; back up `.redops-secret` with the DB.
3. For production Postgres migration: parameterized access stays identical (`database/sql`); add connection TLS + KMS-managed secrets.
4. Re-run this checklist (govulncheck + gosec + scope tests) before every release — CI already gates vet/test/gosec/Trivy.
