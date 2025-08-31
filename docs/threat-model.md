# Threat model — RedOps itself

Assets: assessment data, lab credentials, JWT secret, audit log integrity.
Actors: operator (trusted, authorized), viewer (read-only), outsider (no token), malicious project member.

| # | Abuse case | Control |
|---|---|---|
| 1 | Scan non-consented host | Scope gate + 403 + `target.denied` audit |
| 2 | Inject shell via target field | `Classify()` rejects URLs/flags; no exec in Phase 1; adapters allowlist in Phase 2 |
| 3 | Steal DB | Argon2id hashes only; `0600` file perms; future KMS for Postgres creds |
| 4 | Forge privilege | JWT role claim checked per-write; `admin>operator>viewer` |
| 5 | Cover tracks | Append-only audit; timeline immutable via API (no DELETE endpoints) |
| 6 | DoS API | `middleware.Timeout(15s)`; body cap 1MB; `DisallowUnknownFields` |
| 7 | Secret leak in logs | Never log tokens/hashes; audit stores usernames + results only |

Out of scope for Phase 1: network TLS (terminate at reverse proxy), image scanning (CI Trivy), SSO.
