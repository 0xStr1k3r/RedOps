# Enumeration — Phase 3 module documentation

Service-specific, read-only data collection over Phase-2 assets.
Every module re-enforces scope on the service host before connecting.
No brute force, no credentials, no exploits.

## Module registry

| Module | Handles | Collects | Techniques |
|---|---|---|---|
| `http` | ports 80/443/8080/8000/8443 or name ~http/web | status, redirect, title, server, powered-by/generator, TLS version+cipher, robots.txt, sitemap.xml, 5 missing security headers | T1046, T1594 |
| `ssh-banner` | port 22 or name ~ssh | version banner only, no auth | T1046 |
| `dns` | name dns/domain or port 53 | A records for in-scope hostnames via system resolver | T1590 |
| `tcp-banner` | any TCP port (fallback) | first 1 KB banner or "port open, no banner" | T1046 |

Auto-select (`--module` omitted): `http` → `ssh-banner` → `dns` → `tcp-banner`.
Explicit `--module` overrides matching (e.g. `--port 18099 --module http`).

Deferred to lab-contained Phase 8: SMB share/session checks, FTP anonymous
login checks, LDAP anonymous binds, SNMP community checks. No intrusive
probes ship in Phase 3.

## Safety limits

- Scope enforced twice: `enumeration.Enqueue` and module `Enumerate`.
- Timeouts: 8 s dial, 15 s module default (max 60 s); HTTP bodies capped at 512 KB.
- HTTP: max 3 redirects, `User-Agent: RedOps-lab/1.0`, TLS unverified
  (lab metadata only — never send credentials over these connections).
- DNS: forward A lookups of in-scope names only; no zone transfers.
- Every run writes evidence (SHA-256) + audit + timeline, same as recon.

## Storage

```sql
enum_jobs(id, project_id, host_ip, port, module, status, output_ref, error, created_by, created_at, finished_at)
enum_results(id, project_id, job_id, host_ip, port, module, summary, observations_json, created_at)
```

## Run

```bash
# Inline (no worker):
redops --db redops.db enum run acme --host 10.10.10.10 --port 80
redops --db redops.db enum run acme --host 10.10.10.10 --port 22 --module ssh-banner
redops --db redops.db enum results acme

# Via API + worker:
curl -X POST .../projects/$PID/enumerate -d '{"host":"10.10.10.10","port":80}'  # 202
REDOPS_DB=redops.db ./bin/redops-worker
curl .../projects/$PID/enum-results
```

## Verified (Phase 3 acceptance)

- `httptest` server: title, server, powered-by, robots, missing CSP header all observed.
- Live `python3 -m http.server`: 9 observations incl. `http-title=Lab Console`, `http-robots`.
- Live SSH (port 22): `SSH-2.0-OpenSSH_10.2p1` banner, no auth attempted.
- Out-of-scope (`8.8.8.8`) refused before any connection (403 API / CLI error).
- Unknown module → 400; bad port → 400.
