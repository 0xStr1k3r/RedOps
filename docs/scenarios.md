# Adversary emulation — Phase 11 module documentation

Scripted playbooks composed of existing read-only engines. Each step is
scope-checked, logged with its ATT&CK technique, and annotated with a
defender detection hint — one run serves emulation and detection validation.

## Scenarios

| Scenario | Steps |
|---|---|
| `web-to-admin` | recon nmap (T1046) → enum http (T1594) → raise → validate → paths |
| `internal-network` | recon nmap (T1046) → enum auto/banner (T1592) → raise → paths |

Step kinds: `recon` (fast nmap profile), `enum` (explicit module or auto-match
on discovered services, max 10), `raise`, `validate` (open findings for the
target), `paths` (regenerate). Recon/enum failure stops the run (later steps
would have nothing to work on); platform steps always run to completion.

## Honesty rules

- Explicit modules only run on services they `Handle` (no forced http-on-SSH:
  step reports "no http services discovered").
- The http module fails loudly on non-HTTP ports instead of inventing
  "missing header" findings (regression-tested against an SSH banner).
- Empty results propagate honestly: no services → 0 findings → 0 paths.
- Technique labels only on adversary-mapped steps; platform steps carry
  detection notes but no technique.

## Detection hooks

Every step writes an audit record `scenario.step` with `[detect: ...]` text:

| Step | Defender observable |
|---|---|
| service-discovery | Nmap SYN/version scan from the RedOps host |
| web-enumeration | Sequential GET /, /robots.txt, /sitemap.xml from one client |
| banner-enumeration | Short TCP connections + banner reads, no auth |
| finding-triage/validation/paths | RedOps timeline bursts, no target traffic |

## Run

```bash
redops --db redops.db scenario list
redops --db redops.db scenario run lab web-to-admin --target 127.0.0.1 --wait
redops --db redops.db scenario runs lab

curl -X POST .../projects/$PID/scenarios/web-to-admin/run -d '{"target":"10.10.10.10"}'  # 202
curl .../projects/$PID/scenarios/runs/$RID   # poll to done|failed
```

API: `GET /scenarios` (catalog), `POST .../scenarios/{name}/run → 202`
(unknown → 400, out-of-scope → 403, viewer → 403),
`GET .../scenarios/runs`, `GET .../scenarios/runs/{id}`.
Runs execute in the background (scans exceed HTTP timeouts).

## Verified (Phase 11 acceptance)

- Catalog validation: known kinds/tools only; unknown scenario errors.
- Out-of-scope target fails before any step, creates no run row.
- Platform chain (seeded http service): enum → raise → validate → paths all ok.
- Live SSH-only host: web-to-admin 5/5 ok with honest zeros
  ("no http services discovered", 0 findings, 0 paths).
- Live earlier run caught and fixed the http-on-SSH false-positive factory.
- API: 400/403 contracts, 202 + poll to terminal state, viewer 403.
