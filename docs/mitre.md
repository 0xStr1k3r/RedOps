# MITRE ATT&CK — Phase 5 module documentation

Embedded enterprise matrix (101 techniques, 14 tactics) plus per-project
coverage aggregated from real assessment data. No network calls, no TAXII
dependency — the matrix ships in `internal/mitre/matrix.go`.

## Matrix

- `GET /api/v1/mitre/tactics` (public): 14 tactics, canonical order TA0043 → TA0040.
- `GET /api/v1/mitre/techniques[?tactic=Discovery]` (public): id, name, tactic, platform.
- Integrity test enforces: unique IDs, every technique references a known tactic.
- IDs/names follow the public enterprise matrix; T1078 (multi-tactic in MITRE)
  is grouped under Persistence with a note.
- Future: full STIX/TAXII import replaces `ExtraTechniques` without changing the API.

## Coverage model

`GET /api/v1/projects/{id}/techniques` (auth) aggregates three evidence sources:

| Source | How a technique is counted |
|---|---|
| `findings` | finding `technique_id` (1 per finding) |
| `enum` | enum observation `technique_id` (1 per observation) |
| `recon` | finished job's module default (nmap/httpx→T1046, dnsx/subfinder→T1590) |

Payload: per-tactic `{tactic, total, seen, techniques[{id, name, count, sources, findings}]}`,
plus top-level `seen/total`. Techniques seen merge counts across sources
(e.g. T1046 from a finding + a recon job = one entry, count 2).

## Run

```bash
redops --db redops.db mitre tactics
redops --db redops.db mitre techniques --tactic Discovery
redops --db redops.db mitre coverage acme
```

## Verified (Phase 5 acceptance)

- Matrix: 14 tactics, 101 techniques, no duplicate IDs, all tactics resolve.
- Unit coverage: seeded finding (T1046) + enum observations (T1594×2) +
  finished nmap job → `seen 2`, T1046 `{count 2, sources [findings recon], findings 1}`.
- Live on Phase-4 DB: `coverage 3/101` (T1595/T1594/T1046 with correct sources).
- API: public matrix endpoints 200 without token; project coverage 401 without token.
