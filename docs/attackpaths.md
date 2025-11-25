# Attack paths — Phase 7 module documentation

Deterministic attack-path analysis over the Phase-6 graph. The engine links
**observed facts only** (targets, hosts, services, findings, techniques) and
scores them. It never claims exploitability: all engine output is
`observed`/`potential`; `validated`/`confirmed` require operator verification.

## Algorithm

1. Entries: `Target` + `Host` nodes. Objectives: `Finding` nodes (each extended
   one hop through `MAPS_TO` to its `Technique` as a second path).
2. BFS shortest path per entry→objective pair (max 8 hops, max 50 paths).
3. Sort by risk desc, then length asc. Regenerate = full replace (fresh IDs).

## Scoring

```text
risk = severity_base + 5 × min(techniques, 3) − 2 × max(0, hops − 4), clamped 0–100
severity_base: critical 100 / high 75 / medium 50 / low 25 / info 10
```

- **Confidence**: `observed` default; `potential` when the chain holds ≥2
  findings or ≥2 techniques (correlated observations). Engine never emits
  `validated`/`confirmed`.
- **Required privileges**: `network-access <host>:<port>` per Service step.
  Credential/privesc edges arrive with AD/cloud phases.

## Confirm workflow

`POST .../attack-paths/{id}/confirm {"confidence":"validated|confirmed"}`
(operator only; downgrades rejected — use the findings workflow instead).
Audited as `attackpath.confirm`.

## Run

```bash
redops --db redops.db paths generate acme
redops --db redops.db paths list acme --min-risk 50
redops --db redops.db paths confirm acme <id-prefix> --confidence validated

curl -X POST .../projects/$PID/attack-paths/generate -H "Authorization: Bearer $TOKEN"
curl ".../projects/$PID/attack-paths?min_risk=75" -H "Authorization: Bearer $TOKEN"
```

API: `POST .../generate → {generated}`, `GET .../attack-paths[?min_risk]`,
`GET .../attack-paths/{id}`, `POST .../attack-paths/{id}/confirm`.

## Verified (Phase 7 acceptance)

- Fixture graph: top path = high-severity chain to technique, risk ≥75,
  techniques/privileges populated, sorted by risk, never validated/confirmed.
- `Score` unit tests: critical caps 100, high+1tech=80, long info path floors 0.
- Persistence: regenerate replaces (no dupes); confirm upgrades, rejects bogus/downgrade.
- Live chained DB: 4 paths (risk 50–55), confirm → validated.
- Honest empty: DB with findings but no entry points (no targets/hosts) → 0 paths,
  not invented ones.
- Full CLI flag audit after cobra `Commands()` sorting fix (flags now attached
  to command variables, never by index).
