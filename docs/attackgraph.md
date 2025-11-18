# Attack graph — Phase 6 module documentation

Asset graph derived from stored assessment data. **Offline-first**: build,
JSON/Cypher/DOT export, and the API work with zero infrastructure. Neo4j is
an optional sync target for visual exploration and later attack-path queries.

## Model

```text
Project -HAS_TARGET-> Target -MATCHES-> Host -RUNS-> Service
                                              -HAS_FINDING-> Finding -MAPS_TO-> Technique
```

| Node | Key | Props |
|---|---|---|
| Project | `project:<uuid>` | name |
| Target | `target:<value>` | value, type |
| Host | `host:<ip>` | ip, hostname, os, source |
| Service | `svc:<ip>:<port>/<proto>` | host, port, protocol, state, name, product, version |
| Finding | `finding:<uuid>` | title, severity, target, source |
| Technique | `technique:<T-ID>` | technique_id |

| Edge | Meaning | Reason example |
|---|---|---|
| HAS_TARGET | scope target under assessment | "target X in scope, added by alice" |
| MATCHES | target observed as live host | "scope target observed as live host" |
| HAS_HOST | host discovered | "host discovered by nmap" |
| RUNS | service on host | "port observed open (nginx 1.24)" |
| HAS_FINDING | finding attached to service/host/project | "rule http raised [low] finding" |
| MAPS_TO | finding to technique | "rule catalog maps observation to T1046" |

Attachment rule: finding target `host:port` → its Service; bare host → Host;
anything else → Project. Nothing is orphaned. AD kinds (User, Group,
Credential) arrive with later phases.

## Offline use

```bash
redops --db redops.db graph show acme                  # summary counts
redops --db redops.db graph show acme --format cypher  # paste into Neo4j Browser
redops --db redops.db graph show acme --format dot | dot -Tpng -o graph.png
```

API: `GET .../graph` (JSON nodes/edges/stats), `GET .../graph/cypher` (text).

## Neo4j sync

```bash
docker run -d --name neo4j -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/<pass> neo4j:5-community
export REDOPS_NEO4J_URI=bolt://127.0.0.1:7687 REDOPS_NEO4J_USER=neo4j REDOPS_NEO4J_PASS=<pass>
redops --db redops.db graph sync acme
# or: POST .../graph/sync (operator) → {"synced_nodes": N, "synced_edges": M}
```

Sync uses MERGE batches grouped by kind/type (idempotent re-runs), UNWIND
parameters for all values; labels/relationship types come only from
allowlisted internal constants. Unconfigured → CLI error / HTTP 501;
unreachable → HTTP 502. Credentials via env only, never flags or git.

Useful Cypher after sync:

```cypher
MATCH p=(h:Host)-[:RUNS]->(s:Service)-[:HAS_FINDING]->(f:Finding)-[:MAPS_TO]->(t:Technique)
RETURN p LIMIT 50;
MATCH (f:Finding) WHERE f.severity IN ['high','critical'] RETURN f.title, f.target;
```

## Verified (Phase 6 acceptance)

- Seeded store: 1 target/host/service + 2 findings → 6 nodes/6 edges, all reasons set.
- Live Phase-4 DB: 11 nodes/16 edges; Cypher replayable (MERGE + reason props); DOT renders.
- Live Neo4j 5 (Docker): `graph sync` pushed N nodes/M edges; re-sync added nothing;
  Cypher above returns the host→service→finding→technique path.
- Validation tests: unknown node kind rejected before connecting; empty URI → "not configured".
