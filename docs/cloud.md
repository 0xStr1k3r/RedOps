# Cloud IAM analysis — Phase 12 module documentation

Offline-first AWS IAM trust-graph analysis. Imports are **static JSON
documents** (console exports, Terraform plans, lab fixtures) — RedOps never
calls AWS APIs and needs no cloud credentials.

## Import schema (`lab/cloud-iam-example.json`)

```json
{
  "users": [{"name": "dev-alice", "policies": ["ReadOnly"], "groups": ["developers"]}],
  "roles": [{"name": "DeployRole", "assume_from": ["dev-alice"], "policies": ["Deploy"]}],
  "policies": [{"name": "ReadOnly", "statements": [{"effect": "Allow", "actions": ["ec2:Describe*"]}]}]
}
```

Validation rejects: unknown policy references, empty statements, bad effects,
duplicate/malformed names, non-JSON. Principals are user/role names or `"*"`.

## Analysis

- **Admin reachability**: per-user BFS over `CAN_ASSUME` trust edges;
  a principal reaching a policy that Allows `iam:*`/`*` is an admin path
  (risk 90, T1078). Explicit `Deny` overrides `Allow`.
- **Wildcard trust**: roles assumable by `"*"` are warnings (risk 75).
- Action matching: `*`, `svc:*` prefix, exact — case-insensitive.
- Resources are intentionally out of math (documented limitation — scope them
  in review; a `*`-action policy on one bucket still flags, by design).

## Graph integration

Imports become `User`/`Role`/`Policy` nodes (`CAN_ASSUME`, `HAS_POLICY`)
merged into the unified graph: `graph show`, Cypher export, and Neo4j sync
include them with zero extra work. Principals resolve to existing user/role
nodes; `"*"` and externals get explicit anchors (edges never dangle).

## Run

```bash
redops --db redops.db cloud import acme --file iam.json   # replace semantics
redops --db redops.db cloud assets acme
redops --db redops.db cloud paths acme

curl -X POST .../projects/$PID/cloud/import -H "Authorization: Bearer $TOKEN" --data-binary @iam.json
curl .../projects/$PID/cloud/paths -H "Authorization: Bearer $TOKEN"
```

API: `POST .../cloud/import` (operator, 1 MB cap),
`GET .../cloud/assets`, `GET .../cloud/paths` (auth).

## Verified (Phase 12 acceptance)

- Fixture: `dev-alice → DeployRole → AdminRole → Administrator` (risk 90) +
  `PublicTestRole` wildcard warning (risk 75); clean auditor → zero paths.
- `Deny iam:*` overrides `Allow *` (no path); 5 malformed documents rejected.
- Live: import → assets (4 users/3 roles/3 policies) → paths → unified graph
  (11 nodes incl. cloud, 9 cloud edges in Cypher export).
