// Package cloud performs offline-first AWS IAM trust-graph analysis.
// Imports are static JSON documents (console exports, Terraform plans, or
// lab fixtures) — RedOps never calls AWS APIs. Analysis finds
// assumption chains (user → role → …) reaching admin policies and flags
// over-broad trust (wildcard principals). Results merge into the unified
// attack graph and export to Neo4j like any other nodes.
package cloud
