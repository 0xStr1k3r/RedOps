// Package validation re-observes finding evidence with read-only checks.
// A validator confirms the condition still holds (missing header still
// missing, robots still reachable) and promotes finding confidence to
// validated. Nothing here authenticates, brute-forces, exploits, or mutates
// the target: HTTP GET, TLS handshake, and banner reads only.
//
// Validation confirms EXPOSURE, not exploitability: attack paths still need
// operator confirmation (Phase 7) because a confirmed finding does not prove
// a chained path is traversable.
package validation
