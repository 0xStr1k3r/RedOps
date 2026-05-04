# Changelog

All notable RedOps development, newest first.

## Unreleased

## 2026-03 — Hardening + UI research
- ATT&CK heat matrix, dashboard widgets, findings filters, pan-zoom graph
- Auth rate limiting, cloud-metadata SSRF guard, DB 0600, server timeouts
- `govulncheck` clean (Go 1.26.8), `gosec` clean, full security review

## 2026-02 — Single binary, GUI, installer
- `redops serve` (API + embedded GUI) and `redops worker` subcommands
- Dark SPA: 10 views, no build step; universal `install.sh`
- Insights engine, Navigator layer export

## 2026-01 — Analysis + reporting
- Attack paths (BFS + risk scoring + confirm workflow)
- Validation engine (read-only validators), evidence hash chain
- Markdown/HTML/PDF reports, adversary-emulation playbooks, cloud IAM analysis

## 2025-12 — Graph + findings
- Attack graph builder, Neo4j MERGE sync, Cypher/DOT export
- Findings rule catalog, deduped store, raise endpoint

## 2025-11 — MITRE coverage
- Embedded enterprise matrix (101 techniques), per-project coverage

## 2025-09 — Recon + enumeration
- Tool adapters (nmap/httpx/dnsx/subfinder), job queues, HTTP/SSH/DNS modules

## 2025-08 — Foundation
- Project/scope/target management with scope enforcement, Argon2id + JWT auth
