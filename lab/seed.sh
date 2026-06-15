#!/usr/bin/env bash
# Seeds a demo assessment against the local VulnLab sandbox and runs the full
# read-only pipeline: recon -> enum -> raise -> validate -> paths -> report.
# TESTING ONLY: loopback targets, scratch DB. For real engagements use explicit
# project scope per docs/usage.md — never point this at foreign systems.
set -euo pipefail
DB="${REDOPS_DB:-$HOME/vulnlab.db}"
PROJECT="${1:-vulnlab}"

log() { printf '\033[1;32m[seed]\033[0m %s\n' "$*"; }
command -v redops >/dev/null || { echo "redops not on PATH (run install.sh)"; exit 1; }
curl -fsS -m 3 http://127.0.0.1:8080/ >/dev/null || { echo "web01 not up: docker compose -f lab/docker-compose.yml up -d"; exit 1; }

log "project + scope (loopback only)"
redops --db "$DB" project create "$PROJECT" --scope 127.0.0.1/32 --description "VulnLab demo" || true
redops --db "$DB" target add "$PROJECT" 127.0.0.1 || true

log "recon (fast profile)"
redops --db "$DB" recon run "$PROJECT" --tool nmap --target 127.0.0.1 --profile fast

log "enumerate discovered services"
redops --db "$DB" assets "$PROJECT"

log "enum web + ssh explicitly (published lab ports)"
redops --db "$DB" enum run "$PROJECT" --host 127.0.0.1 --port 8080 --module http || true
redops --db "$DB" enum run "$PROJECT" --host 127.0.0.1 --port 2222 --module ssh-banner || true

log "raise + validate + paths"
redops --db "$DB" findings raise "$PROJECT"
FIRST="$(redops --db "$DB" findings list "$PROJECT" --status open | head -1 | awk '{print $1}')"
[ -n "$FIRST" ] && redops --db "$DB" validate finding "$PROJECT" "$FIRST" || true
redops --db "$DB" paths generate "$PROJECT"

log "report"
redops --db "$DB" report generate "$PROJECT" --format html --out "$PROJECT-report.html"

log "done — findings:"
redops --db "$DB" findings list "$PROJECT"
