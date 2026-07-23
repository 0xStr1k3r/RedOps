#!/usr/bin/env bash
# Smoke test for the lab sandbox: brings up web01, runs one recon + enum +
# raise cycle against 127.0.0.1, and asserts findings appear. Testing only.
set -euo pipefail
cd "$(dirname "$0")/.."
DB="$(mktemp -u /tmp/redops-labtest-XXXX.db)"
trap 'rm -f "$DB"' EXIT

echo "== starting lab web01 =="
if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
  docker compose -f lab/docker-compose.yml up -d web01
  DOWN="docker compose -f lab/docker-compose.yml down"
elif command -v docker >/dev/null; then
  echo "need docker compose plugin; start web01 manually (see lab/README.md)"; exit 1
else
  echo "docker not installed; skip"; exit 0
fi
trap 'eval "$DOWN" >/dev/null 2>&1 || true; rm -f "$DB"' EXIT
sleep 2

echo "== pipeline against 127.0.0.1:8080 =="
./bin/redops --db "$DB" project create labtest --scope 127.0.0.1/32
./bin/redops --db "$DB" target add labtest 127.0.0.1
./bin/redops --db "$DB" enum run labtest --host 127.0.0.1 --port 8080 --module http
./bin/redops --db "$DB" findings raise labtest
N="$(./bin/redops --db "$DB" findings list labtest | wc -l)"
echo "findings: $N"
[ "$N" -ge 3 ] || { echo "expected >=3 findings from web01"; exit 1; }
echo "smoke test passed"
