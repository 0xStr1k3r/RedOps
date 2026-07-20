#!/usr/bin/env bash
# Hot backup for a RedOps SQLite database + JWT secret.
# Usage: scripts/backup.sh [/var/lib/redops/redops.db] [backup-dir]
# Keeps 14 daily copies. Safe to run from cron while the server is up
# (SQLite backup API via .backup avoids copying a live WAL mid-write).
set -euo pipefail
DB="${1:-/var/lib/redops/redops.db}"
OUT="${2:-/var/backups/redops}"
KEEP=14

[ -f "$DB" ] || { echo "no database at $DB"; exit 1; }
command -v sqlite3 >/dev/null || { echo "sqlite3 CLI required"; exit 1; }
mkdir -p "$OUT"
STAMP="$(date +%F)"
sqlite3 "$DB" ".backup '$OUT/redops-$STAMP.db'"
SECDIR="$(dirname "$DB")/.redops-secret"
[ -f "$SECDIR" ] && cp -p "$SECDIR" "$OUT/redops-secret-$STAMP" && chmod 600 "$OUT/redops-secret-$STAMP"
chmod 600 "$OUT/redops-$STAMP.db"
ls -t "$OUT"/redops-*.db | tail -n +$((KEEP + 1)) | xargs -r rm -f
echo "backup: $OUT/redops-$STAMP.db"
