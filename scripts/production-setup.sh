#!/usr/bin/env bash
# Production user guide: the single redops binary as a locked-down service.
# Run AFTER install.sh. Creates a redops user, prepares /var/lib/redops,
# and enables the systemd unit from deployments/redops.service.
set -euo pipefail
PREFIX="${PREFIX:-/usr/local}"
run() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }
command -v redops >/dev/null || { echo "install redops first (install.sh)"; exit 1; }

echo "== service user =="
if ! id redops >/dev/null 2>&1; then
  run useradd --system --home /var/lib/redops --shell /usr/sbin/nologin redops
fi

echo "== data dir =="
run install -d -m 700 -o redops -g redops /var/lib/redops
# One-time init so the DB exists with redops ownership before systemd starts.
run -u redops redops --db /var/lib/redops/redops.db project list >/dev/null

echo "== secrets =="
run install -d -m 700 -o root -g redops /etc/redops
if [ ! -f /etc/redops/env ]; then
  SECRET="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  run tee /etc/redops/env >/dev/null <<EOF
REDOPS_JWT_SECRET=$SECRET
EOF
  run chown root:redops /etc/redops/env
  run chmod 640 /etc/redops/env
  echo "wrote /etc/redops/env (0640 root:redops) — back this up"
fi

echo "== systemd =="
run cp "$(dirname "$0")/../deployments/redops.service" /etc/systemd/system/redops.service
run systemctl daemon-reload
run systemctl enable --now redops.service
run systemctl --no-pager status redops.service | head -5

echo
echo "done. next:"
echo "  * worker:  run 'redops --db /var/lib/redops/redops.db worker' as user redops"
echo "             (add a second unit copying redops.service with worker in ExecStart)"
echo "  * TLS:     place deployments/nginx-redops.conf behind your proxy"
echo "  * backups: cron 3 2 * * * $PREFIX/../share/redops/scripts/backup.sh 2>/dev/null || scripts/backup.sh"
echo "  * health:  curl -s localhost:8080/healthz"
