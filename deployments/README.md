# deployments/ — production deployment assets (all for the single `redops` binary)
#   redops.service        systemd unit (User=redops, secrets via /etc/redops/env)
#   nginx-redops.conf     TLS reverse proxy in front of loopback-bound serve
# Hardened setup: scripts/production-setup.sh · Backups: scripts/backup.sh
# Lab sandbox lives in ../lab (testing only, not the product).
