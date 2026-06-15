# lab/ — TESTING SANDBOX ONLY (not part of the RedOps product)

This directory is a small, separate playground for trying RedOps against
throwaway local targets. Nothing here ships with, configures, or is required
by the product itself: the API, CLI, GUI, and installer never touch `lab/`.

Contents:

- `docker-compose.yml` — VulnLab demo targets, loopback-bound only:
  `web01` (intentionally vulnerable web app) and `ssh01` (banner-only SSH,
  password auth disabled). Needs the Docker Compose plugin; without it, use
  plain `docker run` (commands below).
- `web01/` — Python stdlib demo app (missing headers, robots.txt, admin
  title). Read the source before running it; never expose it beyond loopback.
- `seed.sh` — drives the full read-only pipeline against the lab into a
  scratch DB (`~/vulnlab.db`). Destroys nothing; creates demo data only.
- `cloud-iam-example.json` — synthetic IAM fixture for offline cloud-import
  tests (fictional data, no real credentials). Used by unit tests.

Run the lab:

```bash
cd lab && docker compose up -d --build   # or without the plugin:
# docker network create vulnlab  # (optional; default bridge is fine)
# docker build -t vulnlab-web01 ./web01
# docker run -d --name web01 -p 127.0.0.1:8080:8080 vulnlab-web01
# docker run -d --name ssh01 -p 127.0.0.1:2222:2222 \
#   -e PASSWORD_ACCESS=false -e USER_NAME=labuser linuxserver/openssh-server:latest
./seed.sh                       # full pipeline into ~/vulnlab.db
docker compose down             # teardown (or docker rm -f web01 ssh01)
```

Rules: lab targets are the ONLY systems RedOps may touch without a formal
assessment scope. For real work, define project scope explicitly
(see `docs/usage.md`) and keep this sandbox out of it.
