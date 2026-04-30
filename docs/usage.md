# RedOps usage guide

Complete operator manual: install, credentials, GUI, every CLI command,
API cookbook, background services, troubleshooting.

## 1. Install

One binary (`redops`) contains everything: CLI, API server, embedded GUI,
worker. Three ways to get it:

```bash
# A. Universal installer — Debian/Ubuntu, Arch, RHEL/Fedora/Rocky/Alma, openSUSE, Alpine
curl -fsSL https://raw.githubusercontent.com/redops/redops/main/install.sh | bash
# options: --prefix DIR | --without-nmap | --service | --uninstall | --help

# B. From source (Go >= 1.21; module toolchain auto-upgrades)
git clone https://github.com/redops/redops.git && cd redops
make build            # bin/redops (+ api/worker splits)
make install          # installs bin/redops to /usr/local/bin (PREFIX=... to override)

# C. Docker (API only; GUI included, DB in volume)
REDOPS_JWT_SECRET=$(openssl rand -hex 32) docker compose up -d
# Neo4j graph sync: docker compose --profile graph up -d  (needs NEO4J_AUTH=neo4j/<pass> in .env)
```

The installer adds: `curl`, `git`, `make`, `gcc`, `nmap` (recommended;
skip with `--without-nmap` — nmap jobs then fail with an install hint),
and a Go toolchain (distro package, else official tarball).

Verify: `redops version` → `redops <git-sha>`.

## 2. Credentials (read this first)

**There are no default credentials — by design.** Shipping `admin/admin`
would turn every install into a target.

- **Bootstrap:** the first user registered via GUI or API becomes `admin`.
  Register at `http://127.0.0.1:8080` → Register tab, or:
  `curl -X POST localhost:8080/api/v1/auth/register -d '{"username":"alice","password":"..."}'`
- **Later users** default to `viewer` (read-only); admins can't be
  self-granted (see `docs/api.md`).
- **Roles:** `admin > operator > viewer`. All writes need `operator`+;
  reports/graph/reads need any login.
- **JWT secret** resolution for `redops serve`: `--secret` flag →
  `$REDOPS_JWT_SECRET` → auto-generated `<dbdir>/.redops-secret` (mode 0600).
  Back it up; rotating it logs everyone out. Minimum 32 characters.
- **Passwords:** Argon2id-hashed, min 8 chars, never logged.

## 3. Five-minute quickstart

```bash
export DB=~/redops.db
redops --db $DB serve --addr 127.0.0.1:8080 &   # API + GUI
redops --db $DB worker &                        # job runner (second shell)
# open http://127.0.0.1:8080 → Register (you are admin) → Projects → New
# scope: 10.10.10.0/24 · add target 10.10.10.10 (8.8.8.8 is refused: 403)
# Operations → recon nmap → findings Raise → paths Generate → Reports → PDF
```

CLI-only equivalent (same DB file, no server needed for local ops):

```bash
redops --db $DB project create acme --scope 10.10.10.0/24
redops --db $DB target add acme 10.10.10.10
redops --db $DB recon run acme --tool nmap --target 10.10.10.10 --profile fast
redops --db $DB enum run acme --host 10.10.10.10 --port 80
redops --db $DB findings raise acme
redops --db $DB validate finding acme <id>
redops --db $DB paths generate acme
redops --db $DB report generate acme --format pdf --out acme.pdf
```

## 4. GUI guide

Open the serve address. Views (sidebar):

| View | What you do there |
|---|---|
| Projects | create/select projects, set initial scope |
| Overview | metric cards, top findings/paths, recent timeline |
| Findings | filter table, **Raise** (rule engine), **Validate** per row, Ack |
| Attack paths | **Generate**, risk-sorted chains, **Confirm** (→ validated) |
| ATT&CK | tactic rows with observed technique chips (hover = counts/sources) |
| Graph | layered SVG (target→host→service→finding→technique); Cypher download |
| Operations | queue recon/enum, run scenarios async, cloud IAM import, validators list |
| Timeline | chronological audit of everything |
| Evidence | operation ledger + chain status |
| Reports | one-click Markdown/HTML/PDF download |

Session = JWT in browser storage; 401 returns you to login. The connection
pill shows API reachability.

## 5. CLI command reference

Global flag: `--db PATH` (default `redops.db`; server/worker share the file).

```text
redops version
redops serve --addr :8080 --secret ...        # API + GUI (secret: flag>env>auto-file)
redops worker --interval 5s --once            # poll recon/enum queues

redops project create NAME [--scope CIDR...] [--description T]
redops project list
redops scope add PROJECT VALUE                # CIDR, IP, or domain
redops target add PROJECT VALUE               # denied when out of scope
redops status PROJECT

redops recon run PROJECT --tool nmap|httpx|dnsx|subfinder --target V [--ports 80,443] [--profile fast|full|top100] [--async]
redops recon list PROJECT
redops assets PROJECT                         # hosts + services inventory

redops enum run PROJECT --host H --port P [--module http|ssh-banner|dns|tcp-banner]
redops enum results PROJECT

redops findings list PROJECT [--severity low] [--status open]
redops findings raise PROJECT                 # rule engine, idempotent
redops findings update PROJECT ID [--status resolved] [--confidence validated] [--severity low]
redops validate validators
redops validate finding PROJECT ID            # read-only re-check → validated

redops mitre tactics
redops mitre techniques [--tactic Discovery]
redops mitre coverage PROJECT

redops graph show PROJECT [--format summary|cypher|dot]
redops graph sync PROJECT                     # needs REDOPS_NEO4J_URI/USER/PASS

redops paths generate PROJECT
redops paths list PROJECT [--min-risk 50]
redops paths confirm PROJECT ID --confidence validated|confirmed

redops evidence list PROJECT
redops evidence verify PROJECT

redops report generate PROJECT [--format markdown|html|pdf] [--out file]

redops scenario list
redops scenario run PROJECT NAME --target V [--wait]
redops scenario runs PROJECT

redops cloud import PROJECT --file iam.json
redops cloud assets PROJECT
redops cloud paths PROJECT
```

IDs accept unambiguous prefixes (`findings update acme 79e920a9 ...`).

## 6. API cookbook

```bash
B=http://127.0.0.1:8080; DB=~/redops.db
redops --db $DB serve &  redops --db $DB worker &
curl -s -X POST $B/api/v1/auth/register -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password-123"}'
T=$(curl -s -X POST $B/api/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password-123"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
A="Authorization: Bearer $T"; J='Content-Type: application/json'
PID=$(curl -s -X POST $B/api/v1/projects -H "$A" -H "$J" -d '{"name":"acme"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
curl -s -X POST $B/api/v1/projects/$PID/scope -H "$A" -H "$J" -d '{"value":"10.10.10.0/24"}'
curl -s -X POST $B/api/v1/projects/$PID/targets -H "$A" -H "$J" -d '{"value":"10.10.10.10"}'
curl -s -X POST $B/api/v1/projects/$PID/recon -H "$A" -H "$J" -d '{"tool":"nmap","target":"10.10.10.10"}'   # 202
curl -s $B/api/v1/projects/$PID/assets -H "$A"
curl -s -X POST $B/api/v1/projects/$PID/enumerate -H "$A" -H "$J" -d '{"host":"10.10.10.10","port":80}'    # 202
curl -s -X POST $B/api/v1/projects/$PID/findings/raise -H "$A" -H "$J" -d '{}'
curl -s $B/api/v1/projects/$PID/findings?severity=high -H "$A"
curl -s $B/api/v1/projects/$PID/techniques -H "$A" | head -c 300; echo
curl -s -X POST $B/api/v1/projects/$PID/attack-paths/generate -H "$A" -H "$J" -d '{}'
curl -s $B/api/v1/projects/$PID/graph -H "$A" | head -c 200; echo
curl -s $B/api/v1/projects/$PID/evidence/verify -H "$A"; echo
curl -s -X POST "$B/api/v1/projects/$PID/report?format=pdf" -H "$A" -o acme.pdf
curl -s $B/api/v1/mitre/tactics | head -c 120; echo   # public, no token
```

Conventions: 202 = queued (poll the resource), 400 = bad input/unknown tool,
401 = login needed, 403 = out-of-scope or viewer-write, 404 = unknown id,
501 = Neo4j unconfigured, 502 = Neo4j unreachable.

## 7. Services & operations

- **Worker:** one `redops worker` per DB (or `REDOPS_WORKER_ONCE=1` for a
  single pass in cron/CI). Recon jobs need `nmap|httpx|dnsx|subfinder`
  binaries; missing ones fail the job with an install hint, never the server.
- **systemd:** `install.sh --service` creates `redops.service`
  (`/var/lib/redops/redops.db`, localhost:8080). Run the worker as a second
  unit or a second `ExecStart` line per your policy.
- **Neo4j (optional):** `docker compose --profile graph up -d` with
  `NEO4J_AUTH` in `.env`, then `graph sync` (CLI) or `POST .../graph/sync`.
  Everything else works without it.
- **Backups:** copy the SQLite file + `.redops-secret` (losing the secret
  only logs users out; losing the DB loses data).

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `scope denied ... outside authorized scope` | target not in project scope — add it via `scope add` (if authorized) |
| recon job `nmap not installed` | install nmap, or use another adapter |
| GUI shows login but calls fail 401 | token expired (12 h) — log in again |
| `redops serve` says secret generated | first run;-back up `<dbdir>/.redops-secret` or set `$REDOPS_JWT_SECRET` |
| `evidence verify` BROKEN | DB was edited outside RedOps — restore backup; chain is tamper-evident by design |
| login loops with 429 | auth rate limit (10/min/IP) — wait a minute; legitimate bursts (tests) hit it too |
| GUI blank after editing `web/` | run `make build` (embeds via `sync-web`), not bare `go build` |
| `report` PDF tiny/empty | generate after discovery; empty projects render skeletons |
| scenario stuck `running` | worker crash mid-run — rerun; queued/running rows are informational |
| port already in use | change `--addr` (serve) — one server per DB file recommended |

## 9. Scope of this tool

Authorized assessments only (your lab, CTF, contracted targets).
RedOps ships **no exploits, no brute force, no C2** — validation is
read-only re-observation. See `SECURITY.md` and per-phase docs in `docs/`.
