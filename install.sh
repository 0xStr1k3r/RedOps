#!/usr/bin/env bash
# =============================================================================
#  RedOps installer — one binary (CLI + API + GUI + worker)
#
#  Verified on package managers:  apt · dnf · yum · pacman · zypper · apk
#  Covers: Debian/Ubuntu/Mint, RHEL/Fedora/Rocky/Alma/CentOS, Arch/Manjaro,
#          openSUSE/SLES, Alpine, and derivatives detected via /etc/os-release.
#
#  Usage:
#    curl -fsSL https://raw.githubusercontent.com/0xStr1k3r/RedOps/main/install.sh | bash
#    install.sh [options]
#
#  Options:
#    --prefix DIR       install prefix                (default /usr/local)
#    --dir DIR          RedOps data directory         (default $HOME/.redops)
#    --with-nmap        also install nmap            (default: auto, see below)
#    --without-nmap     never install nmap
#    --with-postgres    also install PostgreSQL 16    (optional, for scale)
#    --with-redis       also install Redis 7          (optional, for queues)
#    --with-neo4j       also install Neo4j 5          (optional, for graphs)
#    --service          install + enable systemd unit (root + systemd only)
#    --no-start         do not start the service after --service
#    --yes              assume yes (non-interactive)
#    --check            only verify prerequisites, install nothing
#    --uninstall        remove binary, unit and data
#    --force            reinstall even if already installed
#    --verbose          show full command output
#    --version          print installer version and exit
#    --help             this text
#
#  Environment overrides:
#    REDOPS_REPO     git URL or local directory to build from
#    GO_VERSION      Go release to use for the tarball fallback (default 1.26.9)
#    REDOPS_VERSION  git tag/branch to build (default: repo HEAD)
#
#  Exit codes: 0 ok · 1 usage · 2 unsupported OS/arch · 3 missing prerequisites
#              4 build failed · 5 install failed · 6 service failed
# =============================================================================
set -Eeuo pipefail

INSTALLER_VERSION="2.0.0"
MIN_GO_MAJOR=1
MIN_GO_MINOR=21

# ---------- options -----------------------------------------------------------
PREFIX="/usr/local"
DATA_DIR=""
WITH_NMAP="auto"       # auto | yes | no
WITH_POSTGRES="no"
WITH_REDIS="no"
WITH_NEO4J="no"
WITH_SERVICE="no"
AUTO_START="yes"
ASSUME_YES="no"
CHECK_ONLY="no"
UNINSTALL="no"
FORCE="no"
VERBOSE="no"

REPO="${REDOPS_REPO:-https://github.com/0xStr1k3r/RedOps.git}"
GO_VERSION="${GO_VERSION:-1.26.9}"
REDOPS_VERSION="${REDOPS_VERSION:-}"

BIN_NAME="redops"
SERVICE_NAME="redops"
SERVICE_USER="redops"
LOG_FILE=""

# ---------- output helpers ----------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_R=$'\033[1;31m'; C_G=$'\033[1;32m'; C_Y=$'\033[1;33m'
  C_B=$'\033[1;34m'; C_C=$'\033[1;36m'; C_D=$'\033[0m'
else
  C_R=""; C_G=""; C_Y=""; C_B=""; C_C=""; C_D=""
fi
log()  { printf '%s[redops]%s %s\n' "$C_G" "$C_D" "$*"; }
info() { printf '%s[ .. ]%s %s\n' "$C_C" "$C_D" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$C_Y" "$C_D" "$*" >&2; }
err()  { printf '%s[fail]%s %s\n' "$C_R" "$C_D" "$*" >&2; }
dbg()  { [ "$VERBOSE" = "yes" ] && printf '%s[dbg]%s %s\n' "$C_D" "$C_D" "$*" >&2 || true; }
die()  { err "$*"; exit "${2:-1}"; }

# ---------- error trap --------------------------------------------------------
on_error() {
  local code=$? line=${1:-?}
  err "unexpected failure at line $line (exit $code)"
  [ -n "$LOG_FILE" ] && err "full log: $LOG_FILE"
  exit "$code"
}
trap 'on_error $LINENO' ERR

usage() {
  sed -n '2,/^# =\{10,\}/p' "$0" | sed 's/^# \{0,1\}//; s/^# =\{10,\}$//' | sed '/^$/d'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)        [ $# -ge 2 ] || die "--prefix needs a value" 1; PREFIX="$2"; shift 2;;
    --dir)           [ $# -ge 2 ] || die "--dir needs a value" 1; DATA_DIR="$2"; shift 2;;
    --with-nmap)     WITH_NMAP="yes"; shift;;
    --without-nmap)  WITH_NMAP="no"; shift;;
    --with-postgres) WITH_POSTGRES="yes"; shift;;
    --with-redis)    WITH_REDIS="yes"; shift;;
    --with-neo4j)    WITH_NEO4J="yes"; shift;;
    --service)       WITH_SERVICE="yes"; shift;;
    --no-start)      AUTO_START="no"; shift;;
    --yes|-y)        ASSUME_YES="yes"; shift;;
    --check)         CHECK_ONLY="yes"; shift;;
    --uninstall)     UNINSTALL="yes"; shift;;
    --force)         FORCE="yes"; shift;;
    --verbose|-v)    VERBOSE="yes"; shift;;
    --version)       echo "redops installer $INSTALLER_VERSION"; exit 0;;
    --help|-h)       usage; exit 0;;
    *)               die "unknown option: $1  (try --help)" 1;;
  esac
done

# ---------- privilege model ---------------------------------------------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
    if [ "$ASSUME_YES" != "yes" ] && [ -t 0 ]; then
      log "need root for system packages; will use sudo"
      sudo -v || die "sudo failed — cannot continue without privileges" 3
    else
      sudo -n true 2>/dev/null || sudo -v || die "sudo requires a password; re-run with sudo or pre-authorize" 3
    fi
  else
    die "not root and no sudo available. Re-run as root:
       sudo -i && curl -fsSL https://raw.githubusercontent.com/0xStr1k3r/RedOps/main/install.sh | bash" 3
  fi
fi
as_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else $SUDO "$@"; fi; }

# ---------- cleanup -----------------------------------------------------------
WORKDIR=""
cleanup() { [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ] && rm -rf "$WORKDIR"; }
trap cleanup EXIT

# ---------- OS / arch detection ----------------------------------------------
detect_os() {
  [ -r /etc/os-release ] || die "cannot read /etc/os-release — unsupported system" 2
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_NAME="${PRETTY_NAME:-$OS_ID}"
}
detect_arch() {
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64)  GOARCH="amd64";;
    aarch64|arm64) GOARCH="arm64";;
    armv7l)        GOARCH="armv7";;
    i386|i686)     GOARCH="386";;
    *) die "unsupported CPU architecture: $ARCH" 2;;
  esac
}
detect_libc() {
  if [ -f /etc/alpine-release ]; then LIBC="musl"; return; fi
  if ldd --version 2>&1 | grep -qi musl; then LIBC="musl"; return; fi
  local f
  for f in /lib/ld-musl-*.so.*; do [ -e "$f" ] && { LIBC="musl"; return; }; done
  LIBC="glibc"
}

# ---------- package manager ---------------------------------------------------
detect_pm() {
  if   command -v apt-get >/dev/null 2>&1; then PM="apt"
  elif command -v dnf     >/dev/null 2>&1; then PM="dnf"
  elif command -v yum     >/dev/null 2>&1; then PM="yum"
  elif command -v pacman  >/dev/null 2>&1; then PM="pacman"
  elif command -v zypper  >/dev/null 2>&1; then PM="zypper"
  elif command -v apk     >/dev/null 2>&1; then PM="apk"
  else die "no supported package manager found (need one of: apt-get, dnf, yum, pacman, zypper, apk)
       Install one manually, or pre-install the requirements and use --check." 2
  fi
}

# pkg_install <required|optional> <label> <pkg...>
pkg_install() {
  local kind="$1" label="$2"; shift 2
  local -a pkgs=("$@")
  [ ${#pkgs[@]} -eq 0 ] && return 0

  # Skip everything already satisfied.
  local missing=0
  for c in $MISSING_CHECK_CMDS; do command -v "$c" >/dev/null 2>&1 || missing=1; done
  [ "$missing" -eq 0 ] && { dbg "$label: already satisfied"; return 0; }

  info "installing $label: ${pkgs[*]}"
  local rc=0
  case "$PM" in
    apt)    as_root apt-get update -qq >/dev/null 2>&1 || warn "apt-get update reported problems"
            as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}" || rc=$? ;;
    dnf)    as_root dnf install -y -q "${pkgs[@]}" || rc=$? ;;
    yum)    as_root yum install -y -q "${pkgs[@]}" || rc=$? ;;
    pacman) as_root pacman -Sy --noconfirm --needed "${pkgs[@]}" || rc=$? ;;
    zypper) as_root zypper --non-interactive --no-confirm install "${pkgs[@]}" || rc=$? ;;
    apk)    as_root apk add --no-cache "${pkgs[@]}" || rc=$? ;;
  esac
  if [ "$rc" -ne 0 ]; then
    if [ "$kind" = "optional" ]; then
      warn "$label install failed (continuing without it)"
      return 0
    fi
    die "$label install failed (exit $rc). Fix it manually, then re-run:
       # $PM install ${pkgs[*]}" 5
  fi
  return 0
}

# ---------- Go toolchain ------------------------------------------------------
# go_version_ok: true when the go on PATH is >= MIN_GO_MAJOR.MIN_GO_MINOR.
# Parses "go1.26.9" -> major=1 minor=26 (the patch is irrelevant).
go_version_ok() {
  command -v go >/dev/null 2>&1 || return 1
  local v major minor
  v="$(go version 2>/dev/null | awk '{print $3}')"      # go1.26.9 / go1.27rc1
  v="${v#go}"; v="${v%%[^0-9.]*}"                       # strip any rc/suffix
  [ -n "$v" ] || return 1
  major="${v%%.*}"
  minor="${v#*.}"; minor="${minor%%.*}"
  case "$major$minor" in *[!0-9]*|"") return 1;; esac
  [ "$major" -gt "$MIN_GO_MAJOR" ] && return 0
  if [ "$major" -eq "$MIN_GO_MAJOR" ] && [ "$minor" -ge "$MIN_GO_MINOR" ]; then return 0; fi
  return 1
}
install_go_pm() {
  case "$PM" in
    apt)    pkg_install required "Go toolchain" golang-go ;;
    dnf)    pkg_install required "Go toolchain" golang ;;
    yum)    pkg_install required "Go toolchain" golang ;;
    pacman) pkg_install required "Go toolchain" go ;;
    zypper) pkg_install required "Go toolchain" go ;;
    apk)    pkg_install required "Go toolchain" go ;;
  esac
}
install_go_tarball() {
  local url="https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz"
  local dest="/usr/local"
  info "downloading Go $GO_VERSION ($GOARCH)"
  if ! curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 20 "$url" -o "$WORKDIR/go.tgz"; then
    die "could not download $url
       Check network/proxy, or install Go >= ${MIN_GO_MAJOR}.${MIN_GO_MINOR} manually:
       https://go.dev/dl/" 3
  fi
  as_root tar -C "$dest" -xzf "$WORKDIR/go.tgz" || die "failed to unpack Go tarball" 3
  [ -x "$dest/go/bin/go" ] || die "Go unpacked but $dest/go/bin/go missing" 3
  case ":$PATH:" in *":$dest/go/bin:"*) ;; *) export PATH="$dest/go/bin:$PATH" ;; esac
  go_version_ok || die "Go ${GO_VERSION} installed but not usable in PATH ($dest/go/bin)" 3
}

ensure_go() {
  if go_version_ok; then
    log "found $(go version | awk '{print $3}')"
    return 0
  fi
  if command -v go >/dev/null 2>&1; then
    warn "Go $(go version | awk '{print $3}') is older than ${MIN_GO_MAJOR}.${MIN_GO_MINOR} — installing a newer toolchain alongside it"
  else
    info "Go toolchain not found"
  fi
  # Prefer the distro package first; fall back to the official tarball.
  # NOTE: never delete an existing /usr/local/go — the tarball unpacks over it.
  install_go_pm || true
  go_version_ok || install_go_tarball
  go_version_ok || die "could not install a usable Go >= ${MIN_GO_MAJOR}.${MIN_GO_MINOR}.
       Install it from https://go.dev/dl/ and re-run with --check to verify." 3
  log "installed $(go version | awk '{print $3}')"
}

# ---------- source acquisition ----------------------------------------------
acquire_source() {
  if [ -n "$REDOPS_VERSION" ]; then
    WORKDIR="$PWD/.redops-build-$$"
  else
    WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/redops-build-XXXXXX")" || die "cannot create temp dir" 3
  fi

  # Build from a local checkout when we are already inside one.
  if [ -f "./go.mod" ] && grep -q "module github.com/0xStr1k3r/RedOps" ./go.mod 2>/dev/null; then
    SRC="$PWD"
    log "building from current directory ($SRC)"
    return 0
  fi
  if [ -d "$REPO" ]; then
    SRC="$REPO"; log "building from local directory $SRC"; return 0
  fi

  command -v git >/dev/null 2>&1 || die "git is required to fetch the source (or pass --check and build manually)" 3
  info "cloning $REPO"
  if ! git clone --depth 1 ${REDOPS_VERSION:+--branch "$REDOPS_VERSION"} "$REPO" "$WORKDIR/src"; then
    die "git clone failed. Check network/proxy, or download and unpack manually, then re-run inside the directory." 4
  fi
  SRC="$WORKDIR/src"
}

# ---------- build -------------------------------------------------------------
build_binary() {
  [ -f "$SRC/go.mod" ] || die "source at $SRC has no go.mod — wrong directory?" 4
  info "building (pure Go, no cgo — this takes a minute)"
  ( cd "$SRC" && mkdir -p internal/api/webdist \
      && cp -f web/dist/index.html web/dist/app.js web/dist/styles.css internal/api/webdist/ \
      && CGO_ENABLED=0 GOFLAGS="${GOFLAGS:-}" go build -trimpath \
           -ldflags "-s -w -X main.version=${REDOPS_VERSION:-$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo dev)}" \
           -o bin/redops ./cmd/cli ) || die "build failed. Common causes: no disk space, stale module cache.
       Retry with: git clean -xdf && go build ./..." 4
  [ -x "$SRC/bin/redops" ] || die "build produced no binary" 4
  "$SRC/bin/redops" version >/dev/null 2>&1 || die "built binary does not execute" 4
  log "built $("$SRC/bin/redops" version)"
}

# ---------- install -----------------------------------------------------------
install_binary() {
  as_root install -d -m 0755 "$PREFIX/bin"
  as_root install -m 0755 "$SRC/bin/redops" "$PREFIX/bin/$BIN_NAME"
  command -v "$BIN_NAME" >/dev/null 2>&1 || export PATH="$PREFIX/bin:$PATH"
  log "installed $("$PREFIX/bin/$BIN_NAME" version) → $PREFIX/bin/$BIN_NAME"
}

setup_data_dir() {
  local dir="$1"
  as_root install -d -m 0700 "$dir"
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    as_root useradd --system --home "$dir" --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null \
      || as_root adduser -S -D -H -h "$dir" -s /sbin/nologin "$SERVICE_USER" 2>/dev/null \
      || dbg "could not create $SERVICE_USER (will run service as current user)"
  fi
  if id "$SERVICE_USER" >/dev/null 2>&1; then
    as_root chown -R "$SERVICE_USER":"$SERVICE_USER" "$dir" 2>/dev/null || true
  fi
  # Create the DB once so ownership is right before the service starts.
  if id "$SERVICE_USER" >/dev/null 2>&1; then
    as_root -u "$SERVICE_USER" "$PREFIX/bin/$BIN_NAME" --db "$dir/redops.db" project list >/dev/null 2>&1 || true
  else
    "$PREFIX/bin/$BIN_NAME" --db "$dir/redops.db" project list >/dev/null 2>&1 || true
  fi
  [ -f "$dir/redops.db" ] && as_root chmod 0600 "$dir/redops.db" 2>/dev/null || true
}

install_service() {
  command -v systemctl >/dev/null 2>&1 || { warn "systemd not found — skipping service"; return 0; }
  local unit_src="$SRC/deployments/redops.service"
  [ -f "$unit_src" ] || unit_src="$PWD/deployments/redops.service"
  if [ ! -f "$unit_src" ]; then
    cat > "$WORKDIR/$SERVICE_NAME.service" <<EOF
[Unit]
Description=RedOps red-team platform (API + GUI)
After=network.target
[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$DATA_DIR
ExecStart=$PREFIX/bin/$BIN_NAME --db $DATA_DIR/redops.db serve --addr 127.0.0.1:8080
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF
    unit_src="$WORKDIR/$SERVICE_NAME.service"
  fi
  as_root install -m 0644 "$unit_src" "/etc/systemd/system/$SERVICE_NAME.service" \
    || { warn "could not install systemd unit"; return 0; }
  as_root systemctl daemon-reload || true
  as_root systemctl enable "$SERVICE_NAME.service" >/dev/null 2>&1 \
    || { warn "systemctl enable failed"; return 0; }
  if [ "$AUTO_START" = "yes" ]; then
    as_root systemctl restart "$SERVICE_NAME.service" \
      || { warn "service failed to start — check: journalctl -u $SERVICE_NAME -n 50"; return 0; }
    log "service active: systemctl status $SERVICE_NAME"
  else
    log "service installed (not started)"
  fi
}

uninstall_all() {
  log "removing $PREFIX/bin/$BIN_NAME"
  as_root rm -f "$PREFIX/bin/$BIN_NAME"
  if command -v systemctl >/dev/null 2>&1; then
    as_root systemctl disable --now "$SERVICE_NAME.service" >/dev/null 2>&1 || true
    as_root rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    as_root systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  local removed_data="no"
  if [ -n "$DATA_DIR" ] && [ "$DATA_DIR" != "$HOME/.redops" ] && [ -d "$DATA_DIR" ]; then
    as_root rm -rf "$DATA_DIR" && removed_data="yes"
  fi
  if [ "$removed_data" = "yes" ]; then
    log "uninstalled (data directory $DATA_DIR removed)"
  else
    log "uninstalled (data kept at $DATA_DIR — delete it manually if unwanted)"
  fi
}

# ---------- optional services ------------------------------------------------
install_optional_services() {
  [ "$WITH_POSTGRES" = "yes" ] && { info "PostgreSQL requested"; pkg_install optional "PostgreSQL" postgresql postgresql-contrib || true; }
  [ "$WITH_REDIS" = "yes" ]    && { info "Redis requested";    pkg_install optional "Redis" redis || true; }
  if [ "$WITH_NEO4J" = "yes" ]; then
    info "Neo4j requested (container)"
    if command -v docker >/dev/null 2>&1; then
      as_root docker run -d --name redops-neo4j \
        -p 127.0.0.1:7474:7474 -p 127.0.0.1:7687:7687 \
        -e NEO4J_AUTH="neo4j/${REDOPS_NEO4J_PASS:-redops-lab-password}" \
        -e NEO4J_dbms_memory_heap_max__size=512M \
        neo4j:5-community >/dev/null 2>&1 \
        && log "Neo4j container started (bolt://127.0.0.1:7687)" \
        || warn "Neo4j container failed to start"
    else
      warn "docker not installed — Neo4j skipped"
    fi
  fi
}

# ---------- prerequisites check ---------------------------------------------
check_prereqs() {
  local ok=0
  printf '%s=== RedOps installer %s ===%s\n' "$C_B" "$INSTALLER_VERSION" "$C_D"
  printf 'os=%s (%s)  libc=%s  arch=%s\n' "$OS_NAME" "$OS_ID" "$LIBC" "$GOARCH"
  printf 'package manager: %s\n' "$PM"
  echo
  for c in git curl; do
    if command -v "$c" >/dev/null 2>&1; then printf '  %-10s %sfound%s (%s)\n' "$c" "$C_G" "$C_D" "$(command -v "$c")"
    else printf '  %-10s %sMISSING%s\n' "$c" "$C_R" "$C_D"; ok=1; fi
  done
  if go_version_ok; then printf '  %-10s %sfound%s (%s)\n' go "$C_G" "$C_D" "$(go version | awk '{print $3}')"
  else printf '  %-10s %swill be installed%s\n' go "$C_Y" "$C_D"; fi
  for c in systemctl docker; do
    command -v "$c" >/dev/null 2>&1 && printf '  %-10s found (%s)\n' "$c" "$(command -v "$c")" || printf '  %-10s absent (optional)\n' "$c"
  done
  df -Pk /usr/local 2>/dev/null | awk 'NR==2{ if ($4+0 < 512000) { printf "  disk      %sLOW%s (%d MB free in /usr/local, want >= 512 MB)\n","\033[1;31m","\033[0m",$4/1024; exit } else printf "  disk      ok (%d MB free)\n",$4/1024 }'
  echo
  return $ok
}

# ---------- main --------------------------------------------------------------
main() {
  WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/redops-XXXXXX")" 2>/dev/null || WORKDIR="/tmp/redops-$$"
  mkdir -p "$WORKDIR" || die "cannot create temp dir $WORKDIR" 3
  LOG_FILE="$WORKDIR/install.log"

  detect_os; detect_arch; detect_libc; detect_pm
  [ -n "$DATA_DIR" ] || DATA_DIR="$HOME/.redops"

  check_prereqs || true
  if [ "$CHECK_ONLY" = "yes" ]; then
    log "check complete — nothing was installed"
    exit 0
  fi
  if [ "$UNINSTALL" = "yes" ]; then uninstall_all; exit 0; fi

  # Refuse to clobber an existing install unless forced.
  if [ -x "$PREFIX/bin/$BIN_NAME" ] && [ "$FORCE" != "yes" ]; then
    die "$PREFIX/bin/$BIN_NAME already exists ($(command -v "$BIN_NAME" 2>/dev/null || echo "$PREFIX/bin/$BIN_NAME")).
   Use --force to reinstall, or --uninstall to remove it first." 1
  fi

  echo
  log "installing dependencies (package manager: $PM)"
  MISSING_CHECK_CMDS="git curl" ; pkg_install required "base tools"  curl ca-certificates git tar
  MISSING_CHECK_CMDS=""         ; :   # optional extras, always attempt
  case "$PM" in
    apt)    pkg_install required "build tools" make gcc libc6-dev ;;
    dnf|yum) pkg_install required "build tools" make gcc glibc-devel ;;
    pacman) pkg_install required "build tools" make gcc base-devel ;;
    zypper) pkg_install required "build tools" make gcc glibc-devel ;;
    apk)    pkg_install required "build tools" make gcc musl-dev build-base ;;
  esac

  case "$WITH_NMAP" in
    yes)  pkg_install required "nmap" nmap ;;
    auto) if command -v nmap >/dev/null 2>&1; then log "nmap already present"
          else MISSING_CHECK_CMDS="nmap"; pkg_install optional "nmap (recommended for recon)" nmap || warn "recon nmap jobs will fail until nmap is installed"; fi ;;
    no)   info "skipping nmap (--without-nmap)" ;;
  esac

  ensure_go
  acquire_source
  build_binary
  install_binary
  setup_data_dir "$DATA_DIR"
  install_optional_services

  echo
  if [ "$WITH_SERVICE" = "yes" ]; then
    as_root install -d -m 0755 /etc/redops
    install_service
  fi

  cat <<EOF

$(printf '%s' "$C_G")RedOps installed$(printf '%s' "$C_D"): $("$PREFIX/bin/$BIN_NAME" version)
  binary: $PREFIX/bin/$BIN_NAME
  data:   $DATA_DIR/redops.db

$(printf '%s' "$C_B")Next steps$(printf '%s' "$C_D")  (no default credentials — first user becomes admin)
  1) $BIN_NAME --db $DATA_DIR/redops.db serve --addr 127.0.0.1:8080
  2) open http://127.0.0.1:8080  →  Register  →  Log in
  3) create a project, set authorized scope (e.g. 10.10.10.0/24), add targets
  4) $BIN_NAME --db $DATA_DIR/redops.db worker      # second shell: runs recon/enum jobs
  5) $BIN_NAME --db $DATA_DIR/redops.db report generate <project> --format pdf

$(printf '%s' "$C_B")Docs$(printf '%s' "$C_D"): docs/usage.md  ·  --help for options  ·  --uninstall to remove

EOF
}

main "$@"