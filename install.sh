#!/usr/bin/env bash
#
# RedOps installer — Debian/Ubuntu, Arch, RHEL/Fedora/Rocky/Alma, openSUSE, Alpine.
#
# Installs the single `redops` binary (CLI + API + embedded GUI + worker):
#
#   curl -fsSL https://raw.githubusercontent.com/redops/redops/main/install.sh | bash
#   redops --db ~/redops.db serve --addr 127.0.0.1:8080   # API + GUI
#   redops --db ~/redops.db worker                        # job runner (another shell)
#
# Options:
#   --prefix DIR        install prefix (default /usr/local)
#   --without-nmap      skip the nmap install (recon degrades gracefully)
#   --service           install+enable a systemd unit (needs root + systemd)
#   --uninstall         remove the binary (and unit) again
#   --help              this text
#
# Env overrides: REDOPS_REPO (git URL or local dir), GO_VERSION (tarball fallback).
#
set -euo pipefail

PREFIX="/usr/local"
WITH_NMAP=1
WITH_SERVICE=0
UNINSTALL=0
REPO="${REDOPS_REPO:-https://github.com/redops/redops.git}"
GO_VERSION="${GO_VERSION:-1.26.8}"

log()  { printf '\033[1;32m[redops]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[redops]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[redops]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
RedOps installer — Debian/Ubuntu, Arch, RHEL/Fedora/Rocky/Alma, openSUSE, Alpine.

Installs the single `redops` binary (CLI + API + embedded GUI + worker).

Usage:
  install.sh [--prefix DIR] [--without-nmap] [--service] [--uninstall] [--help]

Env overrides: REDOPS_REPO (git URL or local dir), GO_VERSION (Go tarball fallback).
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="${2:?}"; shift 2;;
    --without-nmap) WITH_NMAP=0; shift;;
    --service) WITH_SERVICE=1; shift;;
    --uninstall) UNINSTALL=1; shift;;
    --help|-h) usage; exit 0;;
    *) die "unknown flag $1 (see --help)";;
  esac
done

is_root() { [ "$(id -u)" -eq 0 ]; }
have() { command -v "$1" >/dev/null 2>&1; }
run_root() {
  if is_root; then "$@";
  elif have sudo; then sudo "$@";
  else die "need root (or sudo) for: $*"; fi
}

detect_pm() {
  if have apt-get;   then echo apt;
  elif have pacman;  then echo pacman;
  elif have dnf;     then echo dnf;
  elif have yum;     then echo yum;
  elif have zypper;  then echo zypper;
  elif have apk;     then echo apk;
  else die "no supported package manager found (apt/pacman/dnf/yum/zypper/apk)"; fi
}

# sys_install <pm> <packages...>: best-effort, never fatal (script continues).
sys_install() {
  local pm="$1"; shift
  case "$pm" in
    apt)    run_root apt-get update -qq; run_root apt-get install -y -qq "$@" || true;;
    pacman) run_root pacman -Sy --noconfirm --needed "$@" || true;;
    dnf|yum) run_root "$pm" install -y -q "$@" || true;;
    zypper) run_root zypper --non-interactive install "$@" || true;;
    apk)    run_root apk add --no-cache "$@" || true;;
  esac
}

uninstall() {
  log "removing $PREFIX/bin/redops"
  run_root rm -f "$PREFIX/bin/redops"
  if [ -f /etc/systemd/system/redops.service ]; then
    run_root systemctl disable --now redops.service || true
    run_root rm -f /etc/systemd/system/redops.service
    run_root systemctl daemon-reload || true
  fi
  log "uninstalled"
}

if [ "$UNINSTALL" -eq 1 ]; then uninstall; exit 0; fi

PM="$(detect_pm)"
log "package manager: $PM"

# --- 1. system dependencies -------------------------------------------------
case "$PM" in
  apt)    DEPS="curl ca-certificates git make gcc"; NMAP_PKG="nmap";;
  pacman) DEPS="curl ca-certificates git make gcc"; NMAP_PKG="nmap";;
  dnf|yum) DEPS="curl ca-certificates git make gcc"; NMAP_PKG="nmap";;
  zypper) DEPS="curl ca-certificates git make gcc"; NMAP_PKG="nmap";;
  apk)    DEPS="curl ca-certificates git make gcc musl-dev"; NMAP_PKG="nmap";;
esac
# shellcheck disable=SC2086
sys_install "$PM" $DEPS
if [ "$WITH_NMAP" -eq 1 ]; then
  if have nmap; then log "nmap already present";
  else log "installing nmap (recommended for recon)"; sys_install "$PM" "$NMAP_PKG"; fi
else
  warn "skipping nmap — nmap recon jobs will fail with an install hint"
fi

# --- 2. Go toolchain ---------------------------------------------------------
need_go() {
  have go || return 0
  local v maj min
  v="$(go version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+' | head -1)"
  v="${v#go}"; maj="${v%%.*}"; min="${v##*.}"
  if [ "${maj:-0}" -gt 1 ] || { [ "${maj:-0}" -eq 1 ] && [ "${min:-0}" -ge 21 ]; }; then
    return 1  # have a usable Go (module toolchain auto-upgrades as needed)
  fi
  return 0  # need Go
}
install_go_pm() {
  case "$PM" in
    apt)    sys_install "$PM" golang-go;;
    pacman) sys_install "$PM" go;;
    dnf|yum) sys_install "$PM" golang;;
    zypper) sys_install "$PM" go;;
    apk)    sys_install "$PM" go;;
  esac
}
install_go_tarball() {
  local arch; case "$(uname -m)" in
    x86_64) arch=amd64;; aarch64|arm64) arch=arm64;;
    *) die "unsupported arch $(uname -m) for Go tarball (set up Go manually)";;
  esac
  local dest="/usr/local"; is_root || dest="$HOME/.local"
  log "installing Go $GO_VERSION to $dest (tarball)"
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" -o /tmp/go.tgz
  run_root tar -C "$dest" -xzf /tmp/go.tgz; rm -f /tmp/go.tgz
  export PATH="$dest/go/bin:$PATH"
  if ! is_root && ! echo "$PATH" | grep -q "$HOME/.local/go/bin"; then
    warn "add to PATH: export PATH=\"\$HOME/.local/go/bin:\$PATH\""
  fi
}
if need_go; then
  log "Go missing or too old — trying package manager"
  install_go_pm
  if need_go; then install_go_tarball; fi
fi
have go || { export PATH="/usr/local/go/bin:$HOME/.local/go/bin:$PATH"; }
have go || die "Go toolchain still missing — install Go >= 1.21 manually"
log "$(go version) ready"

# --- 3. source ---------------------------------------------------------------
SRC=""
if [ -f ./go.mod ] && [ -f ./Makefile ] && grep -q "module github.com/redops/redops" ./go.mod 2>/dev/null; then
  SRC="$PWD"; log "building from current directory"
else
  if [ -d "$REPO" ]; then SRC="$REPO"; log "building from $REPO";
  else
    have git || die "git is required to fetch the source"
    SRC="/tmp/redops-src"
    rm -rf "$SRC"; log "cloning $REPO"
    git clone --depth 1 "$REPO" "$SRC"
  fi
fi

# --- 4. build the single binary ----------------------------------------------
log "building redops (single binary: CLI + API + GUI + worker)"
(cd "$SRC" && make build)
BIN="$SRC/bin/redops"
[ -x "$BIN" ] || die "build failed: $BIN missing"

# --- 5. install ---------------------------------------------------------------
log "installing to $PREFIX/bin/redops"
mkbindir() { mkdir -p "$PREFIX/bin" && install -m 0755 "$BIN" "$PREFIX/bin/redops"; }
if [ -w "$PREFIX" ] || [ -w "$PREFIX/bin" ] 2>/dev/null; then mkbindir;
else run_root mkdir -p "$PREFIX/bin" && run_root install -m 0755 "$BIN" "$PREFIX/bin/redops"; fi
command -v redops >/dev/null 2>&1 || export PATH="$PREFIX/bin:$PATH"
redops version || die "installed binary does not run"

# --- 6. optional systemd service ----------------------------------------------
if [ "$WITH_SERVICE" -eq 1 ]; then
  is_root || die "--service needs root"
  have systemctl || die "--service needs systemd"
  run_root mkdir -p /var/lib/redops
  run_root tee /etc/systemd/system/redops.service >/dev/null <<EOF
[Unit]
Description=RedOps red-team platform (API + GUI)
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/redops
ExecStart=$PREFIX/bin/redops --db /var/lib/redops/redops.db serve --addr 127.0.0.1:8080
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
  run_root systemctl daemon-reload
  run_root systemctl enable --now redops.service
  log "service active: systemctl status redops"
fi

cat <<EOF

  RedOps installed: $(redops version) ($PREFIX/bin/redops)

  Next steps (no default credentials — the first registered user is admin):
    1. redops --db ~/redops.db serve --addr 127.0.0.1:8080
    2. open http://127.0.0.1:8080 → Register (first user = admin) → Log in
    3. create a project, add scope (e.g. 10.10.10.0/24), add targets
    4. redops --db ~/redops.db worker        # second shell: runs recon/enum jobs
    5. full guide: docs/usage.md

EOF
