#!/usr/bin/env bash
# SentinelLite log agent: installer for Debian/Ubuntu (and other systemd distributions).
#
# Served by your platform, so one command installs the matching agent:
#
#   curl -fsSL https://SIEM/agent/install.sh | sudo bash -s -- --server https://SIEM --key AGENT_KEY
#
# The key is printed once by `sentinel agents create --name my-host --os linux` on the platform. To keep
# it out of the process list and the shell history, pass it in the environment instead:
#
#   curl -fsSL https://SIEM/agent/install.sh | sudo SENTINEL_AGENT_KEY=AGENT_KEY bash -s -- --server https://SIEM
#
# Safe to run again: it upgrades the agent and keeps your configuration and key (use --force to rewrite
# them). Read it before piping it into a root shell: it is short, and `--help` lists every option.
set -euo pipefail

PREFIX=/opt/sentinel-agent
CONF_DIR=/etc/sentinel-agent
STATE_DIR=/var/lib/sentinel-agent
ACCOUNT=sentinel-agent
UNIT=/etc/systemd/system/sentinel-agent.service

server="" key="${SENTINEL_AGENT_KEY:-}" key_file="" wheel="" traefik_log=""
start_at="end" service=1 uninstall=0 purge=0 force=0

info() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: install-agent.sh --server URL (--key KEY | --key-file FILE) [options]

  --server URL         The platform, e.g. https://siem.example.com (or http://127.0.0.1:8000)
  --key KEY            The agent key (or set SENTINEL_AGENT_KEY, or use --key-file)
  --key-file FILE      Read the key from FILE
  --traefik-log PATH   Also ship Traefik's JSON access log (source traefik.access)
  --start-at end|beginning
                       Where to start a log with no saved position (default: end, only new lines)
  --wheel PATH_OR_URL  Install this agent wheel instead of downloading it from the platform
  --no-service         Install the files only: no systemd unit (containers, WSL)
  --force              Rewrite the configuration and key even if they already exist
  --uninstall          Stop and remove the agent; keeps the configuration and key
  --purge              With --uninstall: also remove the configuration, key, state and account
  -h, --help           This help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --server) server="${2:-}"; shift 2 ;;
    --key) key="${2:-}"; shift 2 ;;
    --key-file) key_file="${2:-}"; shift 2 ;;
    --traefik-log) traefik_log="${2:-}"; shift 2 ;;
    --start-at) start_at="${2:-}"; shift 2 ;;
    --wheel) wheel="${2:-}"; shift 2 ;;
    --no-service) service=0; shift ;;
    --force) force=1; shift ;;
    --uninstall) uninstall=1; shift ;;
    --purge) purge=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (put sudo before bash)"

# ---- uninstall ---------------------------------------------------------------------------------
if [ "$uninstall" -eq 1 ]; then
  if [ -d /run/systemd/system ]; then
    systemctl disable --now sentinel-agent 2>/dev/null || true
  fi
  rm -f "$UNIT"
  [ -d /run/systemd/system ] && systemctl daemon-reload
  rm -rf "$PREFIX"
  if [ "$purge" -eq 1 ]; then
    rm -rf "$CONF_DIR" "$STATE_DIR"
    id -u "$ACCOUNT" >/dev/null 2>&1 && userdel "$ACCOUNT" 2>/dev/null || true
    info "agent, configuration, key, state and account removed"
  else
    info "agent removed (the configuration in $CONF_DIR was kept; add --purge to remove it)"
  fi
  exit 0
fi

# ---- checks ------------------------------------------------------------------------------------
[ -n "$server" ] || { usage >&2; die "--server is required"; }
server="${server%/}"
[[ "$server" =~ ^https?://[^/[:space:]]+$ ]] || die "--server must look like https://host[:port] (no path): $server"
if [[ "$server" == http://* && ! "$server" =~ ^http://(127\.0\.0\.1|localhost|\[::1\])(:|$) ]]; then
  warn "$server is plain http: the agent will send logs and its key unencrypted. Use https outside a lab."
fi

if [ -z "$key" ] && [ -n "$key_file" ]; then
  [ -r "$key_file" ] || die "cannot read $key_file"
  key="$(tr -d '[:space:]' <"$key_file")"
fi
[ -n "$key" ] || die "no key: use --key, --key-file or SENTINEL_AGENT_KEY (create one with 'sentinel agents create')"
[[ "$key" =~ ^[0-9a-fA-F-]{36}\.[A-Za-z0-9_-]{32,128}$ ]] || die "the key is malformed (expected <agent id>.<secret>)"
[[ "$start_at" == end || "$start_at" == beginning ]] || die "--start-at must be end or beginning"
if [ -n "$traefik_log" ] && [[ "$traefik_log" != /* ]]; then die "--traefik-log must be an absolute path"; fi

command -v python3 >/dev/null || die "python3 is required (apt-get install -y python3 python3-venv)"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || die "Python 3.11 or newer is required (found $(python3 -c 'import platform; print(platform.python_version())'))"
python3 -c 'import venv, ensurepip' 2>/dev/null || die "the venv module is missing (apt-get install -y python3-venv)"
if [ "$service" -eq 1 ] && [ ! -d /run/systemd/system ]; then
  die "systemd is not running here; use --no-service to install the files only"
fi

fetch() { # URL DEST : plain Python, so that curl is not required
  python3 - "$1" "$2" <<'PY'
import sys, urllib.request
url, dest = sys.argv[1:3]
with urllib.request.urlopen(url, timeout=30) as response, open(dest, "wb") as out:
    out.write(response.read())
PY
}

info "checking that the platform answers at $server"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fetch "$server/healthz" "$tmp/healthz" 2>/dev/null || die "cannot reach $server/healthz: check the URL and the network"
grep -q '"status"' "$tmp/healthz" || die "$server/healthz is not a SentinelLite platform"

# ---- account and program -----------------------------------------------------------------------
if ! id -u "$ACCOUNT" >/dev/null 2>&1; then
  info "creating the unprivileged account $ACCOUNT"
  useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$ACCOUNT"
fi
if getent group adm >/dev/null; then
  usermod -aG adm "$ACCOUNT"  # lets it read /var/log/auth.log on Debian and Ubuntu
else
  warn "no 'adm' group: make sure $ACCOUNT can read the logs you ship"
fi

if [ -z "$wheel" ]; then
  fetch "$server/agent/wheel-name" "$tmp/wheel-name" \
    || die "cannot ask $server for the agent (an old platform? pass --wheel)"
  wheel_name="$(tr -d '[:space:]' <"$tmp/wheel-name")"
  # A wheel keeps its real file name (pip checks it); refuse anything that is not a plain one.
  [[ "$wheel_name" =~ ^[A-Za-z0-9_.+]+-[A-Za-z0-9_.+]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+\.whl$ ]] \
    || die "the platform answered an unexpected wheel name"
  info "downloading $wheel_name from $server"
  fetch "$server/agent/wheel/$wheel_name" "$tmp/$wheel_name" || die "cannot download the agent from $server"
  wheel="$tmp/$wheel_name"
elif [[ "$wheel" == http://* || "$wheel" == https://* ]]; then
  wheel_name="${wheel##*/}"
  [[ "$wheel_name" == *.whl ]] || die "--wheel URL must end with the wheel's own file name (.whl)"
  fetch "$wheel" "$tmp/$wheel_name" || die "cannot download $wheel"
  wheel="$tmp/$wheel_name"
else
  [ -r "$wheel" ] || die "cannot read $wheel"
fi

info "installing the agent into $PREFIX"
python3 -m venv "$PREFIX"
"$PREFIX/bin/pip" install --quiet --disable-pip-version-check --force-reinstall --no-deps "$wheel"
"$PREFIX/bin/sentinel-agent" --version

# ---- configuration -----------------------------------------------------------------------------
install -d -m 0750 -o root -g "$ACCOUNT" "$CONF_DIR"
install -d -m 0700 -o "$ACCOUNT" -g "$ACCOUNT" "$STATE_DIR"

if [ -e "$CONF_DIR/agent.toml" ] && [ "$force" -eq 0 ]; then
  info "keeping the existing $CONF_DIR/agent.toml (use --force to rewrite it)"
else
  info "writing $CONF_DIR/agent.toml"
  {
    printf '# Written by install-agent.sh. Reference: docs/AGENT.md\n\n'
    printf '[server]\nurl = "%s"\nkey_file = "%s/key"\n\n' "$server" "$CONF_DIR"
    printf '[agent]\nstate_file = "%s/state.json"\nstart_at = "%s"\n\n' "$STATE_DIR" "$start_at"
    printf '[[sources]]\npath = "/var/log/auth.log"\nsource = "linux.auth"\n'
    if [ -n "$traefik_log" ]; then
      printf '\n[[sources]]\npath = "%s"\nsource = "traefik.access"\n' "$traefik_log"
    fi
  } >"$CONF_DIR/agent.toml"
  chown root:"$ACCOUNT" "$CONF_DIR/agent.toml"
  chmod 0640 "$CONF_DIR/agent.toml"
fi

if [ -e "$CONF_DIR/key" ] && [ "$force" -eq 0 ]; then
  info "keeping the existing key file (use --force to replace it)"
else
  info "writing the key to $CONF_DIR/key (readable by $ACCOUNT only)"
  (umask 077 && printf '%s' "$key" >"$CONF_DIR/key")
  chown "$ACCOUNT": "$CONF_DIR/key"
  chmod 0600 "$CONF_DIR/key"
fi
[ -e /var/log/auth.log ] || warn "/var/log/auth.log does not exist here: the agent waits for it (edit $CONF_DIR/agent.toml if your SSH log is elsewhere)"

# ---- service -----------------------------------------------------------------------------------
if [ "$service" -eq 0 ]; then
  info "done (no service installed). Run it with:  $PREFIX/bin/sentinel-agent --config $CONF_DIR/agent.toml"
  exit 0
fi

unit_source="$("$PREFIX/bin/python" -c 'import importlib.resources as r; print(r.files("sentinel_agent") / "data" / "sentinel-agent.service")')"
[ -r "$unit_source" ] || die "the systemd unit is missing from the agent package"
install -m 0644 "$unit_source" "$UNIT"
systemctl daemon-reload
systemctl enable sentinel-agent >/dev/null 2>&1
systemctl restart sentinel-agent

for _ in $(seq 1 15); do
  systemctl is-active --quiet sentinel-agent && break
  sleep 1
done
if ! systemctl is-active --quiet sentinel-agent; then
  journalctl -u sentinel-agent -n 15 --no-pager >&2 || true
  die "the agent did not start: see the log above (exit code 1 = configuration, 2 = the key was refused)"
fi
sleep 3
systemctl is-active --quiet sentinel-agent || { journalctl -u sentinel-agent -n 15 --no-pager >&2; die "the agent stopped right after starting"; }

info "the agent is running"
journalctl -u sentinel-agent -n 3 --no-pager | sed 's/^/    /'
cat <<EOF

Next: on the platform, check that it reports (it sends a heartbeat every minute):

    docker compose exec api sentinel agents list      # 'last seen' should be recent

Logs on this host:  journalctl -u sentinel-agent -f
Uninstall:          bash install-agent.sh --uninstall   (add --purge to remove the key and configuration)
EOF
