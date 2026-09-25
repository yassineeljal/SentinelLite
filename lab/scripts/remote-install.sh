#!/usr/bin/env bash
# Installs and starts the SentinelLite Linux agent. Runs ON the monitored host, as root.
# Called by deploy-agent.sh; safe to run again (idempotent: upgrades and restarts).
#
#   sudo ./remote-install.sh --wheel FILE --unit FILE --key-file FILE --server-url URL \
#        [--with-sshd] [--start-at end|beginning]
set -euo pipefail

wheel="" unit="" key_file="" server_url="" with_sshd=0 start_at="end"
while [ $# -gt 0 ]; do
  case "$1" in
    --wheel) wheel=$2; shift 2 ;;
    --unit) unit=$2; shift 2 ;;
    --key-file) key_file=$2; shift 2 ;;
    --server-url) server_url=$2; shift 2 ;;
    --with-sshd) with_sshd=1; shift ;;
    --start-at) start_at=$2; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done
for required in wheel unit key_file server_url; do
  [ -n "${!required}" ] || { echo "missing --${required//_/-}" >&2; exit 64; }
done
[ "$(id -u)" -eq 0 ] || { echo "must run as root (use sudo)" >&2; exit 77; }
case "$start_at" in end|beginning) ;; *) echo "--start-at must be end or beginning" >&2; exit 64 ;; esac

say() { printf '==> %s\n' "$*"; }

say "packages"
export DEBIAN_FRONTEND=noninteractive
packages=(python3-venv rsyslog)
[ "$with_sshd" -eq 1 ] && packages+=(openssh-server)
apt-get update -qq
apt-get install -y -qq "${packages[@]}" >/dev/null

say "rsyslog (writes /var/log/auth.log)"
systemctl enable --now rsyslog >/dev/null 2>&1
if [ "$with_sshd" -eq 1 ]; then
  say "sshd"
  systemctl enable --now ssh >/dev/null 2>&1
fi
touch /var/log/auth.log  # exists even before the first login (rsyslog keeps the permissions)

say "service user"
id sentinel-agent >/dev/null 2>&1 || useradd --system --home-dir /var/lib/sentinel-agent \
  --shell /usr/sbin/nologin sentinel-agent
usermod -aG adm sentinel-agent  # read access to /var/log/auth.log (group adm on Ubuntu)

say "agent (virtualenv /opt/sentinel-agent)"
python3 -m venv /opt/sentinel-agent
/opt/sentinel-agent/bin/pip install --quiet --force-reinstall "$wheel"

say "configuration and key"
install -d -m 0750 -o root -g sentinel-agent /etc/sentinel-agent
install -m 0600 -o sentinel-agent -g sentinel-agent "$key_file" /etc/sentinel-agent/key
cat > /etc/sentinel-agent/agent.toml <<CONFIG
[server]
url = "$server_url"
key_file = "/etc/sentinel-agent/key"

[agent]
state_file = "/var/lib/sentinel-agent/state.json"
start_at = "$start_at"

[[sources]]
path = "/var/log/auth.log"
source = "linux.auth"
CONFIG
chown root:sentinel-agent /etc/sentinel-agent/agent.toml
chmod 0640 /etc/sentinel-agent/agent.toml

say "systemd unit"
install -m 0644 "$unit" /etc/systemd/system/sentinel-agent.service
systemctl daemon-reload
systemctl enable sentinel-agent >/dev/null 2>&1
systemctl restart sentinel-agent
sleep 3

if systemctl is-active --quiet sentinel-agent; then
  say "sentinel-agent is active"
  journalctl -u sentinel-agent -n 6 --no-pager
else
  echo "sentinel-agent failed to start:" >&2
  journalctl -u sentinel-agent -n 30 --no-pager >&2
  exit 1
fi
