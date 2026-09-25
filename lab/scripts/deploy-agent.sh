#!/usr/bin/env bash
# Registers an agent on the platform and installs it on a monitored host over SSH.
# Runs on the machine that hosts the platform (the Mac). See lab/README.md.
#
#   lab/scripts/deploy-agent.sh --host USER@HOST --server-url URL --name AGENT_NAME \
#       [--with-sshd] [--start-at end|beginning]
#
# The API key is created on the platform, sent over SSH to a private file on the host and never
# printed or left on this machine.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PATH="$HOME/.orbstack/bin:$PATH"
host="" server_url="" name="" with_sshd="" start_at="end"
while [ $# -gt 0 ]; do
  case "$1" in
    --host) host=$2; shift 2 ;;
    --server-url) server_url=$2; shift 2 ;;
    --name) name=$2; shift 2 ;;
    --with-sshd) with_sshd="--with-sshd"; shift ;;
    --start-at) start_at=$2; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done
for required in host server_url name; do
  [ -n "${!required}" ] || { echo "missing --${required//_/-}" >&2; exit 64; }
done
# shellcheck disable=SC2206  # word splitting of SSH_OPTS is intended
ssh_opts=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new ${SSH_OPTS:-})

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chmod 700 "$work"

echo "==> building the agent wheel"
(cd "$repo/agents/linux" && uv build --wheel --out-dir "$work" >/dev/null)
wheel="$(ls "$work"/sentinel_agent-*.whl)"

echo "==> registering agent '$name' on the platform"
output="$(docker compose -f "$repo/deploy/docker-compose.yml" exec -T api \
  sentinel agents create --name "$name" --os linux 2>/dev/null)" || {
  echo "could not create the agent (is the stack up? is the name '$name' already taken?)" >&2
  echo "list agents: docker compose -f deploy/docker-compose.yml exec api sentinel agents list" >&2
  exit 1
}
printf '%s\n' "$output" | sed -n 's/^key: //p' | tr -d '\n' > "$work/key"
[ -s "$work/key" ] || { echo "the platform did not return a key" >&2; exit 1; }
chmod 600 "$work/key"
echo "    $(printf '%s\n' "$output" | head -1)"

echo "==> copying to $host"
remote="$(ssh "${ssh_opts[@]}" "$host" 'mktemp -d')"
scp -q "${ssh_opts[@]}" "$wheel" "$work/key" "$repo/agents/linux/deploy/sentinel-agent.service" \
  "$repo/lab/scripts/remote-install.sh" "$host:$remote/"
trap 'ssh "${ssh_opts[@]}" "$host" "rm -rf $remote" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

echo "==> installing on $host"
# shellcheck disable=SC2086  # $with_sshd is either empty or one option
ssh "${ssh_opts[@]}" "$host" "sudo bash $remote/remote-install.sh \
  --wheel $remote/$(basename "$wheel") --unit $remote/sentinel-agent.service \
  --key-file $remote/key --server-url '$server_url' --start-at $start_at $with_sshd"
