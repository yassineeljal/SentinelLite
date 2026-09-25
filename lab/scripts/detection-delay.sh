#!/usr/bin/env bash
# Measures the "attack -> alert" delay of the latest ssh-bruteforce alert for a source IP.
# Runs on the platform host (the Mac). Optional: the attack_start_ms printed by the attack script.
#
#   lab/scripts/detection-delay.sh SOURCE_IP [ATTACK_START_MS]
#
# Clocks: the delays are only meaningful when the attacker, the target and the platform share a
# clock (true for OrbStack machines; with separate VMs keep them NTP-synchronised).
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PATH="$HOME/.orbstack/bin:$PATH"
ip="${1:-}"
attack_start_ms="${2:-}"
[[ "$ip" =~ ^[0-9.]+$ ]] || { echo "usage: $0 SOURCE_IP [ATTACK_START_MS]" >&2; exit 64; }
[ -z "$attack_start_ms" ] || [[ "$attack_start_ms" =~ ^[0-9]+$ ]] || { echo "ATTACK_START_MS must be an integer" >&2; exit 64; }

pg_user="$(sed -n 's/^POSTGRES_USER=//p' "$repo/deploy/.env")"
row="$(docker compose -f "$repo/deploy/docker-compose.yml" exec -T postgres \
  psql -U "$pg_user" -d sentinel -tA -F'|' -c "
  SELECT (extract(epoch from (SELECT min(e.ts) FROM events e
            WHERE e.event_id = ANY (ARRAY(SELECT jsonb_array_elements_text(a.event_ids)))))*1000)::bigint,
         (extract(epoch from a.ts)*1000)::bigint,
         (extract(epoch from a.created_at)*1000)::bigint,
         a.match_count, left(a.alert_id, 12)
  FROM alerts a WHERE a.rule_id = 'ssh-bruteforce' AND host(a.src_ip) = '$ip'
  ORDER BY a.ts DESC LIMIT 1")"
[ -n "$row" ] || { echo "no ssh-bruteforce alert for $ip yet" >&2; exit 1; }

IFS='|' read -r first_ms trigger_ms stored_ms count alert <<< "$row"
fmt() { python3 -c "import sys,datetime; print(datetime.datetime.fromtimestamp(int(sys.argv[1])/1000, datetime.timezone.utc).strftime('%H:%M:%S.%f')[:-3])" "$1"; }
echo "alert $alert ($count failed logins from $ip)"
[ -z "$attack_start_ms" ] || echo "attack started            $(fmt "$attack_start_ms") UTC"
echo "first failure logged       $(fmt "$first_ms") UTC"
echo "threshold reached (5th)    $(fmt "$trigger_ms") UTC"
echo "alert stored               $(fmt "$stored_ms") UTC"
echo "-- delays"
echo "  threshold reached -> alert stored : $((stored_ms - trigger_ms)) ms"
echo "  first failure     -> alert stored : $((stored_ms - first_ms)) ms"
[ -z "$attack_start_ms" ] || echo "  attack start      -> alert stored : $((stored_ms - attack_start_ms)) ms"
