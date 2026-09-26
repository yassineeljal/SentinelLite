#!/usr/bin/env bash
# Downloads the free DB-IP "Lite" city and ASN databases (MaxMind format) into deploy/geoip/.
#
#   deploy/fetch-geoip.sh
#
# The databases are published monthly (start of the month): if this month's file is not there yet,
# last month's is used. Licence: Creative Commons Attribution 4.0, see deploy/geoip/ATTRIBUTION.txt
# (keep the attribution wherever the data is shown). The files are ignored by Git: never commit them.
# Nothing here needs an account or an API key, and no address of yours is ever sent to DB-IP:
# lookups happen locally, only these two files are downloaded.
set -euo pipefail

dest="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/geoip"
mkdir -p "$dest"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fetch() { # kind (city|asn)
  local kind="$1" month url
  for month in "$(date -u +%Y-%m)" "$(date -u -v-1m +%Y-%m 2>/dev/null || date -u -d 'last month' +%Y-%m)"; do
    url="https://download.db-ip.com/free/dbip-${kind}-lite-${month}.mmdb.gz"
    if curl --fail --silent --show-error --location --proto '=https' --max-time 600 \
         -o "$work/$kind.mmdb.gz" "$url"; then
      gzip -t "$work/$kind.mmdb.gz"                      # a truncated download must not replace a good file
      gunzip -c "$work/$kind.mmdb.gz" > "$work/$kind.mmdb"
      [ "$(wc -c < "$work/$kind.mmdb")" -gt 1000000 ] || { echo "$kind database is suspiciously small" >&2; exit 1; }
      mv "$work/$kind.mmdb" "$dest/dbip-${kind}-lite.mmdb"
      echo "dbip-${kind}-lite.mmdb  ($month, $(du -h "$dest/dbip-${kind}-lite.mmdb" | cut -f1))"
      return 0
    fi
  done
  echo "could not download the $kind database" >&2
  return 1
}

fetch city
fetch asn
cat > "$dest/ATTRIBUTION.txt" <<'T'
IP geolocation data by DB-IP (https://db-ip.com), licensed under the Creative Commons
Attribution 4.0 International License (https://creativecommons.org/licenses/by/4.0/).
T
echo "done: $dest"
