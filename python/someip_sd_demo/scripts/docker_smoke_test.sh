#!/usr/bin/env bash
# Plain container-engine equivalent of the "smoketest" compose profile
# (no compose plugin needed): confirms this setup actually delivers
# IPv6 multicast between two containers on the bridge, before trusting
# the full demo to it. Exits 0 if the multicast packet was received, 1
# if not. Prints both containers' logs either way.
#
# Works with Docker or Podman: set CONTAINER_ENGINE=podman to use
# Podman (defaults to docker).
set -euo pipefail
cd "$(dirname "$0")/.."

ENGINE="${CONTAINER_ENGINE:-docker}"
IMAGE=someip-sd-sim
NET=someip-sd-net
SUBNET="fd53:7cb8:383:2::/64"

"$ENGINE" build -t "$IMAGE" .

"$ENGINE" network inspect "$NET" >/dev/null 2>&1 || \
  "$ENGINE" network create --driver bridge --ipv6 --subnet "$SUBNET" "$NET"

"$ENGINE" rm -f mcast-recv mcast-send >/dev/null 2>&1 || true

"$ENGINE" run -d --name mcast-recv --network "$NET" --ip6 "fd53:7cb8:383:2::10" \
  -e MCAST_IFACE=eth0 --entrypoint python3 "$IMAGE" scripts/mcast_smoke_test.py recv

sleep 1

"$ENGINE" run --name mcast-send --network "$NET" --ip6 "fd53:7cb8:383:2::11" \
  -e MCAST_IFACE=eth0 --entrypoint python3 "$IMAGE" scripts/mcast_smoke_test.py send || true

STATUS="$("$ENGINE" wait mcast-recv)"

echo "=== mcast-recv logs ==="
"$ENGINE" logs mcast-recv
echo "=== mcast-send logs ==="
"$ENGINE" logs mcast-send

"$ENGINE" rm -f mcast-recv mcast-send >/dev/null 2>&1 || true

if [ "$STATUS" = "0" ]; then
  echo "PASS: multicast delivered between containers on this $ENGINE setup."
else
  echo "FAIL: multicast NOT delivered (exit $STATUS) -- see README's --peer-addr fallback."
fi
exit "$STATUS"
