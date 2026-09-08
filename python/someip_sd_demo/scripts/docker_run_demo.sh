#!/usr/bin/env bash
# Plain container-engine equivalent of `docker compose up` (no compose
# plugin needed). Builds the image, creates the IPv6 bridge network if
# it doesn't already exist, and starts both containers at their real
# addresses, exactly like docker-compose.yml does.
#
# Works with Docker or Podman: set CONTAINER_ENGINE=podman to use
# Podman (defaults to docker).
#
# Usage: scripts/docker_run_demo.sh
# Then:  docker logs -f sd-server   /   docker logs -f sd-client
#        (or: podman logs -f ..., matching whichever engine you used)
# Stop:  scripts/docker_stop_demo.sh
set -euo pipefail
cd "$(dirname "$0")/.."

ENGINE="${CONTAINER_ENGINE:-docker}"
IMAGE=someip-sd-sim
NET=someip-sd-net
SUBNET="fd53:7cb8:383:2::/64"
SERVER_ADDR="fd53:7cb8:383:2::56"
CLIENT_ADDR="fd53:7cb8:383:2::1:117"

"$ENGINE" build -t "$IMAGE" .

"$ENGINE" network inspect "$NET" >/dev/null 2>&1 || \
  "$ENGINE" network create --driver bridge --ipv6 --subnet "$SUBNET" "$NET"

"$ENGINE" rm -f sd-server sd-client >/dev/null 2>&1 || true

"$ENGINE" run -d --name sd-server --network "$NET" --ip6 "$SERVER_ADDR" "$IMAGE" \
  sd-server --local-addr "$SERVER_ADDR" --unicast-port 30490 --interface eth0 --log-level DEBUG

"$ENGINE" run -d --name sd-client --network "$NET" --ip6 "$CLIENT_ADDR" "$IMAGE" \
  sd-client --local-addr "$CLIENT_ADDR" --unicast-port 30490 --interface eth0 --log-level DEBUG

echo "Started sd-server and sd-client on network '$NET' (engine: $ENGINE)."
echo "Tail logs:  $ENGINE logs -f sd-server   /   $ENGINE logs -f sd-client"
echo "Stop:       scripts/docker_stop_demo.sh"
