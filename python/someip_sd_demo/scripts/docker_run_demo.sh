#!/usr/bin/env bash
# Plain-`docker` equivalent of `docker compose up` (no compose plugin
# needed) -- for hosts where `docker compose`/`docker-compose` isn't
# installed. Builds the image, creates the IPv6 bridge network if it
# doesn't already exist, and starts both containers at their real
# addresses, exactly like docker-compose.yml does.
#
# Usage: scripts/docker_run_demo.sh
# Then:  docker logs -f sd-server   /   docker logs -f sd-client
# Stop:  scripts/docker_stop_demo.sh
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=someip-sd-sim
NET=someip-sd-net
SUBNET="fd53:7cb8:383:2::/64"
SERVER_ADDR="fd53:7cb8:383:2::56"
CLIENT_ADDR="fd53:7cb8:383:2::1:117"

docker build -t "$IMAGE" .

docker network inspect "$NET" >/dev/null 2>&1 || \
  docker network create --driver bridge --ipv6 --subnet "$SUBNET" "$NET"

docker rm -f sd-server sd-client >/dev/null 2>&1 || true

docker run -d --name sd-server --network "$NET" --ip6 "$SERVER_ADDR" "$IMAGE" \
  sd-server --local-addr "$SERVER_ADDR" --unicast-port 30490 --interface eth0 --log-level DEBUG

docker run -d --name sd-client --network "$NET" --ip6 "$CLIENT_ADDR" "$IMAGE" \
  sd-client --local-addr "$CLIENT_ADDR" --unicast-port 30490 --interface eth0 --log-level DEBUG

echo "Started sd-server and sd-client on network '$NET'."
echo "Tail logs:  docker logs -f sd-server   /   docker logs -f sd-client"
echo "Stop:       scripts/docker_stop_demo.sh"
