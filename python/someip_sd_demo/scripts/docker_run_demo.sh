#!/usr/bin/env bash
# Plain container-engine equivalent of `docker compose up` (no compose
# plugin needed). Builds the image, creates the IPv6 bridge network if
# it doesn't already exist, and starts both containers at their real
# addresses, exactly like docker-compose.yml does.
#
# Works with Docker or Podman: set CONTAINER_ENGINE=podman to use
# Podman (defaults to docker). Static-IPv6-per-container syntax differs
# between the two (Docker: `--network NET --ip6 ADDR`; Podman: `--network
# NET:ip6=ADDR` -- Podman's top-level `--ip6` flag is newer than 4.2.1's
# CNI network backend and isn't recognized there), so this branches on
# $ENGINE rather than guessing one syntax works for both.
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

net_args() {  # net_args <ipv6-addr> -- prints the --network... args for this engine
  if [ "$ENGINE" = "podman" ]; then
    printf -- '--network\n%s:ip6=%s\n' "$NET" "$1"
  else
    printf -- '--network\n%s\n--ip6\n%s\n' "$NET" "$1"
  fi
}

"$ENGINE" build -t "$IMAGE" .

"$ENGINE" network inspect "$NET" >/dev/null 2>&1 || \
  "$ENGINE" network create --driver bridge --ipv6 --subnet "$SUBNET" "$NET"

"$ENGINE" rm -f sd-server sd-client >/dev/null 2>&1 || true

mapfile -t SERVER_NET_ARGS < <(net_args "$SERVER_ADDR")
"$ENGINE" run -d --name sd-server "${SERVER_NET_ARGS[@]}" "$IMAGE" \
  sd-server --local-addr "$SERVER_ADDR" --unicast-port 30490 --interface eth0 --log-level DEBUG

mapfile -t CLIENT_NET_ARGS < <(net_args "$CLIENT_ADDR")
"$ENGINE" run -d --name sd-client "${CLIENT_NET_ARGS[@]}" "$IMAGE" \
  sd-client --local-addr "$CLIENT_ADDR" --unicast-port 30490 --interface eth0 --log-level DEBUG

echo "Started sd-server and sd-client on network '$NET' (engine: $ENGINE)."
echo "Tail logs:  $ENGINE logs -f sd-server   /   $ENGINE logs -f sd-client"
echo "Stop:       scripts/docker_stop_demo.sh"
