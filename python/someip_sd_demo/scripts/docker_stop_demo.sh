#!/usr/bin/env bash
# Tears down what docker_run_demo.sh / docker_smoke_test.sh started.
# Works with Docker or Podman: set CONTAINER_ENGINE=podman to match
# whichever engine you started the demo with.
set -euo pipefail

ENGINE="${CONTAINER_ENGINE:-docker}"

"$ENGINE" rm -f sd-server sd-client mcast-recv mcast-send >/dev/null 2>&1 || true
"$ENGINE" network rm someip-sd-net >/dev/null 2>&1 || true
echo "Stopped and cleaned up ($ENGINE)."
