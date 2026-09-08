#!/usr/bin/env bash
# Tears down what docker_run_demo.sh / docker_smoke_test.sh started.
set -euo pipefail

docker rm -f sd-server sd-client mcast-recv mcast-send >/dev/null 2>&1 || true
docker network rm someip-sd-net >/dev/null 2>&1 || true
echo "Stopped and cleaned up."
