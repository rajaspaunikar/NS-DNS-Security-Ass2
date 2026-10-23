#!/usr/bin/env bash
# Installs the static routes listed in the assignment's "Deploy" section for Phase 1.
# Routers forward (ip_forward=1, set via compose sysctls); every other node just needs
# to know a router is the way to reach an off-subnet address.
set -euo pipefail

echo "[client] -> resolver subnet via edge-router"
docker exec client ip route add 172.16.2.0/24 via 172.16.1.2

echo "[resolver] -> authoritative subnet via core-router, client subnet via edge-router"
docker exec resolver ip route add 172.16.3.0/24 via 172.16.2.3
docker exec resolver ip route add 172.16.1.0/24 via 172.16.2.2

echo "[root-ns/tld-ns/domain-ns] -> resolver subnet via core-router"
for ns in root-ns tld-ns domain-ns; do
  docker exec "$ns" ip route add 172.16.2.0/24 via 172.16.3.3
done

echo "Routes installed. Note: client intentionally has NO route to 172.16.3.0/24 —"
echo "that's your Phase 1 isolation proof (direct query to root-ns from client fails)."
