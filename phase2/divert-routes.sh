#!/usr/bin/env bash
# Diverts traffic from the authoritative subnet destined for the resolver
# (172.16.2.10) through the attacker (172.16.2.100) instead of delivering
# it directly. This is a route on core-router ONLY — resolver and
# nameservers stay at their Phase 1 configuration, per the brief.
set -euo pipefail

echo "[core-router] diverting resolver-bound replies via attacker"
docker exec core-router ip route add 172.16.2.10/32 via 172.16.2.100

echo "[attacker] confirming kernel IP forwarding is OFF (must stay off -"
echo "           the interceptor binary does ALL relaying itself; if the"
echo "           kernel forwards too, the real answer reaches resolver"
echo "           regardless of what interceptor.c decides)"
docker exec attacker sysctl net.ipv4.ip_forward

echo "Done. To undo: docker exec core-router ip route del 172.16.2.10/32 via 172.16.2.100"