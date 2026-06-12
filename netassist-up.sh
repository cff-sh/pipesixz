#!/bin/bash
# NetAssist SIT tunnel setup
# Run on VPS to connect to NetAssist tunnel broker.
# Usage: sudo ./netassist-up.sh <local_ipv4>
#   local_ipv4  Your VPS public IPv4 address (e.g. 82.39.86.20)

set -e

LOCAL="${1:-}"
if [ -z "$LOCAL" ]; then
    echo "Usage: sudo $0 <your_vps_public_ipv4>"
    exit 1
fi

SERVER_IPV4="62.205.132.12"
SERVER_IPV6="2a01:d0:ffff:233f::1"
CLIENT_IPV6="2a01:d0:ffff:233f::2"

# Create SIT tunnel
ip tunnel add netassist mode sit remote ${SERVER_IPV4} local ${LOCAL} ttl 200
ip link set netassist up

# Assign IPv6 address
ip addr add ${CLIENT_IPV6}/64 dev netassist

# Default route via NetAssist
ip -6 route add ::/0 dev netassist

echo "NetAssist tunnel is up"
echo "Test: ping6 ${SERVER_IPV6}"
