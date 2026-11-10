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
CLIENT_IPV6="2a01:d0:ffff:233f::2"

# The broker sends protocol 41 back to the address in your panel, so a
# tunnel claiming an address this host does not own fails without saying so.
if ! ip -4 -o addr show | grep -qw "${LOCAL}"; then
    echo "Error: ${LOCAL} is not configured on this host." >&2
    echo "Use the address from 'ip -4 addr' and update the NetAssist panel." >&2
    exit 1
fi

# Re-running must not fail on the leftover tunnel from a previous run.
ip tunnel del netassist 2>/dev/null || true

# Create SIT tunnel
ip tunnel add netassist mode sit remote ${SERVER_IPV4} local ${LOCAL} ttl 200
ip link set netassist up

# Assign IPv6 address
ip addr add ${CLIENT_IPV6}/64 dev netassist

# Default route via NetAssist; 'replace' so a previous default is taken over
ip -6 route replace ::/0 dev netassist

echo "NetAssist tunnel is up"
# The gateway address published in the panel (2a01:d0:ffff:233f::1) does not
# answer ICMP: those packets are routed back into our own tunnel and die of
# a hop-limit loop, which looks like a broken tunnel but is not one. Verify
# against the broker's DNS server and a public host instead.
echo "Test: ping -6 2a01:d0::1                 # broker DNS"
echo "      ping -6 2001:4860:4860::8888       # internet"
echo "If neither answers, check that IPv4 protocol 41 reaches this host"
echo "and that UDP/8899 is open for pipesix clients."
