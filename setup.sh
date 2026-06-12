#!/bin/bash
# pipesix Full Setup Script
# Usage: sudo ./setup.sh <server|client> [--backend route64|netassist]
#   --backend  Upstream IPv6 provider (default: route64)

set -e

MODE="${1:-}"
BACKEND="route64"
if [ "${2:-}" = "--backend" ]; then
    BACKEND="${3:-route64}"
fi

if [ "$MODE" != "server" ] && [ "$MODE" != "client" ]; then
    echo "Usage: sudo $0 <server|client> [--backend route64|netassist]"
    exit 1
fi
if [ "$BACKEND" != "route64" ] && [ "$BACKEND" != "netassist" ]; then
    echo "Backend must be 'route64' or 'netassist'"
    exit 1
fi

# ------ CONFIGURATION (edit these!) ------

if [ "$BACKEND" = "route64" ]; then
    GATEWAY="2a11:6c7:f27:86::1"
    SUBNET="2a11:6c7:f27:86::/64"
    if [ "$MODE" = "server" ]; then
        TUN_ADDR="2a11:6c7:f27:86::2"
        CLIENT_ADDR="2a11:6c7:f27:86::3"
        UPSTREAM_IFACE="wg0"
    else
        SERVER_ADDR="2a11:6c7:f27:86::2"
        TUN_ADDR="2a11:6c7:f27:86::3"
    fi
else
    # NetAssist
    GATEWAY="2a01:d0:ffff:233f::1"
    SUBNET="2a01:d0:a33f::/48"
    if [ "$MODE" = "server" ]; then
        TUN_ADDR="2a01:d0:a33f::1"
        CLIENT_ADDR="2a01:d0:a33f::2"
        UPSTREAM_IFACE="netassist"
    else
        SERVER_ADDR="2a01:d0:a33f::1"
        TUN_ADDR="2a01:d0:a33f::2"
    fi
fi

# -- 1. Enable IPv6 forwarding --
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/99-pipesix.conf

# -- 2. Create pipesix config --
mkdir -p /etc/pipesix

if [ "$MODE" = "server" ]; then
    cat > /etc/pipesix/pipesix.conf <<EOF
mode = server
bind_address = 0.0.0.0
bind_port = 8899
tun_name = tun0
tun_address = ${TUN_ADDR}
tun_prefixlen = 64
tun_mtu = 1500
log_level = info
EOF

    # Route client traffic via pipesix tun
    ip -6 route del ${SUBNET} dev tun0 2>/dev/null || true
    ip -6 route add ${CLIENT_ADDR}/128 dev tun0

    # NAT66 for client internet access
    ip6tables -t nat -A POSTROUTING -s ${CLIENT_ADDR}/128 -o ${UPSTREAM_IFACE} -j MASQUERADE 2>/dev/null || true
    mkdir -p /etc/iptables
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true

    echo "=== Server setup complete ==="
    echo "Run: sudo pipesix -c /etc/pipesix/pipesix.conf"

else
    cat > /etc/pipesix/pipesix.conf <<EOF
mode = client
remote_address = ${SERVER_ADDR}
remote_port = 8899
tun_name = tun0
tun_address = ${TUN_ADDR}
tun_prefixlen = 64
tun_mtu = 1500
log_level = info
EOF

    echo "ip -6 route add default via ${SERVER_ADDR} dev tun0" > /etc/pipesix/route-up.sh
    chmod +x /etc/pipesix/route-up.sh
    ip -6 route add default via ${SERVER_ADDR} dev tun0 2>/dev/null || true

    echo "=== Client setup complete ==="
    echo "Run: sudo pipesix -c /etc/pipesix/pipesix.conf"
fi

echo ""
echo "After starting pipesix, verify with: ping6 ${GATEWAY}"
