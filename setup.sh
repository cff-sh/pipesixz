#!/bin/bash
# pipesix Full Setup Script
# Run on VPS (server) or client machine depending on mode.
# Usage: sudo ./setup.sh <server|client>

set -e

MODE="${1:-}"
if [ "$MODE" != "server" ] && [ "$MODE" != "client" ]; then
    echo "Usage: sudo $0 <server|client>"
    exit 1
fi

# -- Configuration (edit these!) --
# Route64 subnet and gateway
SUBNET="2a11:6c7:f27:86::/64"
GATEWAY="2a11:6c7:f27:86::1"

if [ "$MODE" = "server" ]; then
    TUN_ADDR="2a11:6c7:f27:86::2"
    CLIENT_ADDR="2a11:6c7:f27:86::3"
    WG_IFACE="wg0"
else
    SERVER_ADDR="2a11:6c7:f27:86::2"
    TUN_ADDR="2a11:6c7:f27:86::3"
fi

# -- 1. Enable IPv6 forwarding --
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/99-pipesix.conf

# -- 2. Create pipesix config --
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

    # Route: send client traffic via tun0
    ip -6 route del ${SUBNET} dev tun0 2>/dev/null || true
    ip -6 route add ${CLIENT_ADDR} dev tun0

    # NAT66 for client internet access
    ip6tables -t nat -A POSTROUTING -s ${CLIENT_ADDR} -o ${WG_IFACE} -j MASQUERADE

    # Make NAT persistent
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

    # Default route via VPS tunnel IP
    ip -6 route add default via ${SERVER_ADDR} dev tun0 2>/dev/null || true
    echo "ip -6 route add default via ${SERVER_ADDR} dev tun0" >> /etc/pipesix/route-up.sh

    echo "=== Client setup complete ==="
    echo "Run: sudo pipesix -c /etc/pipesix/pipesix.conf"
fi

# -- 3. Build and install pipesix (if not already) --
if [ ! -f /usr/local/sbin/pipesix ]; then
    make -C /home/allexander_linux/Desktop/pipesix install 2>/dev/null || \
        echo "WARNING: build not found, install pipesix binary manually"
fi

echo ""
echo "After starting pipesix, verify with: ping6 ${GATEWAY}"
