#!/bin/bash
# pipesix Full Setup Script
# Usage:
#   Server: sudo ./setup.sh server [--backend route64|netassist]
#   Client: sudo ./setup.sh client <vps_public_ip> [--backend route64|netassist]

set -e

MODE="${1:-}"

if [ "$MODE" = "server" ]; then
    VPS_PUBLIC_IP=""
    shift 1
elif [ "$MODE" = "client" ]; then
    VPS_PUBLIC_IP="${2:-}"
    if [ -z "$VPS_PUBLIC_IP" ]; then
        echo "Usage: sudo $0 client <vps_public_ip> [--backend ...]"
        exit 1
    fi
    shift 2
else
    echo "Usage: sudo $0 <server|client> [<vps_public_ip>] [--backend route64|netassist]"
    exit 1
fi

BACKEND="route64"
if [ "${1:-}" = "--backend" ]; then
    BACKEND="${2:-route64}"
fi

if [ "$BACKEND" != "route64" ] && [ "$BACKEND" != "netassist" ]; then
    echo "Backend must be 'route64' or 'netassist'"
    exit 1
fi

# ------ CONFIGURATION (edit these for your subnet) ------

if [ "$BACKEND" = "route64" ]; then
    GATEWAY="2a11:6c7:f27:86::1"
    SUBNET="2a11:6c7:f27:86::/64"
    if [ "$MODE" = "server" ]; then
        TUN_ADDR="2a11:6c7:f27:86::2"
        CLIENT_ADDR="2a11:6c7:f27:86::3"
        UPSTREAM_IFACE="wg0"
    else
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
        TUN_ADDR="2a01:d0:a33f::2"
    fi
fi

# -- 1. Enable IPv6 forwarding (only matters on server) --
if [ "$MODE" = "server" ]; then
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/99-pipesix.conf
fi

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

    ip -6 route del ${SUBNET} dev tun0 2>/dev/null || true
    ip -6 route add ${CLIENT_ADDR}/128 dev tun0

    ip6tables -t nat -A POSTROUTING -s ${CLIENT_ADDR}/128 -o ${UPSTREAM_IFACE} -j MASQUERADE 2>/dev/null || true
    mkdir -p /etc/iptables
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true

    echo "=== Server setup complete ==="
    echo "Run: sudo pipesix -c /etc/pipesix/pipesix.conf"

else
    cat > /etc/pipesix/pipesix.conf <<EOF
mode = client
remote_address = ${VPS_PUBLIC_IP}
remote_port = 8899
tun_name = tun0
tun_address = ${TUN_ADDR}
tun_prefixlen = 64
tun_mtu = 1500
log_level = info
EOF

    # Write route-up script (run AFTER starting pipesix)
    cat > /etc/pipesix/route-up.sh <<EOF
#!/bin/bash
ip -6 route add default via ${TUN_ADDR} dev tun0 2>/dev/null || true
EOF
    chmod +x /etc/pipesix/route-up.sh

    echo "=== Client setup complete ==="
    echo ""
    echo "1. Start pipesix:"
    echo "   sudo pipesix -c /etc/pipesix/pipesix.conf"
    echo ""
    echo "2. Add default route (in another terminal):"
    echo "   sudo /etc/pipesix/route-up.sh"
    echo ""
    echo "Or wait for the tunnel to be up, then run step 2."
fi

echo ""
echo "Verify with: ping6 ${GATEWAY}"
