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
    VERIFY="2a11:6c7:f27:86::1"
    SUBNET="2a11:6c7:f27:86::/64"
    TUN_MTU=1500
    if [ "$MODE" = "server" ]; then
        TUN_ADDR="2a11:6c7:f27:86::2"
        CLIENT_ADDR="2a11:6c7:f27:86::3"
        UPSTREAM_IFACE="wg0"
    else
        TUN_ADDR="2a11:6c7:f27:86::3"
        PEER_ADDR="2a11:6c7:f27:86::2"
    fi
else
    # NetAssist. The gateway address from the panel (2a01:d0:ffff:233f::1)
    # does not answer ICMP: packets to it loop back into our own tunnel, so a
    # failed ping there proves nothing. Verify against the broker's DNS.
    VERIFY="2a01:d0::1"
    SUBNET="2a01:d0:a33f::/48"
    # 1480-byte SIT path minus 68 bytes of outer IPv4/UDP and pipesix headers.
    TUN_MTU=1400
    if [ "$MODE" = "server" ]; then
        TUN_ADDR="2a01:d0:a33f::1"
        CLIENT_ADDR="2a01:d0:a33f::2"
        UPSTREAM_IFACE="netassist"
    else
        TUN_ADDR="2a01:d0:a33f::2"
        PEER_ADDR="2a01:d0:a33f::1"
    fi
fi

# -- 1. Enable IPv6 forwarding (only matters on server) --
if [ "$MODE" = "server" ]; then
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    # Idempotent: re-running must not stack duplicate lines in the file.
    if ! grep -qx 'net.ipv6.conf.all.forwarding = 1' \
            /etc/sysctl.d/99-pipesix.conf 2>/dev/null; then
        echo "net.ipv6.conf.all.forwarding = 1" \
            >> /etc/sysctl.d/99-pipesix.conf
    fi
fi

# -- 2. Create pipesix config --
mkdir -p /etc/pipesix

if [ "$MODE" = "server" ]; then
    # Each client gets its own credential; nothing is shared.
    CLIENT_ID="${PIPESIX_CLIENT_ID:-client1}"
    SECRET="$(openssl rand -hex 32 2>/dev/null || \
              head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"

    cat > /etc/pipesix/pipesix.conf <<EOF
mode = server
bind_address = 0.0.0.0
bind_port = 8899
tun_name = tun0
tun_address = ${TUN_ADDR}
tun_prefixlen = 64
tun_mtu = ${TUN_MTU}
client = ${CLIENT_ID}: ${SECRET}
client_route = ${CLIENT_ID} ${CLIENT_ADDR}/128
log_level = info
EOF

    # tun0 does not exist until pipesix starts, so anything that needs the
    # device is done by route-up.sh, which the service runs after startup.
    cat > /etc/pipesix/route-up.sh <<EOF
#!/bin/bash
# Runs after pipesix has created tun0.
EOF

    if [ "$BACKEND" = "netassist" ]; then
        # NetAssist routes the whole /48 to this host, so client addresses
        # are globally reachable: no NAT, and the block belongs on tun0.
        cat >> /etc/pipesix/route-up.sh <<EOF
ip -6 route replace ${SUBNET} dev tun0
EOF
    else
        cat >> /etc/pipesix/route-up.sh <<EOF
# Route64: client traffic is masqueraded onto the WireGuard uplink.
EOF
        ip6tables -t nat -A POSTROUTING -s ${CLIENT_ADDR}/128 -o ${UPSTREAM_IFACE} -j MASQUERADE 2>/dev/null || true
        mkdir -p /etc/iptables
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    fi

    chmod +x /etc/pipesix/route-up.sh

    echo "=== Server setup complete ==="
    echo ""
    echo "Client credentials (add these to that client's config):"
    echo "  client_id = ${CLIENT_ID}"
    echo "  secret = ${SECRET}"
    echo ""
    echo "Add another client by appending two lines to /etc/pipesix/pipesix.conf:"
    echo "  client = <id>: $(pipesix --genkey 2>/dev/null || echo '<pipesix --genkey>')"
    echo "  client_route = <id> <inner ipv6 prefix, e.g. /128 host route>"
    echo ""
    echo "Run: sudo pipesix -c /etc/pipesix/pipesix.conf"

else
    CLIENT_ID="${PIPESIX_CLIENT_ID:-client1}"

    if [ -n "${PIPESIX_SECRET:-}" ]; then
        SECRET_LINE="secret = ${PIPESIX_SECRET}"
    else
        SECRET_LINE="# secret = <the key printed by setup.sh on the server>"
    fi

    cat > /etc/pipesix/pipesix.conf <<EOF
mode = client
client_id = ${CLIENT_ID}
remote_address = ${VPS_PUBLIC_IP}
remote_port = 8899
tun_name = tun0
tun_address = ${TUN_ADDR}
tun_prefixlen = 64
tun_mtu = ${TUN_MTU}
${SECRET_LINE}
log_level = info
EOF

    # Write route-up script (run AFTER starting pipesix)
    cat > /etc/pipesix/route-up.sh <<EOF
#!/bin/bash
# Default route through the tunnel: the gateway is the SERVER's tun address,
# not this client's own address.
ip -6 route replace default via ${PEER_ADDR} dev tun0
EOF
    chmod +x /etc/pipesix/route-up.sh

    echo "=== Client setup complete ==="
    echo ""
    if [ -z "${PIPESIX_SECRET:-}" ]; then
        echo "No credential configured yet: the client cannot connect."
        echo "Re-run as:"
        echo "  sudo PIPESIX_CLIENT_ID=${CLIENT_ID} PIPESIX_SECRET=<key from the server> \\"
        echo "       ./setup.sh client ${VPS_PUBLIC_IP}"
        echo "or fill in the 'client_id' and 'secret' lines by hand."
        echo ""
    fi
    echo "1. Start pipesix:"
    echo "   sudo pipesix -c /etc/pipesix/pipesix.conf"
    echo ""
    echo "2. Add default route (in another terminal):"
    echo "   sudo /etc/pipesix/route-up.sh"
    echo ""
    echo "Or wait for the tunnel to be up, then run step 2."
fi

echo ""
echo "Verify with: ping -6 ${VERIFY}"
