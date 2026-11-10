#!/bin/bash
# WireGuard Route64 setup for VPS
# Edit the keys/endpoint below with your Route64 details.

set -e

cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 2a11:6c7:f27:86::2/64
PrivateKey = YHPEcHMPczxdQpsSB/XLYZFnfEHwnEtw7NvJTAFyNFM=
MTU = 1420

[Peer]
PublicKey = il88Szkt1SxGxGOGpgWwvT/30R/8lz2eQ/D1clddEBg=
Endpoint = 184.107.84.10:443
AllowedIPs = 2a11:6c7:f27:86::/64
PersistentKeepalive = 25
EOF

chmod 600 /etc/wireguard/wg0.conf

wg-quick up wg0

# Make persistent
systemctl enable wg-quick@wg0
