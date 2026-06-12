# pipesix — IPv6 over UDP Tunnel

Connect your machine to the IPv6 internet through a VPS relay. Supports **Route64** (WireGuard) and **NetAssist** (SIT tunnel) as upstream providers.

## Architecture

```
Client (::2) → pipesix → UDP → VPS pipesix → tun0 → [wg0|netassist] → IPv6 internet
```

## Prerequisites

- VPS with a public IPv4
- Route64 or NetAssist tunnel account
- `make`, `gcc`, `libpthread`

## 1. Build & Install

```bash
git clone <your-repo> && cd pipesix
make
sudo make install
```

## 2. Upstream Setup (on VPS)

Choose one:

### Option A — Route64 (WireGuard)

Edit `wg-route64.sh` with your Route64 keys, then:

```bash
sudo ./wg-route64.sh
```

### Option B — NetAssist (SIT tunnel)

```bash
sudo ./netassist-up.sh <your_vps_public_ipv4>
```

Example:

```bash
sudo ./netassist-up.sh 82.39.86.20
```

Verification (either option):

```bash
ping6 2a01:d0:ffff:233f::1   # NetAssist gateway
ping6 2a11:6c7:f27:86::1     # Route64 gateway
```

## 3. Setup pipesix

### VPS (Server)

```bash
sudo ./setup.sh server --backend route64   # if using Route64
sudo ./setup.sh server --backend netassist # if using NetAssist
sudo pipesix -c /etc/pipesix/pipesix.conf
```

### Client Machine

```bash
sudo ./setup.sh client
sudo pipesix -c /etc/pipesix/pipesix.conf
```

## 4. Auto-Start on Boot

```bash
sudo cp pipesix.service /etc/systemd/system/
sudo systemctl enable --now pipesix
```

## 5. Verify

| Test | Command | Expected |
|---|---|---|
| Tunnel to VPS | `ping6 2a01:d0:a33f::1` | Replies from VPS |
| Upstream gateway | `ping6 2a01:d0:ffff:233f::1` | Replies from NetAssist |
| Internet IPv6 | `ping6 2001:4860:4860::8888` | Replies from Google |
| Public IPv6 | `curl -6 https://ifconfig.co` | Shows your /48 address |
| Browser | Open `https://test-ipv6.com` | 10/10 |

## Files

| File | Purpose |
|---|---|
| `setup.sh` | Server/client setup (config + routes + NAT) |
| `pipesix.service` | systemd unit for auto-start |
| `wg-route64.sh` | Route64 WireGuard setup |
| `netassist-up.sh` | NetAssist SIT tunnel setup |
