# pipesix — IPv6 over UDP Tunnel

Connect your machine to a Route64 IPv6 subnet through a VPS relay.

## Architecture

```
Client (::3) → pipesix → UDP → VPS pipesix → tun0 → wg0 (WireGuard) → Route64 → Internet
```

## Prerequisites

- A VPS with a public IP
- A [Route64](https://route64.org) tunnel
- `make`, `gcc`, `pthreads` on both machines

## 1. Build

```bash
git clone <your-repo> && cd pipesix
make
sudo make install
```

Installs to `/usr/local/sbin/pipesix`.

## 2. VPS Setup (Server)

### WireGuard → Route64

Edit and run:

```bash
sudo ./wg-route64.sh
```

Before running, replace placeholders in the script with your Route64 keys:

| Field | Your Value |
|---|---|
| `Address` | `2a11:6c7:f27:86::2/64` |
| `Endpoint` | `45.154.96.16:443` |
| `PrivateKey` | *(from Route64 portal)* |
| `PublicKey` | *(from Route64 portal)* |

### Configure & Run pipesix (Server)

```bash
sudo ./setup.sh server
sudo pipesix -c /etc/pipesix/pipesix.conf
```

This enables IPv6 forwarding, adds routes, sets up NAT66, and creates the config.

### Enable on Boot (Server)

```bash
sudo cp pipesix.service /etc/systemd/system/
sudo systemctl enable --now pipesix
```

## 3. Client Setup

### Configure & Run

```bash
sudo ./setup.sh client
sudo pipesix -c /etc/pipesix/pipesix.conf
```

### Add Default Route

The setup script adds it, but if you need to reapply:

```bash
sudo ip -6 route add default via 2a11:6c7:f27:86::2 dev tun0
```

### Enable on Boot (Client)

```bash
sudo cp pipesix.service /etc/systemd/system/
sudo systemctl enable --now pipesix
```

## 4. Verify

| Test | Command | Expected |
|---|---|---|
| Tunnel to VPS | `ping6 2a11:6c7:f27:86::2` | Replies from VPS |
| Route64 gateway | `ping6 2a11:6c7:f27:86::1` | Replies from gateway |
| Internet IPv6 | `ping6 2001:4860:4860::8888` | Replies from Google |
| Public IPv6 | `curl -6 https://ifconfig.co` | Shows `2a11:6c7:f27:86::2` |
| Browser | Open `https://test-ipv6.com` | 10/10 IPv6 ready |

## Files

| File | Purpose |
|---|---|
| `setup.sh` | One-command server/client setup (config + routes + NAT + sysctl) |
| `pipesix.service` | systemd unit for auto-start on boot |
| `wg-route64.sh` | WireGuard config template for Route64 |
| `pipesix.conf.example` | Example pipesix config |
