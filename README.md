# pipesix — IPv6 over UDP Tunnel

Connect your machine to the IPv6 internet through a VPS relay. Supports **Route64** (WireGuard) and **NetAssist** (SIT tunnel) as upstream providers.

## Architecture

```
Client (::2) → pipesix → UDP → VPS pipesix → tun0 → [wg0|netassist] → IPv6 internet
```

## Features

- ChaCha20-Poly1305 authenticated encryption of every frame (RFC 8439), with
  an anti-replay window
- Multiple concurrent clients per server, each with its own session and
  replay window; return traffic is routed by learning each client's inner
  IPv6 addresses
- Client keepalives, echoed by the server for liveness
- Automatic client reconnect with DNS re-resolution and backoff when the
  peer goes silent (`peer_timeout`)
- Session reset frames so restarts on either side do not stall the tunnel
- Server client allow-list (`allow_client`, up to 64 entries)
- SIGHUP reload of log level and timing settings without dropping the tunnel
- Periodic statistics and on-demand dumps via SIGUSR1

Frames are encrypted and authenticated when `secret` is set on both sides.
Without a secret the tunnel carries plaintext and should only be used on a
network you already trust. The wire protocol is version 4, which is not
compatible with 1.x peers.

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
sudo ./setup.sh client <vps_public_ipv4>
sudo pipesix -c /etc/pipesix/pipesix.conf
```

In another terminal, add the default route once the tunnel is up:

```bash
sudo /etc/pipesix/route-up.sh
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

## Operations

```bash
sudo systemctl reload pipesix     # apply log_level/keepalive/peer_timeout/...
sudo kill -USR1 $(pidof pipesix)  # dump statistics now
```

`systemctl reload` sends SIGHUP. Interface, endpoint, secret, mode and
allow-list changes require a restart.

## Security

- Generate a shared secret with `pipesix --genkey` and put the same value in
  the `secret` key on both the server and every client.
- A server without a `secret` logs a warning: frames are plaintext and any
  host that can reach the UDP port can inject traffic.
- The server accepts up to 64 concurrent clients, each tracked by endpoint
  and protected by its own replay window. Sessions idle for longer than
  `session_timeout` are dropped, and the least recently used session is
  evicted when the table is full.

## Testing

```bash
make check
```

Runs the unit tests for cryptography (against RFC known-answer vectors),
the frame codec, the replay window and the configuration parser. No root
privileges are required.
