# pipesix — IPv6 over UDP Tunnel

Connect your machine to the IPv6 internet through a VPS relay. Supports **Route64** (WireGuard) and **NetAssist** (SIT tunnel) as upstream providers.

## Architecture

```
Client (::2) → pipesix → UDP → VPS pipesix → tun0 → [wg0|netassist] → IPv6 internet
```

## Features

- Per-client pre-shared keys with a handshake that derives separate
  client-to-server and server-to-client session keys (HKDF-SHA256), so
  nonces, replay windows and sequence counters are isolated per peer
- ChaCha20-Poly1305 authenticated encryption of every frame (RFC 8439), with
  an anti-replay window
- Multiple concurrent clients per server, each with its own session and
  replay window; return traffic is routed by learning each client's inner
  IPv6 addresses
- Client keepalives, echoed by the server for liveness
- Automatic client reconnect with DNS re-resolution and backoff when the
  peer goes silent (`peer_timeout`)
- Automatic session renegotiation: a client re-handshakes when the server asks
  it to or after reconnecting, so a restart on either side never leaves a
  stale session blocking the tunnel
- Server client allow-list (`allow_client`, up to 64 entries)
- SIGHUP reload of log level and timing settings without dropping the tunnel
- Periodic statistics and on-demand dumps via SIGUSR1

The wire protocol is version 5. It is not compatible with 1.x or 2.0 peers,
and there is no plaintext mode: a client cannot join without a valid
credential.

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

`systemctl reload` sends SIGHUP. Interface, endpoint, credentials, mode and
allow-list changes require a restart.

On a server, `SIGUSR1` also lists every connected client with its id, peer
address, frame count and idle time, so you can see who is actually online
without restarting the relay:

```text
[INFO] Sessions: 2 connected (of 64 slots)
[INFO]   client 'alice' from 203.0.113.5:41622: 1841 frame(s), idle 2s
[INFO]   client 'bob' from [2001:db8::7]:51820: 97 frame(s), idle 41s
```

## Security

Every client has its own pre-shared key. No key is shared between peers, so
compromising one client does not expose another client's traffic.

1. Generate a key per client: `pipesix --genkey`
2. On the server, add one line per client:

   ```
   client = alice: <alice's key>
   client = bob:   <bob's key>
   ```

3. On each client, set its identity and key:

   ```
   client_id = alice
   secret    = <alice's key>
   ```

On first contact the client sends its id and a random nonce, authenticated
with its key. The server looks the id up, verifies the MAC, and replies with
its own nonce and a MAC. Both sides then derive two independent session keys:

```
client-to-server = HKDF-SHA256(psk, salt = cnonce || snonce,
                               info = "pipesix-v5-client-to-server")
server-to-client = HKDF-SHA256(psk, salt = cnonce || snonce,
                               info = "pipesix-v5-server-to-client")
```

Because the keys are per session and per direction, two clients can never
reuse a keystream even if they were mistakenly given the same key, and a
restarted session never repeats a nonce. Handshake frames are the only
plaintext frames; they carry an HMAC and exist purely to bootstrap the keys.

Server side notes:

- A server refuses to start without at least one `client` entry.
- Up to 64 clients are tracked at once, each with its own keys and replay
  window. Sessions idle for longer than `session_timeout` are dropped, and
  the least recently used session is evicted when the table is full.
- Unknown client ids and bad handshake MACs are logged and counted as
  authentication failures.
- Handshake-required hints are rate limited, so the server cannot be used as
  a UDP amplifier.

## Testing

```bash
make check
```

Runs the unit tests for cryptography (against RFC known-answer vectors),
the frame codec, the replay window and the configuration parser. No root
privileges are required.
