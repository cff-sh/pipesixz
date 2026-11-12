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
  replay window; return traffic is routed by static per-client inner prefixes
  (`client_route`), longest match first
- Client keepalives, echoed by the server for liveness
- Automatic client reconnect with DNS re-resolution and backoff when the
  peer goes silent (`peer_timeout`). A relay that shuts down tells each
  client so in its own session, so a restart on the server reconnects in
  seconds instead of waiting out the timeout
- Automatic session renegotiation: a client re-handshakes when the server asks
  it to or after reconnecting, so a restart on either side never leaves a
  stale session blocking the tunnel
- Server client allow-list (`allow_client`, up to 64 entries)
- SIGHUP reload of log level, timing settings and keys on both ends, so a
  credential can be rotated without restarting a process
- Runtime client provisioning: `--add-client` and `--remove-client` rewrite
  the configuration atomically and make a running server reload it
- Periodic statistics and on-demand dumps via SIGUSR1, plus Prometheus
  metrics over HTTP (`metrics_address`) or `--metrics`
- Path-MTU feedback: a packet larger than the relay's `tun_mtu` is answered
  with an ICMPv6 Packet Too Big instead of being dropped silently, so the
  client lowers its MTU and the retransmission fits

The wire protocol is version 5. It is not compatible with 1.x or 2.0 peers,
and there is no plaintext mode: a client cannot join without a valid
credential.

## Prerequisites

- VPS with a public IPv4
- Route64 or NetAssist tunnel account
- `make`, `gcc`, `libpthread`
- macOS client: Xcode command line tools (`xcode-select --install`)
- Windows client: MinGW-w64 and `wintun.dll` (see [Windows client](#windows-client))

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
sudo ./netassist-up.sh 184.107.84.10
```

Verification (either option):

```bash
ping -6 2a01:d0::1           # NetAssist DNS (the documented /64 gateway
                             # address does not answer ICMP on this broker)
ping -6 2a11:6c7:f27:86::1   # Route64 gateway
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
| Upstream | `ping -6 2a01:d0::1` | Replies via NetAssist (the documented gateway address loops and never answers) |
| Internet IPv6 | `ping -6 2001:4860:4860::8888` | Replies from Google |
| Public IPv6 | `curl -6 https://ifconfig.co` | Shows your /48 address |
| Browser | Open `https://test-ipv6.com` | 10/10 |

## Files

| File | Purpose |
|---|---|
| `build.sh` | Multi-platform build and packaging (Linux binaries, Windows exe) |
| `setup.sh` | Server/client setup (config + routes + NAT) |
| `pipesix.service` | systemd unit for auto-start |
| `wg-route64.sh` | Route64 WireGuard setup |
| `netassist-up.sh` | NetAssist SIT tunnel setup |

## Operations

```bash
sudo systemctl reload pipesix     # apply log_level/keepalive/peer_timeout/...
sudo kill -USR1 $(pidof pipesix)  # dump statistics now
sudo pipesix --rotate-all         # new client keys, printed and reloaded
```

`systemctl reload` sends SIGHUP. It applies `log_level`, `keepalive`,
`peer_timeout`, `session_timeout`, `stats_interval` and the credentials: the
`client`/`client_route` table on a server, the `secret` and `client_id` on a
client. Interface, endpoint, mode and allow-list changes require a restart.

### Control channel

While pipesix runs it also listens on a UNIX socket derived from the
absolute path of its configuration file, with mode `0600`. The socket
lives in `/run/pipesix/pipesix-<uid>-<hash>.sock`, or in `/tmp` when
`/run` is not writable, and is removed when the process exits. Windows
has no equivalent, so these commands are POSIX only.

```bash
sudo pipesix --status -c /etc/pipesix/pipesix.conf
sudo pipesix --kick client1 -c /etc/pipesix/pipesix.conf
```

`--status` prints the mode, configuration path, uptime, the tun and
listen addresses, one line per session (client id, peer, bytes in and
out, frames, idle time, return route) and the traffic counters. On a
client it reports the client id, remote endpoint and its own counters in
the same shape, so one command works on both ends.

`--kick <client-id>` drops that client's session and sends it a handshake
hint. A client that still holds the configured key reconnects at once. A
client whose key was removed from the configuration simply stops, so the
command also works as a disconnect.

The same replacement happens without the command: when a client
re-handshakes, the newest authenticated handshake for that client id
retires any session it left on an earlier address, so a restart or a NAT
rebind does not leave a dead route behind for `session_timeout` seconds.

```text
$ sudo pipesix --status
OK
mode: server
config: /etc/pipesix/pipesix.conf
uptime: 532s
tun: tun0 2a01:d0:a33f::1/64
listen: 0.0.0.0:8899
sessions: 1 of 64
  client1 from 203.0.113.5:41622 rx=1841 B tx=96 B frames=7 idle=2s route=2a01:d0:a33f::2/128
stats[server]: uptime=532s tx=7 pkts/336 B rx=9 pkts/672 B dropped=0 invalid=0 auth_fail=0 replayed=0 errors=0 last_rx=recent
```

Add `--json` to get the same report as one JSON object. The control
channel's `OK` line is stripped, so stdout is valid JSON on its own and can
be piped straight into an agent or `jq`:

```bash
sudo pipesix --status --json -c /etc/pipesix/pipesix.conf | jq .sessions.active
```

The server report carries `mode`, `config`, `uptime_seconds`, `tun`,
`listen`, a `sessions` object (active count, capacity and one entry per
client with `client_id`, `peer`, `rx_bytes`, `tx_bytes`, `frames`,
`idle_seconds` and `route`) and `stats`. A client reports `client_id`,
`remote`, `session` and the same `stats` object. `route` is `null` when the
client has no `client_route`, and `--json` is only valid with `--status`.

### Prometheus metrics

Set `metrics_address` (and optionally `metrics_port`, default 9100) to serve
`GET /metrics` over HTTP, in the Prometheus text format:

```ini
metrics_address = 127.0.0.1
metrics_port    = 9100
```

The endpoint is off by default and, unlike the control socket, needs a port of
its own, so bind it to localhost or a private interface: it has no
authentication and exposes client ids and counters.

```bash
curl -s http://127.0.0.1:9100/metrics | grep pipesix_
```

```text
pipesix_uptime_seconds{mode="server"} 532
pipesix_tx_packets_total{mode="server"} 7
pipesix_rx_bytes_total{mode="server"} 672
pipesix_last_rx_timestamp_seconds{mode="server"} 1762600000
pipesix_sessions_active 1
pipesix_sessions_capacity 64
pipesix_session_rx_bytes{client="mac1"} 35651
```

Both roles export the shared counters (`tx`/`rx` packets and bytes, `dropped`,
`invalid`, `auth_failures`, `replayed`, `errors`, `uptime_seconds`,
`last_rx_timestamp_seconds`) with a `mode` label. A server adds
`pipesix_sessions_active`, `pipesix_sessions_capacity` and per-client
`pipesix_session_rx_bytes`, `_tx_bytes`, `_frames` and `_idle_seconds`; a client
adds `pipesix_session_open`.

`pipesix --metrics -c /etc/pipesix/pipesix.conf` prints the same body over the
control channel, without a listening port:

```bash
sudo pipesix --metrics -c /etc/pipesix/pipesix.conf | grep pipesix_sessions
```

Changing `metrics_address` or `metrics_port` needs a restart, like
`bind_address`; the rest of the settings keep reloading over SIGHUP.

### Provisioning clients

```bash
sudo pipesix --add-client bob --route 2a01:d0:a33f::3/128 \
    -c /etc/pipesix/pipesix.conf
sudo pipesix --remove-client bob -c /etc/pipesix/pipesix.conf
```

`--add-client` generates a key, appends the `client` and `client_route`
lines, re-parses the whole file and only then replaces it, so a rejected
route, a duplicate id or a duplicate prefix leaves the file untouched. It
prints the key once, for the client's `secret` line. A running server is
asked to reload over the control channel, so the new client can connect
immediately; without a running instance the change applies when it starts.
`--remove-client` drops both lines and the running server disconnects the
session on the same reload; removing the last client is refused, because a
server needs at least one credential.

Without `--route` the client is admitted but only receives return traffic
while it is the single connected session.

### Rotating a key

On the server, a changed `client` line only disturbs the client whose key
changed: its session is dropped, it is asked to handshake again, and every
other client keeps its tunnel. On the client, a changed `secret` makes it
re-handshake on the existing socket:

```bash
NEWKEY=$(pipesix --genkey)
# Server: rotate alice's credential
sudo sed -i "s|^client = alice:.*|client = alice: ${NEWKEY}|" \
    /etc/pipesix/pipesix.conf
sudo systemctl reload pipesix
# Then on alice's machine: adopt the same key
sudo sed -i "s|^secret = .*|secret = ${NEWKEY}|" /etc/pipesix/pipesix.conf
sudo systemctl reload pipesix
```

Doing the server first means the client's next handshake succeeds immediately;
in the other order its attempts are rejected and it retries with backoff, so
the tunnel closes until both ends agree. Until the client has the new key all
of its handshakes fail, which is what makes the same procedure work as
revocation. Removing a `client` line and reloading disconnects that client
immediately. Changing only a `client_route` updates routing for the live
session without a re-handshake.

To rotate every client at once, `--rotate-all` generates a key per `client`
line, writes them into the file — comments, ordering and spacing are left
alone, and the rewritten file is parsed and checked before it replaces the
original — then prints them:

```bash
sudo pipesix --rotate-all -c /etc/pipesix/pipesix.conf
```

On Linux the command then sends SIGHUP to every running pipesix whose command
line names that configuration file, so the server adopts the keys immediately;
an instance started without `-c` counts when the default path is the one being
rotated, and a client or a second server on another file is left alone. Where
`/proc` is not available it prints a reminder to reload by hand instead.

The keys still have to reach the clients; nothing pushes them there. A client
whose key was not updated cannot handshake again — which is the point when you
rotate because a key leaked.

On a server, `SIGUSR1` also lists every connected client with its id, peer
address, frame count and idle time, so you can see who is actually online
without restarting the relay:

```text
[INFO] Sessions: 2 connected (of 64 slots)
[INFO]   client 'alice' from 203.0.113.5:41622: 1841 frame(s), idle 2s
[INFO]   client 'bob' from [2001:db8::7]:51820: 97 frame(s), idle 41s
```

### MTU and Packet Too Big

`tun_mtu` is the largest packet the relay's TUN device can carry upstream.
When a client sends something larger, the relay does not drop it silently: it
returns an ICMPv6 Packet Too Big (RFC 4443) that quotes the packet and carries
the relay's MTU, so the client's kernel lowers the path MTU for that
destination and resends at a size that fits.

The reply is sent inside the client's own session and logged once per session:

```text
[WARN] Client 'mac1' sent a 1500-byte packet but tun_mtu is 1400; returned
ICMPv6 Packet Too Big so its kernel lowers the path MTU
```

That is why a client with `tun_mtu = 1500` in front of a 1400-byte relay path
degrades (`dropped` grows, the transfer slows down) instead of black-holing.
Setting the client's `tun_mtu` to the path MTU still avoids the extra round
trip; the feedback only guarantees the tunnel recovers on its own.

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

4. On the server, give each client the inner prefix it owns, so return
   traffic can be routed back to it:

   ```
   client = alice: <alice's key>
   client_route = alice 2001:db8:1::/64
   ```

   `client_route` must follow its `client` line. A bare address means a
   `/128` host route, and the most specific prefix wins, so a host route can
   be carved out of a client's broader prefix. Two clients may not claim the
   same prefix. Without a route a client only receives return traffic while
   it is the single connected client.

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
- A session is bound to the client's current UDP endpoint. A valid
  re-handshake for a client id retires the session that id held on another
  endpoint, so a restarted or re-homed client cannot be shadowed by its
  own stale entry.
- Unknown client ids and bad handshake MACs are logged and counted as
  authentication failures.
- Handshake-required hints are rate limited, so the server cannot be used as
  a UDP amplifier.

## macOS client

The client also runs on macOS through the kernel's `utun` driver; server mode
stays on the VPS. Build it on the Mac with the command line tools:

```bash
xcode-select --install     # once, if clang is not installed yet
git clone <your-repo> && cd pipesix
make
sudo make install          # optional; ./pipesix works without it
```

Creating a `utun` interface needs root, so run pipesix with `sudo`. The
configuration is the same as on Linux; `tun_name` is ignored because the
kernel hands out the next free `utunN`. Copy the tunnel prefix from the
server's `tun_address` / `route-up.sh` rather than from
`pipesix.conf.example`: `tun_address` must sit inside the prefix the relay
routes to its `tun0`, or replies are dropped on the VPS and the client sees
silent packet loss.

```ini
mode = client
client_id = mac1
remote_address = 184.107.84.10
remote_port = 8899
tun_address = 2a01:d0:a33f::3
tun_prefixlen = 64
tun_mtu = 1400
secret = <the key the server printed for mac1>
log_level = info
```

On the VPS, create the matching client and give it its own inner address:

```bash
sudo pipesix --add-client mac1 --route 2a01:d0:a33f::3/128 \
    -c /etc/pipesix/pipesix.conf
```

Start the client and note the interface name in the log:

```bash
sudo pipesix -c /etc/pipesix/pipesix.conf
# [INFO] TUN device 'utun4' created (fd=5)
```

In a second terminal, send the default route through that interface, using the
name from the log:

```bash
sudo route add -inet6 default -interface utun4
```

macOS may keep preferring the router-advertised default on `en0`. Check with
`netstat -rn -f inet6 | head`; if traffic still leaves through `en0`, replace
the default:

```bash
sudo route change -inet6 default -interface utun4
```

After stopping pipesix, remove the route so normal connectivity returns:

```bash
sudo route delete -inet6 default -interface utun4
```

Verify with `ping6 2001:4860:4860::8888` and `curl -6 https://ifconfig.co`.
Signals behave as on Linux: `sudo killall -HUP pipesix` reloads the
configuration (for example after rotating `secret`) and
`sudo killall -USR1 pipesix` dumps the statistics. `sudo pipesix --status
-c <config>` works too; on macOS the control socket lives in `/tmp`, since
there is no `/run`.

`setup.sh`, `pipesix.service` and the `ip`/`route` scripts target Linux, so on
macOS the configuration and route are set by hand as shown above.

## Windows client

The client also runs on Windows, through Wintun — the Layer 3 driver the
WireGuard project publishes. Server mode stays on the VPS.

Build with MinGW-w64, either cross-compiling from Linux or inside MSYS2:

```bash
make windows          # produces pipesix.exe
```

Install `wintun.dll` from <https://www.wintun.net/> next to `pipesix.exe`. The
DLL is loaded at run time and never linked, so building needs no extra SDK and
the binary still starts (and says what is missing) when it is absent.

A Windows client uses the same configuration file as everywhere else; only the
device name differs, because it names the Wintun adapter rather than a `tunX`:

```ini
mode = client
client_id = client1
remote_address = 184.107.84.10
remote_port = 8899
tun_name = pipesix
tun_address = 2a01:d0:a33f::2
tun_prefixlen = 64
tun_mtu = 1400
secret = <the key setup.sh printed>
log_level = info
```

Run it from a console started as Administrator: pipesix creates (or reuses) the
`pipesix` adapter and configures its IPv6 address and MTU. The default
configuration path on Windows is `pipesix.conf` in the current directory, or
pass `-c`.

Add the default route yourself once the tunnel is up. Windows otherwise keeps
using its own router-advertised IPv6 default, so traffic would leave through
the local ISP instead of the tunnel:

```powershell
netsh interface ipv6 add route ::/0 "pipesix" 2a01:d0:a33f::1
```

Windows has no signals, so the two runtime controls are command line options
that reach the running instance through a per-configuration named event:

```powershell
pipesix.exe --reload -c pipesix.conf    # instead of SIGHUP
pipesix.exe --stats  -c pipesix.conf    # instead of SIGUSR1
```

Stop the tunnel with Ctrl+C. `setup.sh`, `pipesix.service` and the `ip`/`route`
scripts are POSIX-only, but the configuration format and the wire protocol are
shared, so a Windows client talks to an unchanged Linux server.

## Release builds

`build.sh` produces self-contained artifacts for the platforms pipesix runs
on. It stages each target under `dist/`, writes `SHA256SUMS`, and skips a
target whose toolchain is not installed (so `--all` works on a machine with
only the native compiler):

| Target | Toolchain | Artifacts |
|---|---|---|
| `linux-amd64` | `gcc` | `pipesix-<ver>-linux-amd64.tar.gz`, `pipesix_<ver>_amd64.deb` |
| `linux-arm64` | `aarch64-linux-gnu-gcc` | `pipesix-<ver>-linux-arm64.tar.gz`, `pipesix_<ver>_arm64.deb` |
| `windows-amd64` | `x86_64-w64-mingw32-gcc` | `pipesix-<ver>-windows-amd64.zip` (`pipesix.exe`) |

```bash
./build.sh                          # host platform
./build.sh --all                    # every target whose toolchain exists
./build.sh --target windows-amd64 --version 2.2.0
make dist                           # same as ./build.sh --all
```

The tarball carries the binary, example configuration, systemd unit, setup
scripts and documentation. The `.deb` installs the binary to
`/usr/local/sbin`, the example config to `/etc/pipesix` and the unit to
`/lib/systemd/system`. The Windows zip carries `pipesix.exe`; download
`wintun.dll` separately from <https://www.wintun.net/> and place it next to
the executable.

`.github/workflows/ci.yml` builds and tests every push and pull request with
gcc, clang and the address/UB sanitizers, cross-builds all three targets,
and on a `v*` tag publishes the archives and checksums as a release.

## Testing

```bash
make check
```

Runs the unit tests for cryptography (against RFC known-answer vectors),
the frame codec, the replay window and the configuration parser. No root
privileges are required.
