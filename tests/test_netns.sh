#!/usr/bin/env bash
#
# test_netns.sh - integration tests with a real TUN device and network
# namespaces.
#
# This test needs root (CAP_NET_ADMIN) and Linux iproute2. It is kept out
# of `make check` because unit tests must run without privileges; CI runs
# it with sudo. The relay and client live in separate namespaces connected
# by a veth, so the outer UDP path is real while their inner IPv6 routes
# stay isolated from the host.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$ROOT/pipesix}
RELAY_NS=psx-relay-$$
CLIENT_NS=psx-client-$$
RELAY_VETH=psxr$$
CLIENT_VETH=psxc$$
WORK=
SERVER_PID=
SERVER_B_PID=
CLIENT_PID=

log() {
    printf '\n== %s\n' "$*"
}

die() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    local rc=$?

    trap - EXIT INT TERM
    if [ "$rc" -ne 0 ] && [ -n "$WORK" ]; then
        printf '\n--- integration logs (%s) ---\n' "$WORK" >&2
        for f in "$WORK"/*.log; do
            [ -f "$f" ] || continue
            printf '\n--- %s ---\n' "$f" >&2
            tail -n 80 "$f" >&2 || true
        done
    fi

    [ -z "$CLIENT_PID" ] || kill "$CLIENT_PID" 2>/dev/null || true
    [ -z "$SERVER_B_PID" ] || kill "$SERVER_B_PID" 2>/dev/null || true
    [ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null || true
    [ -z "$CLIENT_PID" ] || wait "$CLIENT_PID" 2>/dev/null || true
    [ -z "$SERVER_B_PID" ] || wait "$SERVER_B_PID" 2>/dev/null || true
    [ -z "$SERVER_PID" ] || wait "$SERVER_PID" 2>/dev/null || true

    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$RELAY_NS" 2>/dev/null || true
    [ -z "$WORK" ] || rm -rf "$WORK"

    exit "$rc"
}
trap cleanup EXIT INT TERM

[ "$(id -u)" -eq 0 ] || die "run this test as root (make check-netns under sudo)"
[ -x "$BIN" ] || die "missing $BIN; build it first"
command -v ip >/dev/null 2>&1 || die "iproute2 is required"
command -v ping >/dev/null 2>&1 || die "iputils-ping is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
[ -c /dev/net/tun ] || die "/dev/net/tun is unavailable"

WORK=$(mktemp -d /tmp/pipesix-netns.XXXXXX)
chmod 700 "$WORK"

SERVER_CONF=$WORK/server-a.conf
SERVER_B_CONF=$WORK/server-b.conf
CLIENT_CONF=$WORK/client.conf
SERVER_LOG=$WORK/server-a.log
SERVER_B_LOG=$WORK/server-b.log
CLIENT_LOG=$WORK/client.log
ALICE_KEY=$WORK/alice.key

status_json() {
    "$BIN" --status --json -c "$1" 2>/dev/null
}

json_number() {
    python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]][sys.argv[2]])' "$1" "$2"
}

active_sessions() {
    status_json "$1" | json_number sessions active
}

wait_for_active() {
    local conf=$1 wanted=$2 timeout=${3:-30}
    local i value

    for i in $(seq 1 "$timeout"); do
        if value=$(active_sessions "$conf" 2>/dev/null); then
            [ "$value" = "$wanted" ] && return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_control() {
    local conf=$1 timeout=${2:-20}
    local i

    for i in $(seq 1 "$timeout"); do
        "$BIN" --status -c "$conf" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

wait_for_link() {
    local ns=$1 dev=$2 timeout=${3:-15}
    local i

    for i in $(seq 1 "$timeout"); do
        ip -n "$ns" link show "$dev" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

log "setting up namespaces"
ip netns add "$RELAY_NS"
ip netns add "$CLIENT_NS"
ip link add "$RELAY_VETH" type veth peer name "$CLIENT_VETH"
ip link set "$RELAY_VETH" netns "$RELAY_NS"
ip link set "$CLIENT_VETH" netns "$CLIENT_NS"

ip -n "$RELAY_NS" link set lo up
ip -n "$CLIENT_NS" link set lo up
ip -n "$RELAY_NS" addr add 10.200.0.1/24 dev "$RELAY_VETH"
ip -n "$RELAY_NS" addr add 10.200.0.3/24 dev "$RELAY_VETH"
ip -n "$CLIENT_NS" addr add 10.200.0.2/24 dev "$CLIENT_VETH"
ip -n "$RELAY_NS" link set "$RELAY_VETH" up
ip -n "$CLIENT_NS" link set "$CLIENT_VETH" up
ip netns exec "$RELAY_NS" sysctl -qw net.ipv6.conf.all.disable_ipv6=0
ip netns exec "$CLIENT_NS" sysctl -qw net.ipv6.conf.all.disable_ipv6=0

KEY=$("$BIN" --genkey)
printf '%s\n' "$KEY" > "$ALICE_KEY"
chmod 600 "$ALICE_KEY"

cat > "$SERVER_CONF" <<EOF
mode = server
tun_name = psx0
tun_address = fd00:1::1/64
bind_address = 10.200.0.1
bind_port = 18899
allow_client = 10.200.0.2
client_secret_file = alice $ALICE_KEY
client_route = alice fd00:1:1::/64
client_deny = alice fd00:dead::/64
audit_log = $WORK/audit.jsonl
log_level = debug
EOF

cat > "$SERVER_B_CONF" <<EOF
mode = server
tun_name = psx1
tun_address = fd00:2::1/64
bind_address = 10.200.0.3
bind_port = 18899
allow_client = 10.200.0.2
client_secret_file = alice $ALICE_KEY
client_route = alice fd00:1:1::/64
log_level = debug
EOF

cat > "$CLIENT_CONF" <<EOF
mode = client
tun_name = psx0
tun_address = fd00:1:1::2/64
remote_address = 10.200.0.3,10.200.0.1
remote_port = 18899
client_id = alice
secret = $KEY
keepalive = 5
peer_timeout = 15
endpoint_failback = on
endpoint_failback_interval = 2
log_level = debug
EOF

"$BIN" -t -c "$SERVER_CONF"
"$BIN" -t -c "$SERVER_B_CONF"
"$BIN" -t -c "$CLIENT_CONF"

log "starting relay A"
ip netns exec "$RELAY_NS" "$BIN" -c "$SERVER_CONF" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
wait_for_control "$SERVER_CONF" || die "relay A control socket did not appear"
wait_for_link "$RELAY_NS" psx0 || die "relay A TUN device did not appear"
ip -n "$RELAY_NS" -6 route replace fd00:1:1::/64 dev psx0

log "starting client (preferred relay B is down)"
ip netns exec "$CLIENT_NS" "$BIN" -c "$CLIENT_CONF" >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
wait_for_control "$CLIENT_CONF" 40 || die "client control socket did not appear"
wait_for_link "$CLIENT_NS" psx0 || die "client TUN device did not appear"
ip -n "$CLIENT_NS" -6 route replace fd00:1::/64 dev psx0
wait_for_active "$SERVER_CONF" 1 40 || die "client did not establish a session on relay A"

log "real TUN traffic"
ip netns exec "$CLIENT_NS" ping -6 -c 2 -W 3 fd00:1::1 >/dev/null ||
    die "inner ping through the tunnel failed"

log "destination ACL"
ip -n "$CLIENT_NS" -6 route replace fd00:dead::/64 dev psx0
if ip netns exec "$CLIENT_NS" ping -6 -c 1 -W 2 fd00:dead::1 >/dev/null 2>&1; then
    die "a denied destination was reachable"
fi
DENIED=$(status_json "$SERVER_CONF" | json_number stats policy_denied)
[ "$DENIED" -ge 1 ] || die "the ACL drop was not counted"

log "authenticated doctor probe"
DOCTOR=$(ip netns exec "$CLIENT_NS" "$BIN" --doctor -c "$CLIENT_CONF")
printf '%s\n' "$DOCTOR"
printf '%s\n' "$DOCTOR" | grep -q 'endpoint 1: FAIL' ||
    die "doctor did not report the down preferred relay"
printf '%s\n' "$DOCTOR" | grep -q 'endpoint 2: OK' ||
    die "doctor did not authenticate relay A"

log "file-backed staged key rotation"
STAGE_OUT=$("$BIN" --stage-key alice -c "$SERVER_CONF" 2>/dev/null)
printf '%s\n' "$STAGE_OUT"
[ -f "$ALICE_KEY.next" ] || die "staging did not create the .next key file"
grep -q '^client_next_file = alice ' "$SERVER_CONF" ||
    die "staging did not write client_next_file"
grep -q "$(cat "$ALICE_KEY.next")" "$SERVER_CONF" &&
    die "the staged secret leaked into the main configuration" || true

NEW_KEY=$(cat "$ALICE_KEY.next")
sed -i "s|^secret = .*|secret = $NEW_KEY|" "$CLIENT_CONF"
kill -HUP "$CLIENT_PID"
sleep 2
wait_for_active "$SERVER_CONF" 1 20 || die "client did not reconnect with the staged key"

"$BIN" --promote-key alice -c "$SERVER_CONF" >/dev/null
grep -q '^client_next_file = ' "$SERVER_CONF" &&
    die "promotion left client_next_file behind" || true
[ ! -e "$ALICE_KEY.next" ] || die "promotion left the staged key file behind"
grep -q "$NEW_KEY" "$ALICE_KEY" || die "promotion did not update the current key file"

log "client expiry"
"$BIN" --expire-client alice 2000-01-01 -c "$SERVER_CONF" >/dev/null
wait_for_active "$SERVER_CONF" 0 20 || die "expired client kept its session"
"$BIN" --expire-client alice never -c "$SERVER_CONF" >/dev/null
wait_for_active "$SERVER_CONF" 1 30 || die "client was not re-admitted after clearing expiry"

log "failback to the preferred relay"
ip netns exec "$RELAY_NS" "$BIN" -c "$SERVER_B_CONF" >"$SERVER_B_LOG" 2>&1 &
SERVER_B_PID=$!
wait_for_control "$SERVER_B_CONF" || die "relay B control socket did not appear"
wait_for_link "$RELAY_NS" psx1 || die "relay B TUN device did not appear"
ip -n "$RELAY_NS" -6 route replace fd00:1:1::/64 dev psx1
wait_for_active "$SERVER_B_CONF" 1 30 || die "client did not fail back to relay B"

log "all network-namespace tests passed"
