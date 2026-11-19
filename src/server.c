/*
 * server.c - pipesix Server Mode Implementation
 *
 * The server relays between clients and the upstream TUN route:
 *
 *   Client -> UDP -> receiver loop -> TUN -> upstream gateway
 *   Client <- UDP <- sender loop   <- TUN <- upstream gateway
 *
 * Every client completes a pre-shared-key handshake before it can send
 * traffic. The server holds one credential per client id, and a
 * successful handshake derives two fresh session keys (one per
 * direction) that exist only for that client and that session. Nonces,
 * replay windows and sequence counters therefore never mix between
 * peers, even if several clients are behind the same NAT.
 *
 * Multiple clients are supported concurrently. Sessions are keyed by
 * UDP endpoint, expire after 'session_timeout' seconds without traffic,
 * and the least recently used session is evicted when the table is
 * full.
 *
 * Return traffic is routed by static per-client prefixes ('client_route'
 * in the configuration) rather than by watching where traffic came from,
 * so the server can send to a client that has never sent anything and a
 * client cannot inherit another client's addresses. The sender picks the
 * longest matching prefix. When exactly one client is connected the
 * lookup falls back to that session, so a single-client deployment needs
 * no routes at all.
 *
 * An optional allow-list ('allow_client') restricts which source
 * addresses may reach the tunnel at all.
 */

#include "server.h"
#include "audit.h"
#include "config.h"
#include "control.h"
#include "crypto.h"
#include "ipv6.h"
#include "logger.h"
#include "metrics.h"
#include "platform.h"
#include "policy.h"
#include "proto.h"
#include "runtime.h"
#include "stats.h"
#include "tun.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define POLL_INTERVAL_MS        500
#define SERVER_MAX_CLIENTS      64
#define SERVER_MAX_HINTS_PER_SEC 10

typedef struct {
    int                     active;
    int                     established;
    char                    client_id[CONFIG_MAX_CLIENT_ID];
    struct sockaddr_storage addr;
    socklen_t               addr_len;
    uint8_t                 rx_key[PIPESIX_KEY_LEN];
    uint8_t                 tx_key[PIPESIX_KEY_LEN];
    uint8_t                 cnonce[PIPESIX_HANDSHAKE_NONCE_LEN];
    uint8_t                 snonce[PIPESIX_HANDSHAKE_NONCE_LEN];
    /* Static route for return traffic, copied from the credential. */
    uint8_t                 prefix[16];
    int                     prefix_len;
    pipesix_replay_t        replay;
    time_t                  last_seen;
    uint64_t                frames;
    uint64_t                rx_bytes;
    uint64_t                tx_bytes;
    uint64_t                throttled;
    /* Set once a packet's source fell outside the session's route. */
    int                     route_warned;
    /* Set once the client was told its packet exceeded the relay MTU. */
    int                     mtu_warned;
    /* Set once the first ACL drop of this session reached the audit log. */
    int                     acl_audited;
    /* Per-client limits, resolved from the configuration at handshake. */
    int                     policy_index;   /* -1 = no limits configured */
    int                     policy_warned;  /* logged once per session */
    /* Index in the credential table; owns this client's period usage. */
    int                     client_index;   /* -1 = unknown client */
    /* Quota notices are sent once per session, state and period. */
    int                     quota_warn_sent;
    int                     quota_exhausted_sent;
    int                     notice_period;
    /* Set when the client asked for quota state; enables period pushes. */
    int                     quota_requested;
    pipesix_bucket_t        rx_bucket;
    pipesix_bucket_t        tx_bucket;
    /* Separate low-rate buckets used after a throttled client's quota. */
    pipesix_bucket_t        rx_over_bucket;
    pipesix_bucket_t        tx_over_bucket;
} server_session_t;

typedef struct {
    pipesix_config_t  *config;
    tun_device_t      *tun;
    int                udp_fd;
    int                sock_family;
    _Atomic uint64_t   seq;
    uint32_t           salt;
    _Atomic int        session_timeout;
    server_session_t   sessions[SERVER_MAX_CLIENTS];
    time_t             hint_window;
    int                hint_count;
    pthread_mutex_t    lock;
    pipesix_stats_t    stats;
    /*
     * Daily usage and quota, one entry per configured client, indexed like
     * config->clients. Every client is counted, with or without a quota,
     * so 'pipesix --usage' can report it and a limit added later starts
     * from the bytes already moved today.
     */
    pipesix_quota_t    quotas[CONFIG_MAX_CLIENTS];
    /* Period index whose counters are live; rolled when the clock moves. */
    int                usage_period;
    /* One warning per failure streak, so a broken history file is quiet. */
    int                history_warned;
    /* One warning per failure streak, so a broken state file is not noisy. */
    int                quota_save_warned;
} server_context_t;

static uint64_t next_seq(server_context_t *ctx)
{
    return atomic_fetch_add_explicit(&ctx->seq, 1, memory_order_relaxed);
}

/*
 * Resolve a client id to its configured policy entry, or -1 when it has
 * none. The quota table in the context is indexed the same way.
 */
static int policy_lookup(const pipesix_config_t *config, const char *id)
{
    int i;

    for (i = 0; i < config->policy_count; i++) {
        if (strcmp(config->policies[i].id, id) == 0) {
            return i;
        }
    }

    return -1;
}

/*
 * Index of a client in the credential table.
 *
 * The usage counters are indexed the same way, so an established
 * session can charge its own client's counter without a string lookup.
 */
static int client_index_lookup(const pipesix_config_t *config, const char *id)
{
    int i;

    for (i = 0; i < config->client_count; i++) {
        if (strcmp(config->clients[i].id, id) == 0) {
            return i;
        }
    }

    return -1;
}

/* An administrative state check, before authentication or a data frame. */
static int client_cred_available(const pipesix_client_cred_t *cred,
                                 time_t now)
{
    if (cred->disabled) {
        return 0;
    }
    if (cred->has_expiry && (int64_t)now >= cred->expires_at) {
        return 0;
    }
    return 1;
}

/* Effective bytes-per-second caps for the two directions. */
static uint64_t policy_rate_in_bps(const pipesix_client_policy_t *policy)
{
    return policy != NULL ? pipesix_policy_rate_in(policy) * 125u : 0;
}

static uint64_t policy_rate_out_bps(const pipesix_client_policy_t *policy)
{
    return policy != NULL ? pipesix_policy_rate_out(policy) * 125u : 0;
}

/*
 * Check a handshake INIT against the current key and, when present, the
 * staged key. Returns 0 for no match, 1 for the current key, 2 for the
 * staged key and -1 when a configured key cannot be parsed.
 */
static int credential_match(const pipesix_client_cred_t *cred,
                            const uint8_t *payload, size_t payload_len,
                            uint8_t psk[PIPESIX_KEY_LEN])
{
    if (pipesix_key_from_string(cred->secret, psk) != 0) {
        return -1;
    }
    if (pipesix_handshake_init_verify(payload, payload_len, psk) ==
        PIPESIX_OK) {
        return 1;
    }

    if (cred->has_next_secret) {
        if (pipesix_key_from_string(cred->next_secret, psk) != 0) {
            return -1;
        }
        if (pipesix_handshake_init_verify(payload, payload_len, psk) ==
            PIPESIX_OK) {
            return 2;
        }
    }

    memset(psk, 0, PIPESIX_KEY_LEN);
    return 0;
}

/* Quota in bytes for a client id, or 0 when it has none. */
static uint64_t quota_limit_for(const pipesix_config_t *config,
                                const char *id)
{
    int policy = policy_lookup(config, id);

    if (policy < 0) {
        return 0;
    }

    return config->policies[policy].quota_mib * 1048576u;
}

/* Bytes per second used after a throttled client has used its quota. */
static uint64_t quota_throttle_bps(const pipesix_config_t *config)
{
    if (!config->quota_throttle || config->quota_throttle_kbps == 0) {
        return 0;
    }

    return config->quota_throttle_kbps * 125u;
}

static void send_session_quota_state(server_context_t *ctx,
                                     const struct sockaddr_storage *peer,
                                     socklen_t peer_len,
                                     const uint8_t key[PIPESIX_KEY_LEN],
                                     int client_index);
static int save_quota_state(server_context_t *ctx);

/*
 * Close the live accounting period and open 'new_period'.
 *
 * The old totals are appended to the usage history (when configured)
 * before the counters are reset, so no completed period is lost even if
 * the relay was idle at the boundary. Requires ctx->lock: both data-path
 * threads call this through quota_admit().
 */
static void roll_quota_period_locked(server_context_t *ctx, int old_period,
                                     int new_period)
{
    policy_usage_t usage[CONFIG_MAX_CLIENTS];
    int count = 0;
    int i;

    if (old_period >= 0 && ctx->config->usage_history[0] != '\0') {
        for (i = 0; i < ctx->config->client_count; i++) {
            snprintf(usage[count].id, sizeof(usage[count].id), "%s",
                     ctx->config->clients[i].id);
            usage[count].period = old_period;
            usage[count].used = policy_quota_used(&ctx->quotas[i], old_period);
            count++;
        }

        if (count > 0 &&
            policy_history_append(ctx->config->usage_history,
                                  ctx->config->quota_period, usage,
                                  count) != 0) {
            if (!ctx->history_warned) {
                log_warn("Cannot append to the usage history '%s': %s",
                         ctx->config->usage_history, strerror(errno));
                ctx->history_warned = 1;
            }
        } else {
            ctx->history_warned = 0;
        }
    }

    for (i = 0; i < ctx->config->client_count; i++) {
        policy_quota_restore(&ctx->quotas[i], 0, new_period);
    }

    ctx->usage_period = new_period;

    /* A client that asked for its quota state gets the new period now. */
    for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
        server_session_t *session = &ctx->sessions[i];

        if (session->active && session->established &&
            session->quota_requested) {
            send_session_quota_state(ctx, &session->addr, session->addr_len,
                                     session->tx_key, session->client_index);
        }
    }
}

/*
 * Charge one packet against a client's quota.
 *
 * Returns 1 when the packet may pass, 0 when it has to be dropped. When
 * the configured quota and grace are used up, *throttle is set to let the
 * caller apply the over-quota bucket instead of dropping outright. On the
 * call that crosses the warning threshold, or the one that first reaches
 * the exhausted state, *notify_* is set so the caller can tell the client
 * once it releases the session lock. The caller must hold that lock: both
 * data-path threads charge the same counter.
 */
static int quota_admit(server_context_t *ctx, server_session_t *session,
                       size_t bytes, time_t now, int *notify_warn,
                       int *notify_gone, int *throttle)
{
    pipesix_quota_t *quota;
    const pipesix_client_policy_t *policy = NULL;
    uint64_t limit;
    uint64_t used;
    uint64_t grace;
    uint64_t effective;
    int period;

    *notify_warn = 0;
    *notify_gone = 0;
    *throttle = 0;

    if (session->client_index < 0) {
        return 1;
    }

    quota = &ctx->quotas[session->client_index];
    period = policy_period(now, ctx->config->quota_period);

    if (ctx->usage_period != period) {
        roll_quota_period_locked(ctx, ctx->usage_period, period);
    }

    /* A session that spans midnight or a month boundary warns again. */
    if (session->notice_period != period) {
        session->notice_period = period;
        session->quota_warn_sent = 0;
        session->quota_exhausted_sent = 0;
    }

    (void)policy_quota_charge(quota, bytes, period);

    if (session->policy_index >= 0) {
        policy = &ctx->config->policies[session->policy_index];
    }

    limit = quota->limit;
    if (limit == 0) {
        return 1;
    }

    /*
     * The grace allowance is enforced here rather than inside the quota
     * counter: policy_quota_charge() still counts every byte, and the
     * counter stays comparable across restarts and history records.
     */
    grace = ctx->config->quota_grace_mib * 1048576u;
    effective = (limit > UINT64_MAX - grace) ? UINT64_MAX : limit + grace;
    used = policy_quota_used(quota, period);

    if (used > effective) {
        if (!session->quota_exhausted_sent) {
            session->quota_exhausted_sent = 1;
            *notify_gone = 1;
            audit_event("quota_exhausted", session->client_id, "",
                        "quota and grace used up");
        }

        if (ctx->config->quota_throttle) {
            *throttle = 1;
            return 1;
        }
        return 0;
    }

    if (policy != NULL && policy->warn_percent > 0 &&
        !session->quota_warn_sent) {
        if (used * 100u >= limit * policy->warn_percent) {
            session->quota_warn_sent = 1;
            *notify_warn = 1;
        }
    }

    return 1;
}

static int sockaddr_equal(const struct sockaddr_storage *a,
                          const struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family) {
        return 0;
    }

    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *x = (const struct sockaddr_in *)(const void *)a;
        const struct sockaddr_in *y = (const struct sockaddr_in *)(const void *)b;

        return x->sin_port == y->sin_port &&
               x->sin_addr.s_addr == y->sin_addr.s_addr;
    }

    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *x = (const struct sockaddr_in6 *)(const void *)a;
        const struct sockaddr_in6 *y = (const struct sockaddr_in6 *)(const void *)b;

        return x->sin6_port == y->sin6_port &&
               x->sin6_scope_id == y->sin6_scope_id &&
               memcmp(&x->sin6_addr, &y->sin6_addr,
                      sizeof(x->sin6_addr)) == 0;
    }

    return 0;
}

static void format_peer(const struct sockaddr *addr, socklen_t addr_len,
                        char *out, size_t out_size)
{
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];

    if (getnameinfo(addr, addr_len, host, sizeof(host),
                    serv, sizeof(serv),
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        snprintf(out, out_size, "unknown");
        return;
    }

    if (addr->sa_family == AF_INET6) {
        snprintf(out, out_size, "[%s]:%s", host, serv);
    } else {
        snprintf(out, out_size, "%s:%s", host, serv);
    }
}

/*
 * Return non-zero when the peer is permitted by 'allow_client'.
 * An empty allow-list permits any sender.
 */
static int peer_allowed(const server_context_t *ctx,
                        const struct sockaddr *addr, socklen_t addr_len)
{
    char host[NI_MAXHOST];
    int i;

    if (ctx->config->allow_client_count == 0) {
        return 1;
    }

    if (getnameinfo(addr, addr_len, host, sizeof(host), NULL, 0,
                    NI_NUMERICHOST) != 0) {
        return 0;
    }

    for (i = 0; i < ctx->config->allow_client_count; i++) {
        if (strcmp(host, ctx->config->allow_client[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

/*
 * Return non-zero when a client's destination policy forbids 'dest'.
 *
 * The deny list wins over the allow list, and an allow list is closed:
 * once a client has one entry, a destination outside it is dropped. With
 * 'client_isolation' on, every other configured client's return prefix is
 * denied as well, including clients that are currently offline. Requires
 * ctx->lock, because the credential table can be replaced by a reload.
 */
static int client_acl_denies(const pipesix_config_t *config,
                             const char *client_id,
                             const uint8_t dest[16])
{
    const pipesix_client_cred_t *cred = config_find_client(config, client_id);
    int i;

    if (cred == NULL) {
        return 0;
    }

    for (i = 0; i < cred->deny_count; i++) {
        if (ipv6_prefix_match(cred->deny[i], cred->deny_len[i], dest)) {
            return 1;
        }
    }

    if (cred->allow_count > 0) {
        int allowed = 0;

        for (i = 0; i < cred->allow_count; i++) {
            if (ipv6_prefix_match(cred->allow[i], cred->allow_len[i], dest)) {
                allowed = 1;
                break;
            }
        }
        if (!allowed) {
            return 1;
        }
    }

    if (config->client_isolation) {
        for (i = 0; i < config->client_count; i++) {
            const pipesix_client_cred_t *other = &config->clients[i];

            if (other == cred || other->prefix_len <= 0) {
                continue;
            }
            if (ipv6_prefix_match(other->prefix, other->prefix_len, dest)) {
                return 1;
            }
        }
    }

    return 0;
}

/*
 * ---------------------------------------------------------------------
 * Session and route tables (all helpers require ctx->lock)
 * ---------------------------------------------------------------------
 */

static int session_find(const server_context_t *ctx,
                        const struct sockaddr_storage *peer)
{
    int i;

    for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
        if (ctx->sessions[i].active &&
            sockaddr_equal(&ctx->sessions[i].addr, peer)) {
            return i;
        }
    }

    return -1;
}

/*
 * Allocate a session slot for a new peer, evicting the least recently
 * used session when the table is full.
 */
static int session_alloc(server_context_t *ctx,
                         const struct sockaddr_storage *peer,
                         socklen_t peer_len, int *evicted)
{
    int slot = -1;
    int i;

    *evicted = 0;

    for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
        if (!ctx->sessions[i].active) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        time_t oldest = ctx->sessions[0].last_seen;

        slot = 0;
        for (i = 1; i < SERVER_MAX_CLIENTS; i++) {
            if (ctx->sessions[i].last_seen < oldest) {
                oldest = ctx->sessions[i].last_seen;
                slot = i;
            }
        }
        *evicted = 1;
    }

    memset(&ctx->sessions[slot], 0, sizeof(ctx->sessions[slot]));
    ctx->sessions[slot].active = 1;
    ctx->sessions[slot].addr = *peer;
    ctx->sessions[slot].addr_len = peer_len;
    ctx->sessions[slot].last_seen = time(NULL);
    pipesix_replay_reset(&ctx->sessions[slot].replay);

    return slot;
}

/*
 * Drop sessions for 'client_id' that are still bound to another endpoint.
 *
 * A client that re-handshakes from a new source port (NAT rebind, restart,
 * or a second instance) leaves its previous session behind, and that
 * session keeps the client's static route until session_timeout. Return
 * traffic then has two candidates for the same client id, and the route
 * table may keep picking the dead one. The newest authenticated handshake
 * wins, so older endpoints are dropped here.
 *
 * Requires ctx->lock. Returns the number of sessions dropped.
 */
static int session_drop_superseded(server_context_t *ctx, const char *client_id,
                                   const struct sockaddr_storage *peer)
{
    int dropped = 0;
    int i;

    for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
        server_session_t *session = &ctx->sessions[i];

        if (!session->active || !session->established) {
            continue;
        }
        if (strcmp(session->client_id, client_id) != 0) {
            continue;
        }
        if (sockaddr_equal(&session->addr, peer)) {
            continue;
        }

        session->active = 0;
        session->established = 0;
        memset(session->rx_key, 0, sizeof(session->rx_key));
        memset(session->tx_key, 0, sizeof(session->tx_key));
        dropped++;
    }

    return dropped;
}

static int count_active(const server_context_t *ctx)
{
    int i;
    int active = 0;

    for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
        if (ctx->sessions[i].active) {
            active++;
        }
    }

    return active;
}

/*
 * Return the index of the only active session, or -1 when there is no
 * session or more than one.
 */
static int sole_session(const server_context_t *ctx)
{
    int i;
    int found = -1;

    for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
        if (ctx->sessions[i].active && ctx->sessions[i].established) {
            if (found >= 0) {
                return -1;
            }
            found = i;
        }
    }

    return found;
}

/*
 * Resolve an inner destination address to a session using the static
 * per-client routes ('client_route' in the configuration).
 *
 * The most specific prefix wins, so a host route can be carved out of a
 * client's broader prefix. Prefixes are copied into the session at
 * handshake time, so routing never walks the configuration under the
 * lock.
 *
 * Returns the session index, or -1 when no configured route matches.
 */
static int route_lookup(server_context_t *ctx, const uint8_t addr[16])
{
    int best = -1;
    int best_len = -1;
    int i;

    for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
        if (!ctx->sessions[i].established ||
            ctx->sessions[i].prefix_len <= 0) {
            continue;
        }
        if (ctx->sessions[i].prefix_len <= best_len) {
            continue;
        }
        if (!ipv6_prefix_match(ctx->sessions[i].prefix,
                               ctx->sessions[i].prefix_len, addr)) {
            continue;
        }

        best = i;
        best_len = ctx->sessions[i].prefix_len;
    }

    return best;
}

/*
 * ---------------------------------------------------------------------
 * Control frames
 * ---------------------------------------------------------------------
 */

/*
 * Send an empty control frame (no payload, no key) to a peer.
 */
static void send_empty_control(server_context_t *ctx,
                              const struct sockaddr_storage *peer,
                              socklen_t peer_len, uint16_t flags)
{
    uint8_t frame[PIPESIX_MAX_FRAME];
    size_t frame_len;

    frame_len = pipesix_frame_build(frame, sizeof(frame), flags, 0, 0,
                                    NULL, 0, NULL);
    if (frame_len == 0) {
        return;
    }

    if (sendto(ctx->udp_fd, frame, frame_len, 0,
               (const struct sockaddr *)peer, peer_len) !=
        (ssize_t)frame_len) {
        log_debug("Failed to send a control frame: %s", strerror(errno));
    }
}

/*
 * Ask a peer to run the handshake, rate limited so a flood of spoofed
 * datagrams cannot turn the server into an amplifier.
 */
/*
 * Send a control frame inside a session, authenticated with the
 * server-to-client key.
 *
 * Used for the quota notices: unlike a plaintext hint, a spoofed datagram
 * cannot fake one, so a client never takes "quota exhausted" from an
 * off-path attacker.
 */
static void send_session_control(server_context_t *ctx,
                                 const struct sockaddr_storage *peer,
                                 socklen_t peer_len,
                                 const uint8_t key[PIPESIX_KEY_LEN],
                                 uint16_t flag)
{
    uint8_t frame[PIPESIX_HEADER_SIZE + PIPESIX_AUTH_TAG_SIZE];
    size_t frame_len;

    if (key == NULL) {
        return;
    }

    frame_len = pipesix_frame_build(frame, sizeof(frame), flag, ctx->salt,
                                    next_seq(ctx), NULL, 0, key);
    if (frame_len == 0) {
        return;
    }

    if (sendto(ctx->udp_fd, frame, frame_len, 0,
               (const struct sockaddr *)peer, peer_len) !=
        (ssize_t)frame_len) {
        log_debug("Failed to send a control frame: %s", strerror(errno));
    }
}

/*
 * Send a client its current quota state, authenticated in its session.
 *
 * The client asks for this periodically rather than the server pushing
 * it, so a client that does not know the flag is never sent a frame it
 * would reject as invalid.
 */
static void send_session_quota_state(server_context_t *ctx,
                                     const struct sockaddr_storage *peer,
                                     socklen_t peer_len,
                                     const uint8_t key[PIPESIX_KEY_LEN],
                                     int client_index)
{
    pipesix_quota_state_t state;
    uint8_t payload[PIPESIX_QUOTA_STATE_LEN];
    uint8_t frame[PIPESIX_HEADER_SIZE + PIPESIX_QUOTA_STATE_LEN +
                  PIPESIX_AUTH_TAG_SIZE];
    size_t payload_len;
    size_t frame_len;
    time_t now;
    int period;

    if (key == NULL || client_index < 0) {
        return;
    }

    now = time(NULL);
    period = policy_period(now, ctx->config->quota_period);
    memset(&state, 0, sizeof(state));
    state.limit_bytes = ctx->quotas[client_index].limit;
    state.used_bytes = policy_quota_used(&ctx->quotas[client_index], period);
    state.period_start =
        (int64_t)policy_period_start(period, ctx->config->quota_period);
    state.period_end =
        (int64_t)policy_period_end(period, ctx->config->quota_period);

    payload_len = pipesix_quota_state_encode(payload, sizeof(payload),
                                             &state);
    if (payload_len == 0) {
        return;
    }

    frame_len = pipesix_frame_build(frame, sizeof(frame),
                                    PIPESIX_FLAG_QUOTA_STATE, ctx->salt,
                                    next_seq(ctx), payload, payload_len,
                                    key);
    if (frame_len == 0) {
        return;
    }

    if (sendto(ctx->udp_fd, frame, frame_len, 0,
               (const struct sockaddr *)peer, peer_len) !=
        (ssize_t)frame_len) {
        log_debug("Failed to send the quota state: %s", strerror(errno));
    }
}

static void send_need_handshake(server_context_t *ctx,
                                const struct sockaddr_storage *peer,
                                socklen_t peer_len)
{
    time_t now = time(NULL);
    int allowed = 0;

    pthread_mutex_lock(&ctx->lock);
    if (ctx->hint_window != now) {
        ctx->hint_window = now;
        ctx->hint_count = 0;
    }
    if (ctx->hint_count < SERVER_MAX_HINTS_PER_SEC) {
        ctx->hint_count++;
        allowed = 1;
    }
    pthread_mutex_unlock(&ctx->lock);

    if (!allowed) {
        return;
    }

    send_empty_control(ctx, peer, peer_len, PIPESIX_FLAG_HANDSHAKE_NEEDED);
}

/*
 * Tell every connected client that the relay is going away.
 *
 * Without this a client only notices silence, after peer_timeout (two
 * minutes by default), so a 'systemctl restart' would black-hole the
 * tunnel for that long. The frame carries the session's own
 * server-to-client key, so a spoofed datagram cannot tear a session down
 * the way a plaintext hint could; it goes out after the worker threads
 * have stopped, so no data frame can overtake it.
 */
static void send_closing_to_sessions(server_context_t *ctx)
{
    struct sockaddr_storage addr[SERVER_MAX_CLIENTS];
    socklen_t addr_len[SERVER_MAX_CLIENTS];
    uint8_t keys[SERVER_MAX_CLIENTS][PIPESIX_KEY_LEN];
    int count = 0;
    int i;

    pthread_mutex_lock(&ctx->lock);
    for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
        if (!ctx->sessions[i].active || !ctx->sessions[i].established) {
            continue;
        }
        addr[count] = ctx->sessions[i].addr;
        addr_len[count] = ctx->sessions[i].addr_len;
        memcpy(keys[count], ctx->sessions[i].tx_key, PIPESIX_KEY_LEN);
        count++;
    }
    pthread_mutex_unlock(&ctx->lock);

    for (i = 0; i < count; i++) {
        uint8_t frame[PIPESIX_HEADER_SIZE + PIPESIX_AUTH_TAG_SIZE];
        size_t frame_len;

        frame_len = pipesix_frame_build(frame, sizeof(frame),
                                        PIPESIX_FLAG_SERVER_CLOSING, ctx->salt,
                                        next_seq(ctx), NULL, 0, keys[i]);
        memset(keys[i], 0, PIPESIX_KEY_LEN);

        if (frame_len == 0) {
            continue;
        }

        if (sendto(ctx->udp_fd, frame, frame_len, 0,
                   (const struct sockaddr *)&addr[i], addr_len[i]) !=
            (ssize_t)frame_len) {
            log_debug("Failed to send the shutdown notice: %s",
                      strerror(errno));
        }
    }

    if (count > 0) {
        log_info("Told %d connected client(s) the server is shutting down",
                 count);
    }
}

/*
 * Echo a keepalive back to the client that sent one.
 */
static void send_keepalive(server_context_t *ctx,
                           const struct sockaddr_storage *peer,
                           socklen_t peer_len)
{
    uint8_t frame[PIPESIX_MAX_FRAME];
    uint8_t key[PIPESIX_KEY_LEN];
    size_t frame_len;
    int slot;

    pthread_mutex_lock(&ctx->lock);
    slot = session_find(ctx, peer);
    if (slot >= 0 && ctx->sessions[slot].established) {
        memcpy(key, ctx->sessions[slot].tx_key, sizeof(key));
    } else {
        slot = -1;
    }
    pthread_mutex_unlock(&ctx->lock);

    if (slot < 0) {
        return;
    }

    frame_len = pipesix_frame_build(frame, sizeof(frame),
                                    PIPESIX_FLAG_KEEPALIVE, ctx->salt,
                                    next_seq(ctx), NULL, 0, key);
    memset(key, 0, sizeof(key));

    if (frame_len == 0) {
        return;
    }

    if (sendto(ctx->udp_fd, frame, frame_len, 0,
               (const struct sockaddr *)peer, peer_len) !=
        (ssize_t)frame_len) {
        log_debug("Failed to send keepalive: %s", strerror(errno));
    }
}

/*
 * ---------------------------------------------------------------------
 * Handshake
 * ---------------------------------------------------------------------
 */

/*
 * Answer an authenticated reachability probe. This deliberately does not
 * touch the session table: --doctor and failback probing must not evict a
 * live client or change its keys.
 */
static void handle_probe(server_context_t *ctx,
                         const struct sockaddr_storage *peer,
                         socklen_t peer_len, const uint8_t *payload,
                         size_t payload_len)
{
    char id[CONFIG_MAX_CLIENT_ID];
    char peer_str[NI_MAXHOST + NI_MAXSERV + 8];
    const pipesix_client_cred_t *cred;
    pipesix_client_cred_t cred_copy;
    uint8_t psk[PIPESIX_KEY_LEN];
    uint8_t cnonce[PIPESIX_HANDSHAKE_NONCE_LEN];
    uint8_t snonce[PIPESIX_HANDSHAKE_NONCE_LEN];
    uint8_t resp[PIPESIX_HANDSHAKE_RESP_MAX];
    uint8_t frame[PIPESIX_MAX_FRAME];
    size_t resp_len;
    size_t frame_len;
    int matched;

    if (pipesix_handshake_init_peek(payload, payload_len, id, sizeof(id),
                                    cnonce) != PIPESIX_OK) {
        stats_add_invalid(&ctx->stats);
        return;
    }

    pthread_mutex_lock(&ctx->lock);
    cred = config_find_client(ctx->config, id);
    if (cred != NULL) {
        cred_copy = *cred;
    }
    pthread_mutex_unlock(&ctx->lock);

    if (cred == NULL || !client_cred_available(&cred_copy, time(NULL))) {
        return;
    }

    matched = credential_match(&cred_copy, payload, payload_len, psk);
    if (matched <= 0) {
        memset(psk, 0, sizeof(psk));
        return;
    }

    if (pipesix_random_bytes(snonce, sizeof(snonce)) != 0) {
        memset(psk, 0, sizeof(psk));
        return;
    }

    resp_len = pipesix_handshake_resp_build(resp, sizeof(resp), cnonce,
                                            snonce, psk);
    memset(psk, 0, sizeof(psk));
    if (resp_len == 0) {
        return;
    }

    frame_len = pipesix_frame_build(frame, sizeof(frame),
                                    PIPESIX_FLAG_PROBE_RESP, 0, 0, resp,
                                    resp_len, NULL);
    if (frame_len == 0) {
        return;
    }

    if (sendto(ctx->udp_fd, frame, frame_len, 0,
               (const struct sockaddr *)peer, peer_len) !=
        (ssize_t)frame_len) {
        format_peer((const struct sockaddr *)peer, peer_len, peer_str,
                    sizeof(peer_str));
        log_debug("Failed to send a probe response to %s: %s", peer_str,
                  strerror(errno));
    }
}

static void handle_handshake_init(server_context_t *ctx,
                                  const struct sockaddr_storage *peer,
                                  socklen_t peer_len,
                                  const uint8_t *payload, size_t payload_len)
{
    char id[CONFIG_MAX_CLIENT_ID];
    char peer_str[NI_MAXHOST + NI_MAXSERV + 8];
    const pipesix_client_cred_t *cred;
    pipesix_client_cred_t cred_copy;
    uint8_t psk[PIPESIX_KEY_LEN];
    uint8_t cnonce[PIPESIX_HANDSHAKE_NONCE_LEN];
    uint8_t snonce[PIPESIX_HANDSHAKE_NONCE_LEN];
    uint8_t c2s[PIPESIX_KEY_LEN];
    uint8_t s2c[PIPESIX_KEY_LEN];
    uint8_t resp[PIPESIX_HANDSHAKE_RESP_MAX];
    uint8_t frame[PIPESIX_MAX_FRAME];
    size_t resp_len;
    size_t frame_len;
    int slot;
    int retransmit = 0;
    int evicted = 0;
    int superseded = 0;
    int had_session = 0;
    int session_count;

    if (pipesix_handshake_init_peek(payload, payload_len, id, sizeof(id),
                                    cnonce) != PIPESIX_OK) {
        stats_add_invalid(&ctx->stats);
        stats_add_handshake_failure(&ctx->stats);
        return;
    }

    /*
     * Copy the credential while holding the session lock: a SIGHUP reload
     * may replace the whole table at any moment, and the rest of the
     * handshake must see one consistent entry.
     */
    pthread_mutex_lock(&ctx->lock);
    cred = config_find_client(ctx->config, id);
    if (cred != NULL) {
        cred_copy = *cred;
    }
    pthread_mutex_unlock(&ctx->lock);

    if (cred == NULL) {
        format_peer((const struct sockaddr *)peer, peer_len,
                    peer_str, sizeof(peer_str));
        log_warn("Handshake from %s for unknown client '%s'",
                 peer_str, id);
        stats_add_auth_failure(&ctx->stats);
        stats_add_handshake_failure(&ctx->stats);
        return;
    }

    format_peer((const struct sockaddr *)peer, peer_len, peer_str,
                sizeof(peer_str));

    if (!client_cred_available(&cred_copy, time(NULL))) {
        log_warn("Handshake from %s for client '%s' refused: client is %s",
                 peer_str, id,
                 cred_copy.disabled ? "disabled" : "expired");
        audit_event("client_refused", id, peer_str, "client is %s",
                    cred_copy.disabled ? "disabled" : "expired");
        stats_add_auth_failure(&ctx->stats);
        stats_add_handshake_failure(&ctx->stats);
        return;
    }

    {
        int matched = credential_match(&cred_copy, payload, payload_len, psk);

        if (matched < 0) {
            log_error("Cannot derive a key for client '%s'", id);
            stats_add_handshake_failure(&ctx->stats);
            return;
        }
        if (matched == 0) {
            log_warn("Handshake from %s failed authentication for client "
                     "'%s'", peer_str, id);
            audit_event("handshake_failed", id, peer_str,
                        "authentication failed");
            stats_add_auth_failure(&ctx->stats);
            stats_add_handshake_failure(&ctx->stats);
            return;
        }
    }

    pthread_mutex_lock(&ctx->lock);

    /*
     * The client now lives at this endpoint, so retire any session it
     * left on an earlier one before allocating its slot. Otherwise the
     * stale entry would keep competing for the client's route.
     */
    superseded = session_drop_superseded(ctx, id, peer);

    slot = session_find(ctx, peer);
    if (slot < 0) {
        slot = session_alloc(ctx, peer, peer_len, &evicted);
    }

    /* Whether this handshake replaces a session that already existed. */
    had_session = ctx->sessions[slot].established;

    if (ctx->sessions[slot].established &&
        strcmp(ctx->sessions[slot].client_id, id) == 0 &&
        memcmp(ctx->sessions[slot].cnonce, cnonce, sizeof(cnonce)) == 0) {
        /*
         * The client retransmitted its request because the response was
         * lost. Repeat the same response so both ends stay on one key
         * set instead of half-committing to a new one.
         */
        memcpy(snonce, ctx->sessions[slot].snonce, sizeof(snonce));
        retransmit = 1;
    } else {
        if (pipesix_random_bytes(snonce, sizeof(snonce)) != 0) {
            /* Never leave a half-established session usable. */
            ctx->sessions[slot].active = 0;
            pthread_mutex_unlock(&ctx->lock);
            memset(psk, 0, sizeof(psk));
            log_error("Cannot generate a handshake nonce: %s",
                      strerror(errno));
            stats_add_handshake_failure(&ctx->stats);
            return;
        }

        pipesix_session_keys(psk, cnonce, snonce, c2s, s2c);

        memcpy(ctx->sessions[slot].rx_key, c2s, sizeof(c2s));
        memcpy(ctx->sessions[slot].tx_key, s2c, sizeof(s2c));
        memcpy(ctx->sessions[slot].cnonce, cnonce, sizeof(cnonce));
        memcpy(ctx->sessions[slot].snonce, snonce, sizeof(snonce));
        memset(ctx->sessions[slot].client_id, 0,
               sizeof(ctx->sessions[slot].client_id));
        snprintf(ctx->sessions[slot].client_id,
                 sizeof(ctx->sessions[slot].client_id), "%s", id);
        ctx->sessions[slot].established = 1;
        ctx->sessions[slot].addr = *peer;
        ctx->sessions[slot].addr_len = peer_len;
        ctx->sessions[slot].frames = 0;
        ctx->sessions[slot].throttled = 0;
        ctx->sessions[slot].route_warned = 0;
        ctx->sessions[slot].mtu_warned = 0;
        ctx->sessions[slot].acl_audited = 0;
        ctx->sessions[slot].quota_warn_sent = 0;
        ctx->sessions[slot].quota_exhausted_sent = 0;
        ctx->sessions[slot].notice_period = -1;
        ctx->sessions[slot].quota_requested = 0;
        pipesix_replay_reset(&ctx->sessions[slot].replay);

        {
            int policy = policy_lookup(ctx->config, id);
            uint64_t rate_bps = 0;

            ctx->sessions[slot].policy_index = policy;
            ctx->sessions[slot].policy_warned = 0;
            ctx->sessions[slot].client_index =
                client_index_lookup(ctx->config, id);

            if (policy >= 0) {
                rate_bps = policy_rate_in_bps(&ctx->config->policies[policy]);
            }

            policy_bucket_init(&ctx->sessions[slot].rx_bucket, rate_bps,
                               policy_now_ms());
            policy_bucket_init(
                &ctx->sessions[slot].tx_bucket,
                policy >= 0
                    ? policy_rate_out_bps(&ctx->config->policies[policy])
                    : 0,
                policy_now_ms());
            policy_bucket_init(&ctx->sessions[slot].rx_over_bucket,
                               quota_throttle_bps(ctx->config),
                               policy_now_ms());
            policy_bucket_init(&ctx->sessions[slot].tx_over_bucket,
                               quota_throttle_bps(ctx->config),
                               policy_now_ms());
        }
    }

    memcpy(ctx->sessions[slot].prefix, cred_copy.prefix,
           sizeof(ctx->sessions[slot].prefix));
    ctx->sessions[slot].prefix_len = cred_copy.prefix_len;
    ctx->sessions[slot].last_seen = time(NULL);
    session_count = count_active(ctx);

    pthread_mutex_unlock(&ctx->lock);

    if (superseded > 0) {
        format_peer((const struct sockaddr *)peer, peer_len,
                    peer_str, sizeof(peer_str));
        log_info("Client '%s' re-handshook from %s; dropped %d stale "
                 "session(s) on the previous endpoint", id, peer_str,
                 superseded);
    }

    memset(c2s, 0, sizeof(c2s));
    memset(s2c, 0, sizeof(s2c));

    /* The PSK is still needed to sign the response. */
    resp_len = pipesix_handshake_resp_build(resp, sizeof(resp),
                                            cnonce, snonce, psk);
    memset(psk, 0, sizeof(psk));

    if (resp_len == 0) {
        log_error("Cannot build the handshake response");
        stats_add_handshake_failure(&ctx->stats);
        return;
    }

    frame_len = pipesix_frame_build(frame, sizeof(frame),
                                    PIPESIX_FLAG_HANDSHAKE_RESP, 0, 0,
                                    resp, resp_len, NULL);
    if (frame_len == 0) {
        log_error("Cannot build the handshake response frame");
        stats_add_handshake_failure(&ctx->stats);
        return;
    }

    if (sendto(ctx->udp_fd, frame, frame_len, 0,
               (const struct sockaddr *)peer, peer_len) !=
        (ssize_t)frame_len) {
        log_warn("Failed to send the handshake response: %s",
                 strerror(errno));
        stats_add_handshake_failure(&ctx->stats);
        return;
    }

    if (retransmit) {
        log_debug("Resent handshake response to client '%s'", id);
        return;
    }

    stats_add_handshake(&ctx->stats);
    if (had_session || superseded > 0) {
        stats_add_rekey(&ctx->stats);
    }

    format_peer((const struct sockaddr *)peer, peer_len,
                peer_str, sizeof(peer_str));

    if (evicted) {
        log_warn("Session table full; evicted the least recently used "
                 "client to admit '%s'", id);
    }

    log_info("Client '%s' handshake from %s (crypto=chacha20-poly1305, "
             "%d active)", id, peer_str, session_count);
    audit_event("handshake", id, peer_str, "authenticated, %d active",
                session_count);
}

/*
 * Drop sessions that have been idle for longer than session_timeout.
 */
static void sessions_expire(server_context_t *ctx, time_t now)
{
    int expired[SERVER_MAX_CLIENTS];
    int blocked[SERVER_MAX_CLIENTS];
    char blocked_id[SERVER_MAX_CLIENTS][CONFIG_MAX_CLIENT_ID];
    int timeout = atomic_load(&ctx->session_timeout);
    int count = 0;
    int blocked_count = 0;
    int i;

    pthread_mutex_lock(&ctx->lock);

    for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
        server_session_t *session = &ctx->sessions[i];
        const pipesix_client_cred_t *cred;

        if (!session->active) {
            continue;
        }

        cred = config_find_client(ctx->config, session->client_id);
        if (cred == NULL || !client_cred_available(cred, now)) {
            snprintf(blocked_id[blocked_count],
                     sizeof(blocked_id[blocked_count]), "%s",
                     session->client_id);
            blocked[blocked_count++] = i;
            session->active = 0;
            session->established = 0;
            memset(session->rx_key, 0, sizeof(session->rx_key));
            memset(session->tx_key, 0, sizeof(session->tx_key));
            continue;
        }

        if (timeout <= 0 || (now - session->last_seen) <= (time_t)timeout) {
            continue;
        }

        session->active = 0;
        session->established = 0;
        memset(session->rx_key, 0, sizeof(session->rx_key));
        memset(session->tx_key, 0, sizeof(session->tx_key));
        expired[count++] = i;
    }

    pthread_mutex_unlock(&ctx->lock);

    for (i = 0; i < count; i++) {
        server_session_t *session = &ctx->sessions[expired[i]];
        char peer_str[NI_MAXHOST + NI_MAXSERV + 8];

        format_peer((const struct sockaddr *)&session->addr, session->addr_len,
                    peer_str, sizeof(peer_str));
        log_info("Client '%s' session %s expired after %d seconds of "
                 "inactivity (%llu frames)",
                 session->client_id[0] != '\0' ? session->client_id : "?",
                 peer_str, timeout, (unsigned long long)session->frames);
    }

    for (i = 0; i < blocked_count; i++) {
        server_session_t *session = &ctx->sessions[blocked[i]];
        char peer_str[NI_MAXHOST + NI_MAXSERV + 8];

        format_peer((const struct sockaddr *)&session->addr, session->addr_len,
                    peer_str, sizeof(peer_str));
        log_warn("Client '%s' session %s closed: client is disabled or "
                 "expired", blocked_id[i], peer_str);
        audit_event("session_blocked", blocked_id[i], peer_str,
                    "closed because the client is disabled or expired");
    }
}

/*
 * Log one line per active client session.
 *
 * Triggered by SIGUSR1 so an operator can see who is connected, from
 * where, and how recently they were heard from, without restarting the
 * relay. The snapshot is taken under the session lock and logged after
 * the lock is released, so reporting never blocks the data path.
 */
static void sessions_dump(server_context_t *ctx)
{
    char ids[SERVER_MAX_CLIENTS][CONFIG_MAX_CLIENT_ID];
    char peers[SERVER_MAX_CLIENTS][96];
    uint64_t frames[SERVER_MAX_CLIENTS];
    time_t last_seen[SERVER_MAX_CLIENTS];
    time_t now = time(NULL);
    int count = 0;
    int i;

    pthread_mutex_lock(&ctx->lock);

    for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
        if (!ctx->sessions[i].active) {
            continue;
        }

        snprintf(ids[count], sizeof(ids[count]), "%s",
                 ctx->sessions[i].client_id[0] != '\0'
                     ? ctx->sessions[i].client_id
                     : "?");
        format_peer((const struct sockaddr *)&ctx->sessions[i].addr,
                    ctx->sessions[i].addr_len, peers[count],
                    sizeof(peers[count]));
        frames[count] = ctx->sessions[i].frames;
        last_seen[count] = ctx->sessions[i].last_seen;
        count++;
    }

    pthread_mutex_unlock(&ctx->lock);

    if (count == 0) {
        log_info("Sessions: none connected");
        return;
    }

    log_info("Sessions: %d connected (of %d slots)", count,
             SERVER_MAX_CLIENTS);

    for (i = 0; i < count; i++) {
        log_info("  client '%s' from %s: %llu frame(s), idle %lds",
                 ids[i], peers[i], (unsigned long long)frames[i],
                 (long)(now - last_seen[i]));
    }
}

/*
 * Look up a credential in a snapshot of the credential table.
 */
static const pipesix_client_cred_t *find_cred_in(
    const pipesix_client_cred_t *table, int count, const char *id)
{
    int i;

    for (i = 0; i < count; i++) {
        if (strcmp(table[i].id, id) == 0) {
            return &table[i];
        }
    }

    return NULL;
}

/*
 * Today's usage for one client, kept across a reload.
 *
 * The id points into the credential snapshot rather than copying it: that
 * table is immutable for the duration of the reload.
 */
typedef struct {
    const char *id;
    uint64_t    used;
    int         period;
} quota_snapshot_t;

/*
 * Apply a SIGHUP reload.
 *
 * Timing settings are replaced in place. In server mode the per-client
 * credential table is replaced as well, and live sessions are reconciled
 * against it:
 *
 *   - a client whose key changed has its session torn down and is asked
 *     to handshake again, so the old key stops working immediately;
 *   - a client removed from the configuration is disconnected;
 *   - a changed 'client_route' is applied to the live session, which is
 *     safe because that session is already authenticated.
 *
 * Sessions that are not mentioned above are left alone, so rotating one
 * key does not disturb any other client.
 */
static int server_metrics_body(char *out, size_t size, void *arg);
static int server_ready(char *out, size_t size, void *arg);

static void reload_config(server_context_t *ctx)
{
    pipesix_client_cred_t before[CONFIG_MAX_CLIENTS];
    char old_metrics_address[CONFIG_MAX_ADDRESS];
    char old_metrics_token[CONFIG_MAX_SECRET];
    int old_metrics_port = ctx->config->metrics_port;
    struct sockaddr_storage hint_addr[SERVER_MAX_CLIENTS];
    socklen_t hint_addr_len[SERVER_MAX_CLIENTS];
    char hint_ids[SERVER_MAX_CLIENTS][CONFIG_MAX_CLIENT_ID];
    char dropped_ids[SERVER_MAX_CLIENTS][CONFIG_MAX_CLIENT_ID];
    char blocked_ids[SERVER_MAX_CLIENTS][CONFIG_MAX_CLIENT_ID];
    quota_snapshot_t old_usage[CONFIG_MAX_CLIENTS];
    int before_count = ctx->config->client_count;
    int old_usage_count = 0;
    int hint_count = 0;
    int dropped_count = 0;
    int blocked_count = 0;
    int rerouted = 0;
    int rc;
    int i;

    memcpy(before, ctx->config->clients, sizeof(before));
    snprintf(old_metrics_address, sizeof(old_metrics_address), "%s",
             ctx->config->metrics_address);
    snprintf(old_metrics_token, sizeof(old_metrics_token), "%s",
             ctx->config->metrics_token);

    /* Today's usage, keyed by the credential table it belongs to. */
    for (i = 0; i < before_count; i++) {
        old_usage[i].id = before[i].id;
        old_usage[i].period = atomic_load_explicit(&ctx->quotas[i].period,
                                                   memory_order_relaxed);
        old_usage[i].used = atomic_load_explicit(&ctx->quotas[i].used,
                                                 memory_order_relaxed);
    }
    old_usage_count = before_count;

    /*
     * The table swap has to exclude the receiver thread, which reads
     * credentials while handling a handshake.
     */
    pthread_mutex_lock(&ctx->lock);
    rc = config_reload_runtime(ctx->config);
    pthread_mutex_unlock(&ctx->lock);

    if (rc != 0) {
        log_error("Configuration reload failed; keeping the previous "
                  "settings and credentials");
        return;
    }

    logger_set_level(ctx->config->log_level);
    logger_set_json(ctx->config->log_json);
    atomic_store(&ctx->session_timeout, ctx->config->session_timeout);

    if (audit_open(ctx->config->audit_log) != 0) {
        log_warn("Cannot open the audit log '%s': %s",
                 ctx->config->audit_log, strerror(errno));
    }

    if (strcmp(old_metrics_address, ctx->config->metrics_address) != 0 ||
        old_metrics_port != ctx->config->metrics_port ||
        strcmp(old_metrics_token, ctx->config->metrics_token) != 0) {
        metrics_stop();
        if (metrics_start(ctx->config, server_metrics_body, server_ready,
                          ctx) != 0) {
            log_warn("The new metrics settings could not be applied");
        }
    }

    pthread_mutex_lock(&ctx->lock);

    /*
     * The credential table may have been reordered, shrunk or grown, and
     * the quota table is indexed the same way. Move usage by client id,
     * not by index, so a reload never charges one client's bytes to
     * another. A client that gained a quota keeps the usage it already
     * accumulated today.
     */
    {
        int period = policy_period(time(NULL), ctx->config->quota_period);

        for (i = 0; i < ctx->config->client_count; i++) {
            const char *id = ctx->config->clients[i].id;
            uint64_t limit = quota_limit_for(ctx->config, id);
            int j;

            policy_quota_init(&ctx->quotas[i], limit);

            for (j = 0; j < old_usage_count; j++) {
                if (strcmp(old_usage[j].id, id) == 0) {
                    if (old_usage[j].period == period) {
                        policy_quota_restore(&ctx->quotas[i],
                                             old_usage[j].used,
                                             old_usage[j].period);
                    }
                    break;
                }
            }
        }

        for (i = ctx->config->client_count; i < CONFIG_MAX_CLIENTS; i++) {
            policy_quota_init(&ctx->quotas[i], 0);
        }
    }

    for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
        server_session_t *session = &ctx->sessions[i];
        const pipesix_client_cred_t *old_cred;
        const pipesix_client_cred_t *new_cred;

        if (!session->active) {
            continue;
        }

        old_cred = find_cred_in(before, before_count, session->client_id);
        new_cred = config_find_client(ctx->config, session->client_id);

        if (new_cred == NULL) {
            snprintf(dropped_ids[dropped_count],
                     sizeof(dropped_ids[dropped_count]), "%s",
                     session->client_id);
            dropped_count++;

            session->active = 0;
            session->established = 0;
            session->prefix_len = 0;
            memset(session->rx_key, 0, sizeof(session->rx_key));
            memset(session->tx_key, 0, sizeof(session->tx_key));
            continue;
        }

        if (!client_cred_available(new_cred, time(NULL))) {
            snprintf(blocked_ids[blocked_count],
                     sizeof(blocked_ids[blocked_count]), "%s",
                     session->client_id);
            blocked_count++;

            session->active = 0;
            session->established = 0;
            session->prefix_len = 0;
            memset(session->rx_key, 0, sizeof(session->rx_key));
            memset(session->tx_key, 0, sizeof(session->tx_key));
            continue;
        }

        if (old_cred == NULL ||
            strcmp(old_cred->secret, new_cred->secret) != 0) {
            /*
             * The key rotated: the session must not outlive it. The
             * address is snapshotted under the lock because the receiver
             * thread may reuse this slot as soon as we let go.
             */
            hint_addr[hint_count] = session->addr;
            hint_addr_len[hint_count] = session->addr_len;
            snprintf(hint_ids[hint_count],
                     sizeof(hint_ids[hint_count]), "%s",
                     session->client_id);
            hint_count++;

            session->established = 0;
            session->prefix_len = 0;
            memset(session->rx_key, 0, sizeof(session->rx_key));
            memset(session->tx_key, 0, sizeof(session->tx_key));
            pipesix_replay_reset(&session->replay);
            continue;
        }

        if (session->prefix_len != new_cred->prefix_len ||
            memcmp(session->prefix, new_cred->prefix,
                   sizeof(session->prefix)) != 0) {
            memcpy(session->prefix, new_cred->prefix,
                   sizeof(session->prefix));
            session->prefix_len = new_cred->prefix_len;
            session->route_warned = 0;
            rerouted++;
        }

        {
            int policy = policy_lookup(ctx->config, session->client_id);
            uint64_t rate_bps = 0;

            if (policy >= 0) {
                rate_bps = ctx->config->policies[policy].rate_kbps * 125u;
            }

            session->policy_index = policy;
            session->client_index =
                client_index_lookup(ctx->config, session->client_id);
            session->policy_warned = 0;
            session->quota_warn_sent = 0;
            session->quota_exhausted_sent = 0;
            session->notice_period = -1;

            /*
             * Keep the refilled tokens when the cap did not change; only
             * a new rate may reset the bucket.
             */
            rate_bps = (policy >= 0)
                           ? policy_rate_in_bps(&ctx->config->policies[policy])
                           : 0;
            if (session->rx_bucket.rate_bps != rate_bps) {
                policy_bucket_init(&session->rx_bucket, rate_bps,
                                   policy_now_ms());
            }
            rate_bps = (policy >= 0)
                           ? policy_rate_out_bps(&ctx->config->policies[policy])
                           : 0;
            if (session->tx_bucket.rate_bps != rate_bps) {
                policy_bucket_init(&session->tx_bucket, rate_bps,
                                   policy_now_ms());
            }

            /* A reload may switch the quota action or its overage rate. */
            policy_bucket_init(&session->rx_over_bucket,
                               quota_throttle_bps(ctx->config),
                               policy_now_ms());
            policy_bucket_init(&session->tx_over_bucket,
                               quota_throttle_bps(ctx->config),
                               policy_now_ms());
        }
    }

    pthread_mutex_unlock(&ctx->lock);

    /* Frames go out after the lock is released. */
    for (i = 0; i < hint_count; i++) {
        send_empty_control(ctx, &hint_addr[i], hint_addr_len[i],
                           PIPESIX_FLAG_HANDSHAKE_NEEDED);
        log_warn("Client '%s' key changed; session revoked and a new "
                 "handshake requested", hint_ids[i]);
        audit_event("key_changed", hint_ids[i], "",
                    "session revoked and re-handshake requested");
    }

    for (i = 0; i < dropped_count; i++) {
        log_warn("Client '%s' was removed from the configuration; its "
                 "session was dropped", dropped_ids[i]);
        audit_event("client_removed", dropped_ids[i], "",
                    "session dropped after configuration reload");
    }

    for (i = 0; i < blocked_count; i++) {
        log_warn("Client '%s' is disabled or expired; its session was "
                 "dropped", blocked_ids[i]);
        audit_event("session_blocked", blocked_ids[i], "",
                    "session dropped by configuration reload");
    }

    if (rerouted > 0) {
        log_info("%d live session(s) picked up a new return route",
                 rerouted);
    }

    log_info("Configuration reloaded (keys, ACLs, limits, log settings, "
             "timing, quotas, paths, metrics): %d credential(s), "
             "%d limit(s); interface and mode changes need a restart",
             ctx->config->client_count, ctx->config->policy_count);
    audit_event("reload", "", "", "configuration reloaded: %d client(s)",
                ctx->config->client_count);
}

/*
 * Tell a client that one of its packets is too large for the relay
 * (ICMPv6 Packet Too Big, RFC 4443).
 *
 * Without this the relay's kernel drops the oversized packet on write and
 * the client keeps retrying it: the classic PMTU black hole, which is what
 * forces an operator to guess at tun_mtu. The message is sent inside the
 * client's own session, quoted back from its packet, so its kernel lowers
 * the path MTU for that destination and resends at a size that fits.
 *
 * The frame is addressed from the session table snapshot taken under the
 * lock: the slot may be recycled by a re-handshake, and a frame built for
 * the wrong session would only fail authentication at the client.
 */
static void send_packet_too_big(server_context_t *ctx, int slot,
                                const struct sockaddr_storage *peer,
                                socklen_t peer_len,
                                const uint8_t *payload, size_t payload_len)
{
    char client_id[CONFIG_MAX_CLIENT_ID];
    uint8_t src[16];
    uint8_t key[PIPESIX_KEY_LEN];
    uint8_t packet[1280];
    uint8_t frame[PIPESIX_MAX_FRAME];
    const pipesix_ipv6_header_t *inner = NULL;
    size_t packet_len;
    size_t frame_len;
    uint32_t mtu;
    int first = 0;

    if (slot < 0 || ctx->config->tun_mtu <= 0) {
        return;
    }

    if (inet_pton(AF_INET6, ctx->config->tun_address, src) != 1) {
        return;
    }

    if (ipv6_parse_header(payload, payload_len, &inner) != 0) {
        return;
    }

    pthread_mutex_lock(&ctx->lock);

    if (!ctx->sessions[slot].active || !ctx->sessions[slot].established ||
        !sockaddr_equal(&ctx->sessions[slot].addr, peer)) {
        pthread_mutex_unlock(&ctx->lock);
        return;
    }

    memcpy(key, ctx->sessions[slot].tx_key, sizeof(key));
    snprintf(client_id, sizeof(client_id), "%s",
             ctx->sessions[slot].client_id);
    if (!ctx->sessions[slot].mtu_warned) {
        ctx->sessions[slot].mtu_warned = 1;
        first = 1;
    }

    pthread_mutex_unlock(&ctx->lock);

    mtu = (uint32_t)ctx->config->tun_mtu;

    packet_len = ipv6_build_packet_too_big(packet, sizeof(packet), src,
                                           inner->source_addr, mtu, payload,
                                           payload_len);
    if (packet_len == 0) {
        memset(key, 0, sizeof(key));
        return;
    }

    frame_len = pipesix_frame_build(frame, sizeof(frame), 0, ctx->salt,
                                    next_seq(ctx), packet, packet_len, key);
    memset(key, 0, sizeof(key));

    if (frame_len == 0) {
        return;
    }

    if (sendto(ctx->udp_fd, frame, frame_len, 0,
               (const struct sockaddr *)peer, peer_len) !=
        (ssize_t)frame_len) {
        log_debug("Failed to send ICMPv6 Packet Too Big: %s",
                  strerror(errno));
        return;
    }

    if (first) {
        log_warn("Client '%s' sent a %zu-byte packet but tun_mtu is %u; "
                 "returned ICMPv6 Packet Too Big so its kernel lowers the "
                 "path MTU",
                 client_id, payload_len, (unsigned)mtu);
    }
}

/*
 * Receiver loop (UDP -> TUN)
 */
static void *receiver_loop(void *arg)
{
    server_context_t *ctx = (server_context_t *)arg;
    uint8_t frame_buf[PIPESIX_RECV_BUF_SIZE];
    struct pollfd pfd;
    char period_name[24];

    pfd.fd = ctx->udp_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    log_info("Receiver thread started (UDP -> TUN)");

    while (!runtime_should_stop()) {
        struct sockaddr_storage peer;
        socklen_t peer_len = sizeof(peer);
        pipesix_frame_t frame;
        uint16_t flags;
        ssize_t nread;
        int ready;
        int rc;
        int slot;
        time_t now;
        char peer_str[NI_MAXHOST + NI_MAXSERV + 8];
        char mismatch_id[CONFIG_MAX_CLIENT_ID];
        uint8_t mismatch_src[16];
        uint8_t mismatch_prefix[16];
        int mismatch_prefix_len = 0;
        int mismatch = 0;
        char policy_id[CONFIG_MAX_CLIENT_ID];
        uint64_t policy_rate = 0;
        uint64_t policy_quota = 0;
        int policy_warn = 0;
        struct sockaddr_storage notify_addr;
        socklen_t notify_len = 0;
        uint8_t notify_key[PIPESIX_KEY_LEN];
        int notify_warn = 0;
        int notify_gone = 0;
        int source_denied = 0;
        int acl_denied = 0;
        int acl_audit = 0;
        char acl_id[CONFIG_MAX_CLIENT_ID];
        char acl_dest[INET6_ADDRSTRLEN];

        ready = poll(&pfd, 1, POLL_INTERVAL_MS);
        if (ready < 0) {
            if (errno == EINTR) continue;
            log_error("poll() on UDP socket failed: %s", strerror(errno));
            stats_add_error(&ctx->stats);
            runtime_request_stop();
            break;
        }
        if (ready == 0) {
            continue;
        }

        memset(&peer, 0, sizeof(peer));
        nread = recvfrom(ctx->udp_fd, frame_buf, sizeof(frame_buf), 0,
                         (struct sockaddr *)&peer, &peer_len);
        if (nread < 0) {
            if (errno == EINTR) continue;
            log_error("UDP recvfrom failed: %s", strerror(errno));
            stats_add_error(&ctx->stats);
            runtime_request_stop();
            break;
        }

        if (!peer_allowed(ctx, (struct sockaddr *)&peer, peer_len)) {
            log_debug("Dropping datagram from a non-allowed peer");
            stats_add_dropped(&ctx->stats);
            continue;
        }

        rc = pipesix_frame_peek(frame_buf, (size_t)nread, &flags);
        if (rc != PIPESIX_OK) {
            format_peer((struct sockaddr *)&peer, peer_len,
                        peer_str, sizeof(peer_str));
            log_warn("Dropping malformed datagram (%zd bytes) from %s: %s",
                     nread, peer_str, pipesix_strerror(rc));
            stats_add_invalid(&ctx->stats);
            continue;
        }

        if ((flags & PIPESIX_FLAG_HANDSHAKE_INIT) != 0) {
            pipesix_frame_t init;

            if (pipesix_frame_parse(frame_buf, (size_t)nread, &init, NULL) ==
                PIPESIX_OK) {
                handle_handshake_init(ctx, &peer, peer_len,
                                      init.payload, init.payload_len);
            } else {
                stats_add_invalid(&ctx->stats);
            }
            continue;
        }

        if ((flags & PIPESIX_FLAG_PROBE_REQ) != 0) {
            pipesix_frame_t probe;

            if (pipesix_frame_parse(frame_buf, (size_t)nread, &probe, NULL) ==
                PIPESIX_OK) {
                handle_probe(ctx, &peer, peer_len, probe.payload,
                             probe.payload_len);
            } else {
                stats_add_invalid(&ctx->stats);
            }
            continue;
        }

        if ((flags & (PIPESIX_FLAG_HANDSHAKE_RESP |
                      PIPESIX_FLAG_HANDSHAKE_NEEDED |
                      PIPESIX_FLAG_PROBE_RESP)) != 0) {
            continue;
        }

        pthread_mutex_lock(&ctx->lock);

        slot = session_find(ctx, &peer);
        if (slot < 0 || !ctx->sessions[slot].established) {
            pthread_mutex_unlock(&ctx->lock);
            send_need_handshake(ctx, &peer, peer_len);
            stats_add_dropped(&ctx->stats);
            continue;
        }

        rc = pipesix_frame_parse(frame_buf, (size_t)nread, &frame,
                                 ctx->sessions[slot].rx_key);
        if (rc != PIPESIX_OK) {
            pthread_mutex_unlock(&ctx->lock);
            format_peer((struct sockaddr *)&peer, peer_len,
                        peer_str, sizeof(peer_str));
            log_warn("Dropping invalid datagram (%zd bytes) from %s: %s",
                     nread, peer_str, pipesix_strerror(rc));
            stats_add_invalid(&ctx->stats);
            if (rc == PIPESIX_ERR_AUTH) {
                stats_add_auth_failure(&ctx->stats);
            }
            continue;
        }

        if (!pipesix_replay_accept(&ctx->sessions[slot].replay, frame.seq)) {
            pthread_mutex_unlock(&ctx->lock);
            log_warn("Rejected replayed/out-of-window frame (seq=%llu)",
                     (unsigned long long)frame.seq);
            stats_add_replayed(&ctx->stats);
            continue;
        }

        if ((frame.flags & PIPESIX_FLAG_QUOTA_REQUEST) != 0) {
            ctx->sessions[slot].quota_requested = 1;
            send_session_quota_state(ctx, &ctx->sessions[slot].addr,
                                     ctx->sessions[slot].addr_len,
                                     ctx->sessions[slot].tx_key,
                                     ctx->sessions[slot].client_index);
            pthread_mutex_unlock(&ctx->lock);
            continue;
        }

        now = time(NULL);
        ctx->sessions[slot].last_seen = now;
        ctx->sessions[slot].frames++;
        ctx->sessions[slot].rx_bytes += (uint64_t)frame.payload_len;

        /*
         * Per-client limits are applied to forwarded data only, and before
         * the TUN write so a throttled client never reaches the upstream.
         * The bucket belongs to this session and this thread; the daily
         * quota is shared with the sender, which is why it is atomic.
         */
        if ((frame.flags & PIPESIX_FLAG_KEEPALIVE) == 0 &&
            frame.payload_len > 0) {
            server_session_t *session = &ctx->sessions[slot];
            int allowed;
            int quota_over = 0;
            uint64_t now_ms = policy_now_ms();

            allowed = policy_bucket_allow(&session->rx_bucket,
                                          frame.payload_len, now_ms);

            if (allowed) {
                allowed = quota_admit(ctx, session, frame.payload_len, now,
                                      &notify_warn, &notify_gone,
                                      &quota_over);

                if (allowed && quota_over) {
                    allowed = policy_bucket_allow(&session->rx_over_bucket,
                                                  frame.payload_len, now_ms);
                }

                if (notify_warn || notify_gone) {
                    notify_addr = session->addr;
                    notify_len = session->addr_len;
                    memcpy(notify_key, session->tx_key, sizeof(notify_key));
                }
            }

            if (!allowed) {
                if (!session->policy_warned) {
                    session->policy_warned = 1;
                    policy_warn = 1;
                    snprintf(policy_id, sizeof(policy_id), "%s",
                             session->client_id);
                    if (session->policy_index >= 0) {
                        policy_rate =
                            ctx->config->policies[session->policy_index]
                                .rate_kbps;
                        policy_quota =
                            ctx->config->policies[session->policy_index]
                                .quota_mib;
                    }
                }

                session->throttled++;
                pthread_mutex_unlock(&ctx->lock);

                if (policy_warn) {
                    policy_period_name(ctx->config->quota_period,
                                       period_name, sizeof(period_name));
                    log_warn("Client '%s' exceeded its per-client limits; "
                             "%s traffic (rate %llu kbit/s, quota "
                             "%llu MiB/%s)",
                             policy_id,
                             quota_over ? "throttling" : "dropping",
                             (unsigned long long)policy_rate,
                             (unsigned long long)policy_quota,
                             period_name);
                }
                if (notify_gone) {
                    send_session_control(ctx, &notify_addr, notify_len,
                                         notify_key,
                                         PIPESIX_FLAG_QUOTA_EXHAUSTED);
                }
                stats_add_throttled(&ctx->stats);
                continue;
            }
        }

        /*
         * A client whose inner source address falls outside the route it
         * was given never sees the replies: the sender has no route for
         * that address. That is what a client and server configured for
         * different upstreams look like on the wire, and it is silent
         * otherwise, so report it once per session.
         *
         * The same parse gives the destination ACL and isolation check,
         * which is the boundary strict_source does not cover: a valid
         * client must not be able to reach another tenant's route.
         */
        if (frame.payload_len >= IPV6_HEADER_LEN) {
            const pipesix_ipv6_header_t *inner = NULL;

            if (ipv6_parse_header(frame.payload, frame.payload_len,
                                  &inner) == 0) {
                if (client_acl_denies(ctx->config,
                                      ctx->sessions[slot].client_id,
                                      inner->dest_addr)) {
                    acl_denied = 1;
                    snprintf(acl_id, sizeof(acl_id), "%s",
                             ctx->sessions[slot].client_id);
                    ipv6_addr_to_str(inner->dest_addr, acl_dest,
                                     sizeof(acl_dest));
                    if (!ctx->sessions[slot].acl_audited) {
                        ctx->sessions[slot].acl_audited = 1;
                        acl_audit = 1;
                    }
                }

                if ((ctx->config->strict_source ||
                     !ctx->sessions[slot].route_warned) &&
                    ctx->sessions[slot].prefix_len > 0 &&
                    !ipv6_prefix_match(ctx->sessions[slot].prefix,
                                       ctx->sessions[slot].prefix_len,
                                       inner->source_addr)) {
                    if (!ctx->sessions[slot].route_warned) {
                        ctx->sessions[slot].route_warned = 1;
                        mismatch = 1;
                        memcpy(mismatch_src, inner->source_addr,
                               sizeof(mismatch_src));
                        memcpy(mismatch_prefix, ctx->sessions[slot].prefix,
                               sizeof(mismatch_prefix));
                        mismatch_prefix_len = ctx->sessions[slot].prefix_len;
                        snprintf(mismatch_id, sizeof(mismatch_id), "%s",
                                 ctx->sessions[slot].client_id);
                    }
                    if (ctx->config->strict_source) {
                        source_denied = 1;
                    }
                }
            }
        }

        pthread_mutex_unlock(&ctx->lock);

        if (notify_gone || notify_warn) {
            send_session_control(ctx, &notify_addr, notify_len, notify_key,
                                 notify_gone
                                     ? PIPESIX_FLAG_QUOTA_EXHAUSTED
                                     : PIPESIX_FLAG_QUOTA_WARNING);
            memset(notify_key, 0, sizeof(notify_key));
        }

        if (acl_denied) {
            log_warn("Client '%s' sent a packet to %s, which its "
                     "destination policy or client_isolation forbids; "
                     "dropping it", acl_id, acl_dest);
            if (acl_audit) {
                audit_event("acl_denied", acl_id, "", "destination %s",
                            acl_dest);
            }
            stats_add_policy_denied(&ctx->stats);
            continue;
        }

        if (source_denied) {
            if (mismatch) {
                char src_str[INET6_ADDRSTRLEN];
                char prefix_str[INET6_ADDRSTRLEN];

                ipv6_addr_to_str(mismatch_src, src_str, sizeof(src_str));
                ipv6_addr_to_str(mismatch_prefix, prefix_str,
                                 sizeof(prefix_str));
                log_warn("Client '%s' sends from %s, which is outside its "
                         "route %s/%d; dropping the packet "
                         "(strict_source)",
                         mismatch_id, src_str, prefix_str,
                         mismatch_prefix_len);
            }
            stats_add_dropped(&ctx->stats);
            continue;
        }

        if (mismatch) {
            char src_str[INET6_ADDRSTRLEN];
            char prefix_str[INET6_ADDRSTRLEN];

            ipv6_addr_to_str(mismatch_src, src_str, sizeof(src_str));
            ipv6_addr_to_str(mismatch_prefix, prefix_str,
                             sizeof(prefix_str));

            log_warn("Client '%s' sends from %s, which is outside its "
                     "route %s/%d; return traffic will not reach it (check "
                     "that the client and server use the same "
                     "subnet/backend)",
                     mismatch_id, src_str, prefix_str,
                     mismatch_prefix_len);
        }

        if ((frame.flags & PIPESIX_FLAG_KEEPALIVE) != 0) {
            log_debug("Keepalive received from client");
            send_keepalive(ctx, &peer, peer_len);
            continue;
        }

        if (frame.payload_len == 0) {
            continue;
        }

        if (ipv6_validate_packet(frame.payload, frame.payload_len) != 0) {
            log_debug("Dropping frame with invalid IPv6 payload");
            stats_add_invalid(&ctx->stats);
            continue;
        }

        /*
         * Checked before the write: a kernel may drop an oversized packet
         * silently, or fail the write, and either way the client would keep
         * retrying it without ever learning why.
         */
        if (ctx->config->tun_mtu > 0 &&
            frame.payload_len > (size_t)ctx->config->tun_mtu) {
            send_packet_too_big(ctx, slot, &peer, peer_len, frame.payload,
                                frame.payload_len);
            stats_add_dropped(&ctx->stats);
            continue;
        }

        {
            ssize_t nwritten = tun_write(ctx->tun, frame.payload,
                                         frame.payload_len);

            if (nwritten < 0) {
                if (errno == EMSGSIZE) {
                    send_packet_too_big(ctx, slot, &peer, peer_len,
                                        frame.payload, frame.payload_len);
                    stats_add_dropped(&ctx->stats);
                } else {
                    log_error("TUN write failed: %s", strerror(errno));
                    stats_add_error(&ctx->stats);
                }
                continue;
            }
        }

        stats_add_rx(&ctx->stats, frame.payload_len);
        ipv6_log_packet(frame.payload, frame.payload_len, "RX");
    }

    log_info("Receiver thread exiting");
    return NULL;
}

/*
 * Sender loop (TUN -> UDP)
 */
static void *sender_loop(void *arg)
{
    server_context_t *ctx = (server_context_t *)arg;
    uint8_t packet[PIPESIX_MAX_PACKET];
    uint8_t frame[PIPESIX_MAX_FRAME];
    struct pollfd pfd;
    char period_name[24];

    pfd.fd = ctx->tun->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    log_info("Sender thread started (TUN -> UDP)");

    while (!runtime_should_stop()) {
        struct sockaddr_storage dest;
        socklen_t dest_len = 0;
        const pipesix_ipv6_header_t *header;
        uint8_t key[PIPESIX_KEY_LEN];
        ssize_t nread;
        int ready;
        int slot;
        uint64_t seq;
        size_t frame_len;
        char denied_id[CONFIG_MAX_CLIENT_ID];
        uint64_t policy_rate = 0;
        uint64_t policy_quota = 0;
        int denied = 0;
        int denied_warn = 0;
        struct sockaddr_storage notify_addr;
        socklen_t notify_len = 0;
        uint8_t notify_key[PIPESIX_KEY_LEN];
        int notify_warn = 0;
        int notify_gone = 0;
        int quota_over = 0;

        ready = poll(&pfd, 1, POLL_INTERVAL_MS);
        if (ready < 0) {
            if (errno == EINTR) continue;
            log_error("poll() on TUN failed: %s", strerror(errno));
            stats_add_error(&ctx->stats);
            runtime_request_stop();
            break;
        }
        if (ready == 0) {
            continue;
        }

        nread = tun_read(ctx->tun, packet, sizeof(packet));
        if (nread < 0) {
            if (errno != EINTR) {
                log_error("TUN read failed: %s", strerror(errno));
                stats_add_error(&ctx->stats);
            }
            continue;
        }
        if (nread == 0) {
            continue;
        }

        if (ipv6_parse_header(packet, (size_t)nread, &header) != 0) {
            stats_add_invalid(&ctx->stats);
            continue;
        }

        memset(&dest, 0, sizeof(dest));
        memset(key, 0, sizeof(key));

        pthread_mutex_lock(&ctx->lock);

        slot = route_lookup(ctx, header->dest_addr);
        if (slot < 0) {
            /* No learned route: a single client gets everything. */
            slot = sole_session(ctx);
        }

        /*
         * Egress policy: the client pays for return traffic too. Checked
         * before the key is copied, so a throttled packet never touches
         * the crypto path.
         */
        if (slot >= 0) {
            server_session_t *session = &ctx->sessions[slot];
            int allowed;
            uint64_t now_ms = policy_now_ms();

            allowed = policy_bucket_allow(&session->tx_bucket,
                                          (size_t)nread, now_ms);

            if (allowed) {
                allowed = quota_admit(ctx, session, (size_t)nread,
                                      time(NULL), &notify_warn,
                                      &notify_gone, &quota_over);

                if (allowed && quota_over) {
                    allowed = policy_bucket_allow(&session->tx_over_bucket,
                                                  (size_t)nread, now_ms);
                }

                if (notify_warn || notify_gone) {
                    notify_addr = session->addr;
                    notify_len = session->addr_len;
                    memcpy(notify_key, session->tx_key, sizeof(notify_key));
                }
            }

            if (!allowed) {
                denied = 1;
                session->throttled++;
                if (!session->policy_warned) {
                    session->policy_warned = 1;
                    denied_warn = 1;
                    snprintf(denied_id, sizeof(denied_id), "%s",
                             session->client_id);
                    if (session->policy_index >= 0) {
                        policy_rate =
                            ctx->config->policies[session->policy_index]
                                .rate_kbps;
                        policy_quota =
                            ctx->config->policies[session->policy_index]
                                .quota_mib;
                    }
                }
            } else {
                dest = session->addr;
                dest_len = session->addr_len;
                memcpy(key, session->tx_key, sizeof(key));
                /*
                 * Counted when the packet is handed to sendto();
                 * attributing a rare send failure would need a second pass
                 * over the lock.
                 */
                session->tx_bytes += (uint64_t)nread;
            }
        }

        pthread_mutex_unlock(&ctx->lock);

        if (notify_gone || notify_warn) {
            send_session_control(ctx, &notify_addr, notify_len, notify_key,
                                 notify_gone
                                     ? PIPESIX_FLAG_QUOTA_EXHAUSTED
                                     : PIPESIX_FLAG_QUOTA_WARNING);
            memset(notify_key, 0, sizeof(notify_key));
        }

        if (denied) {
            if (denied_warn) {
                policy_period_name(ctx->config->quota_period,
                                   period_name, sizeof(period_name));
                log_warn("Client '%s' exceeded its per-client limits; "
                         "%s traffic (rate %llu kbit/s, quota "
                         "%llu MiB/%s)",
                         denied_id,
                         quota_over ? "throttling" : "dropping",
                         (unsigned long long)policy_rate,
                         (unsigned long long)policy_quota,
                         period_name);
            }
            stats_add_throttled(&ctx->stats);
            continue;
        }

        if (slot < 0) {
            stats_add_dropped(&ctx->stats);
            continue;
        }

        seq = next_seq(ctx);
        frame_len = pipesix_frame_build(frame, sizeof(frame), 0, ctx->salt,
                                        seq, packet, (size_t)nread, key);
        memset(key, 0, sizeof(key));

        if (frame_len == 0) {
            log_warn("Failed to build frame for %zd-byte packet", nread);
            stats_add_dropped(&ctx->stats);
            continue;
        }

        if (sendto(ctx->udp_fd, frame, frame_len, 0,
                   (struct sockaddr *)&dest, dest_len) !=
            (ssize_t)frame_len) {
            log_error("UDP send to client failed: %s", strerror(errno));
            stats_add_error(&ctx->stats);
            continue;
        }

        stats_add_tx(&ctx->stats, (size_t)nread);
        ipv6_log_packet(packet, (size_t)nread, "TX");
    }

    log_info("Sender thread exiting");
    return NULL;
}

static int bind_socket(const pipesix_config_t *config)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp;
    char port_str[16];
    int gai;
    int fd = -1;
    int family = AF_UNSPEC;

    snprintf(port_str, sizeof(port_str), "%d", config->bind_port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_PASSIVE;

    gai = getaddrinfo(config->bind_address, port_str, &hints, &result);
    if (gai != 0) {
        log_error("Failed to resolve bind address '%s': %s",
                  config->bind_address, gai_strerror(gai));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        int optval = 1;

        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }

        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

        if (rp->ai_family == AF_INET6) {
            int off = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
        }

        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            family = rp->ai_family;
            break;
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(result);

    if (fd < 0) {
        log_error("Failed to bind UDP socket to %s:%d: %s",
                  config->bind_address, config->bind_port, strerror(errno));
        return -1;
    }

    log_info("UDP server listening on %s:%d (%s, fd=%d)",
             config->bind_address, config->bind_port,
             family == AF_INET6 ? "AF_INET6" : "AF_INET", fd);

    return fd;
}

/*
 * ---------------------------------------------------------------------
 * Control channel (--status, --kick)
 * ---------------------------------------------------------------------
 */

/*
 * Append to a reply buffer, reporting when the text no longer fits.
 *
 * The format attribute makes every call site compile-checked. The
 * diagnostic pragma below covers the vsnprintf() inside this wrapper,
 * which necessarily receives the format as a parameter; with the
 * attribute in place that is the only place the format is not a literal.
 */
static int server_control_append(char *buf, size_t size, size_t *used,
                                 const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static int server_control_append(char *buf, size_t size, size_t *used,
                                 const char *fmt, ...)
{
    va_list args;
    int n;

    if (*used >= size) {
        return -1;
    }

    va_start(args, fmt);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
    n = vsnprintf(buf + *used, size - *used, fmt, args);
#pragma GCC diagnostic pop
    va_end(args);

    if (n < 0) {
        return -1;
    }
    if ((size_t)n >= size - *used) {
        buf[size - 1] = '\0';
        return -1;
    }

    *used += (size_t)n;
    return 0;
}

/*
 * Format the current state into a control reply.
 *
 * The session table is snapshotted under the lock and formatted after it
 * is released, so an operator running --status never stalls the data
 * path behind getnameinfo() or a large write.
 */
static const char *client_state_text(const pipesix_client_cred_t *cred,
                                     time_t now);

static int server_status(server_context_t *ctx, char *reply, size_t size)
{
    char ids[SERVER_MAX_CLIENTS][CONFIG_MAX_CLIENT_ID];
    char peers[SERVER_MAX_CLIENTS][96];
    char routes[SERVER_MAX_CLIENTS][INET6_ADDRSTRLEN + 8];
    char limits[SERVER_MAX_CLIENTS][256];
    char period_name[24];
    uint64_t frames[SERVER_MAX_CLIENTS];
    uint64_t rx_bytes[SERVER_MAX_CLIENTS];
    uint64_t tx_bytes[SERVER_MAX_CLIENTS];
    uint64_t rate_in_kbps[SERVER_MAX_CLIENTS];
    uint64_t rate_out_kbps[SERVER_MAX_CLIENTS];
    uint64_t quota_mib[SERVER_MAX_CLIENTS];
    uint64_t quota_remaining[SERVER_MAX_CLIENTS];
    char states[SERVER_MAX_CLIENTS][16];
    int64_t expires_at[SERVER_MAX_CLIENTS];
    int staged_key[SERVER_MAX_CLIENTS];
    long idle[SERVER_MAX_CLIENTS];
    time_t now = time(NULL);
    time_t started = ctx->stats.started;
    unsigned long uptime;
    size_t used = 0;
    int count = 0;
    int i;

    policy_period_name(ctx->config->quota_period, period_name,
                       sizeof(period_name));

    pthread_mutex_lock(&ctx->lock);

    for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
        server_session_t *session = &ctx->sessions[i];

        if (!session->active) {
            continue;
        }

        snprintf(ids[count], sizeof(ids[count]), "%s",
                 session->client_id[0] != '\0' ? session->client_id : "?");
        format_peer((const struct sockaddr *)&session->addr,
                    session->addr_len, peers[count], sizeof(peers[count]));

        {
            const pipesix_client_cred_t *cred =
                config_find_client(ctx->config, ids[count]);

            snprintf(states[count], sizeof(states[count]), "%s",
                     client_state_text(cred, now));
            expires_at[count] = (cred != NULL && cred->has_expiry)
                                    ? cred->expires_at
                                    : 0;
            staged_key[count] = (cred != NULL && cred->has_next_secret);
        }

        if (session->prefix_len > 0) {
            char prefix_str[INET6_ADDRSTRLEN];

            if (inet_ntop(AF_INET6, session->prefix, prefix_str,
                          sizeof(prefix_str)) != NULL) {
                snprintf(routes[count], sizeof(routes[count]), "%s/%d",
                         prefix_str, session->prefix_len);
            } else {
                snprintf(routes[count], sizeof(routes[count]), "?/%d",
                         session->prefix_len);
            }
        } else {
            snprintf(routes[count], sizeof(routes[count]), "none");
        }

        frames[count] = session->frames;
        rx_bytes[count] = session->rx_bytes;
        tx_bytes[count] = session->tx_bytes;
        rate_in_kbps[count] = 0;
        rate_out_kbps[count] = 0;
        quota_mib[count] = 0;
        quota_remaining[count] = 0;
        snprintf(limits[count], sizeof(limits[count]), "null");

        if (session->policy_index >= 0) {
            const pipesix_client_policy_t *policy =
                &ctx->config->policies[session->policy_index];

            rate_in_kbps[count] = pipesix_policy_rate_in(policy);
            rate_out_kbps[count] = pipesix_policy_rate_out(policy);
            quota_mib[count] = policy->quota_mib;

            if (policy->quota_mib > 0 && session->client_index >= 0) {
                quota_remaining[count] = policy_quota_remaining(
                    &ctx->quotas[session->client_index],
                    policy_period(now, ctx->config->quota_period));
            }

            snprintf(limits[count], sizeof(limits[count]),
                     "{\"rate_kbps\":%llu,\"rate_in_kbps\":%llu,"
                     "\"rate_out_kbps\":%llu,\"quota_mib\":%llu,"
                     "\"quota_period\":\"%s\","
                     "\"quota_remaining_bytes\":%llu}",
                     (unsigned long long)((rate_in_kbps[count] >
                                           rate_out_kbps[count])
                                              ? rate_in_kbps[count]
                                              : rate_out_kbps[count]),
                     (unsigned long long)rate_in_kbps[count],
                     (unsigned long long)rate_out_kbps[count],
                     (unsigned long long)quota_mib[count],
                     period_name,
                     (unsigned long long)quota_remaining[count]);
        }

        idle[count] = (long)(now - session->last_seen);
        count++;
    }

    pthread_mutex_unlock(&ctx->lock);

    uptime = (now > started) ? (unsigned long)(now - started) : 0ul;

    if (server_control_append(reply, size, &used, "OK\n") != 0 ||
        server_control_append(reply, size, &used, "mode: server\n") != 0 ||
        server_control_append(reply, size, &used, "config: %s\n",
                              ctx->config->config_path) != 0 ||
        server_control_append(reply, size, &used, "uptime: %lus\n",
                              uptime) != 0 ||
        server_control_append(reply, size, &used, "tun: %s %s/%d\n",
                              ctx->config->tun_name,
                              ctx->config->tun_address,
                              ctx->config->tun_prefixlen) != 0 ||
        server_control_append(reply, size, &used, "listen: %s:%d\n",
                              ctx->config->bind_address,
                              ctx->config->bind_port) != 0 ||
        server_control_append(reply, size, &used, "sessions: %d of %d\n",
                              count, SERVER_MAX_CLIENTS) != 0) {
        return -1;
    }

    for (i = 0; i < count; i++) {
        if (server_control_append(reply, size, &used,
                                  "  %s from %s rx=%llu B tx=%llu B "
                                  "frames=%llu idle=%lds route=%s",
                                  ids[i], peers[i],
                                  (unsigned long long)rx_bytes[i],
                                  (unsigned long long)tx_bytes[i],
                                  (unsigned long long)frames[i],
                                  idle[i], routes[i]) != 0) {
            return -1;
        }

        if (rate_in_kbps[i] > 0 || rate_out_kbps[i] > 0) {
            if (server_control_append(reply, size, &used,
                                      " rate=%llu/%llu kbit/s",
                                      (unsigned long long)rate_in_kbps[i],
                                      (unsigned long long)rate_out_kbps[i]) !=
                0) {
                return -1;
            }
        }

        if (quota_mib[i] > 0 &&
            server_control_append(reply, size, &used,
                                  " quota=%llu MiB/%s left=%llu B",
                                  (unsigned long long)quota_mib[i],
                                  period_name,
                                  (unsigned long long)quota_remaining[i]) != 0) {
            return -1;
        }

        if (server_control_append(
                reply, size, &used,
                " state=%s expires_at=%lld staged_key=%s\n", states[i],
                (long long)expires_at[i], staged_key[i] ? "yes" : "no") !=
            0) {
            return -1;
        }
    }

    {
        char stats_line[512];

        stats_format(&ctx->stats, "server", stats_line, sizeof(stats_line));

        if (server_control_append(reply, size, &used, "%s\n",
                                  stats_line) != 0) {
            return -1;
        }
    }

    return 0;
}

/*
 * Format the current state as JSON, for --status --json.
 *
 * Same snapshot as server_status(): the session table is copied under the
 * lock and formatted afterwards. Client ids come from validated
 * configuration, and peers and routes are numeric, so only the strings an
 * operator sets need escaping.
 */
static int server_status_json(server_context_t *ctx, char *reply, size_t size)
{
    char ids[SERVER_MAX_CLIENTS][CONFIG_MAX_CLIENT_ID];
    char peers[SERVER_MAX_CLIENTS][96];
    char routes[SERVER_MAX_CLIENTS][INET6_ADDRSTRLEN + 12];
    char limits[SERVER_MAX_CLIENTS][256];
    char states[SERVER_MAX_CLIENTS][16];
    int64_t expires_at[SERVER_MAX_CLIENTS];
    int staged_key[SERVER_MAX_CLIENTS];
    char period_name[24];
    uint64_t frames[SERVER_MAX_CLIENTS];
    uint64_t rx_bytes[SERVER_MAX_CLIENTS];
    uint64_t tx_bytes[SERVER_MAX_CLIENTS];
    uint64_t rate_in_kbps[SERVER_MAX_CLIENTS];
    uint64_t rate_out_kbps[SERVER_MAX_CLIENTS];
    uint64_t quota_mib[SERVER_MAX_CLIENTS];
    uint64_t quota_remaining[SERVER_MAX_CLIENTS];
    long idle[SERVER_MAX_CLIENTS];
    char config_esc[1024];
    char tun_name_esc[256];
    char tun_addr_esc[256];
    char bind_esc[256];
    char stats_json[768];
    time_t now = time(NULL);
    time_t started = ctx->stats.started;
    unsigned long uptime;
    size_t used = 0;
    int count = 0;
    int i;

    policy_period_name(ctx->config->quota_period, period_name,
                       sizeof(period_name));

    pthread_mutex_lock(&ctx->lock);

    for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
        server_session_t *session = &ctx->sessions[i];

        if (!session->active) {
            continue;
        }

        snprintf(ids[count], sizeof(ids[count]), "%s",
                 session->client_id[0] != '\0' ? session->client_id : "?");
        format_peer((const struct sockaddr *)&session->addr,
                    session->addr_len, peers[count], sizeof(peers[count]));

        {
            const pipesix_client_cred_t *cred =
                config_find_client(ctx->config, ids[count]);

            snprintf(states[count], sizeof(states[count]), "%s",
                     client_state_text(cred, now));
            expires_at[count] = (cred != NULL && cred->has_expiry)
                                    ? cred->expires_at
                                    : 0;
            staged_key[count] = (cred != NULL && cred->has_next_secret);
        }

        if (session->prefix_len > 0) {
            char prefix_str[INET6_ADDRSTRLEN];

            if (inet_ntop(AF_INET6, session->prefix, prefix_str,
                          sizeof(prefix_str)) != NULL) {
                snprintf(routes[count], sizeof(routes[count]),
                         "\"%s/%d\"", prefix_str, session->prefix_len);
            } else {
                snprintf(routes[count], sizeof(routes[count]),
                         "\"?/%d\"", session->prefix_len);
            }
        } else {
            snprintf(routes[count], sizeof(routes[count]), "null");
        }

        frames[count] = session->frames;
        rx_bytes[count] = session->rx_bytes;
        tx_bytes[count] = session->tx_bytes;
        rate_in_kbps[count] = 0;
        rate_out_kbps[count] = 0;
        quota_mib[count] = 0;
        quota_remaining[count] = 0;
        snprintf(limits[count], sizeof(limits[count]), "null");

        if (session->policy_index >= 0) {
            const pipesix_client_policy_t *policy =
                &ctx->config->policies[session->policy_index];

            rate_in_kbps[count] = pipesix_policy_rate_in(policy);
            rate_out_kbps[count] = pipesix_policy_rate_out(policy);
            quota_mib[count] = policy->quota_mib;

            if (policy->quota_mib > 0 && session->client_index >= 0) {
                quota_remaining[count] = policy_quota_remaining(
                    &ctx->quotas[session->client_index],
                    policy_period(now, ctx->config->quota_period));
            }

            snprintf(limits[count], sizeof(limits[count]),
                     "{\"rate_kbps\":%llu,\"rate_in_kbps\":%llu,"
                     "\"rate_out_kbps\":%llu,\"quota_mib\":%llu,"
                     "\"quota_period\":\"%s\","
                     "\"quota_remaining_bytes\":%llu}",
                     (unsigned long long)((rate_in_kbps[count] >
                                           rate_out_kbps[count])
                                              ? rate_in_kbps[count]
                                              : rate_out_kbps[count]),
                     (unsigned long long)rate_in_kbps[count],
                     (unsigned long long)rate_out_kbps[count],
                     (unsigned long long)quota_mib[count],
                     period_name,
                     (unsigned long long)quota_remaining[count]);
        }

        idle[count] = (long)(now - session->last_seen);
        count++;
    }

    pthread_mutex_unlock(&ctx->lock);

    uptime = (now > started) ? (unsigned long)(now - started) : 0ul;

    if (control_json_escape(ctx->config->config_path, config_esc,
                            sizeof(config_esc)) != 0 ||
        control_json_escape(ctx->config->tun_name, tun_name_esc,
                            sizeof(tun_name_esc)) != 0 ||
        control_json_escape(ctx->config->tun_address, tun_addr_esc,
                            sizeof(tun_addr_esc)) != 0 ||
        control_json_escape(ctx->config->bind_address, bind_esc,
                            sizeof(bind_esc)) != 0) {
        snprintf(reply, size, "ERR cannot encode the status as JSON\n");
        return -1;
    }

    if (server_control_append(
            reply, size, &used,
            "OK\n{\"mode\":\"server\",\"config\":\"%s\","
            "\"uptime_seconds\":%lu,"
            "\"tun\":{\"name\":\"%s\",\"address\":\"%s\","
            "\"prefixlen\":%d},"
            "\"listen\":{\"address\":\"%s\",\"port\":%d},"
            "\"sessions\":{\"active\":%d,\"capacity\":%d,"
            "\"clients\":[",
            config_esc, uptime, tun_name_esc, tun_addr_esc,
            ctx->config->tun_prefixlen, bind_esc, ctx->config->bind_port,
            count, SERVER_MAX_CLIENTS) != 0) {
        goto too_large;
    }

    for (i = 0; i < count; i++) {
        if (server_control_append(
                reply, size, &used,
                "%s{\"client_id\":\"%s\",\"peer\":\"%s\","
                "\"rx_bytes\":%llu,\"tx_bytes\":%llu,\"frames\":%llu,"
                "\"idle_seconds\":%ld,\"route\":%s,\"limits\":%s,"
                "\"state\":\"%s\",\"expires_at\":%lld,"
                "\"staged_key\":%s}",
                i > 0 ? "," : "", ids[i], peers[i],
                (unsigned long long)rx_bytes[i],
                (unsigned long long)tx_bytes[i],
                (unsigned long long)frames[i], idle[i], routes[i],
                limits[i], states[i], (long long)expires_at[i],
                staged_key[i] ? "true" : "false") != 0) {
            goto too_large;
        }
    }

    stats_format_json(&ctx->stats, "server", stats_json,
                      sizeof(stats_json));

    if (server_control_append(reply, size, &used, "]},\"stats\":%s}\n",
                              stats_json) != 0) {
        goto too_large;
    }

    return 0;

too_large:
    snprintf(reply, size, "ERR status is too large to report\n");
    return -1;
}

/*
 * Format the per-client usage report, for --usage.
 *
 * Unlike --status this walks the credential table, not the session table,
 * so a client that is currently offline still shows the bytes it moved
 * today (and its remaining quota). All three formats are one control
 * reply: text keeps the OK line like --status, JSON and CSV are stripped
 * by the CLI before they reach stdout.
 */
typedef enum {
    USAGE_TEXT,
    USAGE_JSON,
    USAGE_CSV
} usage_format_t;

/* Administrative state shown by --status and --usage. */
static const char *client_state_text(const pipesix_client_cred_t *cred,
                                     time_t now)
{
    if (cred == NULL) {
        return "unknown";
    }
    if (cred->disabled) {
        return "disabled";
    }
    if (cred->has_expiry && cred->expires_at <= (int64_t)now) {
        return "expired";
    }
    return "enabled";
}

static int server_usage(server_context_t *ctx, char *reply, size_t size,
                        usage_format_t format)
{
    char ids[CONFIG_MAX_CLIENTS][CONFIG_MAX_CLIENT_ID];
    uint64_t bytes_used[CONFIG_MAX_CLIENTS];
    uint64_t quota[CONFIG_MAX_CLIENTS];
    uint64_t left[CONFIG_MAX_CLIENTS];
    uint64_t rate[CONFIG_MAX_CLIENTS];
    int connected[CONFIG_MAX_CLIENTS];
    char states[CONFIG_MAX_CLIENTS][16];
    int64_t expires_at[CONFIG_MAX_CLIENTS];
    int staged_key[CONFIG_MAX_CLIENTS];
    char config_esc[1024];
    char start_str[16] = "?";
    char end_str[16] = "?";
    char kind[24];
    time_t now = time(NULL);
    int period = policy_period(now, ctx->config->quota_period);
    time_t start = policy_period_start(period, ctx->config->quota_period);
    time_t end = policy_period_end(period, ctx->config->quota_period);

    policy_period_name(ctx->config->quota_period, kind, sizeof(kind));
    struct tm tm;
    size_t len = 0;
    int count = 0;
    int i;
    int j;

    if (gmtime_r(&start, &tm) == NULL ||
        strftime(start_str, sizeof(start_str), "%Y-%m-%d", &tm) == 0) {
        snprintf(start_str, sizeof(start_str), "start-%d", period);
    }
    if (gmtime_r(&end, &tm) == NULL ||
        strftime(end_str, sizeof(end_str), "%Y-%m-%d", &tm) == 0) {
        snprintf(end_str, sizeof(end_str), "end-%d", period);
    }

    pthread_mutex_lock(&ctx->lock);

    for (i = 0; i < ctx->config->client_count; i++) {
        const char *id = ctx->config->clients[i].id;
        int policy = policy_lookup(ctx->config, id);

        snprintf(ids[count], sizeof(ids[count]), "%s", id);
        bytes_used[count] = policy_quota_used(&ctx->quotas[i], period);
        quota[count] = ctx->quotas[i].limit;
        left[count] = (quota[count] > 0)
                          ? policy_quota_remaining(&ctx->quotas[i], period)
                          : 0;
        if (policy >= 0) {
            uint64_t rate_in = pipesix_policy_rate_in(
                &ctx->config->policies[policy]);
            uint64_t rate_out = pipesix_policy_rate_out(
                &ctx->config->policies[policy]);
            rate[count] = rate_in > rate_out ? rate_in : rate_out;
        } else {
            rate[count] = 0;
        }
        connected[count] = 0;
        snprintf(states[count], sizeof(states[count]), "%s",
                 client_state_text(&ctx->config->clients[i], now));
        expires_at[count] = ctx->config->clients[i].has_expiry
                                ? ctx->config->clients[i].expires_at
                                : 0;
        staged_key[count] = ctx->config->clients[i].has_next_secret;

        for (j = 0; j < SERVER_MAX_CLIENTS; j++) {
            if (ctx->sessions[j].active &&
                strcmp(ctx->sessions[j].client_id, ids[count]) == 0) {
                connected[count] = 1;
                break;
            }
        }

        count++;
    }

    pthread_mutex_unlock(&ctx->lock);

    if (format == USAGE_CSV) {
        if (server_control_append(
                reply, size, &len,
                "OK\nclient_id,period_start,period_end,used_bytes,"
                "quota_bytes,quota_remaining_bytes,rate_kbps,connected,"
                "state,expires_at,staged_key\n") != 0) {
            return -1;
        }

        for (i = 0; i < count; i++) {
            if (server_control_append(
                    reply, size, &len,
                    "%s,%s,%s,%llu,%llu,%llu,%llu,%s,%s,%lld,%s\n",
                    ids[i], start_str, end_str,
                    (unsigned long long)bytes_used[i],
                    (unsigned long long)quota[i],
                    (unsigned long long)left[i],
                    (unsigned long long)rate[i],
                    connected[i] ? "true" : "false", states[i],
                    (long long)expires_at[i],
                    staged_key[i] ? "true" : "false") != 0) {
                return -1;
            }
        }

        return 0;
    }

    if (format == USAGE_JSON) {
        if (control_json_escape(ctx->config->config_path, config_esc,
                                sizeof(config_esc)) != 0) {
            snprintf(reply, size, "ERR cannot encode the usage as JSON\n");
            return -1;
        }

        if (server_control_append(
                reply, size, &len,
                "OK\n{\"mode\":\"server\",\"config\":\"%s\","
                "\"period\":{\"kind\":\"%s\",\"start_unix\":%lld,"
                "\"end_unix\":%lld},\"clients\":[",
                config_esc, kind, (long long)start, (long long)end) != 0) {
            goto too_large;
        }

        for (i = 0; i < count; i++) {
            if (server_control_append(
                    reply, size, &len,
                    "%s{\"client_id\":\"%s\",\"used_bytes\":%llu,"
                    "\"quota_bytes\":%llu,"
                    "\"quota_remaining_bytes\":%llu,"
                    "\"rate_kbps\":%llu,\"connected\":%s,"
                    "\"state\":\"%s\",\"expires_at\":%lld,"
                    "\"staged_key\":%s}",
                    i > 0 ? "," : "", ids[i],
                    (unsigned long long)bytes_used[i],
                    (unsigned long long)quota[i],
                    (unsigned long long)left[i],
                    (unsigned long long)rate[i],
                    connected[i] ? "true" : "false", states[i],
                    (long long)expires_at[i],
                    staged_key[i] ? "true" : "false") != 0) {
                goto too_large;
            }
        }

        if (server_control_append(reply, size, &len, "]}\n") != 0) {
            goto too_large;
        }

        return 0;
    }

    if (server_control_append(reply, size, &len,
                              "OK\nmode: server\nconfig: %s\n"
                              "period: %s %s..%s UTC\n"
                              "usage: %d client(s)\n",
                              ctx->config->config_path, kind, start_str,
                              end_str, count) != 0) {
        goto too_large;
    }

    for (i = 0; i < count; i++) {
        if (server_control_append(reply, size, &len, "  %s used=%llu B",
                                  ids[i],
                                  (unsigned long long)bytes_used[i]) != 0) {
            goto too_large;
        }

        if (quota[i] > 0) {
            if (server_control_append(reply, size, &len,
                                      " quota=%llu B left=%llu B",
                                      (unsigned long long)quota[i],
                                      (unsigned long long)left[i]) != 0) {
                goto too_large;
            }
        } else if (server_control_append(reply, size, &len,
                                         " quota=unlimited") != 0) {
            goto too_large;
        }

        if (rate[i] > 0) {
            if (server_control_append(reply, size, &len,
                                      " rate=%llu kbit/s",
                                      (unsigned long long)rate[i]) != 0) {
                goto too_large;
            }
        } else if (server_control_append(reply, size, &len,
                                         " rate=unlimited") != 0) {
            goto too_large;
        }

        if (server_control_append(
                reply, size, &len,
                " connected=%s state=%s expires_at=%lld staged_key=%s\n",
                connected[i] ? "yes" : "no", states[i],
                (long long)expires_at[i],
                staged_key[i] ? "yes" : "no") != 0) {
            goto too_large;
        }
    }

    return 0;

too_large:
    snprintf(reply, size, "ERR usage is too large to report\n");
    return -1;
}

/*
 * Render the Prometheus body for the metrics endpoint.
 *
 * Same rule as --status: the session table is copied under the lock and
 * formatted afterwards, so a scrape never stalls the data path behind a
 * full table. Client ids are validated at configuration time, so they
 * need no label escaping.
 */
static int server_ready(char *out, size_t size, void *arg)
{
    server_context_t *ctx = (server_context_t *)arg;
    int sessions;

    if (ctx->tun == NULL || ctx->tun->fd < 0 || ctx->udp_fd < 0) {
        snprintf(out, size, "not ready: tun or socket is closed\n");
        return 0;
    }

    pthread_mutex_lock(&ctx->lock);
    sessions = count_active(ctx);
    pthread_mutex_unlock(&ctx->lock);

    snprintf(out, size, "ready: tun=ok udp=ok sessions=%d\n", sessions);
    return 1;
}

static int server_metrics_body(char *out, size_t size, void *arg)
{
    server_context_t *ctx = (server_context_t *)arg;
    char ids[SERVER_MAX_CLIENTS][CONFIG_MAX_CLIENT_ID];
    uint64_t frames[SERVER_MAX_CLIENTS];
    uint64_t rx_bytes[SERVER_MAX_CLIENTS];
    uint64_t tx_bytes[SERVER_MAX_CLIENTS];
    uint64_t throttled[SERVER_MAX_CLIENTS];
    uint64_t quota_limit[SERVER_MAX_CLIENTS];
    uint64_t quota_remaining[SERVER_MAX_CLIENTS];
    long idle[SERVER_MAX_CLIENTS];
    time_t now = time(NULL);
    size_t used;
    int count = 0;
    int i;

    pthread_mutex_lock(&ctx->lock);

    for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
        server_session_t *session = &ctx->sessions[i];

        if (!session->active) {
            continue;
        }

        snprintf(ids[count], sizeof(ids[count]), "%s",
                 session->client_id[0] != '\0' ? session->client_id : "?");
        frames[count] = session->frames;
        rx_bytes[count] = session->rx_bytes;
        tx_bytes[count] = session->tx_bytes;
        throttled[count] = session->throttled;
        quota_limit[count] = 0;
        quota_remaining[count] = 0;

        if (session->policy_index >= 0 &&
            ctx->config->policies[session->policy_index].quota_mib > 0 &&
            session->client_index >= 0) {
            quota_limit[count] = ctx->quotas[session->client_index].limit;
            quota_remaining[count] = policy_quota_remaining(
                &ctx->quotas[session->client_index],
                policy_period(now, ctx->config->quota_period));
        }

        idle[count] = (long)(now - session->last_seen);
        count++;
    }

    pthread_mutex_unlock(&ctx->lock);

    if (stats_format_prometheus(&ctx->stats, "server", out, size) != 0) {
        return -1;
    }

    used = strlen(out);

    if (server_control_append(
            out, size, &used,
            "# HELP pipesix_sessions_active Authenticated sessions in the "
            "table.\n# TYPE pipesix_sessions_active gauge\n"
            "pipesix_sessions_active %d\n"
            "# HELP pipesix_sessions_capacity Session table capacity.\n"
            "# TYPE pipesix_sessions_capacity gauge\n"
            "pipesix_sessions_capacity %d\n",
            count, SERVER_MAX_CLIENTS) != 0) {
        return -1;
    }

    if (server_control_append(
            out, size, &used,
            "# HELP pipesix_session_rx_bytes Bytes one client has sent "
            "since it connected.\n# TYPE pipesix_session_rx_bytes gauge\n"
            "# HELP pipesix_session_tx_bytes Bytes sent to one client since "
            "it connected.\n# TYPE pipesix_session_tx_bytes gauge\n"
            "# HELP pipesix_session_frames Frames accepted from one "
            "client.\n# TYPE pipesix_session_frames gauge\n"
            "# HELP pipesix_session_idle_seconds Seconds since the last "
            "frame from one client.\n"
            "# TYPE pipesix_session_idle_seconds gauge\n"
            "# HELP pipesix_session_throttled Packets dropped by one "
            "client's rate or quota limits since it connected.\n"
            "# TYPE pipesix_session_throttled gauge\n"
            "# HELP pipesix_session_quota_limit_bytes Bytes one client may "
            "move per quota period. Only exported for clients with a "
            "quota.\n"
            "# TYPE pipesix_session_quota_limit_bytes gauge\n"
            "# HELP pipesix_session_quota_remaining_bytes Bytes left in one "
            "client's quota for the current period. Only exported for "
            "clients with a quota.\n"
            "# TYPE pipesix_session_quota_remaining_bytes gauge\n") != 0) {
        return -1;
    }

    for (i = 0; i < count; i++) {
        if (server_control_append(
                out, size, &used,
                "pipesix_session_throttled{client=\"%s\"} %llu\n",
                ids[i], (unsigned long long)throttled[i]) != 0) {
            return -1;
        }

        if (quota_limit[i] > 0 &&
            server_control_append(
                out, size, &used,
                "pipesix_session_quota_limit_bytes{client=\"%s\"} %llu\n"
                "pipesix_session_quota_remaining_bytes{client=\"%s\"} "
                "%llu\n",
                ids[i], (unsigned long long)quota_limit[i],
                ids[i], (unsigned long long)quota_remaining[i]) != 0) {
            return -1;
        }

        if (server_control_append(
                out, size, &used,
                "pipesix_session_rx_bytes{client=\"%s\"} %llu\n"
                "pipesix_session_tx_bytes{client=\"%s\"} %llu\n"
                "pipesix_session_frames{client=\"%s\"} %llu\n"
                "pipesix_session_idle_seconds{client=\"%s\"} %ld\n",
                ids[i], (unsigned long long)rx_bytes[i],
                ids[i], (unsigned long long)tx_bytes[i],
                ids[i], (unsigned long long)frames[i],
                ids[i], idle[i]) != 0) {
            return -1;
        }
    }

    return 0;
}

/*
 * Drop every session that belongs to a client id.
 *
 * The client is sent a handshake hint afterwards, so a peer that still
 * holds the configured key reconnects at once - which clears the stale
 * session a restarted client would otherwise leave behind - while a
 * revoked peer simply stops.
 */
static int server_kick(server_context_t *ctx, const char *id, char *reply,
                       size_t size)
{
    struct sockaddr_storage peers[SERVER_MAX_CLIENTS];
    socklen_t peer_len[SERVER_MAX_CLIENTS];
    int count = 0;
    int i;

    if (id[0] == '\0') {
        snprintf(reply, size, "ERR usage: kick <client-id>\n");
        return -1;
    }

    pthread_mutex_lock(&ctx->lock);

    for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
        server_session_t *session = &ctx->sessions[i];

        if (!session->active || strcmp(session->client_id, id) != 0) {
            continue;
        }

        peers[count] = session->addr;
        peer_len[count] = session->addr_len;
        count++;

        session->active = 0;
        session->established = 0;
        session->prefix_len = 0;
        memset(session->rx_key, 0, sizeof(session->rx_key));
        memset(session->tx_key, 0, sizeof(session->tx_key));
        pipesix_replay_reset(&session->replay);
    }

    pthread_mutex_unlock(&ctx->lock);

    if (count == 0) {
        snprintf(reply, size, "ERR no session for client '%s'\n", id);
        return -1;
    }

    for (i = 0; i < count; i++) {
        send_need_handshake(ctx, &peers[i], peer_len[i]);
    }

    snprintf(reply, size,
             "OK dropped %d session(s) for client '%s'; it will handshake "
             "again\n", count, id);
    return 0;
}

/*
 * Reset, credit or add usage for one client. Used by --reset-usage and
 * --credit-usage when a counter needs correcting without waiting for the
 * next period. The state file is written immediately so a restart keeps
 * the correction.
 */
static int server_usage_adjust(server_context_t *ctx, const char *id,
                               int mode, uint64_t mib, char *reply,
                               size_t size)
{
    struct sockaddr_storage peers[SERVER_MAX_CLIENTS];
    socklen_t peer_len[SERVER_MAX_CLIENTS];
    uint8_t keys[SERVER_MAX_CLIENTS][PIPESIX_KEY_LEN];
    uint64_t delta;
    uint64_t used;
    uint64_t updated;
    int period;
    int index;
    int count = 0;
    int i;

    if (id == NULL || id[0] == '\0') {
        snprintf(reply, size, "ERR usage: usage-reset <id> or "
                              "usage-credit <id> <MiB>\n");
        return -1;
    }

    delta = mib * 1048576u;
    period = policy_period(time(NULL), ctx->config->quota_period);

    pthread_mutex_lock(&ctx->lock);

    index = client_index_lookup(ctx->config, id);
    if (index < 0) {
        pthread_mutex_unlock(&ctx->lock);
        snprintf(reply, size, "ERR unknown client '%s'\n", id);
        return -1;
    }

    used = policy_quota_used(&ctx->quotas[index], period);

    if (mode == 0) {
        updated = 0;
    } else if (mode == 1) {
        updated = (delta >= used) ? 0 : used - delta;
    } else {
        updated = (used > UINT64_MAX - delta) ? UINT64_MAX : used + delta;
    }

    policy_quota_restore(&ctx->quotas[index], updated, period);

    for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
        server_session_t *session = &ctx->sessions[i];

        if (!session->active || !session->established ||
            strcmp(session->client_id, id) != 0) {
            continue;
        }

        peers[count] = session->addr;
        peer_len[count] = session->addr_len;
        memcpy(keys[count], session->tx_key, sizeof(keys[count]));
        count++;
    }

    pthread_mutex_unlock(&ctx->lock);

    for (i = 0; i < count; i++) {
        send_session_quota_state(ctx, &peers[i], peer_len[i], keys[i],
                                 index);
        memset(keys[i], 0, sizeof(keys[i]));
    }

    if (save_quota_state(ctx) != 0) {
        log_warn("Usage for client '%s' was adjusted in memory but could "
                 "not be saved", id);
    }

    log_info("Usage for client '%s' adjusted: %s%llu MiB (used %llu -> "
             "%llu B)",
             id, mode == 0 ? "reset; " : (mode == 1 ? "credited " : "added "),
             (unsigned long long)mib, (unsigned long long)used,
             (unsigned long long)updated);

    snprintf(reply, size,
             "OK client '%s' usage is now %llu B for this period\n",
             id, (unsigned long long)updated);
    return 0;
}

static int server_control_handler(const char *request, char *reply,
                                  size_t size, void *arg)
{
    server_context_t *ctx = (server_context_t *)arg;

    if (strcmp(request, "usage json") == 0) {
        return server_usage(ctx, reply, size, USAGE_JSON);
    }

    if (strcmp(request, "usage csv") == 0) {
        return server_usage(ctx, reply, size, USAGE_CSV);
    }

    if (strcmp(request, "usage") == 0) {
        return server_usage(ctx, reply, size, USAGE_TEXT);
    }

    if (strcmp(request, "status json") == 0) {
        return server_status_json(ctx, reply, size);
    }

    if (strcmp(request, "status") == 0) {
        return server_status(ctx, reply, size);
    }

    if (strcmp(request, "stats") == 0) {
        size_t used = 0;

        if (server_control_append(reply, size, &used, "OK\n") != 0) {
            return -1;
        }
        stats_format(&ctx->stats, "server", reply + used, size - used);
        return 0;
    }

    if (strcmp(request, "metrics") == 0) {
        /*
         * The control channel prefixes every reply with OK so the CLI can
         * tell a handled request from a rejected one; --metrics strips it
         * and prints the body, which is what Prometheus would scrape.
         */
        if (size < 4) {
            return -1;
        }
        snprintf(reply, size, "OK\n");
        return server_metrics_body(reply + 3, size - 3, ctx);
    }

    if (strncmp(request, "usage-reset ", 12) == 0) {
        return server_usage_adjust(ctx, request + 12, 0, 0, reply, size);
    }

    if (strncmp(request, "usage-credit ", 13) == 0) {
        char id[CONFIG_MAX_CLIENT_ID];
        unsigned long long mib;

        if (sscanf(request + 13, "%31s %llu", id, &mib) != 2 ||
            mib > 1048576u) {
            snprintf(reply, size, "ERR usage: usage-credit <id> <MiB>\n");
            return -1;
        }
        return server_usage_adjust(ctx, id, 1, (uint64_t)mib, reply, size);
    }

    if (strncmp(request, "usage-add ", 10) == 0) {
        char id[CONFIG_MAX_CLIENT_ID];
        unsigned long long mib;

        if (sscanf(request + 10, "%31s %llu", id, &mib) != 2 ||
            mib > 1048576u) {
            snprintf(reply, size, "ERR usage: usage-add <id> <MiB>\n");
            return -1;
        }
        return server_usage_adjust(ctx, id, 2, (uint64_t)mib, reply, size);
    }

    if (strcmp(request, "reload") == 0) {
        /*
         * The CLI has already rewritten and validated the file; this only
         * asks the main loop to adopt it. The reload lands on the next
         * tick, so the reply says "requested" rather than "reloaded".
         */
        runtime_request_reload();
        snprintf(reply, size, "OK reload requested\n");
        return 0;
    }

    if (strncmp(request, "kick ", 5) == 0) {
        return server_kick(ctx, request + 5, reply, size);
    }

    if (strcmp(request, "kick") == 0) {
        snprintf(reply, size, "ERR usage: kick <client-id>\n");
        return -1;
    }

    snprintf(reply, size, "ERR unknown request '%s'\n", request);
    return -1;
}

/*
 * Restore the current UTC day's counters from the state file.
 *
 * Called once before the worker threads start, so it needs no lock. A
 * missing file means nothing has been saved yet, and an entry for another
 * day is left behind: the quota resets at midnight anyway. Entries for
 * ids that no longer exist are ignored, which is what makes removing a
 * client and restoring an older file harmless.
 */
static void load_quota_state(server_context_t *ctx)
{
    policy_usage_t stored[CONFIG_MAX_CLIENTS];
    int stored_kind = 0;
    int count = 0;
    int restored = 0;
    int period = policy_period(time(NULL), ctx->config->quota_period);
    int i;

    if (ctx->config->quota_state[0] == '\0') {
        return;
    }

    if (policy_state_load(ctx->config->quota_state, &stored_kind, stored,
                          CONFIG_MAX_CLIENTS, &count) != 0) {
        log_warn("Cannot read the quota state file '%s': %s",
                 ctx->config->quota_state, strerror(errno));
        return;
    }

    if (stored_kind != ctx->config->quota_period) {
        char old_name[24];
        char new_name[24];

        policy_period_name(stored_kind, old_name, sizeof(old_name));
        policy_period_name(ctx->config->quota_period, new_name,
                           sizeof(new_name));
        log_info("Quota state '%s' was saved for a %s quota; starting this "
                 "%s from zero", ctx->config->quota_state, old_name,
                 new_name);
        return;
    }

    /*
     * The relay was down across a boundary: archive the stored period
     * before the counters are reset for the current one.
     */
    if (ctx->config->usage_history[0] != '\0') {
        policy_usage_t old[CONFIG_MAX_CLIENTS];
        int old_count = 0;

        for (i = 0; i < count; i++) {
            if (stored[i].period != period && stored[i].used > 0) {
                old[old_count++] = stored[i];
            }
        }

        if (old_count > 0 &&
            policy_history_append(ctx->config->usage_history,
                                  ctx->config->quota_period, old,
                                  old_count) != 0) {
            log_warn("Cannot append to the usage history '%s': %s",
                     ctx->config->usage_history, strerror(errno));
        }
    }

    for (i = 0; i < count; i++) {
        int index = client_index_lookup(ctx->config, stored[i].id);

        if (index < 0) {
            log_debug("Ignoring quota state for unknown client '%s'",
                      stored[i].id);
            continue;
        }

        if (stored[i].period != period) {
            continue;
        }

        policy_quota_restore(&ctx->quotas[index], stored[i].used,
                             (int)stored[i].period);
        restored++;
    }

    if (restored > 0) {
        log_info("Restored today's quota usage for %d client(s) from '%s'",
                 restored, ctx->config->quota_state);
    }
}

/*
 * Write every client's current usage to the state file.
 *
 * Safe to call at any time: the counters are read atomically under the
 * session lock, and the file is replaced atomically. A failure is logged
 * once per failure streak, since this runs every 30 seconds.
 */
/*
 * Roll the accounting period when the clock crosses a boundary.
 *
 * Called from the main loop, so history is written even when no packet
 * happens to arrive at midnight. quota_admit() does the same check under
 * the same lock, so traffic cannot slip in between.
 */
static void sync_quota_period(server_context_t *ctx)
{
    int period = policy_period(time(NULL), ctx->config->quota_period);

    pthread_mutex_lock(&ctx->lock);
    if (ctx->usage_period != period) {
        roll_quota_period_locked(ctx, ctx->usage_period, period);
    }
    pthread_mutex_unlock(&ctx->lock);
}

static int save_quota_state(server_context_t *ctx)
{
    policy_usage_t usage[CONFIG_MAX_CLIENTS];
    int count = 0;
    int i;

    if (ctx->config->quota_state[0] == '\0') {
        return 0;
    }

    pthread_mutex_lock(&ctx->lock);

    for (i = 0; i < ctx->config->client_count; i++) {
        snprintf(usage[count].id, sizeof(usage[count].id), "%s",
                 ctx->config->clients[i].id);
        usage[count].period = (int64_t)atomic_load_explicit(
            &ctx->quotas[i].period, memory_order_relaxed);
        usage[count].used = atomic_load_explicit(&ctx->quotas[i].used,
                                                 memory_order_relaxed);
        count++;
    }

    pthread_mutex_unlock(&ctx->lock);

    if (policy_state_save(ctx->config->quota_state,
                          ctx->config->quota_period, usage, count) != 0) {
        if (!ctx->quota_save_warned) {
            log_warn("Cannot write the quota state file '%s': %s",
                     ctx->config->quota_state, strerror(errno));
            ctx->quota_save_warned = 1;
        }
        return -1;
    }

    ctx->quota_save_warned = 0;
    return 0;
}

int server_start(pipesix_config_t *config)
{
    tun_device_t tun;
    server_context_t ctx;
    pthread_t receiver_thread;
    pthread_t sender_thread;
    uint64_t seed = 0;
    uint32_t salt = 0;
    int rc;

    tun_init(&tun);

    log_info("Opening TUN device '%s'", config->tun_name);
    if (tun_open(&tun, config->tun_name, config->tun_address,
                 config->tun_prefixlen, config->tun_mtu) != 0) {
        log_error("Failed to open TUN device");
        return -1;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.config = config;
    ctx.tun = &tun;
    ctx.udp_fd = bind_socket(config);
    if (ctx.udp_fd < 0) {
        tun_close(&tun);
        return -1;
    }

    if (pipesix_random_bytes(&seed, sizeof(seed)) != 0) {
        seed = ((uint64_t)time(NULL) << 32) | (uint64_t)(uint32_t)getpid();
    }
    if (pipesix_random_bytes(&salt, sizeof(salt)) != 0) {
        salt = (uint32_t)time(NULL) ^ (uint32_t)getpid();
    }

    atomic_init(&ctx.seq, seed);
    atomic_init(&ctx.session_timeout, config->session_timeout);
    ctx.salt = salt;
    stats_init(&ctx.stats);

    if (audit_open(config->audit_log) != 0) {
        log_warn("Cannot open the audit log '%s': %s", config->audit_log,
                 strerror(errno));
    }
    audit_event("startup", "", "", "server starting in %s mode",
                config->mode);

    {
        int i;

        /*
         * Every configured client gets an accounting entry, even without
         * a quota: --usage reports what it moved today, and a limit added
         * later does not start from zero.
         */
        for (i = 0; i < config->client_count; i++) {
            policy_quota_init(&ctx.quotas[i],
                              quota_limit_for(config, config->clients[i].id));
        }
    }

    ctx.usage_period = policy_period(time(NULL), config->quota_period);
    load_quota_state(&ctx);

    rc = pthread_mutex_init(&ctx.lock, NULL);
    if (rc != 0) {
        log_error("Failed to initialize session mutex: %s", strerror(rc));
        close(ctx.udp_fd);
        tun_close(&tun);
        return -1;
    }

    control_set_handler(server_control_handler, &ctx);
    metrics_start(config, server_metrics_body, server_ready, &ctx);

    /*
     * The TUN device, UDP socket and metrics listener are open, so the
     * data path no longer needs root. Drop before the worker threads
     * start, which also means a later failure cannot leave a root helper
     * thread behind.
     */
    if (psix_drop_privileges(config->user, config->group) != 0) {
        log_error("Cannot drop privileges to user '%s' group '%s': %s",
                  config->user, config->group, strerror(errno));
        metrics_stop();
        pthread_mutex_destroy(&ctx.lock);
        close(ctx.udp_fd);
        tun_close(&tun);
        return -1;
    }
    if (config->user[0] != '\0') {
        log_info("Dropped privileges to user '%s'%s%s", config->user,
                 config->group[0] != '\0' ? " group '" : "",
                 config->group[0] != '\0' ? config->group : "");
    }

    rc = pthread_create(&receiver_thread, NULL, receiver_loop, &ctx);
    if (rc != 0) {
        log_error("Failed to create receiver thread: %s", strerror(rc));
        metrics_stop();
        pthread_mutex_destroy(&ctx.lock);
        close(ctx.udp_fd);
        tun_close(&tun);
        return -1;
    }

    rc = pthread_create(&sender_thread, NULL, sender_loop, &ctx);
    if (rc != 0) {
        log_error("Failed to create sender thread: %s", strerror(rc));
        runtime_request_stop();
        pthread_join(receiver_thread, NULL);
        metrics_stop();
        pthread_mutex_destroy(&ctx.lock);
        close(ctx.udp_fd);
        tun_close(&tun);
        return -1;
    }

    {
        int i;
        int routed = 0;

        for (i = 0; i < config->client_count; i++) {
            if (config->clients[i].prefix_len > 0) {
                routed++;
            }
        }

        log_info("Server tunnel ready (crypto=chacha20-poly1305, "
                 "clients=%d, routed=%d, max_clients=%d, "
                 "session_timeout=%ds, allow_client=%d, policies=%d)",
                 config->client_count, routed, SERVER_MAX_CLIENTS,
                 config->session_timeout, config->allow_client_count,
                 config->policy_count);
    }
    log_info("Server is running. Send SIGINT/SIGTERM to stop, "
             "SIGUSR1 for stats, SIGHUP to reload.");

    {
        time_t last_report = time(NULL);
        time_t last_quota_save = time(NULL);

        while (!runtime_should_stop()) {
            struct timespec delay;
            time_t now;

            delay.tv_sec = 1;
            delay.tv_nsec = 0;
            nanosleep(&delay, NULL);
            now = time(NULL);

            if (runtime_take_reload_request()) {
                reload_config(&ctx);
                last_report = now;
            }

            if (runtime_take_stats_request()) {
                stats_dump(&ctx.stats, "server");
                sessions_dump(&ctx);
                last_report = now;
            } else if (config->stats_interval > 0 &&
                       (now - last_report) >=
                           (time_t)config->stats_interval) {
                stats_dump(&ctx.stats, "server");
                last_report = now;
            }

            sessions_expire(&ctx, now);
            sync_quota_period(&ctx);

            if (ctx.config->quota_state[0] != '\0' &&
                (now - last_quota_save) >= 30) {
                save_quota_state(&ctx);
                last_quota_save = now;
            }
        }
    }

    /*
     * Stops the control thread, so no handler runs while the state it
     * reports on is torn down. The metrics endpoint reads the same state
     * and goes first.
     */
    metrics_stop();
    control_stop();

    log_info("Initiating graceful shutdown...");

    pthread_join(receiver_thread, NULL);
    log_info("Receiver thread joined");

    pthread_join(sender_thread, NULL);
    log_info("Sender thread joined");

    /* The counters no longer change; keep today's usage for a restart. */
    save_quota_state(&ctx);

    /*
     * The session table and the socket are still intact, and no worker can
     * race a data frame in front of it: tell the clients now, not after
     * peer_timeout.
     */
    send_closing_to_sessions(&ctx);

    {
        int i;

        for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
            memset(ctx.sessions[i].rx_key, 0, sizeof(ctx.sessions[i].rx_key));
            memset(ctx.sessions[i].tx_key, 0, sizeof(ctx.sessions[i].tx_key));
        }
    }

    pthread_mutex_destroy(&ctx.lock);
    close(ctx.udp_fd);
    log_info("UDP socket closed");

    tun_close(&tun);
    stats_dump(&ctx.stats, "server");

    audit_event("shutdown", "", "", "server stopped");
    audit_close();
    log_info("Server shutdown complete");
    return 0;
}
