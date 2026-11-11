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
#include "config.h"
#include "control.h"
#include "crypto.h"
#include "ipv6.h"
#include "logger.h"
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
    /* Set once a packet's source fell outside the session's route. */
    int                     route_warned;
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
} server_context_t;

static uint64_t next_seq(server_context_t *ctx)
{
    return atomic_fetch_add_explicit(&ctx->seq, 1, memory_order_relaxed);
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
    int session_count;

    if (pipesix_handshake_init_peek(payload, payload_len, id, sizeof(id),
                                    cnonce) != PIPESIX_OK) {
        stats_add_invalid(&ctx->stats);
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
        return;
    }

    if (pipesix_key_from_string(cred_copy.secret, psk) != 0) {
        log_error("Cannot derive a key for client '%s'", id);
        return;
    }

    if (pipesix_handshake_init_verify(payload, payload_len, psk) !=
        PIPESIX_OK) {
        format_peer((const struct sockaddr *)peer, peer_len,
                    peer_str, sizeof(peer_str));
        log_warn("Handshake from %s failed authentication for client '%s'",
                 peer_str, id);
        stats_add_auth_failure(&ctx->stats);
        memset(psk, 0, sizeof(psk));
        return;
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
        ctx->sessions[slot].route_warned = 0;
        pipesix_replay_reset(&ctx->sessions[slot].replay);
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
        return;
    }

    frame_len = pipesix_frame_build(frame, sizeof(frame),
                                    PIPESIX_FLAG_HANDSHAKE_RESP, 0, 0,
                                    resp, resp_len, NULL);
    if (frame_len == 0) {
        log_error("Cannot build the handshake response frame");
        return;
    }

    if (sendto(ctx->udp_fd, frame, frame_len, 0,
               (const struct sockaddr *)peer, peer_len) !=
        (ssize_t)frame_len) {
        log_warn("Failed to send the handshake response: %s",
                 strerror(errno));
        return;
    }

    if (retransmit) {
        log_debug("Resent handshake response to client '%s'", id);
        return;
    }

    format_peer((const struct sockaddr *)peer, peer_len,
                peer_str, sizeof(peer_str));

    if (evicted) {
        log_warn("Session table full; evicted the least recently used "
                 "client to admit '%s'", id);
    }

    log_info("Client '%s' handshake from %s (crypto=chacha20-poly1305, "
             "%d active)", id, peer_str, session_count);
}

/*
 * Drop sessions that have been idle for longer than session_timeout.
 */
static void sessions_expire(server_context_t *ctx, time_t now)
{
    int expired[SERVER_MAX_CLIENTS];
    int timeout = atomic_load(&ctx->session_timeout);
    int count = 0;
    int i;

    if (timeout <= 0) {
        return;
    }

    pthread_mutex_lock(&ctx->lock);

    for (i = 0; i < SERVER_MAX_CLIENTS; i++) {
        server_session_t *session = &ctx->sessions[i];

        if (!session->active) {
            continue;
        }
        if ((now - session->last_seen) <= (time_t)timeout) {
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
static void reload_config(server_context_t *ctx)
{
    pipesix_client_cred_t before[CONFIG_MAX_CLIENTS];
    struct sockaddr_storage hint_addr[SERVER_MAX_CLIENTS];
    socklen_t hint_addr_len[SERVER_MAX_CLIENTS];
    char hint_ids[SERVER_MAX_CLIENTS][CONFIG_MAX_CLIENT_ID];
    char dropped_ids[SERVER_MAX_CLIENTS][CONFIG_MAX_CLIENT_ID];
    int before_count = ctx->config->client_count;
    int hint_count = 0;
    int dropped_count = 0;
    int rerouted = 0;
    int rc;
    int i;

    memcpy(before, ctx->config->clients, sizeof(before));

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
    atomic_store(&ctx->session_timeout, ctx->config->session_timeout);

    pthread_mutex_lock(&ctx->lock);

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
    }

    pthread_mutex_unlock(&ctx->lock);

    /* Frames go out after the lock is released. */
    for (i = 0; i < hint_count; i++) {
        send_empty_control(ctx, &hint_addr[i], hint_addr_len[i],
                           PIPESIX_FLAG_HANDSHAKE_NEEDED);
        log_warn("Client '%s' key changed; session revoked and a new "
                 "handshake requested", hint_ids[i]);
    }

    for (i = 0; i < dropped_count; i++) {
        log_warn("Client '%s' was removed from the configuration; its "
                 "session was dropped", dropped_ids[i]);
    }

    if (rerouted > 0) {
        log_info("%d live session(s) picked up a new return route",
                 rerouted);
    }

    log_info("Configuration reloaded (log_level, keepalive, "
             "session_timeout, stats_interval, %d credential(s)); "
             "interface, endpoint and mode changes need a restart",
             ctx->config->client_count);
}

/*
 * Receiver loop (UDP -> TUN)
 */
static void *receiver_loop(void *arg)
{
    server_context_t *ctx = (server_context_t *)arg;
    uint8_t frame_buf[PIPESIX_RECV_BUF_SIZE];
    struct pollfd pfd;

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

        if ((flags & (PIPESIX_FLAG_HANDSHAKE_RESP |
                      PIPESIX_FLAG_HANDSHAKE_NEEDED)) != 0) {
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

        now = time(NULL);
        ctx->sessions[slot].last_seen = now;
        ctx->sessions[slot].frames++;
        ctx->sessions[slot].rx_bytes += (uint64_t)frame.payload_len;

        /*
         * A client whose inner source address falls outside the route it
         * was given never sees the replies: the sender has no route for
         * that address. That is what a client and server configured for
         * different upstreams look like on the wire, and it is silent
         * otherwise, so report it once per session.
         */
        if (!ctx->sessions[slot].route_warned &&
            ctx->sessions[slot].prefix_len > 0 &&
            frame.payload_len >= IPV6_HEADER_LEN) {
            const pipesix_ipv6_header_t *inner = NULL;

            if (ipv6_parse_header(frame.payload, frame.payload_len,
                                  &inner) == 0 &&
                !ipv6_prefix_match(ctx->sessions[slot].prefix,
                                   ctx->sessions[slot].prefix_len,
                                   inner->source_addr)) {
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
        }

        pthread_mutex_unlock(&ctx->lock);

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

        {
            ssize_t nwritten = tun_write(ctx->tun, frame.payload,
                                         frame.payload_len);

            if (nwritten < 0) {
                log_error("TUN write failed: %s", strerror(errno));
                stats_add_error(&ctx->stats);
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

        if (slot >= 0) {
            dest = ctx->sessions[slot].addr;
            dest_len = ctx->sessions[slot].addr_len;
            memcpy(key, ctx->sessions[slot].tx_key, sizeof(key));
            /*
             * Counted when the packet is handed to sendto(); attributing
             * a rare send failure would need a second pass over the lock.
             */
            ctx->sessions[slot].tx_bytes += (uint64_t)nread;
        }

        pthread_mutex_unlock(&ctx->lock);

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
static int server_status(server_context_t *ctx, char *reply, size_t size)
{
    char ids[SERVER_MAX_CLIENTS][CONFIG_MAX_CLIENT_ID];
    char peers[SERVER_MAX_CLIENTS][96];
    char routes[SERVER_MAX_CLIENTS][INET6_ADDRSTRLEN + 8];
    uint64_t frames[SERVER_MAX_CLIENTS];
    uint64_t rx_bytes[SERVER_MAX_CLIENTS];
    uint64_t tx_bytes[SERVER_MAX_CLIENTS];
    long idle[SERVER_MAX_CLIENTS];
    time_t now = time(NULL);
    time_t started = ctx->stats.started;
    unsigned long uptime;
    size_t used = 0;
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
        format_peer((const struct sockaddr *)&session->addr,
                    session->addr_len, peers[count], sizeof(peers[count]));

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
                                  "frames=%llu idle=%lds route=%s\n",
                                  ids[i], peers[i],
                                  (unsigned long long)rx_bytes[i],
                                  (unsigned long long)tx_bytes[i],
                                  (unsigned long long)frames[i],
                                  idle[i], routes[i]) != 0) {
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
    uint64_t frames[SERVER_MAX_CLIENTS];
    uint64_t rx_bytes[SERVER_MAX_CLIENTS];
    uint64_t tx_bytes[SERVER_MAX_CLIENTS];
    long idle[SERVER_MAX_CLIENTS];
    char config_esc[1024];
    char tun_name_esc[256];
    char tun_addr_esc[256];
    char bind_esc[256];
    char stats_json[512];
    time_t now = time(NULL);
    time_t started = ctx->stats.started;
    unsigned long uptime;
    size_t used = 0;
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
        format_peer((const struct sockaddr *)&session->addr,
                    session->addr_len, peers[count], sizeof(peers[count]));

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
                "\"idle_seconds\":%ld,\"route\":%s}",
                i > 0 ? "," : "", ids[i], peers[i],
                (unsigned long long)rx_bytes[i],
                (unsigned long long)tx_bytes[i],
                (unsigned long long)frames[i], idle[i], routes[i]) != 0) {
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

static int server_control_handler(const char *request, char *reply,
                                  size_t size, void *arg)
{
    server_context_t *ctx = (server_context_t *)arg;

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

    rc = pthread_mutex_init(&ctx.lock, NULL);
    if (rc != 0) {
        log_error("Failed to initialize session mutex: %s", strerror(rc));
        close(ctx.udp_fd);
        tun_close(&tun);
        return -1;
    }

    rc = pthread_create(&receiver_thread, NULL, receiver_loop, &ctx);
    if (rc != 0) {
        log_error("Failed to create receiver thread: %s", strerror(rc));
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
        pthread_mutex_destroy(&ctx.lock);
        close(ctx.udp_fd);
        tun_close(&tun);
        return -1;
    }

    control_set_handler(server_control_handler, &ctx);

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
                 "session_timeout=%ds, allow_client=%d)",
                 config->client_count, routed, SERVER_MAX_CLIENTS,
                 config->session_timeout, config->allow_client_count);
    }
    log_info("Server is running. Send SIGINT/SIGTERM to stop, "
             "SIGUSR1 for stats, SIGHUP to reload.");

    {
        time_t last_report = time(NULL);

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
        }
    }

    /*
     * Stops the control thread, so no handler runs while the state it
     * reports on is torn down.
     */
    control_stop();

    log_info("Initiating graceful shutdown...");

    pthread_join(receiver_thread, NULL);
    log_info("Receiver thread joined");

    pthread_join(sender_thread, NULL);
    log_info("Sender thread joined");

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

    log_info("Server shutdown complete");
    return 0;
}
