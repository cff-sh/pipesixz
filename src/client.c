/*
 * client.c - pipesix Client Mode Implementation
 *
 * The client owns a TUN device and a connected UDP socket:
 *
 *   Applications -> TUN -> forward loop -> UDP -> server
 *   Applications <- TUN <- reverse loop <- UDP <- server
 *
 * Before any traffic flows the client completes a pre-shared-key
 * handshake with the server (see proto.h). Each handshake derives two
 * fresh session keys, one per direction, so this client's nonces and
 * replay state are isolated from every other peer even when several
 * clients share a server.
 *
 * Both loops use poll() with a short timeout so shutdown requests are
 * handled promptly. Frames are encrypted with ChaCha20-Poly1305,
 * protected against replay by a sliding sequence window, and a
 * keepalive is sent when the tunnel is idle so NAT mappings stay open
 * and the server can echo liveness back.
 *
 * The main thread watches for dead peers: when no valid frame has been
 * received for peer_timeout seconds it joins the workers, re-resolves
 * the server address, reconnects, re-handshakes with exponential
 * backoff and restarts the workers. A handshake request from the
 * server triggers the same renegotiation without reconnecting. SIGHUP
 * reloads the runtime-tunable configuration; when this client's own id
 * or key changed it re-handshakes on the existing socket, so a key can
 * be rotated without restarting the tunnel.
 */

#include "client.h"
#include "audit.h"
#include "control.h"
#include "config.h"
#include "crypto.h"
#include "ipv6.h"
#include "logger.h"
#include "metrics.h"
#include "policy.h"
#include "proto.h"
#include "runtime.h"
#include "stats.h"
#include "platform.h"
#include "tun.h"

#include <errno.h>
#if !defined(_WIN32)
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define POLL_INTERVAL_MS     500
#define RECONNECT_MAX_DELAY  30u
#define HANDSHAKE_TIMEOUT_MS 5000

typedef struct {
    pipesix_config_t  *config;
    tun_device_t      *tun;
    psix_socket_t      udp_fd;
    uint8_t            psk[PIPESIX_KEY_LEN];
    uint8_t            tx_key[PIPESIX_KEY_LEN];
    uint8_t            rx_key[PIPESIX_KEY_LEN];
    _Atomic uint64_t   seq;
    _Atomic uint32_t   salt;
    _Atomic time_t     last_rx;
    _Atomic int        keepalive;
    _Atomic int        stop_workers;
    _Atomic int        handshake_needed;
    _Atomic int        server_closing;
    /* Last quota state the server reported (see PIPESIX_FLAG_QUOTA_STATE). */
    _Atomic int        quota_valid;
    _Atomic uint64_t   quota_limit;
    _Atomic uint64_t   quota_used;
    _Atomic int64_t    quota_start;
    _Atomic int64_t    quota_end;
    _Atomic time_t     last_quota_request;
    /* Ordered relay list and the endpoint currently in use. */
    size_t             endpoint_index;
    char               remote_current[CONFIG_MAX_ADDRESS];
    pipesix_replay_t   replay;
    pipesix_stats_t    stats;
} client_context_t;

static uint64_t next_seq(client_context_t *ctx)
{
    return atomic_fetch_add_explicit(&ctx->seq, 1, memory_order_relaxed);
}

/*
 * Sleep for whole seconds, waking up early when a shutdown is
 * requested.
 */
static void sleep_seconds(unsigned int seconds)
{
    unsigned int i;

    for (i = 0; i < seconds && !runtime_should_stop(); i++) {
        psix_sleep(1);
    }
}

/*
 * Build and send one frame on the connected UDP socket.
 *
 * Returns 0 on success, -1 on failure with errno set.
 */
static int send_frame(client_context_t *ctx, uint16_t flags,
                      const uint8_t *payload, size_t payload_len)
{
    uint8_t frame[PIPESIX_MAX_FRAME];
    size_t frame_len;

    frame_len = pipesix_frame_build(frame, sizeof(frame), flags,
                                    atomic_load_explicit(&ctx->salt,
                                                         memory_order_relaxed),
                                    next_seq(ctx), payload, payload_len,
                                    ctx->tx_key);
    if (frame_len == 0) {
        errno = EINVAL;
        return -1;
    }

    if (psix_send(ctx->udp_fd, frame, frame_len, 0) != (ssize_t)frame_len) {
        return -1;
    }

    return 0;
}

/*
 * Start a new session: fresh salt, fresh sequence seed and an empty
 * replay window.
 */
static void reset_session(client_context_t *ctx)
{
    uint64_t seed = 0;
    uint32_t salt = 0;

    if (pipesix_random_bytes(&seed, sizeof(seed)) != 0) {
        seed = ((uint64_t)time(NULL) << 32) |
               (uint64_t)(uint32_t)getpid();
    }
    if (pipesix_random_bytes(&salt, sizeof(salt)) != 0) {
        salt = (uint32_t)time(NULL) ^ (uint32_t)getpid();
    }

    atomic_store(&ctx->seq, seed);
    atomic_store(&ctx->salt, salt);
    pipesix_replay_reset(&ctx->replay);
    atomic_store_explicit(&ctx->last_quota_request, 0, memory_order_relaxed);
    atomic_store_explicit(&ctx->quota_valid, 0, memory_order_relaxed);
}

/*
 * Run one handshake attempt.
 *
 * Returns 0 once session keys are installed, -1 if the attempt timed
 * out, was rejected, or the server went away.
 */
static int handshake_once(client_context_t *ctx, int timeout_ms)
{
    uint8_t init_body[PIPESIX_HANDSHAKE_INIT_MAX];
    uint8_t frame[PIPESIX_MAX_FRAME];
    uint8_t buf[PIPESIX_RECV_BUF_SIZE];
    uint8_t cnonce[PIPESIX_HANDSHAKE_NONCE_LEN];
    uint8_t echoed_cnonce[PIPESIX_HANDSHAKE_NONCE_LEN];
    uint8_t snonce[PIPESIX_HANDSHAKE_NONCE_LEN];
    size_t body_len;
    size_t frame_len;
    time_t deadline;

    if (pipesix_random_bytes(cnonce, sizeof(cnonce)) != 0) {
        log_error("Cannot generate a handshake nonce: %s", strerror(errno));
        stats_add_handshake_failure(&ctx->stats);
        return -1;
    }

    body_len = pipesix_handshake_init_build(init_body, sizeof(init_body),
                                            ctx->config->client_id, cnonce,
                                            ctx->psk);
    if (body_len == 0) {
        log_error("Cannot build the handshake request (check 'client_id')");
        stats_add_handshake_failure(&ctx->stats);
        return -1;
    }

    frame_len = pipesix_frame_build(frame, sizeof(frame),
                                    PIPESIX_FLAG_HANDSHAKE_INIT, 0, 0,
                                    init_body, body_len, NULL);
    if (frame_len == 0) {
        log_error("Cannot build the handshake frame");
        stats_add_handshake_failure(&ctx->stats);
        return -1;
    }

    if (psix_send(ctx->udp_fd, frame, frame_len, 0) != (ssize_t)frame_len) {
        log_warn("Failed to send the handshake request: %s", strerror(errno));
        stats_add_handshake_failure(&ctx->stats);
        return -1;
    }

    deadline = time(NULL) + (time_t)((timeout_ms + 999) / 1000);

    while (!runtime_should_stop() && time(NULL) <= deadline) {
        pipesix_frame_t parsed;
        uint16_t flags;
        ssize_t nread;
        int ready;

        ready = psix_socket_wait(ctx->udp_fd, POLL_INTERVAL_MS);
        if (ready < 0) {
            if (errno == EINTR) continue;
            log_warn("poll() during handshake failed: %s", strerror(errno));
            stats_add_handshake_failure(&ctx->stats);
            return -1;
        }
        if (ready == 0) {
            continue;
        }

        nread = psix_recv(ctx->udp_fd, buf, sizeof(buf), 0);
        if (nread < 0) {
            if (errno == EINTR) continue;
            log_warn("Handshake receive failed: %s", strerror(errno));
            stats_add_handshake_failure(&ctx->stats);
            return -1;
        }

        if (pipesix_frame_peek(buf, (size_t)nread, &flags) != PIPESIX_OK) {
            continue;
        }
        if ((flags & PIPESIX_FLAG_HANDSHAKE_RESP) == 0) {
            continue; /* Stale data frame from an earlier session. */
        }

        if (pipesix_frame_parse(buf, (size_t)nread, &parsed, NULL) !=
            PIPESIX_OK) {
            continue;
        }

        if (pipesix_handshake_resp_verify(parsed.payload, parsed.payload_len,
                                          ctx->psk, echoed_cnonce) !=
            PIPESIX_OK) {
            log_warn("Handshake response from the server failed verification");
            stats_add_auth_failure(&ctx->stats);
            stats_add_handshake_failure(&ctx->stats);
            return -1;
        }

        if (memcmp(echoed_cnonce, cnonce, sizeof(cnonce)) != 0) {
            continue; /* Response to a different attempt. */
        }

        memcpy(snonce, parsed.payload + PIPESIX_HANDSHAKE_NONCE_LEN,
               sizeof(snonce));

        pipesix_session_keys(ctx->psk, cnonce, snonce,
                             ctx->tx_key, ctx->rx_key);

        stats_add_handshake(&ctx->stats);
        log_info("Handshake completed as client '%s'",
                 ctx->config->client_id);
        audit_event("handshake", ctx->config->client_id, "",
                    "client session established");
        return 0;
    }

    /* The attempt ran out of time without a response. */
    if (!runtime_should_stop()) {
        stats_add_handshake_failure(&ctx->stats);
    }
    return -1;
}

static int reconnect_peer(client_context_t *ctx);
static size_t remote_endpoint_count(const pipesix_config_t *config);
static const char *remote_endpoint(const pipesix_config_t *config,
                                   size_t index);

/*
 * Handshake until it succeeds or a shutdown is requested.
 *
 * With more than one configured endpoint, two failed attempts move on to
 * the next relay instead of retrying a relay that accepts UDP but never
 * answers (a blackholed port, or a host that is down).
 *
 * Returns 0 on success, -1 if shutdown interrupted the attempts.
 */
static int handshake(client_context_t *ctx)
{
    unsigned int delay = 1u;
    unsigned int failures = 0;

    while (!runtime_should_stop()) {
        if (handshake_once(ctx, HANDSHAKE_TIMEOUT_MS) == 0) {
            return 0;
        }
        if (runtime_should_stop()) {
            break;
        }

        failures++;
        if (remote_endpoint_count(ctx->config) > 1 && failures >= 2) {
            log_warn("Handshake failed with '%s'; trying the next relay "
                     "endpoint",
                     ctx->remote_current[0] != '\0'
                         ? ctx->remote_current
                         : remote_endpoint(ctx->config,
                                           ctx->endpoint_index));
            psix_close(ctx->udp_fd);
            ctx->udp_fd = PSIX_INVALID_SOCKET;

            if (reconnect_peer(ctx) != 0) {
                return -1;
            }

            reset_session(ctx);
            failures = 0;
            delay = 1u;
            continue;
        }

        log_warn("Handshake with the server failed; retrying in %u seconds",
                 delay);
        sleep_seconds(delay);

        if (delay < RECONNECT_MAX_DELAY) {
            delay *= 2u;
            if (delay > RECONNECT_MAX_DELAY) {
                delay = RECONNECT_MAX_DELAY;
            }
        }
    }

    return -1;
}

/*
 * Forward loop (TUN -> UDP)
 */
static void *forward_loop(void *arg)
{
    client_context_t *ctx = (client_context_t *)arg;
    uint8_t packet[PIPESIX_MAX_PACKET];
    time_t last_send = time(NULL);

    log_info("Forward thread started (TUN -> UDP)");

    while (!runtime_should_stop() && !atomic_load(&ctx->stop_workers)) {
        int ready = tun_wait(ctx->tun, POLL_INTERVAL_MS);
        time_t now;
        int keepalive;

        if (ready < 0) {
            if (errno == EINTR) continue;
            log_error("poll() on TUN failed: %s", strerror(errno));
            stats_add_error(&ctx->stats);
            runtime_request_stop();
            break;
        }

        now = time(NULL);
        keepalive = atomic_load(&ctx->keepalive);

        /*
         * Ask once per session, and again after a quota notice. The
         * server keeps the state fresh at period boundaries.
         */
        if (atomic_load_explicit(&ctx->last_quota_request,
                                 memory_order_relaxed) == 0) {
            if (send_frame(ctx, PIPESIX_FLAG_QUOTA_REQUEST, NULL, 0) == 0) {
                atomic_store_explicit(&ctx->last_quota_request, now,
                                      memory_order_relaxed);
            }
        }

        if (ready > 0) {
            ssize_t nread = tun_read(ctx->tun, packet, sizeof(packet));

            if (nread < 0) {
                if (errno != EINTR) {
                    log_error("TUN read failed: %s", strerror(errno));
                    stats_add_error(&ctx->stats);
                }
                continue;
            }

            if (nread > 0) {
                if (send_frame(ctx, 0, packet, (size_t)nread) != 0) {
                    log_error("UDP send failed: %s", strerror(errno));
                    stats_add_error(&ctx->stats);
                    continue;
                }

                stats_add_tx(&ctx->stats, (size_t)nread);
                ipv6_log_packet(packet, (size_t)nread, "TX");
                last_send = now;
            }
        }

        /* Keep the path (and any NAT binding) alive while idle. */
        if (keepalive > 0 &&
            (now - last_send) >= (time_t)keepalive) {
            if (send_frame(ctx, PIPESIX_FLAG_KEEPALIVE, NULL, 0) == 0) {
                log_debug("Sent keepalive");
                last_send = now;
            } else {
                log_warn("Failed to send keepalive: %s", strerror(errno));
                stats_add_error(&ctx->stats);
            }
        }
    }

    log_info("Forward thread exiting");
    return NULL;
}

/*
 * Reverse loop (UDP -> TUN)
 */
static void *reverse_loop(void *arg)
{
    client_context_t *ctx = (client_context_t *)arg;
    uint8_t frame_buf[PIPESIX_RECV_BUF_SIZE];

    log_info("Reverse thread started (UDP -> TUN)");

    while (!runtime_should_stop() && !atomic_load(&ctx->stop_workers)) {
        int ready = psix_socket_wait(ctx->udp_fd, POLL_INTERVAL_MS);
        pipesix_frame_t frame;
        uint16_t flags;
        int rc;
        ssize_t nread;

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

        nread = psix_recv(ctx->udp_fd, frame_buf, sizeof(frame_buf), 0);
        if (nread < 0) {
            if (errno == EINTR) continue;
            log_error("UDP receive failed: %s", strerror(errno));
            stats_add_error(&ctx->stats);
            runtime_request_stop();
            break;
        }

        if (pipesix_frame_peek(frame_buf, (size_t)nread, &flags) != PIPESIX_OK) {
            stats_add_invalid(&ctx->stats);
            continue;
        }

        if ((flags & PIPESIX_FLAG_HANDSHAKE_NEEDED) != 0) {
            log_info("Server requested a new handshake");
            atomic_store(&ctx->handshake_needed, 1);
            continue;
        }

        if ((flags & (PIPESIX_FLAG_HANDSHAKE_INIT |
                      PIPESIX_FLAG_HANDSHAKE_RESP)) != 0) {
            continue;
        }

        rc = pipesix_frame_parse(frame_buf, (size_t)nread, &frame,
                                 ctx->rx_key);
        if (rc != PIPESIX_OK) {
            log_warn("Dropping invalid frame (%lld bytes): %s",
                     (long long)nread, pipesix_strerror(rc));
            stats_add_invalid(&ctx->stats);
            if (rc == PIPESIX_ERR_AUTH) {
                stats_add_auth_failure(&ctx->stats);
            }
            continue;
        }

        if (!pipesix_replay_accept(&ctx->replay, frame.seq)) {
            log_warn("Dropping replayed/out-of-window frame (seq=%llu)",
                     (unsigned long long)frame.seq);
            stats_add_replayed(&ctx->stats);
            continue;
        }

        atomic_store(&ctx->last_rx, time(NULL));

        if ((frame.flags & PIPESIX_FLAG_KEEPALIVE) != 0) {
            log_debug("Keepalive received from server");
            continue;
        }

        if ((frame.flags & PIPESIX_FLAG_SERVER_CLOSING) != 0) {
            log_info("Server is shutting down; reconnecting");
            atomic_store(&ctx->server_closing, 1);
            continue;
        }

        if ((frame.flags & PIPESIX_FLAG_QUOTA_EXHAUSTED) != 0) {
            log_error("Server reports the quota is exhausted; traffic is "
                      "throttled or dropped until the period resets");
            atomic_store(&ctx->last_quota_request, 0);
            continue;
        }

        if ((frame.flags & PIPESIX_FLAG_QUOTA_WARNING) != 0) {
            log_warn("Server reports the quota is nearly exhausted");
            atomic_store(&ctx->last_quota_request, 0);
            continue;
        }

        if ((frame.flags & PIPESIX_FLAG_QUOTA_STATE) != 0) {
            pipesix_quota_state_t state;

            if (pipesix_quota_state_decode(frame.payload, frame.payload_len,
                                           &state) != PIPESIX_OK) {
                stats_add_invalid(&ctx->stats);
                continue;
            }

            atomic_store(&ctx->quota_limit, state.limit_bytes);
            atomic_store(&ctx->quota_used, state.used_bytes);
            atomic_store(&ctx->quota_start, state.period_start);
            atomic_store(&ctx->quota_end, state.period_end);
            atomic_store(&ctx->quota_valid, 1);
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

    log_info("Reverse thread exiting");
    return NULL;
}

/*
 * Resolve the server and connect the UDP socket.
 *
 * Returns the connected socket, or PSIX_INVALID_SOCKET on failure.
 * The socket is a SOCKET on Windows, which is pointer sized, so it must
 * not travel through an int.
 */
static size_t remote_endpoint_count(const pipesix_config_t *config)
{
    return config->remote_count > 0 ? (size_t)config->remote_count : 1u;
}

static const char *remote_endpoint(const pipesix_config_t *config,
                                   size_t index)
{
    if (config->remote_count > 0 && index < (size_t)config->remote_count) {
        return config->remote_endpoints[index];
    }

    return config->remote_address;
}

static psix_socket_t connect_server(const pipesix_config_t *config,
                                    size_t endpoint_index,
                                    char *chosen, size_t chosen_size,
                                    int quiet)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp;
    const char *host_name = remote_endpoint(config, endpoint_index);
    char port_str[16];
    int gai;
    psix_socket_t fd = PSIX_INVALID_SOCKET;

    snprintf(port_str, sizeof(port_str), "%d", config->remote_port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    gai = getaddrinfo(host_name, port_str, &hints, &result);
    if (gai != 0) {
        log_error("Failed to resolve server address '%s': %s",
                  host_name, gai_strerror(gai));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        char host[NI_MAXHOST];
        char serv[NI_MAXSERV];

        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == PSIX_INVALID_SOCKET) {
            continue;
        }

        if (psix_connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            if (getnameinfo(rp->ai_addr, rp->ai_addrlen,
                            host, sizeof(host), serv, sizeof(serv),
                            NI_NUMERICHOST | NI_NUMERICSERV) == 0 &&
                !quiet) {
                log_info("UDP connected to %s:%s (%s, endpoint %llu)", host,
                         serv,
                         rp->ai_family == AF_INET6 ? "AF_INET6" : "AF_INET",
                         (unsigned long long)(endpoint_index + 1));
            }
            if (chosen != NULL && chosen_size > 0) {
                size_t name_len = strlen(host_name);

                if (name_len >= chosen_size) {
                    name_len = chosen_size - 1;
                }
                memcpy(chosen, host_name, name_len);
                chosen[name_len] = '\0';
            }
            break;
        }

        psix_close(fd);
        fd = PSIX_INVALID_SOCKET;
    }

    freeaddrinfo(result);

    if (fd == PSIX_INVALID_SOCKET) {
        log_error("Failed to connect UDP socket to %s:%d: %s",
                  host_name, config->remote_port, strerror(errno));
    }

    return fd;
}

/*
 * Send one side-effect-free authenticated probe and wait for its signed
 * reply. It never changes a session, so it is safe while a tunnel is live.
 *
 * Returns 0 when the endpoint answered with a valid response, -1 otherwise.
 */
static int probe_endpoint(const pipesix_config_t *config, size_t index,
                          const uint8_t psk[PIPESIX_KEY_LEN], int timeout_ms,
                          char *chosen, size_t chosen_size,
                          unsigned long long *rtt_ms)
{
    uint8_t init_body[PIPESIX_HANDSHAKE_INIT_MAX];
    uint8_t frame[PIPESIX_MAX_FRAME];
    uint8_t buf[PIPESIX_RECV_BUF_SIZE];
    uint8_t cnonce[PIPESIX_HANDSHAKE_NONCE_LEN];
    uint8_t echoed[PIPESIX_HANDSHAKE_NONCE_LEN];
    uint8_t probe_key[PIPESIX_KEY_LEN];
    psix_socket_t fd;
    size_t body_len;
    size_t frame_len;
    time_t deadline;
    uint64_t started;

    memcpy(probe_key, psk, sizeof(probe_key));
    fd = connect_server(config, index, chosen, chosen_size, 1);
    if (fd == PSIX_INVALID_SOCKET) {
        memset(probe_key, 0, sizeof(probe_key));
        return -1;
    }

    if (pipesix_random_bytes(cnonce, sizeof(cnonce)) != 0) {
        psix_close(fd);
        memset(probe_key, 0, sizeof(probe_key));
        return -1;
    }
    body_len = pipesix_handshake_init_build(init_body, sizeof(init_body),
                                            config->client_id, cnonce,
                                            probe_key);
    memset(probe_key, 0, sizeof(probe_key));
    if (body_len == 0) {
        psix_close(fd);
        return -1;
    }
    frame_len = pipesix_frame_build(frame, sizeof(frame),
                                    PIPESIX_FLAG_PROBE_REQ, 0, 0,
                                    init_body, body_len, NULL);
    if (frame_len == 0 ||
        psix_send(fd, frame, frame_len, 0) != (ssize_t)frame_len) {
        psix_close(fd);
        return -1;
    }

    started = policy_now_ms();
    deadline = time(NULL) + (time_t)((timeout_ms + 999) / 1000);
    while (time(NULL) <= deadline) {
        pipesix_frame_t parsed;
        uint16_t flags;
        ssize_t nread;
        int ready = psix_socket_wait(fd, POLL_INTERVAL_MS);

        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ready == 0) {
            continue;
        }

        nread = psix_recv(fd, buf, sizeof(buf), 0);
        if (nread < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pipesix_frame_peek(buf, (size_t)nread, &flags) != PIPESIX_OK ||
            (flags & PIPESIX_FLAG_PROBE_RESP) == 0) {
            continue;
        }
        if (pipesix_frame_parse(buf, (size_t)nread, &parsed, NULL) !=
            PIPESIX_OK) {
            continue;
        }
        if (pipesix_handshake_resp_verify(parsed.payload, parsed.payload_len,
                                          psk, echoed) != PIPESIX_OK ||
            memcmp(echoed, cnonce, sizeof(cnonce)) != 0) {
            continue;
        }

        if (rtt_ms != NULL) {
            uint64_t finish = policy_now_ms();
            *rtt_ms = finish >= started ? finish - started : 0;
        }
        psix_close(fd);
        return 0;
    }

    psix_close(fd);
    return -1;
}

int client_doctor(const pipesix_config_t *config)
{
    uint8_t psk[PIPESIX_KEY_LEN];
    size_t count;
    size_t i;
    int ok = 0;

    if (config == NULL || strcmp(config->mode, "client") != 0) {
        fprintf(stderr, "Error: --doctor needs a client configuration\n");
        return -1;
    }
    if (pipesix_key_from_string(config->secret, psk) != 0) {
        fprintf(stderr, "Error: cannot derive the key from 'secret'\n");
        return -1;
    }

    count = remote_endpoint_count(config);
    printf("config: OK\nclient_id: %s\ntun: %s %s/%d\n",
           config->client_id, config->tun_name, config->tun_address,
           config->tun_prefixlen);

    for (i = 0; i < count; i++) {
        char chosen[CONFIG_MAX_ADDRESS] = "";
        unsigned long long rtt = 0;

        if (probe_endpoint(config, i, psk, HANDSHAKE_TIMEOUT_MS, chosen,
                           sizeof(chosen), &rtt) == 0) {
            printf("endpoint %llu: OK  %s (%llu ms, authenticated)\n",
                   (unsigned long long)(i + 1),
                   chosen[0] != '\0' ? chosen : remote_endpoint(config, i),
                   rtt);
            ok++;
        } else {
            printf("endpoint %llu: FAIL %s (no authenticated reply)\n",
                   (unsigned long long)(i + 1), remote_endpoint(config, i));
        }
    }

    memset(psk, 0, sizeof(psk));
    if (ok == 0) {
        fprintf(stderr, "No relay endpoint answered the probe.\n");
        return -1;
    }
    printf("doctor: %d of %llu endpoint(s) reachable\n", ok,
           (unsigned long long)count);
    return 0;
}

/*
 * Reconnect to the server, retrying with exponential backoff until it
 * succeeds or a shutdown is requested.
 *
 * Returns 0 on success, -1 if shutdown interrupted the attempts.
 */
static int reconnect_peer(client_context_t *ctx)
{
    unsigned int delay = 1u;
    size_t count = remote_endpoint_count(ctx->config);
    size_t start = count > 0
                       ? (ctx->endpoint_index + 1u) % count
                       : 0u;

    while (!runtime_should_stop()) {
        size_t i;

        for (i = 0; i < count; i++) {
            size_t index = (start + i) % count;
            psix_socket_t fd = connect_server(ctx->config, index,
                                              ctx->remote_current,
                                              sizeof(ctx->remote_current),
                                              0);

            if (fd != PSIX_INVALID_SOCKET) {
                ctx->udp_fd = fd;
                ctx->endpoint_index = index;
                return 0;
            }
        }

        if (count > 1) {
            log_warn("All %llu relay endpoints failed; retrying in %u "
                     "seconds", (unsigned long long)count, delay);
        } else {
            log_warn("Reconnect failed; retrying in %u seconds", delay);
        }
        sleep_seconds(delay);

        if (delay < RECONNECT_MAX_DELAY) {
            delay *= 2u;
            if (delay > RECONNECT_MAX_DELAY) {
                delay = RECONNECT_MAX_DELAY;
            }
        }
    }

    return -1;
}

static int start_workers(client_context_t *ctx, pthread_t *forward,
                         pthread_t *reverse)
{
    int rc;

    rc = pthread_create(forward, NULL, forward_loop, ctx);
    if (rc != 0) {
        log_error("Failed to create forward thread: %s", strerror(rc));
        return -1;
    }

    rc = pthread_create(reverse, NULL, reverse_loop, ctx);
    if (rc != 0) {
        log_error("Failed to create reverse thread: %s", strerror(rc));
        atomic_store(&ctx->stop_workers, 1);
        pthread_join(*forward, NULL);
        return -1;
    }

    return 0;
}

/*
 * Stop both worker threads and wait for them.
 */
static void stop_workers(client_context_t *ctx, pthread_t *forward,
                         pthread_t *reverse)
{
    atomic_store(&ctx->stop_workers, 1);
    pthread_join(*forward, NULL);
    pthread_join(*reverse, NULL);
    atomic_store(&ctx->stop_workers, 0);
}

/*
 * Renegotiate the session on the existing socket.
 *
 * Returns 0 on success, -1 on shutdown or failure to restart workers.
 */
static int renegotiate(client_context_t *ctx)
{
    if (handshake(ctx) != 0) {
        return -1;
    }

    reset_session(ctx);
    atomic_store(&ctx->last_rx, time(NULL));
    stats_add_rekey(&ctx->stats);

    return 0;
}

/*
 * Render the Prometheus body for the metrics endpoint.
 *
 * The counters are shared with --status; the extra gauge tells a scraper
 * whether this client currently holds a session, which is what an alert
 * on "tunnel down" actually wants.
 */
static int client_ready(char *out, size_t size, void *arg)
{
    client_context_t *ctx = (client_context_t *)arg;

    if (ctx->udp_fd == PSIX_INVALID_SOCKET) {
        snprintf(out, size, "not ready: no server socket\n");
        return 0;
    }

    snprintf(out, size, "ready: session=%s\n",
             atomic_load(&ctx->last_rx) == 0 ? "idle" : "open");
    return 1;
}

static int client_metrics_body(char *out, size_t size, void *arg)
{
    client_context_t *ctx = (client_context_t *)arg;
    size_t used;
    int n;

    if (stats_format_prometheus(&ctx->stats, "client", out, size) != 0) {
        return -1;
    }

    used = strlen(out);

    n = snprintf(out + used, size - used,
                 "# HELP pipesix_session_open Whether this client holds a "
                 "UDP session to the server.\n"
                 "# TYPE pipesix_session_open gauge\n"
                 "pipesix_session_open{client_id=\"%s\"} %d\n",
                 ctx->config->client_id,
                 ctx->udp_fd == PSIX_INVALID_SOCKET ? 0 : 1);

    if (n < 0 || (size_t)n >= size - used) {
        return -1;
    }

    return 0;
}

/*
 * Control channel handler: report the client's tunnel state.
 */
static int client_control_handler(const char *request, char *reply,
                                  size_t reply_size, void *arg)
{
    client_context_t *ctx = (client_context_t *)arg;
    char stats_line[512];
    time_t now = time(NULL);
    unsigned long uptime;

    if (strcmp(request, "status json") == 0) {
        char config_esc[1024];
        char tun_name_esc[256];
        char tun_addr_esc[256];
        char remote_esc[512];
        char stats_json[768];
        char quota_json[192];
        int n;

        if (control_json_escape(ctx->config->config_path, config_esc,
                                sizeof(config_esc)) != 0 ||
            control_json_escape(ctx->config->tun_name, tun_name_esc,
                                sizeof(tun_name_esc)) != 0 ||
            control_json_escape(ctx->config->tun_address, tun_addr_esc,
                                sizeof(tun_addr_esc)) != 0 ||
            control_json_escape(
                ctx->remote_current[0] != '\0'
                    ? ctx->remote_current
                    : ctx->config->remote_address,
                remote_esc, sizeof(remote_esc)) != 0) {
            snprintf(reply, reply_size,
                     "ERR cannot encode the status as JSON\n");
            return -1;
        }

        uptime = (now > ctx->stats.started)
                     ? (unsigned long)(now - ctx->stats.started)
                     : 0ul;

        stats_format_json(&ctx->stats, "client", stats_json,
                          sizeof(stats_json));

        if (atomic_load(&ctx->quota_valid)) {
            uint64_t limit = atomic_load(&ctx->quota_limit);
            uint64_t used = atomic_load(&ctx->quota_used);
            uint64_t left = (limit > 0)
                                ? (used >= limit ? 0 : limit - used)
                                : 0;

            snprintf(quota_json, sizeof(quota_json),
                     ",\"quota\":{\"limit_bytes\":%llu,"
                     "\"used_bytes\":%llu,\"remaining_bytes\":%llu,"
                     "\"period_start_unix\":%lld,"
                     "\"period_end_unix\":%lld}",
                     (unsigned long long)limit,
                     (unsigned long long)used,
                     (unsigned long long)left,
                     (long long)atomic_load(&ctx->quota_start),
                     (long long)atomic_load(&ctx->quota_end));
        } else {
            quota_json[0] = '\0';
        }

        n = snprintf(reply, reply_size,
                     "OK\n{\"mode\":\"client\",\"config\":\"%s\","
                     "\"client_id\":\"%s\","
                     "\"remote\":{\"address\":\"%s\",\"port\":%d},"
                     "\"tun\":{\"name\":\"%s\",\"address\":\"%s\","
                     "\"prefixlen\":%d},"
                     "\"uptime_seconds\":%lu,\"session\":\"%s\"%s,"
                     "\"stats\":%s}\n",
                     config_esc, ctx->config->client_id, remote_esc,
                     ctx->config->remote_port, tun_name_esc, tun_addr_esc,
                     ctx->config->tun_prefixlen, uptime,
                     ctx->udp_fd == PSIX_INVALID_SOCKET ? "closed" : "open",
                     quota_json, stats_json);

        if (n < 0 || (size_t)n >= reply_size) {
            snprintf(reply, reply_size,
                     "ERR status is too large to report\n");
            return -1;
        }

        return 0;
    }

    if (strcmp(request, "metrics") == 0) {
        if (reply_size < 4) {
            return -1;
        }
        snprintf(reply, reply_size, "OK\n");
        return client_metrics_body(reply + 3, reply_size - 3, ctx);
    }

    if (strcmp(request, "status") != 0 && strcmp(request, "stats") != 0) {
        snprintf(reply, reply_size, "ERR unknown request '%s'\n", request);
        return -1;
    }

    stats_format(&ctx->stats, "client", stats_line, sizeof(stats_line));

    if (strcmp(request, "stats") == 0) {
        snprintf(reply, reply_size, "OK\n%s\n", stats_line);
        return 0;
    }

    uptime = (now > ctx->stats.started)
                 ? (unsigned long)(now - ctx->stats.started)
                 : 0ul;

    {
        char quota_line[192];

        if (atomic_load(&ctx->quota_valid)) {
            char start[16] = "?";
            char end[16] = "?";
            uint64_t limit = atomic_load(&ctx->quota_limit);
            uint64_t used = atomic_load(&ctx->quota_used);
            uint64_t left = (limit > 0)
                                ? (used >= limit ? 0 : limit - used)
                                : 0;

            (void)policy_format_date((time_t)atomic_load(&ctx->quota_start),
                                     start, sizeof(start));
            (void)policy_format_date((time_t)atomic_load(&ctx->quota_end),
                                     end, sizeof(end));

            if (limit > 0) {
                snprintf(quota_line, sizeof(quota_line),
                         "quota: used=%llu B limit=%llu B left=%llu B "
                         "period=%s..%s UTC\n",
                         (unsigned long long)used,
                         (unsigned long long)limit,
                         (unsigned long long)left, start, end);
            } else {
                snprintf(quota_line, sizeof(quota_line),
                         "quota: used=%llu B limit=unlimited "
                         "period=%s..%s UTC\n",
                         (unsigned long long)used, start, end);
            }
        } else {
            quota_line[0] = '\0';
        }

        snprintf(reply, reply_size,
                 "OK\n"
                 "mode: client\n"
                 "client_id: %s\n"
                 "remote: %s:%d\n"
                 "tun: %s %s/%d\n"
                 "uptime: %lus\n"
                 "session: %s\n"
                 "%s"
                 "%s\n",
                 ctx->config->client_id,
                 ctx->remote_current[0] != '\0'
                     ? ctx->remote_current
                     : ctx->config->remote_address,
                 ctx->config->remote_port, ctx->config->tun_name,
                 ctx->config->tun_address, ctx->config->tun_prefixlen,
                 uptime,
                 ctx->udp_fd == PSIX_INVALID_SOCKET ? "closed" : "open",
                 quota_line, stats_line);
    }
    return 0;
}

int client_start(pipesix_config_t *config)
{
    tun_device_t tun;
    client_context_t ctx;
    pthread_t forward_thread;
    pthread_t reverse_thread;
    int workers_running = 0;

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
    ctx.udp_fd = PSIX_INVALID_SOCKET;

    if (pipesix_key_from_string(config->secret, ctx.psk) != 0) {
        log_error("Failed to derive the pre-shared key from 'secret'");
        tun_close(&tun);
        return -1;
    }

    atomic_init(&ctx.seq, 0);
    atomic_init(&ctx.salt, 0);
    atomic_init(&ctx.last_rx, time(NULL));
    atomic_init(&ctx.keepalive, config->keepalive);
    atomic_init(&ctx.stop_workers, 0);
    atomic_init(&ctx.handshake_needed, 0);
    atomic_init(&ctx.server_closing, 0);
    atomic_init(&ctx.quota_valid, 0);
    atomic_init(&ctx.last_quota_request, 0);
    pipesix_replay_reset(&ctx.replay);
    stats_init(&ctx.stats);

    if (audit_open(config->audit_log) != 0) {
        log_warn("Cannot open the audit log '%s': %s", config->audit_log,
                 strerror(errno));
    }
    audit_set_process_actor("service");
    audit_event("startup", config->client_id, "", "client starting");

    {
        size_t endpoints = remote_endpoint_count(config);
        size_t i;

        for (i = 0; i < endpoints; i++) {
            ctx.udp_fd = connect_server(config, i, ctx.remote_current,
                                        sizeof(ctx.remote_current), 0);
            if (ctx.udp_fd != PSIX_INVALID_SOCKET) {
                ctx.endpoint_index = i;
                break;
            }
        }
    }
    if (ctx.udp_fd == PSIX_INVALID_SOCKET) {
        tun_close(&tun);
        return -1;
    }

    reset_session(&ctx);

    /*
     * Creating the TUN device and binding the socket needed root; the
     * tunnel itself does not. Drop before the handshake so no packet or
     * credential is processed with elevated privileges.
     */
    if (psix_drop_privileges(config->user, config->group) != 0) {
        log_error("Cannot drop privileges to user '%s' group '%s': %s",
                  config->user, config->group, strerror(errno));
        psix_close(ctx.udp_fd);
        tun_close(&tun);
        return -1;
    }
    if (config->user[0] != '\0') {
        log_info("Dropped privileges to user '%s'%s%s", config->user,
                 config->group[0] != '\0' ? " group '" : "",
                 config->group[0] != '\0' ? config->group : "");
    }

    if (handshake(&ctx) != 0) {
        log_info("Shutdown requested before the handshake completed");
        psix_close(ctx.udp_fd);
        tun_close(&tun);
        return 0;
    }

    if (start_workers(&ctx, &forward_thread, &reverse_thread) != 0) {
        psix_close(ctx.udp_fd);
        tun_close(&tun);
        return -1;
    }
    workers_running = 1;

    control_set_handler(client_control_handler, &ctx);
    metrics_start(config, client_metrics_body, client_ready, &ctx);

    log_info("Client tunnel ready (crypto=chacha20-poly1305, client_id=%s, "
             "endpoint=%s, keepalive=%ds, peer_timeout=%ds)",
             config->client_id,
             ctx.remote_current[0] != '\0' ? ctx.remote_current : "?",
             atomic_load(&ctx.keepalive), config->peer_timeout);
    log_info("Client is running. Send SIGINT/SIGTERM to stop, "
             "SIGUSR1 for stats, SIGHUP to reload.");

    {
        time_t last_report = time(NULL);
        time_t last_failback_probe = time(NULL);

        while (!runtime_should_stop()) {
            uint8_t new_psk[PIPESIX_KEY_LEN] = {0};
            time_t now;
            int keepalive;
            int rotate = 0;
            int remote_changed = 0;

            psix_sleep(1);
            now = time(NULL);

            if (runtime_take_reload_request()) {
                char old_id[CONFIG_MAX_CLIENT_ID];
                char old_secret[CONFIG_MAX_SECRET];
                char old_remote[CONFIG_MAX_REMOTE_LIST];
                char old_metrics_address[CONFIG_MAX_ADDRESS];
                char old_metrics_token[CONFIG_MAX_SECRET];
                int old_remote_port = config->remote_port;
                int old_metrics_port = config->metrics_port;

                memcpy(old_id, config->client_id, sizeof(old_id));
                memcpy(old_secret, config->secret, sizeof(old_secret));
                snprintf(old_remote, sizeof(old_remote), "%s",
                         config->remote_address);
                snprintf(old_metrics_address, sizeof(old_metrics_address),
                         "%s", config->metrics_address);
                snprintf(old_metrics_token, sizeof(old_metrics_token), "%s",
                         config->metrics_token);

                if (config_reload_runtime(config) == 0) {
                    logger_set_level(config->log_level);
                    logger_set_json(config->log_json);
                    atomic_store(&ctx.keepalive, config->keepalive);

                    if (audit_open(config->audit_log) != 0) {
                        log_warn("Cannot open the audit log '%s': %s",
                                 config->audit_log, strerror(errno));
                    }

                    remote_changed =
                        strcmp(old_remote, config->remote_address) != 0 ||
                        old_remote_port != config->remote_port;

                    if (strcmp(old_metrics_address,
                               config->metrics_address) != 0 ||
                        old_metrics_port != config->metrics_port ||
                        strcmp(old_metrics_token,
                               config->metrics_token) != 0) {
                        metrics_stop();
                        if (metrics_start(config, client_metrics_body,
                                          client_ready, &ctx) != 0) {
                            log_warn("The new metrics settings could not "
                                     "be applied");
                        }
                    }

                    log_info("Configuration reloaded (log_level, log_format, "
                             "keepalive, peer_timeout, stats_interval, "
                             "endpoints, failback, audit, metrics)");
                    audit_event("reload", config->client_id, "",
                                "configuration reloaded");

                    /*
                     * Our own key or identity changed, so the server will
                     * not accept the current session keys any more. Derive
                     * the new key before touching the session: if the key
                     * is unusable the live tunnel keeps working.
                     */
                    if (strcmp(old_id, config->client_id) != 0 ||
                        strcmp(old_secret, config->secret) != 0) {
                        if (pipesix_key_from_string(config->secret,
                                                    new_psk) == 0) {
                            rotate = 1;
                            log_info("Client credentials changed; "
                                     "re-handshaking with the server");
                        } else {
                            memset(new_psk, 0, sizeof(new_psk));
                            log_error("Cannot derive a key from the new "
                                      "'secret'; keeping the current "
                                      "session");
                        }
                    }
                } else {
                    log_error("Configuration reload failed; keeping the "
                              "previous settings");
                }

                memset(old_secret, 0, sizeof(old_secret));
                last_report = now;
            }

            if (rotate || remote_changed) {
                /* The workers encrypt with tx_key/rx_key: stop them first. */
                if (workers_running) {
                    stop_workers(&ctx, &forward_thread, &reverse_thread);
                    workers_running = 0;
                }

                if (rotate) {
                    memset(ctx.psk, 0, sizeof(ctx.psk));
                    memset(ctx.tx_key, 0, sizeof(ctx.tx_key));
                    memset(ctx.rx_key, 0, sizeof(ctx.rx_key));
                    memcpy(ctx.psk, new_psk, sizeof(ctx.psk));
                    memset(new_psk, 0, sizeof(new_psk));
                }

                if (remote_changed) {
                    psix_close(ctx.udp_fd);
                    ctx.udp_fd = PSIX_INVALID_SOCKET;
                    ctx.endpoint_index =
                        remote_endpoint_count(config) - 1;
                    if (reconnect_peer(&ctx) != 0) {
                        break;
                    }
                }

                if (renegotiate(&ctx) != 0) {
                    break;
                }

                if (start_workers(&ctx, &forward_thread, &reverse_thread)
                    != 0) {
                    metrics_stop();
                    control_stop();
                    psix_close(ctx.udp_fd);
                    tun_close(&tun);
                    return -1;
                }

                workers_running = 1;
                last_report = now;
                continue;
            }

            /*
             * Probe the preferred endpoint on a temporary socket. The
             * probe is authenticated but creates no session, so a live
             * tunnel keeps running while we decide whether to fail back.
             */
            if (config->endpoint_failback && ctx.endpoint_index > 0 &&
                config->endpoint_failback_interval > 0 &&
                (now - last_failback_probe) >=
                    (time_t)config->endpoint_failback_interval) {
                char preferred[CONFIG_MAX_ADDRESS] = "";

                last_failback_probe = now;
                if (probe_endpoint(config, 0, ctx.psk, HANDSHAKE_TIMEOUT_MS,
                                   preferred, sizeof(preferred), NULL) == 0) {
                    psix_socket_t new_fd;

                    log_info("Preferred relay endpoint responded; failing "
                             "back from endpoint %llu",
                             (unsigned long long)(ctx.endpoint_index + 1));
                    stop_workers(&ctx, &forward_thread, &reverse_thread);
                    workers_running = 0;

                    new_fd = connect_server(config, 0, ctx.remote_current,
                                            sizeof(ctx.remote_current), 0);
                    if (new_fd == PSIX_INVALID_SOCKET) {
                        log_warn("Could not connect to the preferred relay; "
                                 "staying on the current endpoint");
                        if (start_workers(&ctx, &forward_thread,
                                          &reverse_thread) != 0) {
                            metrics_stop();
                            control_stop();
                            psix_close(ctx.udp_fd);
                            tun_close(&tun);
                            return -1;
                        }
                        workers_running = 1;
                    } else {
                        psix_close(ctx.udp_fd);
                        ctx.udp_fd = new_fd;
                        ctx.endpoint_index = 0;
                        if (renegotiate(&ctx) != 0) {
                            break;
                        }
                        if (start_workers(&ctx, &forward_thread,
                                          &reverse_thread) != 0) {
                            metrics_stop();
                            control_stop();
                            psix_close(ctx.udp_fd);
                            tun_close(&tun);
                            return -1;
                        }
                        workers_running = 1;
                        last_report = now;
                        log_info("Failed back to the preferred relay");
                        continue;
                    }
                }
            }

            if (runtime_take_stats_request()) {
                stats_dump(&ctx.stats, "client");
                last_report = now;
            } else if (config->stats_interval > 0 &&
                       (now - last_report) >=
                           (time_t)config->stats_interval) {
                stats_dump(&ctx.stats, "client");
                last_report = now;
            }

            if (atomic_exchange_explicit(&ctx.handshake_needed, 0,
                                         memory_order_relaxed) != 0) {
                log_info("Renegotiating the session with the server");

                stop_workers(&ctx, &forward_thread, &reverse_thread);
                workers_running = 0;

                if (renegotiate(&ctx) != 0) {
                    break;
                }

                if (start_workers(&ctx, &forward_thread,
                                  &reverse_thread) != 0) {
                    metrics_stop();
                    control_stop();
                    psix_close(ctx.udp_fd);
                    tun_close(&tun);
                    return -1;
                }
                workers_running = 1;
                last_report = now;
                continue;
            }

            /*
             * The server announced its own shutdown. Its port is about to
             * stop answering, so waiting out peer_timeout would only keep
             * the tunnel dead for minutes: reconnect right away, with the
             * usual backoff if the relay is not back yet.
             */
            if (atomic_exchange_explicit(&ctx.server_closing, 0,
                                         memory_order_relaxed) != 0) {
                log_info("Server closed the session; reconnecting");

                stop_workers(&ctx, &forward_thread, &reverse_thread);
                workers_running = 0;

                psix_close(ctx.udp_fd);
                ctx.udp_fd = PSIX_INVALID_SOCKET;

                if (reconnect_peer(&ctx) != 0) {
                    break;
                }

                if (renegotiate(&ctx) != 0) {
                    break;
                }

                if (start_workers(&ctx, &forward_thread,
                                  &reverse_thread) != 0) {
                    metrics_stop();
                    control_stop();
                    psix_close(ctx.udp_fd);
                    tun_close(&tun);
                    return -1;
                }
                workers_running = 1;
                last_report = now;

                log_info("Client reconnected");
            }

            keepalive = atomic_load(&ctx.keepalive);
            if (config->peer_timeout > 0 && keepalive > 0 &&
                (now - atomic_load(&ctx.last_rx)) >=
                    (time_t)config->peer_timeout) {
                log_warn("No traffic from the server for %d seconds; "
                         "reconnecting", config->peer_timeout);

                stop_workers(&ctx, &forward_thread, &reverse_thread);
                workers_running = 0;

                psix_close(ctx.udp_fd);
                ctx.udp_fd = PSIX_INVALID_SOCKET;

                if (reconnect_peer(&ctx) != 0) {
                    break;
                }

                if (renegotiate(&ctx) != 0) {
                    break;
                }

                if (start_workers(&ctx, &forward_thread,
                                  &reverse_thread) != 0) {
                    metrics_stop();
                    control_stop();
                    psix_close(ctx.udp_fd);
                    tun_close(&tun);
                    return -1;
                }
                workers_running = 1;
                last_report = now;

                log_info("Client reconnected");
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

    if (workers_running) {
        atomic_store(&ctx.stop_workers, 1);
        pthread_join(forward_thread, NULL);
        log_info("Forward thread joined");

        pthread_join(reverse_thread, NULL);
        log_info("Reverse thread joined");
    }

    memset(ctx.psk, 0, sizeof(ctx.psk));
    memset(ctx.tx_key, 0, sizeof(ctx.tx_key));
    memset(ctx.rx_key, 0, sizeof(ctx.rx_key));

    if (ctx.udp_fd != PSIX_INVALID_SOCKET) {
        psix_close(ctx.udp_fd);
        log_info("UDP socket closed");
    }

    tun_close(&tun);
    stats_dump(&ctx.stats, "client");

    audit_event("shutdown", config->client_id, "", "client stopped");
    audit_close();
    log_info("Client shutdown complete");
    return 0;
}
