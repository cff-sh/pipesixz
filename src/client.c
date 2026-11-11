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
#include "control.h"
#include "config.h"
#include "crypto.h"
#include "ipv6.h"
#include "logger.h"
#include "proto.h"
#include "runtime.h"
#include "stats.h"
#include "platform.h"
#include "tun.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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
        return -1;
    }

    body_len = pipesix_handshake_init_build(init_body, sizeof(init_body),
                                            ctx->config->client_id, cnonce,
                                            ctx->psk);
    if (body_len == 0) {
        log_error("Cannot build the handshake request (check 'client_id')");
        return -1;
    }

    frame_len = pipesix_frame_build(frame, sizeof(frame),
                                    PIPESIX_FLAG_HANDSHAKE_INIT, 0, 0,
                                    init_body, body_len, NULL);
    if (frame_len == 0) {
        log_error("Cannot build the handshake frame");
        return -1;
    }

    if (psix_send(ctx->udp_fd, frame, frame_len, 0) != (ssize_t)frame_len) {
        log_warn("Failed to send the handshake request: %s", strerror(errno));
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
            return -1;
        }
        if (ready == 0) {
            continue;
        }

        nread = psix_recv(ctx->udp_fd, buf, sizeof(buf), 0);
        if (nread < 0) {
            if (errno == EINTR) continue;
            log_warn("Handshake receive failed: %s", strerror(errno));
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
            return -1;
        }

        if (memcmp(echoed_cnonce, cnonce, sizeof(cnonce)) != 0) {
            continue; /* Response to a different attempt. */
        }

        memcpy(snonce, parsed.payload + PIPESIX_HANDSHAKE_NONCE_LEN,
               sizeof(snonce));

        pipesix_session_keys(ctx->psk, cnonce, snonce,
                             ctx->tx_key, ctx->rx_key);

        log_info("Handshake completed as client '%s'",
                 ctx->config->client_id);
        return 0;
    }

    return -1;
}

/*
 * Handshake until it succeeds or a shutdown is requested.
 *
 * Returns 0 on success, -1 if shutdown interrupted the attempts.
 */
static int handshake(client_context_t *ctx)
{
    unsigned int delay = 1u;

    while (!runtime_should_stop()) {
        if (handshake_once(ctx, HANDSHAKE_TIMEOUT_MS) == 0) {
            return 0;
        }
        if (runtime_should_stop()) {
            break;
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
            log_warn("Dropping invalid frame (%zd bytes): %s",
                     nread, pipesix_strerror(rc));
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
static psix_socket_t connect_server(const pipesix_config_t *config)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp;
    char port_str[16];
    int gai;
    psix_socket_t fd = PSIX_INVALID_SOCKET;

    snprintf(port_str, sizeof(port_str), "%d", config->remote_port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    gai = getaddrinfo(config->remote_address, port_str, &hints, &result);
    if (gai != 0) {
        log_error("Failed to resolve server address '%s': %s",
                  config->remote_address, gai_strerror(gai));
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
                            NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
                log_info("UDP connected to %s:%s (%s)", host, serv,
                         rp->ai_family == AF_INET6 ? "AF_INET6" : "AF_INET");
            }
            break;
        }

        psix_close(fd);
        fd = PSIX_INVALID_SOCKET;
    }

    freeaddrinfo(result);

    if (fd == PSIX_INVALID_SOCKET) {
        log_error("Failed to connect UDP socket to %s:%d: %s",
                  config->remote_address, config->remote_port,
                  strerror(errno));
    }

    return fd;
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

    while (!runtime_should_stop()) {
        int fd = connect_server(ctx->config);

        if (fd >= 0) {
            ctx->udp_fd = fd;
            return 0;
        }

        log_warn("Reconnect failed; retrying in %u seconds", delay);
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
        char stats_json[512];
        int n;

        if (control_json_escape(ctx->config->config_path, config_esc,
                                sizeof(config_esc)) != 0 ||
            control_json_escape(ctx->config->tun_name, tun_name_esc,
                                sizeof(tun_name_esc)) != 0 ||
            control_json_escape(ctx->config->tun_address, tun_addr_esc,
                                sizeof(tun_addr_esc)) != 0 ||
            control_json_escape(ctx->config->remote_address, remote_esc,
                                sizeof(remote_esc)) != 0) {
            snprintf(reply, reply_size,
                     "ERR cannot encode the status as JSON\n");
            return -1;
        }

        uptime = (now > ctx->stats.started)
                     ? (unsigned long)(now - ctx->stats.started)
                     : 0ul;

        stats_format_json(&ctx->stats, "client", stats_json,
                          sizeof(stats_json));

        n = snprintf(reply, reply_size,
                     "OK\n{\"mode\":\"client\",\"config\":\"%s\","
                     "\"client_id\":\"%s\","
                     "\"remote\":{\"address\":\"%s\",\"port\":%d},"
                     "\"tun\":{\"name\":\"%s\",\"address\":\"%s\","
                     "\"prefixlen\":%d},"
                     "\"uptime_seconds\":%lu,\"session\":\"%s\","
                     "\"stats\":%s}\n",
                     config_esc, ctx->config->client_id, remote_esc,
                     ctx->config->remote_port, tun_name_esc, tun_addr_esc,
                     ctx->config->tun_prefixlen, uptime,
                     ctx->udp_fd == PSIX_INVALID_SOCKET ? "closed" : "open",
                     stats_json);

        if (n < 0 || (size_t)n >= reply_size) {
            snprintf(reply, reply_size,
                     "ERR status is too large to report\n");
            return -1;
        }

        return 0;
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

    snprintf(reply, reply_size,
             "OK\n"
             "mode: client\n"
             "client_id: %s\n"
             "remote: %s:%d\n"
             "tun: %s %s/%d\n"
             "uptime: %lus\n"
             "session: %s\n"
             "%s\n",
             ctx->config->client_id, ctx->config->remote_address,
             ctx->config->remote_port, ctx->config->tun_name,
             ctx->config->tun_address, ctx->config->tun_prefixlen,
             uptime,
             ctx->udp_fd == PSIX_INVALID_SOCKET ? "closed" : "open",
             stats_line);
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
    pipesix_replay_reset(&ctx.replay);
    stats_init(&ctx.stats);

    ctx.udp_fd = connect_server(config);
    if (ctx.udp_fd == PSIX_INVALID_SOCKET) {
        tun_close(&tun);
        return -1;
    }

    reset_session(&ctx);

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

    log_info("Client tunnel ready (crypto=chacha20-poly1305, client_id=%s, "
             "keepalive=%ds, peer_timeout=%ds)",
             config->client_id, atomic_load(&ctx.keepalive),
             config->peer_timeout);
    log_info("Client is running. Send SIGINT/SIGTERM to stop, "
             "SIGUSR1 for stats, SIGHUP to reload.");

    {
        time_t last_report = time(NULL);

        while (!runtime_should_stop()) {
            uint8_t new_psk[PIPESIX_KEY_LEN] = {0};
            time_t now;
            int keepalive;
            int rotate = 0;

            psix_sleep(1);
            now = time(NULL);

            if (runtime_take_reload_request()) {
                char old_id[CONFIG_MAX_CLIENT_ID];
                char old_secret[CONFIG_MAX_SECRET];

                memcpy(old_id, config->client_id, sizeof(old_id));
                memcpy(old_secret, config->secret, sizeof(old_secret));

                if (config_reload_runtime(config) == 0) {
                    logger_set_level(config->log_level);
                    atomic_store(&ctx.keepalive, config->keepalive);
                    log_info("Configuration reloaded (log_level, keepalive, "
                             "peer_timeout, stats_interval)");

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

            if (rotate) {
                /* The workers encrypt with tx_key/rx_key: stop them first. */
                if (workers_running) {
                    stop_workers(&ctx, &forward_thread, &reverse_thread);
                    workers_running = 0;
                }

                memset(ctx.psk, 0, sizeof(ctx.psk));
                memset(ctx.tx_key, 0, sizeof(ctx.tx_key));
                memset(ctx.rx_key, 0, sizeof(ctx.rx_key));
                memcpy(ctx.psk, new_psk, sizeof(ctx.psk));
                memset(new_psk, 0, sizeof(new_psk));

                if (renegotiate(&ctx) != 0) {
                    break;
                }

                if (start_workers(&ctx, &forward_thread, &reverse_thread)
                    != 0) {
                    control_stop();
                    psix_close(ctx.udp_fd);
                    tun_close(&tun);
                    return -1;
                }

                workers_running = 1;
                last_report = now;
                continue;
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
                    control_stop();
                    psix_close(ctx.udp_fd);
                    tun_close(&tun);
                    return -1;
                }
                workers_running = 1;
                last_report = now;
                continue;
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
     * reports on is torn down.
     */
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

    log_info("Client shutdown complete");
    return 0;
}
