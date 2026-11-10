/*
 * client.c - pipesix Client Mode Implementation
 *
 * The client owns a TUN device and a connected UDP socket:
 *
 *   Applications -> TUN -> forward loop -> UDP -> server
 *   Applications <- TUN <- reverse loop <- UDP <- server
 *
 * Both loops use poll() with a short timeout so shutdown requests are
 * handled promptly. Frames are authenticated with HMAC-SHA256 when a
 * shared secret is configured, protected against replay by a sliding
 * sequence window, and a keepalive is sent when the tunnel is idle so
 * NAT mappings stay open and the server can echo liveness back.
 *
 * The main thread watches for dead peers: when no valid frame has been
 * received for peer_timeout seconds it joins the workers, re-resolves
 * the server address, reconnects with exponential backoff, sends a
 * session reset and restarts the workers. SIGHUP reloads the
 * runtime-tunable configuration without dropping the tunnel.
 */

#include "client.h"
#include "config.h"
#include "crypto.h"
#include "ipv6.h"
#include "logger.h"
#include "proto.h"
#include "runtime.h"
#include "stats.h"
#include "tun.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
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

typedef struct {
    pipesix_config_t  *config;
    tun_device_t      *tun;
    int                udp_fd;
    uint8_t            key[PIPESIX_KEY_LEN];
    int                auth_enabled;
    _Atomic uint64_t   seq;
    _Atomic uint32_t   salt;
    _Atomic time_t     last_rx;
    _Atomic int        keepalive;
    _Atomic int        stop_workers;
    pipesix_replay_t   replay;
    pipesix_stats_t    stats;
} client_context_t;

static uint64_t next_seq(client_context_t *ctx)
{
    return atomic_fetch_add_explicit(&ctx->seq, 1, memory_order_relaxed);
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
                                    ctx->auth_enabled ? ctx->key : NULL);
    if (frame_len == 0) {
        errno = EINVAL;
        return -1;
    }

    if (send(ctx->udp_fd, frame, frame_len, 0) != (ssize_t)frame_len) {
        return -1;
    }

    return 0;
}

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

static void send_session_reset(client_context_t *ctx)
{
    if (send_frame(ctx, PIPESIX_FLAG_RESET, NULL, 0) != 0) {
        log_debug("Failed to send session reset: %s", strerror(errno));
    }
}

/*
 * Forward loop (TUN -> UDP)
 */
static void *forward_loop(void *arg)
{
    client_context_t *ctx = (client_context_t *)arg;
    uint8_t packet[PIPESIX_MAX_PACKET];
    struct pollfd pfd;
    time_t last_send = time(NULL);

    pfd.fd = ctx->tun->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    log_info("Forward thread started (TUN -> UDP)");

    while (!runtime_should_stop() && !atomic_load(&ctx->stop_workers)) {
        int ready = poll(&pfd, 1, POLL_INTERVAL_MS);
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

        if (ready > 0 && (pfd.revents & POLLIN) != 0) {
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
    struct pollfd pfd;

    pfd.fd = ctx->udp_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    log_info("Reverse thread started (UDP -> TUN)");

    while (!runtime_should_stop() && !atomic_load(&ctx->stop_workers)) {
        int ready = poll(&pfd, 1, POLL_INTERVAL_MS);
        pipesix_frame_t frame;
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

        nread = recv(ctx->udp_fd, frame_buf, sizeof(frame_buf), 0);
        if (nread < 0) {
            if (errno == EINTR) continue;
            log_error("UDP receive failed: %s", strerror(errno));
            stats_add_error(&ctx->stats);
            runtime_request_stop();
            break;
        }

        rc = pipesix_frame_parse(frame_buf, (size_t)nread, &frame,
                                 ctx->auth_enabled ? ctx->key : NULL);
        if (rc != PIPESIX_OK) {
            log_warn("Dropping invalid frame (%zd bytes): %s",
                     nread, pipesix_strerror(rc));
            stats_add_invalid(&ctx->stats);
            if (rc == PIPESIX_ERR_AUTH) {
                stats_add_auth_failure(&ctx->stats);
            }
            continue;
        }

        /*
         * A reset starts a new session: clear the replay window before
         * recording the reset frame's own sequence number.
         */
        if ((frame.flags & PIPESIX_FLAG_RESET) != 0) {
            pipesix_replay_reset(&ctx->replay);
            log_info("Server reset the tunnel session");
        }

        if (!pipesix_replay_accept(&ctx->replay, frame.seq)) {
            log_warn("Dropping replayed/out-of-window frame (seq=%u)",
                     (unsigned)frame.seq);
            stats_add_replayed(&ctx->stats);
            continue;
        }

        atomic_store(&ctx->last_rx, time(NULL));

        if ((frame.flags & PIPESIX_FLAG_RESET) != 0) {
            continue;
        }

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
 * Returns the socket descriptor, or -1 on failure.
 */
static int connect_server(const pipesix_config_t *config)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp;
    char port_str[16];
    int gai;
    int fd = -1;

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
        if (fd < 0) {
            continue;
        }

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            if (getnameinfo(rp->ai_addr, rp->ai_addrlen,
                            host, sizeof(host), serv, sizeof(serv),
                            NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
                log_info("UDP connected to %s:%s (%s)", host, serv,
                         rp->ai_family == AF_INET6 ? "AF_INET6" : "AF_INET");
            }
            break;
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(result);

    if (fd < 0) {
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

        {
            unsigned int i;

            for (i = 0; i < delay && !runtime_should_stop(); i++) {
                struct timespec ts;

                ts.tv_sec = 1;
                ts.tv_nsec = 0;
                nanosleep(&ts, NULL);
            }
        }

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
    ctx.udp_fd = -1;

    if (config->secret[0] != '\0') {
        if (pipesix_key_from_string(config->secret, ctx.key) != 0) {
            log_error("Failed to derive authentication key from 'secret'");
            tun_close(&tun);
            return -1;
        }
        ctx.auth_enabled = 1;
    }

    atomic_init(&ctx.seq, 0);
    atomic_init(&ctx.salt, 0);
    atomic_init(&ctx.last_rx, time(NULL));
    atomic_init(&ctx.keepalive, config->keepalive);
    atomic_init(&ctx.stop_workers, 0);
    pipesix_replay_reset(&ctx.replay);
    stats_init(&ctx.stats);

    ctx.udp_fd = connect_server(config);
    if (ctx.udp_fd < 0) {
        tun_close(&tun);
        return -1;
    }

    reset_session(&ctx);
    send_session_reset(&ctx);

    if (start_workers(&ctx, &forward_thread, &reverse_thread) != 0) {
        close(ctx.udp_fd);
        tun_close(&tun);
        return -1;
    }
    workers_running = 1;

    log_info("Client tunnel ready (crypto=%s, keepalive=%ds, peer_timeout=%ds)",
             ctx.auth_enabled ? "chacha20-poly1305" : "plaintext",
             atomic_load(&ctx.keepalive), config->peer_timeout);
    log_info("Client is running. Send SIGINT/SIGTERM to stop, "
             "SIGUSR1 for stats, SIGHUP to reload.");

    {
        time_t last_report = time(NULL);

        while (!runtime_should_stop()) {
            struct timespec delay;
            time_t now;
            int keepalive;

            delay.tv_sec = 1;
            delay.tv_nsec = 0;
            nanosleep(&delay, NULL);
            now = time(NULL);

            if (runtime_take_reload_request()) {
                if (config_reload_runtime(config) == 0) {
                    logger_set_level(config->log_level);
                    atomic_store(&ctx.keepalive, config->keepalive);
                    log_info("Configuration reloaded (log_level, keepalive, "
                             "peer_timeout, stats_interval)");
                } else {
                    log_error("Configuration reload failed; keeping the "
                              "previous settings");
                }
                last_report = now;
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

            keepalive = atomic_load(&ctx.keepalive);
            if (config->peer_timeout > 0 && keepalive > 0 &&
                (now - atomic_load(&ctx.last_rx)) >=
                    (time_t)config->peer_timeout) {
                log_warn("No traffic from the server for %d seconds; "
                         "reconnecting", config->peer_timeout);

                atomic_store(&ctx.stop_workers, 1);
                pthread_join(forward_thread, NULL);
                pthread_join(reverse_thread, NULL);
                workers_running = 0;

                close(ctx.udp_fd);
                ctx.udp_fd = -1;

                if (reconnect_peer(&ctx) != 0) {
                    break;
                }

                reset_session(&ctx);
                send_session_reset(&ctx);
                atomic_store(&ctx.last_rx, time(NULL));
                atomic_store(&ctx.stop_workers, 0);

                if (start_workers(&ctx, &forward_thread,
                                  &reverse_thread) != 0) {
                    close(ctx.udp_fd);
                    tun_close(&tun);
                    return -1;
                }
                workers_running = 1;
                last_report = now;

                log_info("Client reconnected");
            }
        }
    }

    log_info("Initiating graceful shutdown...");

    atomic_store(&ctx.stop_workers, 1);
    if (workers_running) {
        pthread_join(forward_thread, NULL);
        log_info("Forward thread joined");

        pthread_join(reverse_thread, NULL);
        log_info("Reverse thread joined");
    }

    if (ctx.udp_fd >= 0) {
        close(ctx.udp_fd);
        log_info("UDP socket closed");
    }

    tun_close(&tun);
    stats_dump(&ctx.stats, "client");

    log_info("Client shutdown complete");
    return 0;
}
