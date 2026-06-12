/*
 * server.c - pipesix Server Mode Implementation
 *
 * Implements the server-side tunnel operation. The server:
 *
 *   1. Creates a TUN device (tun0) with a configured IPv6 address
 *   2. Binds a UDP socket to listen for client connections
 *   3. Spawns two worker threads:
 *        - network_to_tun: Receives frames from the client via UDP,
 *          decapsulates IPv6 packets, and writes them to the TUN
 *          device for forwarding to the Route64 gateway
 *        - tun_to_network: Reads IPv6 packets from the TUN device
 *          (return traffic from the gateway), encapsulates them
 *          in frames, and sends them back to the client
 *   4. Waits for a shutdown signal, then gracefully terminates
 *
 * The server dynamically learns the client's address from the first
 * received packet and uses that address for all return traffic.
 * In the current implementation, the server serves a single client.
 * If a new client connects, the previous client is replaced.
 */

#include "server.h"
#include "tun.h"
#include "config.h"
#include "proto.h"
#include "ipv6.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/*
 * Receiver Thread (Network -> TUN)
 *
 * Continuously receives frames from the client via UDP recvfrom(),
 * validates the frame header, decapsulates the IPv6 packet, and
 * writes it to the TUN device. The TUN device kernel-side routing
 * then forwards the packet to the Route64 gateway.
 *
 * This thread also learns and updates the client's address so that
 * the sender thread knows where to send return traffic.
 *
 * Parameters:
 *   arg - Pointer to server_context_t
 *
 * Returns:
 *   NULL always
 */
static void *network_to_tun_thread(void *arg)
{
    server_context_t *ctx = (server_context_t *)arg;
    uint8_t recv_buf[PIPESIX_RECV_BUF_SIZE];

    log_info("Receiver thread started (UDP -> TUN)");

    while (*ctx->running) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        ssize_t nrecv;

        /* Receive frame from any client */
        nrecv = recvfrom(ctx->udp_fd, recv_buf, sizeof(recv_buf), 0,
                         (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (nrecv < 0) {
            if (errno == EINTR) continue;
            log_error("UDP recvfrom failed: %s", strerror(errno));
            break;
        }

        /* Validate minimum frame size */
        if (nrecv < (ssize_t)PIPESIX_HEADER_SIZE) {
            log_warn("Received short frame: %zd bytes (minimum %zu)",
                     nrecv, PIPESIX_HEADER_SIZE);
            continue;
        }

        /* Parse and validate frame header */
        pipesix_frame_header_t *hdr = (pipesix_frame_header_t *)recv_buf;

        if (ntohl(hdr->magic) != PIPESIX_MAGIC) {
            log_warn("Invalid frame magic: 0x%08x (expected 0x%08lx) from client",
                     ntohl(hdr->magic), (unsigned long)PIPESIX_MAGIC);
            continue;
        }

        if (ntohs(hdr->version) != PIPESIX_VERSION) {
            log_warn("Unsupported protocol version from client: %u (expected %u)",
                     ntohs(hdr->version), PIPESIX_VERSION);
            continue;
        }

        /* Extract encapsulated packet length */
        uint32_t pkt_length = ntohl(hdr->length);

        if (pkt_length > (uint32_t)(nrecv - (ssize_t)PIPESIX_HEADER_SIZE)) {
            log_warn("Frame length mismatch: header claims %u bytes, "
                     "but only %zd available", pkt_length,
                     nrecv - (ssize_t)PIPESIX_HEADER_SIZE);
            return NULL;
        }

        if (pkt_length == 0) {
            continue;
        }

        /*
         * Update the client address for return traffic.
         * Protected by a mutex to ensure thread-safe access between
         * the receiver and sender threads.
         */
        pthread_mutex_lock(&ctx->client_lock);
        memcpy(&ctx->client_addr, &peer_addr, peer_addr_len);
        ctx->client_addr_len = peer_addr_len;
        ctx->client_initialized = 1;

        /* Log the client address on first connection */
        if (!ctx->client_initialized) {
            char addr_str[INET6_ADDRSTRLEN];
            if (peer_addr.ss_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)&peer_addr;
                inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
                log_info("Client connected from %s:%d", addr_str, ntohs(sin->sin_port));
            } else {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&peer_addr;
                inet_ntop(AF_INET6, &sin6->sin6_addr, addr_str, sizeof(addr_str));
                log_info("Client connected from [%s]:%d", addr_str, ntohs(sin6->sin6_port));
            }
        }
        pthread_mutex_unlock(&ctx->client_lock);

        /* Write the IPv6 packet to the TUN device */
        uint8_t *packet = recv_buf + PIPESIX_HEADER_SIZE;
        ssize_t nwritten = tun_write(ctx->tun, packet, pkt_length);
        if (nwritten < 0) {
            log_error("TUN write failed: %s", strerror(errno));
            continue;
        }

        /* Log packet for diagnostics */
        ipv6_log_packet(packet, pkt_length, "RX");
    }

    log_info("Receiver thread exiting");
    return NULL;
}

/*
 * Sender Thread (TUN -> Network)
 *
 * Continuously reads IPv6 packets from the TUN device (return traffic
 * from the Route64 gateway), encapsulates them in pipesix frames, and
 * sends them back to the connected client.
 *
 * Parameters:
 *   arg - Pointer to server_context_t
 *
 * Returns:
 *   NULL always
 */
static void *tun_to_network_thread(void *arg)
{
    server_context_t *ctx = (server_context_t *)arg;
    uint8_t packet_buf[PIPESIX_MAX_PACKET];

    log_info("Sender thread started (TUN -> UDP)");

    while (*ctx->running) {
        ssize_t nread;

        /* Read IPv6 packet from TUN device (return traffic) */
        nread = tun_read(ctx->tun, packet_buf, sizeof(packet_buf));
        if (nread < 0) {
            if (errno == EINTR) continue;
            log_error("TUN read failed in sender thread: %s", strerror(errno));
            break;
        }

        if (nread == 0) continue;

        /*
         * Check if we have a client to send to.
         * If no client has connected yet, drop the packet silently.
         */
        pthread_mutex_lock(&ctx->client_lock);
        int has_client = ctx->client_initialized;
        pthread_mutex_unlock(&ctx->client_lock);

        if (!has_client) {
            /* No client connected; drop the packet */
            continue;
        }

        /*
         * Build the pipesix frame header for the return packet.
         */
        pipesix_frame_header_t hdr;
        struct iovec iov[2];
        struct msghdr msg;

        hdr.magic   = htonl(PIPESIX_MAGIC);
        hdr.version = htons(PIPESIX_VERSION);
        hdr.flags   = htons(PIPESIX_FLAG_NONE);
        hdr.length  = htonl((uint32_t)nread);

        /* Use gather I/O for zero-copy transmission */
        memset(iov, 0, sizeof(iov));
        iov[0].iov_base = &hdr;
        iov[0].iov_len  = PIPESIX_HEADER_SIZE;
        iov[1].iov_base = packet_buf;
        iov[1].iov_len  = (size_t)nread;

        memset(&msg, 0, sizeof(msg));
        msg.msg_iov    = iov;
        msg.msg_iovlen = 2;

        /*
         * Send to the client.
         * We copy the client address under the lock to avoid holding
         * it during the sendmsg call (which might block).
         */
        pthread_mutex_lock(&ctx->client_lock);
        struct sockaddr_storage send_addr;
        socklen_t send_addr_len;
        memcpy(&send_addr, &ctx->client_addr, ctx->client_addr_len);
        send_addr_len = ctx->client_addr_len;
        pthread_mutex_unlock(&ctx->client_lock);

        msg.msg_name    = &send_addr;
        msg.msg_namelen = send_addr_len;

        if (sendmsg(ctx->udp_fd, &msg, 0) < 0) {
            log_error("UDP sendmsg failed for client: %s", strerror(errno));
            continue;
        }

        /* Log return packet for diagnostics */
        ipv6_log_packet(packet_buf, (size_t)nread, "TX");
    }

    log_info("Sender thread exiting");
    return NULL;
}

int server_start(pipesix_config_t *config)
{
    tun_device_t tun;
    pthread_t recv_thread, send_thread;
    server_context_t ctx;
    volatile int running = 1;
    int rc;

    /* Initialize TUN device structure */
    tun_init(&tun);

    /*
     * Open and configure the TUN device on the server.
     * The TUN device on the server side is connected to the Route64
     * gateway via the system's routing table. Packets written to this
     * TUN device are routed to the gateway, and packets from the
     * gateway appear as reads from this device.
     */
    log_info("Opening TUN device '%s'", config->tun_name);
    if (tun_open(&tun, config->tun_name, config->tun_address,
                 config->tun_prefixlen, config->tun_mtu) != 0) {
        log_error("Failed to open TUN device");
        return -1;
    }

    /*
     * Create a UDP socket and bind to the configured address and port.
     * The server listens for incoming encapsulated packets from the
     * client.
     */
    int udp_fd;
    int sock_family;
    struct addrinfo hints, *res;
    char port_str[16];

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_flags    = AI_PASSIVE;

    snprintf(port_str, sizeof(port_str), "%d", config->bind_port);

    rc = getaddrinfo(config->bind_address, port_str, &hints, &res);
    if (rc != 0) {
        log_error("Failed to resolve bind address '%s': %s",
                  config->bind_address, gai_strerror(rc));
        tun_close(&tun);
        return -1;
    }

    /* Try to create and bind the socket */
    udp_fd = -1;
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        udp_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (udp_fd < 0) continue;

        /* Allow address reuse for quick restarts */
        int optval = 1;
        setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

        if (bind(udp_fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            /* Bind succeeded */
            sock_family = rp->ai_family;
            break;
        }

        close(udp_fd);
        udp_fd = -1;
    }

    freeaddrinfo(res);

    if (udp_fd < 0) {
        log_error("Failed to bind UDP socket to %s:%d: %s",
                  config->bind_address, config->bind_port, strerror(errno));
        tun_close(&tun);
        return -1;
    }

    log_info("UDP server listening on %s:%d (family=%s, fd=%d)",
             config->bind_address, config->bind_port,
             sock_family == AF_INET6 ? "AF_INET6" : "AF_INET", udp_fd);

    /* Initialize server context */
    memset(&ctx, 0, sizeof(ctx));
    ctx.config             = config;
    ctx.tun                = &tun;
    ctx.udp_fd             = udp_fd;
    ctx.sock_family        = sock_family;
    ctx.client_initialized = 0;
    ctx.running            = &running;
    pthread_mutex_init(&ctx.client_lock, NULL);

    /*
     * Launch worker threads.
     * recv_thread: Receives from client, writes to TUN (-> Route64 gateway)
     * send_thread: Reads from TUN (return from gateway), sends to client
     */
    pthread_create(&recv_thread, NULL, network_to_tun_thread, &ctx);
    pthread_create(&send_thread, NULL, tun_to_network_thread, &ctx);

    log_info("Server is running. Waiting for client connection on %s:%d ...",
             config->bind_address, config->bind_port);

    /*
     * Main thread waits for shutdown signal.
     * The running flag is set to 0 by the signal handler in main.c.
     */
    while (running) {
        sleep(1);
    }

    /*
     * Graceful shutdown sequence.
     */
    log_info("Initiating graceful shutdown...");

    pthread_join(recv_thread, NULL);
    log_info("Receiver thread joined");

    pthread_join(send_thread, NULL);
    log_info("Sender thread joined");

    /* Clean up synchronization primitives */
    pthread_mutex_destroy(&ctx.client_lock);

    /* Close UDP socket */
    if (udp_fd >= 0) {
        close(udp_fd);
        log_info("UDP socket closed");
    }

    /* Close TUN device */
    tun_close(&tun);

    log_info("Server shutdown complete");
    return 0;
}
