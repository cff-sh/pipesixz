/*
 * client.c - pipesix Client Mode Implementation
 *
 * Implements the client-side tunnel operation. The client:
 *
 *   1. Creates a TUN device (tun0) with a configured IPv6 address
 *   2. Opens a UDP socket and resolves the server address
 *   3. Spawns two worker threads:
 *        - tun_to_network: Reads IPv6 packets from TUN, encapsulates
 *          them in frames, and sends them to the server via UDP
 *        - network_to_tun: Receives frames from the server via UDP,
 *          decapsulates IPv6 packets, and writes them to TUN
 *   4. Waits for a shutdown signal, then gracefully terminates
 *
 * The use of two threads enables full bidirectional communication
 * through the tunnel, allowing both outbound and inbound traffic.
 */

#include "client.h"
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
 * Forward Thread (TUN -> Network)
 *
 * Continuously reads raw IPv6 packets from the TUN device,
 * encapsulates them in a pipesix frame, and transmits them to
 * the server via UDP sendmsg().
 *
 * Parameters:
 *   arg - Pointer to client_context_t
 *
 * Returns:
 *   NULL always
 */
static void *tun_to_network_thread(void *arg)
{
    client_context_t *ctx = (client_context_t *)arg;
    uint8_t packet_buf[PIPESIX_MAX_PACKET];
    struct sockaddr_storage server_addr;
    socklen_t server_addr_len;
    /* Resolve server address */
    {
        struct addrinfo hints, *res;
        char port_str[16];

        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_family = AF_UNSPEC;

        snprintf(port_str, sizeof(port_str), "%d", ctx->config->remote_port);

        if (getaddrinfo(ctx->config->remote_address, port_str, &hints, &res) != 0) {
            log_error("Failed to resolve server address '%s': %s",
                      ctx->config->remote_address, strerror(errno));
            return NULL;
        }

        memcpy(&server_addr, res->ai_addr, res->ai_addrlen);
        server_addr_len = res->ai_addrlen;
        freeaddrinfo(res);
    }

    log_info("Forward thread started (TUN -> %s:%d)",
             ctx->config->remote_address, ctx->config->remote_port);

    while (*ctx->running) {
        ssize_t nread;

        /* Read IPv6 packet from TUN device */
        nread = tun_read(ctx->tun, packet_buf, sizeof(packet_buf));
        if (nread < 0) {
            if (errno == EINTR) continue;
            log_error("TUN read failed in forward thread: %s", strerror(errno));
            break;
        }

        if (nread == 0) continue;

        /*
         * Build the pipesix frame header.
         * The frame encapsulates the raw IPv6 packet with a header
         * for validation and length information.
         */
        pipesix_frame_header_t hdr;
        struct iovec iov[2];
        struct msghdr msg;

        hdr.magic   = htonl(PIPESIX_MAGIC);
        hdr.version = htons(PIPESIX_VERSION);
        hdr.flags   = htons(PIPESIX_FLAG_NONE);
        hdr.length  = htonl((uint32_t)nread);

        /* Use gather I/O to avoid copying the packet */
        memset(iov, 0, sizeof(iov));
        iov[0].iov_base = &hdr;
        iov[0].iov_len  = PIPESIX_HEADER_SIZE;
        iov[1].iov_base = packet_buf;
        iov[1].iov_len  = (size_t)nread;

        memset(&msg, 0, sizeof(msg));
        msg.msg_name    = &server_addr;
        msg.msg_namelen = server_addr_len;
        msg.msg_iov     = iov;
        msg.msg_iovlen  = 2;

        /* Transmit the frame to the server */
        if (sendmsg(ctx->udp_fd, &msg, 0) < 0) {
            log_error("UDP sendmsg failed: %s", strerror(errno));
            continue;
        }

        /* Log packet for diagnostics (DEBUG level) */
        ipv6_log_packet(packet_buf, (size_t)nread, "TX");
    }

    log_info("Forward thread exiting");
    return NULL;
}

/*
 * Reverse Thread (Network -> TUN)
 *
 * Continuously receives frames from the server via UDP recvmsg(),
 * validates the frame header, decapsulates the IPv6 packet, and
 * writes it to the TUN device.
 *
 * Parameters:
 *   arg - Pointer to client_context_t
 *
 * Returns:
 *   NULL always
 */
static void *network_to_tun_thread(void *arg)
{
    client_context_t *ctx = (client_context_t *)arg;
    uint8_t recv_buf[PIPESIX_RECV_BUF_SIZE];

    log_info("Reverse thread started (UDP -> TUN)");

    while (*ctx->running) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        ssize_t nrecv;

        /* Receive frame from the server */
        nrecv = recvfrom(ctx->udp_fd, recv_buf, sizeof(recv_buf), 0,
                         (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (nrecv < 0) {
            if (errno == EINTR) continue;
            log_error("UDP recvfrom failed in reverse thread: %s", strerror(errno));
            break;
        }

        /* Validate frame size (must at least contain the header) */
        if (nrecv < (ssize_t)PIPESIX_HEADER_SIZE) {
            log_warn("Received short frame: %zd bytes (minimum %zu)",
                     nrecv, PIPESIX_HEADER_SIZE);
            continue;
        }

        /* Parse and validate the frame header */
        pipesix_frame_header_t *hdr = (pipesix_frame_header_t *)recv_buf;

        if (ntohl(hdr->magic) != PIPESIX_MAGIC) {
            log_warn("Invalid frame magic: 0x%08x (expected 0x%08lx)",
                     ntohl(hdr->magic), (unsigned long)PIPESIX_MAGIC);
            continue;
        }

        if (ntohs(hdr->version) != PIPESIX_VERSION) {
            log_warn("Unsupported protocol version: %u (expected %u)",
                     ntohs(hdr->version), PIPESIX_VERSION);
            continue;
        }

        /* Extract the encapsulated IPv6 packet length */
        uint32_t pkt_length = ntohl(hdr->length);

        /* Validate packet length against received data */
        if (pkt_length > (uint32_t)((ssize_t)nrecv - (ssize_t)PIPESIX_HEADER_SIZE)) {
            log_warn("Frame length mismatch: header claims %u bytes, "
                     "but only %zd available", pkt_length,
                     nrecv - (ssize_t)PIPESIX_HEADER_SIZE);
            continue;
        }

        if (pkt_length == 0) {
            continue;
        }

        /* Write the IPv6 packet to the TUN device */
        uint8_t *packet = recv_buf + PIPESIX_HEADER_SIZE;
        ssize_t nwritten = tun_write(ctx->tun, packet, pkt_length);
        if (nwritten < 0) {
            log_error("TUN write failed: %s", strerror(errno));
            continue;
        }

        /* Log packet for diagnostics (DEBUG level) */
        ipv6_log_packet(packet, pkt_length, "RX");
    }

    log_info("Reverse thread exiting");
    return NULL;
}

int client_start(pipesix_config_t *config)
{
    tun_device_t tun;
    pthread_t forward_thread, reverse_thread;
    client_context_t ctx;
    volatile int running = 1;

    /* Initialize TUN device structure */
    tun_init(&tun);

    /*
     * Open and configure the TUN device.
     * This creates tun0 and assigns the configured IPv6 address.
     */
    log_info("Opening TUN device '%s'", config->tun_name);
    if (tun_open(&tun, config->tun_name, config->tun_address,
                 config->tun_prefixlen, config->tun_mtu) != 0) {
        log_error("Failed to open TUN device");
        return -1;
    }

    /*
     * Create UDP socket for communication with the server.
     * Try IPv6 first, fall back to IPv4 if the remote address
     * requires it.
     */
    int udp_fd = -1;
    int sock_family = AF_INET6;

    udp_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (udp_fd < 0) {
        /* Fall back to IPv4 */
        sock_family = AF_INET;
        udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_fd < 0) {
            log_error("Failed to create UDP socket: %s", strerror(errno));
            tun_close(&tun);
            return -1;
        }
    }

    /*
     * For IPv6 sockets, configure dual-stack behavior so we can
     * communicate with both IPv4 and IPv6 remote servers.
     */
    if (sock_family == AF_INET6) {
        int off = 0;
        setsockopt(udp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
    }

    log_info("UDP socket created (family=%s, fd=%d)",
             sock_family == AF_INET6 ? "AF_INET6" : "AF_INET", udp_fd);

    /* Build client context for worker threads */
    memset(&ctx, 0, sizeof(ctx));
    ctx.config      = config;
    ctx.tun         = &tun;
    ctx.udp_fd      = udp_fd;
    ctx.sock_family = sock_family;
    ctx.running     = &running;

    /*
     * Launch worker threads.
     * forward_thread:  Reads from TUN, sends to server
     * reverse_thread:  Receives from server, writes to TUN
     */
    pthread_create(&forward_thread, NULL, tun_to_network_thread, &ctx);
    pthread_create(&reverse_thread, NULL, network_to_tun_thread, &ctx);

    log_info("Client is running. Waiting for shutdown signal...");

    /*
     * Main thread waits for shutdown signal.
     * The running flag is set to 0 by the signal handler in main.c.
     * We periodically check the flag to detect shutdown requests.
     */
    while (running) {
        sleep(1);
    }

    /*
     * Graceful shutdown sequence:
     * 1. Signal threads to stop (running is already 0)
     * 2. Wait for threads to finish with pthread_join
     * 3. Close TUN device and UDP socket
     */
    log_info("Initiating graceful shutdown...");

    pthread_join(forward_thread, NULL);
    log_info("Forward thread joined");

    pthread_join(reverse_thread, NULL);
    log_info("Reverse thread joined");

    /* Close UDP socket */
    if (udp_fd >= 0) {
        close(udp_fd);
        log_info("UDP socket closed");
    }

    /* Close TUN device */
    tun_close(&tun);

    log_info("Client shutdown complete");
    return 0;
}
