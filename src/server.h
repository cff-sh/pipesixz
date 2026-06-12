/*
 * server.h - pipesix Server Mode Interface
 *
 * Implements the server side of the pipesix IPv6 tunnel. The server:
 *   1. Creates a local TUN device (tun0)
 *   2. Binds a UDP socket to listen for client packets
 *   3. Receives encapsulated packets from the client
 *   4. Decapsulates and writes IPv6 packets to the TUN device
 *   5. Reads IPv6 packets from the TUN device
 *   6. Encapsulates and sends them back to the client
 *
 * The server operates in a bidirectional fashion using two threads:
 *   - Receiver thread (UDP -> TUN): Receives from client, writes to TUN
 *   - Sender thread (TUN -> UDP): Reads from TUN, sends to client
 *
 * The server tracks the first client that sends a valid packet and
 * uses that address as the return destination for outbound traffic.
 * In the current implementation, the server serves a single client.
 */

#ifndef PIPESIX_SERVER_H
#define PIPESIX_SERVER_H

#include <pthread.h>
#include <netinet/in.h>
#include "config.h"
#include "tun.h"

/*
 * server_context_t
 *
 * Aggregates all state needed by the server's worker threads.
 * Client address is dynamically learned from the first received
 * packet.
 */
typedef struct {
    pipesix_config_t   *config;            /* Application configuration */
    tun_device_t       *tun;               /* TUN device handle */
    int                 udp_fd;            /* UDP socket file descriptor */
    int                 sock_family;       /* Socket family (AF_INET or AF_INET6) */

    /*
     * Client peer address (learned dynamically).
     * The server sends decapsulated TUN traffic back to this address.
     */
    struct sockaddr_storage  client_addr;      /* Client address */
    socklen_t                client_addr_len;  /* Client address length */
    int                      client_initialized; /* Non-zero once client is known */

    pthread_mutex_t     client_lock;       /* Mutex for client address updates */
    volatile int       *running;           /* Pointer to running flag */
} server_context_t;

/*
 * Start the server mode.
 *
 * Opens the TUN device, creates and binds a UDP socket, and launches
 * the receiver and sender worker threads. Blocks until a shutdown
 * signal is received, then gracefully stops all threads and cleans
 * up resources.
 *
 * Parameters:
 *   config - Validated application configuration
 *
 * Returns:
 *   0 on successful shutdown (signal received)
 *   -1 on initialization failure
 */
int server_start(pipesix_config_t *config);

#endif /* PIPESIX_SERVER_H */
