/*
 * client.h - pipesix Client Mode Interface
 *
 * Implements the client side of the pipesix IPv6 tunnel. The client:
 *   1. Creates a local TUN device (tun0)
 *   2. Reads raw IPv6 packets from the TUN device
 *   3. Encapsulates them in the pipesix protocol frame
 *   4. Transmits encapsulated packets over UDP to the server
 *   5. Receives encapsulated packets from the server
 *   6. Decapsulates and writes them to the TUN device
 *
 * The client operates in a bidirectional fashion using two threads:
 *   - Forward thread (TUN -> UDP): Reads from TUN, sends to server
 *   - Reverse thread (UDP -> TUN): Receives from server, writes to TUN
 *
 * Thread synchronization is minimal since the TUN and UDP file
 * descriptors operate independently.
 */

#ifndef PIPESIX_CLIENT_H
#define PIPESIX_CLIENT_H

#include <pthread.h>
#include "config.h"
#include "tun.h"

/*
 * client_context_t
 *
 * Aggregates all state needed by the client's worker threads.
 * Initialized by client_start() and used throughout the client's
 * lifetime.
 */
typedef struct {
    pipesix_config_t   *config;           /* Application configuration */
    tun_device_t       *tun;              /* TUN device handle */
    int                 udp_fd;           /* UDP socket file descriptor */
    int                 sock_family;      /* Socket family (AF_INET or AF_INET6) */
    volatile int       *running;          /* Pointer to running flag */
} client_context_t;

/*
 * Start the client mode.
 *
 * Opens the TUN device, creates a UDP socket, resolves the server
 * address, and launches the forward and reverse worker threads.
 * Blocks until a shutdown signal is received, then gracefully
 * stops all threads and cleans up resources.
 *
 * Parameters:
 *   config - Validated application configuration
 *
 * Returns:
 *   0 on successful shutdown (signal received)
 *   -1 on initialization failure
 */
int client_start(pipesix_config_t *config);

#endif /* PIPESIX_CLIENT_H */
