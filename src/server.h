/*
 * server.h - pipesix Server Mode Interface
 *
 * The server relays frames between the client and the local TUN
 * device, which is routed to the upstream provider (Route64 or
 * NetAssist):
 *   1. Creates a local TUN device
 *   2. Binds a UDP socket and learns client endpoints from the first
 *      valid frame each client sends
 *   3. Decapsulates frames and writes IPv6 packets to the TUN device
 *   4. Reads return traffic from the TUN device and sends it back to
 *      the client that owns the destination address
 *
 * Up to SERVER_MAX_CLIENTS sessions are tracked concurrently, each
 * with its own replay window. A session expires after
 * 'session_timeout' seconds without traffic.
 */

#ifndef PIPESIX_SERVER_H
#define PIPESIX_SERVER_H

#include "config.h"

/*
 * Start the server mode.
 *
 * Opens the TUN device, binds the UDP socket, and launches the
 * receiver and sender worker threads. Blocks until a shutdown signal
 * is received, then joins the threads and cleans up.
 *
 * Returns:
 *   0 on successful shutdown, -1 on initialization failure
 */
int server_start(pipesix_config_t *config);

#endif /* PIPESIX_SERVER_H */
