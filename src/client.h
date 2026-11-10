/*
 * client.h - pipesix Client Mode Interface
 *
 * The client connects the local TUN device to the server over UDP:
 *   1. Creates a local TUN device
 *   2. Reads raw IPv6 packets from the TUN device and sends them to
 *      the server in authenticated frames
 *   3. Receives frames from the server, validates them, and injects
 *      the IPv6 packets back into the TUN device
 *
 * Two poll-driven worker threads handle the directions. They exit
 * promptly when a shutdown is requested (SIGINT/SIGTERM) and the main
 * thread emits periodic traffic statistics.
 */

#ifndef PIPESIX_CLIENT_H
#define PIPESIX_CLIENT_H

#include "config.h"

/*
 * Start the client mode.
 *
 * Opens the TUN device, resolves and connects the UDP socket, and
 * launches the forward and reverse worker threads. Blocks until a
 * shutdown signal is received, then joins the threads and cleans up.
 *
 * Returns:
 *   0 on successful shutdown, -1 on initialization failure
 */
int client_start(pipesix_config_t *config);

#endif /* PIPESIX_CLIENT_H */
