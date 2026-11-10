/*
 * stats.h - Tunnel Traffic Statistics
 *
 * Lock-free counters shared by the worker threads, plus a formatted
 * summary used for periodic reporting (stats_interval) and on SIGUSR1.
 */

#ifndef PIPESIX_STATS_H
#define PIPESIX_STATS_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef struct {
    _Atomic uint64_t tx_packets;
    _Atomic uint64_t tx_bytes;
    _Atomic uint64_t rx_packets;
    _Atomic uint64_t rx_bytes;
    _Atomic uint64_t dropped;
    _Atomic uint64_t invalid;
    _Atomic uint64_t auth_failures;
    _Atomic uint64_t replayed;
    _Atomic uint64_t errors;
    _Atomic uint64_t last_rx;
    time_t           started;
} pipesix_stats_t;

/* Initialize counters and record the start time. */
void stats_init(pipesix_stats_t *stats);

/* Record a packet sent toward the peer. */
void stats_add_tx(pipesix_stats_t *stats, size_t bytes);

/* Record a packet received from the peer. */
void stats_add_rx(pipesix_stats_t *stats, size_t bytes);

/* Record one dropped packet (no route/session, send failure, ...). */
void stats_add_dropped(pipesix_stats_t *stats);

/* Record one rejected datagram (bad header, length, flags). */
void stats_add_invalid(pipesix_stats_t *stats);

/* Record one authentication failure. */
void stats_add_auth_failure(pipesix_stats_t *stats);

/* Record one replayed or out-of-window frame. */
void stats_add_replayed(pipesix_stats_t *stats);

/* Record a local I/O error. */
void stats_add_error(pipesix_stats_t *stats);

/*
 * Log a one-line summary at INFO level.
 *
 * Parameters:
 *   stats - Counters to report
 *   role  - "client" or "server" (included in the message)
 */
void stats_dump(const pipesix_stats_t *stats, const char *role);

#endif /* PIPESIX_STATS_H */
