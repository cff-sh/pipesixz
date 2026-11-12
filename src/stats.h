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
 * Format the one-line summary into out, NUL-terminated.
 *
 * Used by stats_dump() for the log and by the control channel, so a
 * status report and a periodic log line never disagree.
 */
void stats_format(const pipesix_stats_t *stats, const char *role,
                  char *out, size_t out_size);

/*
 * Format the same counters as a JSON object.
 *
 * The result is self-contained (role, uptime, every counter and
 * last_rx_unix, which is 0 while nothing has been received), so it can be
 * embedded as the value of "stats" in a larger report.
 */
void stats_format_json(const pipesix_stats_t *stats, const char *role,
                       char *out, size_t out_size);

/*
 * Format the same counters as a Prometheus text body.
 *
 * Every metric carries a mode="client" or mode="server" label, so one
 * scrape config can tell the two roles apart. last_rx is exported as a
 * Unix timestamp that stays 0 until something is received.
 *
 * Returns:
 *   0 on success, -1 when the body does not fit (out is then partial)
 */
int stats_format_prometheus(const pipesix_stats_t *stats, const char *role,
                            char *out, size_t out_size);

/*
 * Log a one-line summary at INFO level.
 *
 * Parameters:
 *   stats - Counters to report
 *   role  - "client" or "server" (included in the message)
 */
void stats_dump(const pipesix_stats_t *stats, const char *role);

#endif /* PIPESIX_STATS_H */
