/*
 * stats.c - Tunnel Traffic Statistics
 */

#include "stats.h"
#include "logger.h"

#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>

void stats_init(pipesix_stats_t *stats)
{
    if (stats == NULL) return;

    atomic_store(&stats->tx_packets, 0);
    atomic_store(&stats->tx_bytes, 0);
    atomic_store(&stats->rx_packets, 0);
    atomic_store(&stats->rx_bytes, 0);
    atomic_store(&stats->dropped, 0);
    atomic_store(&stats->invalid, 0);
    atomic_store(&stats->auth_failures, 0);
    atomic_store(&stats->replayed, 0);
    atomic_store(&stats->errors, 0);
    atomic_store(&stats->last_rx, 0);
    stats->started = time(NULL);
}

void stats_add_tx(pipesix_stats_t *stats, size_t bytes)
{
    if (stats == NULL) return;
    atomic_fetch_add_explicit(&stats->tx_packets, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&stats->tx_bytes, (uint64_t)bytes,
                              memory_order_relaxed);
}

void stats_add_rx(pipesix_stats_t *stats, size_t bytes)
{
    if (stats == NULL) return;
    atomic_fetch_add_explicit(&stats->rx_packets, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&stats->rx_bytes, (uint64_t)bytes,
                              memory_order_relaxed);
    atomic_store_explicit(&stats->last_rx, (uint64_t)time(NULL),
                          memory_order_relaxed);
}

void stats_add_dropped(pipesix_stats_t *stats)
{
    if (stats == NULL) return;
    atomic_fetch_add_explicit(&stats->dropped, 1, memory_order_relaxed);
}

void stats_add_invalid(pipesix_stats_t *stats)
{
    if (stats == NULL) return;
    atomic_fetch_add_explicit(&stats->invalid, 1, memory_order_relaxed);
}

void stats_add_auth_failure(pipesix_stats_t *stats)
{
    if (stats == NULL) return;
    atomic_fetch_add_explicit(&stats->auth_failures, 1, memory_order_relaxed);
}

void stats_add_replayed(pipesix_stats_t *stats)
{
    if (stats == NULL) return;
    atomic_fetch_add_explicit(&stats->replayed, 1, memory_order_relaxed);
}

void stats_add_error(pipesix_stats_t *stats)
{
    if (stats == NULL) return;
    atomic_fetch_add_explicit(&stats->errors, 1, memory_order_relaxed);
}

static void format_bytes(uint64_t bytes, char *out, size_t out_size)
{
    static const char *units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
    double value = (double)bytes;
    size_t unit = 0;

    while (value >= 1024.0 && unit < 4u) {
        value /= 1024.0;
        unit++;
    }

    if (unit == 0u) {
        snprintf(out, out_size, "%" PRIu64 " B", bytes);
    } else {
        snprintf(out, out_size, "%.1f %s", value, units[unit]);
    }
}

void stats_format(const pipesix_stats_t *stats, const char *role,
                  char *out, size_t out_size)
{
    char tx_str[32];
    char rx_str[32];
    uint64_t last_rx;
    time_t now;
    unsigned long uptime;

    if (stats == NULL || out == NULL || out_size == 0) return;

    format_bytes(atomic_load_explicit(&stats->tx_bytes, memory_order_relaxed),
                 tx_str, sizeof(tx_str));
    format_bytes(atomic_load_explicit(&stats->rx_bytes, memory_order_relaxed),
                 rx_str, sizeof(rx_str));

    now = time(NULL);
    uptime = (now > stats->started) ? (unsigned long)(now - stats->started) : 0u;
    last_rx = atomic_load_explicit(&stats->last_rx, memory_order_relaxed);

    snprintf(out, out_size,
             "stats[%s]: uptime=%lus tx=%" PRIu64 " pkts/%s "
             "rx=%" PRIu64 " pkts/%s dropped=%" PRIu64 " invalid=%" PRIu64
             " auth_fail=%" PRIu64 " replayed=%" PRIu64 " errors=%" PRIu64
             " last_rx=%s",
             role, uptime,
             atomic_load_explicit(&stats->tx_packets, memory_order_relaxed),
             tx_str,
             atomic_load_explicit(&stats->rx_packets, memory_order_relaxed),
             rx_str,
             atomic_load_explicit(&stats->dropped, memory_order_relaxed),
             atomic_load_explicit(&stats->invalid, memory_order_relaxed),
             atomic_load_explicit(&stats->auth_failures, memory_order_relaxed),
             atomic_load_explicit(&stats->replayed, memory_order_relaxed),
             atomic_load_explicit(&stats->errors, memory_order_relaxed),
             (last_rx == 0) ? "never" : "recent");
}

void stats_format_json(const pipesix_stats_t *stats, const char *role,
                       char *out, size_t out_size)
{
    uint64_t last_rx;
    time_t now;
    unsigned long uptime;

    if (stats == NULL || out == NULL || out_size == 0) return;

    now = time(NULL);
    uptime = (now > stats->started) ? (unsigned long)(now - stats->started)
                                    : 0ul;
    last_rx = atomic_load_explicit(&stats->last_rx, memory_order_relaxed);

    snprintf(out, out_size,
             "{\"role\":\"%s\",\"uptime_seconds\":%lu,"
             "\"tx_packets\":%" PRIu64 ",\"tx_bytes\":%" PRIu64 ","
             "\"rx_packets\":%" PRIu64 ",\"rx_bytes\":%" PRIu64 ","
             "\"dropped\":%" PRIu64 ",\"invalid\":%" PRIu64 ","
             "\"auth_failures\":%" PRIu64 ",\"replayed\":%" PRIu64 ","
             "\"errors\":%" PRIu64 ",\"last_rx_unix\":%" PRIu64 "}",
             role, uptime,
             atomic_load_explicit(&stats->tx_packets, memory_order_relaxed),
             atomic_load_explicit(&stats->tx_bytes, memory_order_relaxed),
             atomic_load_explicit(&stats->rx_packets, memory_order_relaxed),
             atomic_load_explicit(&stats->rx_bytes, memory_order_relaxed),
             atomic_load_explicit(&stats->dropped, memory_order_relaxed),
             atomic_load_explicit(&stats->invalid, memory_order_relaxed),
             atomic_load_explicit(&stats->auth_failures, memory_order_relaxed),
             atomic_load_explicit(&stats->replayed, memory_order_relaxed),
             atomic_load_explicit(&stats->errors, memory_order_relaxed),
             last_rx);
}

void stats_dump(const pipesix_stats_t *stats, const char *role)
{
    char line[512];

    stats_format(stats, role, line, sizeof(line));
    log_info("%s", line);
}
