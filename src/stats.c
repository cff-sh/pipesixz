/*
 * stats.c - Tunnel Traffic Statistics
 */

#include "stats.h"
#include "logger.h"

#include <inttypes.h>
#include <stdarg.h>
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
    atomic_store(&stats->throttled, 0);
    atomic_store(&stats->invalid, 0);
    atomic_store(&stats->auth_failures, 0);
    atomic_store(&stats->handshakes, 0);
    atomic_store(&stats->handshake_failures, 0);
    atomic_store(&stats->rekeys, 0);
    atomic_store(&stats->replayed, 0);
    atomic_store(&stats->errors, 0);
    atomic_store(&stats->last_rx, 0);
    atomic_store(&stats->last_handshake, 0);
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

void stats_add_throttled(pipesix_stats_t *stats)
{
    if (stats == NULL) return;
    atomic_fetch_add_explicit(&stats->throttled, 1, memory_order_relaxed);
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

void stats_add_handshake(pipesix_stats_t *stats)
{
    if (stats == NULL) return;
    atomic_fetch_add_explicit(&stats->handshakes, 1, memory_order_relaxed);
    atomic_store_explicit(&stats->last_handshake, (uint64_t)time(NULL),
                          memory_order_relaxed);
}

void stats_add_handshake_failure(pipesix_stats_t *stats)
{
    if (stats == NULL) return;
    atomic_fetch_add_explicit(&stats->handshake_failures, 1,
                              memory_order_relaxed);
}

void stats_add_rekey(pipesix_stats_t *stats)
{
    if (stats == NULL) return;
    atomic_fetch_add_explicit(&stats->rekeys, 1, memory_order_relaxed);
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
             "rx=%" PRIu64 " pkts/%s dropped=%" PRIu64
             " throttled=%" PRIu64 " invalid=%" PRIu64
             " auth_fail=%" PRIu64 " handshakes=%" PRIu64
             " handshake_fail=%" PRIu64 " rekeys=%" PRIu64
             " replayed=%" PRIu64 " errors=%" PRIu64
             " last_rx=%s",
             role, uptime,
             atomic_load_explicit(&stats->tx_packets, memory_order_relaxed),
             tx_str,
             atomic_load_explicit(&stats->rx_packets, memory_order_relaxed),
             rx_str,
             atomic_load_explicit(&stats->dropped, memory_order_relaxed),
             atomic_load_explicit(&stats->throttled, memory_order_relaxed),
             atomic_load_explicit(&stats->invalid, memory_order_relaxed),
             atomic_load_explicit(&stats->auth_failures, memory_order_relaxed),
             atomic_load_explicit(&stats->handshakes, memory_order_relaxed),
             atomic_load_explicit(&stats->handshake_failures,
                                  memory_order_relaxed),
             atomic_load_explicit(&stats->rekeys, memory_order_relaxed),
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
             "\"dropped\":%" PRIu64 ",\"throttled\":%" PRIu64 ","
             "\"invalid\":%" PRIu64 ","
             "\"auth_failures\":%" PRIu64 ",\"handshakes\":%" PRIu64 ","
             "\"handshake_failures\":%" PRIu64 ",\"rekeys\":%" PRIu64 ","
             "\"replayed\":%" PRIu64 ","
             "\"errors\":%" PRIu64 ",\"last_rx_unix\":%" PRIu64 ","
             "\"last_handshake_unix\":%" PRIu64 "}",
             role, uptime,
             atomic_load_explicit(&stats->tx_packets, memory_order_relaxed),
             atomic_load_explicit(&stats->tx_bytes, memory_order_relaxed),
             atomic_load_explicit(&stats->rx_packets, memory_order_relaxed),
             atomic_load_explicit(&stats->rx_bytes, memory_order_relaxed),
             atomic_load_explicit(&stats->dropped, memory_order_relaxed),
             atomic_load_explicit(&stats->throttled, memory_order_relaxed),
             atomic_load_explicit(&stats->invalid, memory_order_relaxed),
             atomic_load_explicit(&stats->auth_failures, memory_order_relaxed),
             atomic_load_explicit(&stats->handshakes, memory_order_relaxed),
             atomic_load_explicit(&stats->handshake_failures,
                                  memory_order_relaxed),
             atomic_load_explicit(&stats->rekeys, memory_order_relaxed),
             atomic_load_explicit(&stats->replayed, memory_order_relaxed),
             atomic_load_explicit(&stats->errors, memory_order_relaxed),
             last_rx,
             atomic_load_explicit(&stats->last_handshake,
                                  memory_order_relaxed));
}

/*
 * Append one line to a Prometheus body.
 *
 * The format attribute makes every call site compile-checked; the pragma
 * covers the vsnprintf() inside, which necessarily receives the format as
 * a parameter.
 */
static int prometheus_append(char *out, size_t out_size, size_t *used,
                             const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static int prometheus_append(char *out, size_t out_size, size_t *used,
                             const char *fmt, ...)
{
    va_list args;
    int n;

    if (*used >= out_size) {
        return -1;
    }

    va_start(args, fmt);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
    n = vsnprintf(out + *used, out_size - *used, fmt, args);
#pragma GCC diagnostic pop
    va_end(args);

    if (n < 0 || (size_t)n >= out_size - *used) {
        return -1;
    }

    *used += (size_t)n;
    return 0;
}

#define PROM_APPEND(...)                                                      \
    do {                                                                      \
        if (prometheus_append(out, out_size, &used, __VA_ARGS__) != 0) {      \
            return -1;                                                        \
        }                                                                     \
    } while (0)

int stats_format_prometheus(const pipesix_stats_t *stats, const char *role,
                            char *out, size_t out_size)
{
    const char *mode = (role != NULL) ? role : "unknown";
    time_t now;
    unsigned long uptime;
    size_t used = 0;

    if (stats == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    out[0] = '\0';

    now = time(NULL);
    uptime = (now > stats->started) ? (unsigned long)(now - stats->started)
                                    : 0ul;

    PROM_APPEND("# HELP pipesix_uptime_seconds Seconds since this instance "
                 "started.\n# TYPE pipesix_uptime_seconds gauge\n"
                 "pipesix_uptime_seconds{mode=\"%s\"} %lu\n",
                 mode, uptime);

    PROM_APPEND("# HELP pipesix_tx_packets_total Packets sent toward the "
                 "peer.\n# TYPE pipesix_tx_packets_total counter\n"
                 "pipesix_tx_packets_total{mode=\"%s\"} %" PRIu64 "\n",
                 mode,
                 atomic_load_explicit(&stats->tx_packets,
                                      memory_order_relaxed));

    PROM_APPEND("# HELP pipesix_tx_bytes_total Bytes sent toward the peer.\n"
                 "# TYPE pipesix_tx_bytes_total counter\n"
                 "pipesix_tx_bytes_total{mode=\"%s\"} %" PRIu64 "\n",
                 mode,
                 atomic_load_explicit(&stats->tx_bytes,
                                      memory_order_relaxed));

    PROM_APPEND("# HELP pipesix_rx_packets_total Packets accepted from the "
                 "peer.\n# TYPE pipesix_rx_packets_total counter\n"
                 "pipesix_rx_packets_total{mode=\"%s\"} %" PRIu64 "\n",
                 mode,
                 atomic_load_explicit(&stats->rx_packets,
                                      memory_order_relaxed));

    PROM_APPEND("# HELP pipesix_rx_bytes_total Bytes accepted from the "
                 "peer.\n# TYPE pipesix_rx_bytes_total counter\n"
                 "pipesix_rx_bytes_total{mode=\"%s\"} %" PRIu64 "\n",
                 mode,
                 atomic_load_explicit(&stats->rx_bytes,
                                      memory_order_relaxed));

    PROM_APPEND("# HELP pipesix_dropped_total Packets dropped for lack of a "
                 "route or session.\n# TYPE pipesix_dropped_total counter\n"
                 "pipesix_dropped_total{mode=\"%s\"} %" PRIu64 "\n",
                 mode,
                 atomic_load_explicit(&stats->dropped,
                                      memory_order_relaxed));

    PROM_APPEND("# HELP pipesix_throttled_total Packets dropped by a "
                 "per-client rate or quota limit.\n"
                 "# TYPE pipesix_throttled_total counter\n"
                 "pipesix_throttled_total{mode=\"%s\"} %" PRIu64 "\n",
                 mode,
                 atomic_load_explicit(&stats->throttled,
                                      memory_order_relaxed));

    PROM_APPEND("# HELP pipesix_invalid_total Rejected datagrams: bad "
                 "header, length, flags or payload.\n"
                 "# TYPE pipesix_invalid_total counter\n"
                 "pipesix_invalid_total{mode=\"%s\"} %" PRIu64 "\n",
                 mode,
                 atomic_load_explicit(&stats->invalid,
                                      memory_order_relaxed));

    PROM_APPEND("# HELP pipesix_auth_failures_total Handshakes and frames "
                 "that failed authentication.\n"
                 "# TYPE pipesix_auth_failures_total counter\n"
                 "pipesix_auth_failures_total{mode=\"%s\"} %" PRIu64 "\n",
                 mode,
                 atomic_load_explicit(&stats->auth_failures,
                                      memory_order_relaxed));

    PROM_APPEND("# HELP pipesix_handshakes_total Completed handshakes.\n"
                 "# TYPE pipesix_handshakes_total counter\n"
                 "pipesix_handshakes_total{mode=\"%s\"} %" PRIu64 "\n",
                 mode,
                 atomic_load_explicit(&stats->handshakes,
                                      memory_order_relaxed));

    PROM_APPEND("# HELP pipesix_handshake_failures_total Handshake "
                 "attempts that produced no session: malformed request, "
                 "unknown client, bad MAC or an unreachable peer.\n"
                 "# TYPE pipesix_handshake_failures_total counter\n"
                 "pipesix_handshake_failures_total{mode=\"%s\"} %" PRIu64
                 "\n",
                 mode,
                 atomic_load_explicit(&stats->handshake_failures,
                                      memory_order_relaxed));

    PROM_APPEND("# HELP pipesix_rekeys_total Handshakes that replaced an "
                 "existing session: renegotiation, reconnect or a restart "
                 "from a new endpoint.\n"
                 "# TYPE pipesix_rekeys_total counter\n"
                 "pipesix_rekeys_total{mode=\"%s\"} %" PRIu64 "\n",
                 mode,
                 atomic_load_explicit(&stats->rekeys, memory_order_relaxed));

    PROM_APPEND("# HELP pipesix_last_handshake_timestamp_seconds Unix time "
                 "of the last completed handshake, 0 while none has "
                 "completed.\n"
                 "# TYPE pipesix_last_handshake_timestamp_seconds gauge\n"
                 "pipesix_last_handshake_timestamp_seconds{mode=\"%s\"} "
                 "%" PRIu64 "\n",
                 mode,
                 atomic_load_explicit(&stats->last_handshake,
                                      memory_order_relaxed));

    PROM_APPEND("# HELP pipesix_replayed_total Frames rejected by the "
                 "anti-replay window.\n# TYPE pipesix_replayed_total counter\n"
                 "pipesix_replayed_total{mode=\"%s\"} %" PRIu64 "\n",
                 mode,
                 atomic_load_explicit(&stats->replayed,
                                      memory_order_relaxed));

    PROM_APPEND("# HELP pipesix_errors_total Local socket, TUN and thread "
                 "errors.\n# TYPE pipesix_errors_total counter\n"
                 "pipesix_errors_total{mode=\"%s\"} %" PRIu64 "\n",
                 mode,
                 atomic_load_explicit(&stats->errors,
                                      memory_order_relaxed));

    PROM_APPEND("# HELP pipesix_last_rx_timestamp_seconds Unix time of the "
                 "last accepted packet, 0 while nothing has been "
                 "received.\n# TYPE pipesix_last_rx_timestamp_seconds gauge\n"
                 "pipesix_last_rx_timestamp_seconds{mode=\"%s\"} %" PRIu64
                 "\n",
                 mode,
                 atomic_load_explicit(&stats->last_rx,
                                      memory_order_relaxed));

    return 0;
}

#undef PROM_APPEND

void stats_dump(const pipesix_stats_t *stats, const char *role)
{
    char line[512];

    stats_format(stats, role, line, sizeof(line));
    log_info("%s", line);
}
