/*
 * metrics.h - Prometheus Metrics Endpoint
 *
 * A Prometheus server scrapes over HTTP, which the control channel (a
 * UNIX socket) cannot provide, so a running instance can serve
 * GET /metrics on the TCP address from 'metrics_address' /
 * 'metrics_port'. The endpoint is read-only and disabled by default.
 *
 * GET /healthz answers '200 ok' whenever the endpoint is listening, which
 * is the probe a load balancer or systemd wants; it never requires the
 * 'metrics_token' that GET /metrics can demand.
 *
 * The body is produced by a callback the client or server registers, so
 * this module owns the HTTP handling and the role owns the numbers: the
 * same counters and session table that --status reports.
 *
 * Windows has no endpoint; metrics_start() reports success without
 * listening, so the caller needs no platform branch.
 */

#ifndef PIPESIX_METRICS_H
#define PIPESIX_METRICS_H

#include "config.h"

#include <stddef.h>

/*
 * Fill out with a Prometheus text body.
 *
 * Must NUL-terminate out. Returns 0 on success, -1 when the body does
 * not fit, which the endpoint reports as a 500 rather than serving a
 * truncated scrape.
 */
typedef int (*metrics_body_fn)(char *out, size_t out_size, void *arg);

/*
 * Start serving GET /metrics for this configuration.
 *
 * Does nothing when 'metrics_address' is empty or the endpoint is
 * already running. A bind or thread failure is logged and reported, but
 * never stops the tunnel: an operator asking for metrics should not lose
 * the tunnel because the port is taken. The token is copied here, so a
 * later configuration reload cannot change it mid-flight.
 *
 * Returns:
 *   0  the endpoint is running or deliberately disabled
 *  -1  the endpoint was requested but could not be started
 */
int metrics_start(const pipesix_config_t *config, metrics_body_fn body,
                  void *arg);

/*
 * Stop serving and join the thread.
 *
 * Harmless when the endpoint never started. Call it before the state the
 * body callback reads is torn down.
 */
void metrics_stop(void);

/* Non-zero while the endpoint is listening. */
int metrics_running(void);

#endif /* PIPESIX_METRICS_H */
