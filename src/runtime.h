/*
 * runtime.h - Process-wide Runtime State
 *
 * Provides the shutdown flag shared between the signal handlers and all
 * worker threads. Using C11 atomics keeps the flag safe to set from a
 * signal handler and to poll from multiple threads.
 *
 * Also carries the "dump statistics now" request triggered by SIGUSR1
 * and the "reload configuration" request triggered by SIGHUP.
 */

#ifndef PIPESIX_RUNTIME_H
#define PIPESIX_RUNTIME_H

/* Reset runtime state (called once at startup). */
void runtime_init(void);

/* Returns non-zero once a shutdown has been requested. */
int runtime_should_stop(void);

/* Request a graceful shutdown (async-signal-safe). */
void runtime_request_stop(void);

/* Request an immediate statistics dump (async-signal-safe). */
void runtime_request_stats(void);

/* Returns 1 and clears the pending stats request, or 0 if none. */
int runtime_take_stats_request(void);

/* Request a configuration reload (async-signal-safe). */
void runtime_request_reload(void);

/* Returns 1 and clears the pending reload request, or 0 if none. */
int runtime_take_reload_request(void);

#endif /* PIPESIX_RUNTIME_H */
