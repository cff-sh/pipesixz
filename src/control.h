/*
 * control.h - Out-of-Band Control of a Running Instance
 *
 * POSIX delivers reload/statistics requests with signals: SIGHUP reloads
 * the configuration, SIGUSR1 dumps statistics. Windows has no equivalent,
 * so the same two requests travel over per-configuration named events, and
 * the CLI reaches them with 'pipesix --reload' and 'pipesix --stats'.
 *
 * On POSIX the process also listens on a UNIX socket named after the
 * absolute path of its configuration file. That channel carries requests
 * that need an answer ('--status') or a change in the running state
 * ('--kick'), which a signal cannot express:
 *
 *   status              uptime, tun/listen addresses, sessions, counters
 *   stats               counters only
 *   reload              re-read the configuration now (used by
 *                       --add-client and --remove-client)
 *   kick <client-id>    drop that client's session
 *
 * The socket is created with mode 0600 in /run/pipesix when that
 * directory exists or can be created, and in /tmp otherwise. It is
 * removed when the instance exits. Windows has no equivalent, so
 * control_request() reports ENOTSUP there.
 */

#ifndef PIPESIX_CONTROL_H
#define PIPESIX_CONTROL_H

#include <stddef.h>

/*
 * Maximum size of a control reply, including the NUL.
 *
 * It has to hold the whole session table as JSON, so it is sized for
 * SERVER_MAX_CLIENTS entries rather than for the short text report.
 */
#define CONTROL_MAX_REPLY 32768u

/*
 * Handle one control request.
 *
 * The request is a single trimmed line. The handler must NUL-terminate
 * reply and start it with "OK" or "ERR", so an operator can tell a
 * handled request from a rejected one. reply_size includes the NUL.
 *
 * Returns 0 when the request was handled, -1 when it was rejected.
 */
typedef int (*control_handler_fn)(const char *request, char *reply,
                                  size_t reply_size, void *arg);

/*
 * Start listening for control requests for this configuration.
 *
 * Harmless to call on any platform; a no-op where no channel exists.
 */
void control_start(const char *config_path);

/* Stop listening and release the control object. */
void control_stop(void);

/*
 * Register the handler that serves status/kick requests.
 *
 * Called by client_start() and server_start() once the state the handler
 * reports on is initialised, and cleared again before that state goes
 * away. Passing NULL makes the channel answer "not ready".
 */
void control_set_handler(control_handler_fn handler, void *arg);

/*
 * Send one request to the running instance for config_path.
 *
 * The reply is NUL-terminated and fits reply_size. Returns 0 when a
 * reply was received, -1 otherwise (errno says why; ENOENT or
 * ECONNREFUSED means nothing is listening for that configuration).
 */
int control_request(const char *config_path, const char *request,
                    char *reply, size_t reply_size);

/*
 * Escape a string for embedding in a JSON string literal.
 *
 * Writes the escaped body without the surrounding quotes: '"' and '\\'
 * are backslash-escaped, control bytes become \u00XX and everything else
 * is copied through, so UTF-8 input stays valid JSON.
 *
 * Returns:
 *   0  on success
 *  -1  when the result does not fit; out is then empty rather than a
 *      truncated escape
 */
int control_json_escape(const char *in, char *out, size_t out_size);

/*
 * Ask the running instance for config_path to reload its configuration.
 *
 * Returns:
 *   1  a running instance was asked
 *   0  no instance is listening for this configuration
 *  -1  the platform has no control channel (use SIGHUP instead)
 */
int control_request_reload(const char *config_path);

/*
 * Ask the running instance for config_path to dump statistics now.
 *
 * Returns the same values as control_request_reload().
 */
int control_request_stats(const char *config_path);

#endif /* PIPESIX_CONTROL_H */
