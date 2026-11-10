/*
 * control.h - Out-of-Band Control of a Running Instance
 *
 * POSIX delivers these requests with signals: SIGHUP reloads the
 * configuration, SIGUSR1 dumps statistics. Windows has no equivalent, so
 * the same two requests travel over per-configuration named events, and
 * the CLI reaches them with 'pipesix --reload' and 'pipesix --stats'.
 *
 * The control object is created at startup and named after the absolute
 * path of the configuration file, so several instances with different
 * configurations never signal each other. On POSIX control_start() and
 * control_stop() do nothing.
 */

#ifndef PIPESIX_CONTROL_H
#define PIPESIX_CONTROL_H

/*
 * Start listening for control requests for this configuration.
 *
 * Harmless to call on any platform; a no-op where signals are available.
 */
void control_start(const char *config_path);

/* Stop listening and release the control object. */
void control_stop(void);

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
