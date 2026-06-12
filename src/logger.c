/*
 * logger.c - pipesix Logging Implementation
 *
 * Implements a structured logging subsystem with severity levels,
 * optional color-coded terminal output, timestamps, and automatic
 * source location annotation. Output is directed to stderr.
 *
 * Color conventions:
 *   DEBUG - Cyan (low priority detail)
 *   INFO  - Green (normal operations)
 *   WARN  - Yellow (attention suggested)
 *   ERROR - Red (something went wrong)
 *   FATAL - Magenta (unrecoverable)
 */

#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

/*
 * Default logger configuration used when NULL is passed to
 * logger_init(). Provides sensible defaults for production use.
 */
static logger_config_t s_config = {
    .min_level     = LOG_INFO,
    .use_color     = 1,
    .use_timestamp = 1
};

/*
 * Human-readable labels for each log level.
 * Used in log output to indicate severity.
 */
static const char *s_level_labels[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR",
    "FATAL"
};

/*
 * ANSI color codes for terminal output.
 * Used only when use_color is enabled and stderr is a terminal.
 */
static const char *s_level_colors[] = {
    "\033[36m",      /* DEBUG - Cyan    */
    "\033[32m",      /* INFO  - Green   */
    "\033[33m",      /* WARN  - Yellow  */
    "\033[31m",      /* ERROR - Red     */
    "\033[35m"       /* FATAL - Magenta */
};
#define COLOR_RESET "\033[0m"

/*
 * Determine if stderr is connected to a terminal.
 * Colorized output is only enabled when output is a TTY.
 */
static int stderr_is_tty(void)
{
    return isatty(fileno(stderr));
}

int logger_init(const logger_config_t *config)
{
    if (config != NULL) {
        s_config = *config;
    }

    /* Disable color if stderr is not a terminal */
    if (s_config.use_color && !stderr_is_tty()) {
        s_config.use_color = 0;
    }

    return 0;
}

void logger_set_level(log_level_t level)
{
    if (level >= LOG_DEBUG && level <= LOG_FATAL) {
        s_config.min_level = level;
    }
}

void logger_log(log_level_t level, const char *file, int line,
                const char *func, const char *fmt, ...)
{
    va_list args;

    /* Filter by level threshold */
    if (level < s_config.min_level) {
        return;
    }

    /* Validate level bounds */
    if (level > LOG_FATAL) {
        level = LOG_FATAL;
    }

    /*
     * Build the log message using a thread-local-ish approach.
     * In a single-threaded or mutex-protected scenario this buffer
     * is safe. For multi-threaded production use, consider a lock.
     * For now, each log call is self-contained.
     */
    char timestamp[32] = {0};

    if (s_config.use_timestamp) {
        struct timespec ts;
        struct tm tm_info;

        clock_gettime(CLOCK_REALTIME, &ts);
        localtime_r(&ts.tv_sec, &tm_info);

        strftime(timestamp, sizeof(timestamp),
                 "%Y-%m-%d %H:%M:%S", &tm_info);
    }

    /*
     * Format output:
     *   [TIMESTAMP] [LEVEL] [file:line func()] message
     *
     * Example:
     *   [2025-06-12 10:30:45] [INFO] [main.c:42 start()] TUN device opened
     */
    if (s_config.use_color) {
        fprintf(stderr, "%s[%s] [%s%s%s] [%s:%d %s()] ",
                timestamp[0] ? "" : "",
                timestamp,
                s_level_colors[level], s_level_labels[level], COLOR_RESET,
                file, line, func);
    } else {
        fprintf(stderr, "%s[%s] [%s] [%s:%d %s()] ",
                timestamp[0] ? "" : "",
                timestamp,
                s_level_labels[level],
                file, line, func);
    }

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");

    /* Flush after ERROR and FATAL for immediate visibility */
    if (level >= LOG_ERROR) {
        fflush(stderr);
    }

    /* FATAL messages trigger immediate termination */
    if (level == LOG_FATAL) {
        exit(EXIT_FAILURE);
    }
}
