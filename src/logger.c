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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdatomic.h>

/*
 * Default logger configuration used when NULL is passed to
 * logger_init(). Provides sensible defaults for production use.
 */
static logger_config_t s_config = {
    .min_level     = LOG_INFO,
    .use_color     = 1,
    .use_timestamp = 1,
    .use_json      = 0
};

/* Threshold and format are atomic so SIGHUP can change them while workers log. */
static _Atomic int s_min_level = LOG_INFO;
static _Atomic int s_json = 0;

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

    atomic_store(&s_min_level, (int)s_config.min_level);
    atomic_store(&s_json, s_config.use_json);
    return 0;
}

void logger_set_level(log_level_t level)
{
    if (level >= LOG_DEBUG && level <= LOG_FATAL) {
        s_config.min_level = level;
        atomic_store(&s_min_level, (int)level);
    }
}

void logger_set_json(int enabled)
{
    s_config.use_json = enabled ? 1 : 0;
    atomic_store(&s_json, s_config.use_json);
}

/*
 * Escape one string for a JSON string literal.
 *
 * Only the bytes JSON requires are escaped; UTF-8 passes through, so a
 * client id or path is readable in the log. The output is always
 * NUL-terminated, and truncated input is reported by the caller's
 * return value rather than producing invalid JSON.
 */
static int json_escape(const char *in, char *out, size_t out_size)
{
    static const char hex[] = "0123456789abcdef";
    size_t used = 0;
    const unsigned char *p = (const unsigned char *)in;

    if (out_size == 0) {
        return -1;
    }

    while (*p != '\0') {
        const char *escape = NULL;
        char unicode[7];
        size_t len;

        switch (*p) {
            case '"':  escape = "\\\""; break;
            case '\\': escape = "\\\\"; break;
            case '\b': escape = "\\b";  break;
            case '\f': escape = "\\f";  break;
            case '\n': escape = "\\n";  break;
            case '\r': escape = "\\r";  break;
            case '\t': escape = "\\t";  break;
            default: break;
        }

        if (escape != NULL) {
            len = 2;
            if (used + len >= out_size) {
                out[used] = '\0';
                return -1;
            }
            out[used++] = escape[0];
            out[used++] = escape[1];
        } else if (*p < 0x20) {
            unicode[0] = '\\';
            unicode[1] = 'u';
            unicode[2] = '0';
            unicode[3] = '0';
            unicode[4] = hex[(*p >> 4) & 0x0f];
            unicode[5] = hex[*p & 0x0f];
            unicode[6] = '\0';
            len = 6;
            if (used + len >= out_size) {
                out[used] = '\0';
                return -1;
            }
            memcpy(out + used, unicode, len);
            used += len;
        } else {
            if (used + 1 >= out_size) {
                out[used] = '\0';
                return -1;
            }
            out[used++] = (char)*p;
        }

        p++;
    }

    out[used] = '\0';
    return 0;
}

void logger_log(log_level_t level, const char *file, int line,
                const char *func, const char *fmt, ...)
{
    va_list args;

    /* Filter by level threshold */
    if ((int)level < atomic_load(&s_min_level)) {
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
    char timestamp_utc[32] = {0};
    char message[2048];
    char level_name[8];
    char level_upper[8];
    char file_esc[512];
    char func_esc[256];
    char message_esc[4096];
    size_t i;

    if (s_config.use_timestamp) {
        struct timespec ts;
        struct tm tm_info;

        clock_gettime(CLOCK_REALTIME, &ts);
#if defined(_WIN32)
        /* MinGW exposes the MSVC signature: result first, time second. */
        localtime_s(&tm_info, &ts.tv_sec);
#else
        localtime_r(&ts.tv_sec, &tm_info);
#endif

        strftime(timestamp, sizeof(timestamp),
                 "%Y-%m-%d %H:%M:%S", &tm_info);

#if defined(_WIN32)
        gmtime_s(&tm_info, &ts.tv_sec);
#else
        gmtime_r(&ts.tv_sec, &tm_info);
#endif
        strftime(timestamp_utc, sizeof(timestamp_utc),
                 "%Y-%m-%dT%H:%M:%SZ", &tm_info);
    }

    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    /* JSON uses the conventional lower-case level names. */
    snprintf(level_upper, sizeof(level_upper), "%s", s_level_labels[level]);
    for (i = 0; level_upper[i] != '\0'; i++) {
        level_name[i] = (char)tolower((int)(unsigned char)level_upper[i]);
    }
    level_name[i] = '\0';

    if (atomic_load(&s_json)) {
        if (json_escape(file, file_esc, sizeof(file_esc)) != 0 ||
            json_escape(func, func_esc, sizeof(func_esc)) != 0 ||
            json_escape(message, message_esc, sizeof(message_esc)) != 0) {
            return;
        }

        fprintf(stderr,
                "{\"time\":\"%s\",\"level\":\"%s\",\"file\":\"%s\","
                "\"line\":%d,\"func\":\"%s\",\"msg\":\"%s\"}\n",
                timestamp_utc, level_name, file_esc, line, func_esc,
                message_esc);
        if (level >= LOG_ERROR) {
            fflush(stderr);
        }
        if (level == LOG_FATAL) {
            exit(EXIT_FAILURE);
        }
        return;
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

    fputs(message, stderr);

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
