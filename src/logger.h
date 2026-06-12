/*
 * logger.h - pipesix Logging System
 *
 * Provides a structured logging subsystem with multiple severity levels,
 * optional color-coded output, and automatic file/line/function
 * annotation. Designed for operational visibility in production
 * deployments.
 *
 * Usage:
 *   logger_init(LOG_INFO);
 *   log_info("TUN device %s is now up", "tun0");
 *   log_error("Failed to create socket: %s", strerror(errno));
 *
 * Log Levels (in order of increasing severity):
 *   DEBUG - Detailed diagnostic information
 *   INFO  - Normal operational messages
 *   WARN  - Warning conditions that do not halt operation
 *   ERROR - Error conditions that may affect operation
 *   FATAL - Fatal conditions that require immediate shutdown
 */

#ifndef PIPESIX_LOGGER_H
#define PIPESIX_LOGGER_H

#include <stdarg.h>

/*
 * Log Level Enumeration
 *
 * Maps severity levels to integer values for threshold-based filtering.
 * Messages with a level below the configured threshold are suppressed.
 */
typedef enum {
    LOG_DEBUG = 0,               /* Detailed debug information */
    LOG_INFO  = 1,               /* Normal operational messages */
    LOG_WARN  = 2,               /* Warning conditions */
    LOG_ERROR = 3,               /* Error conditions */
    LOG_FATAL = 4                /* Fatal conditions */
} log_level_t;

/*
 * Logger Configuration Structure
 *
 * Controls the behavior of the logging subsystem. Currently supports
 * minimum level filtering. Extensible for future features such as
 * syslog output, file logging, and JSON formatting.
 */
typedef struct {
    log_level_t min_level;       /* Minimum level to log (inclusive) */
    int         use_color;       /* Non-zero for colorized output */
    int         use_timestamp;   /* Non-zero to include timestamps */
} logger_config_t;

/*
 * Initialize the logging subsystem.
 *
 * Sets the minimum log level and prepares the logger for use. Must be
 * called once before any logging macros are invoked. Not thread-safe
 * with respect to concurrent logger_init() calls.
 *
 * Parameters:
 *   config - Logger configuration (may be NULL for defaults)
 *
 * Returns:
 *   0 on success, -1 on failure (logs to stderr directly on failure)
 */
int logger_init(const logger_config_t *config);

/*
 * Set the minimum log level threshold.
 *
 * Messages with a level below this threshold will be suppressed.
 * Can be called at any time to adjust verbosity.
 *
 * Parameters:
 *   level - New minimum log level
 */
void logger_set_level(log_level_t level);

/*
 * Core logging function.
 *
 * Formats and outputs a log message with metadata. Typically invoked
 * through the convenience macros below rather than directly.
 *
 * Parameters:
 *   level - Severity level of the message
 *   file  - Source file name (__FILE__)
 *   line  - Source line number (__LINE__)
 *   func  - Function name (__func__)
 *   fmt   - printf-style format string
 *   ...   - Variable arguments for format string
 */
void logger_log(log_level_t level, const char *file, int line,
                const char *func, const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));

/*
 * Convenience Macros
 *
 * These macros wrap logger_log() with automatic source location
 * annotation. Use them instead of calling logger_log() directly.
 *
 * Examples:
 *   log_debug("Packet size: %zu", pkt_len);
 *   log_info("Connection established to %s", remote_addr);
 *   log_warn("Retransmission timeout");
 *   log_error("sendto() failed: %s", strerror(errno));
 *   log_fatal("Out of memory");
 */
#define log_debug(fmt, ...) \
    do { \
        logger_log(LOG_DEBUG, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__); \
    } while (0)

#define log_info(fmt, ...) \
    do { \
        logger_log(LOG_INFO,  __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__); \
    } while (0)

#define log_warn(fmt, ...) \
    do { \
        logger_log(LOG_WARN,  __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__); \
    } while (0)

#define log_error(fmt, ...) \
    do { \
        logger_log(LOG_ERROR, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__); \
    } while (0)

#define log_fatal(fmt, ...) \
    do { \
        logger_log(LOG_FATAL, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__); \
    } while (0)

#endif /* PIPESIX_LOGGER_H */
