/*
 * config.h - pipesix Configuration Management
 *
 * Defines the configuration data structures and parsing interface for
 * the pipesix tunnel application. The configuration is read from a
 * flat key-value configuration file with support for comments,
 * whitespace trimming, and input validation.
 *
 * Configuration File Format:
 *
 *   # This is a comment
 *   key = value
 *
 * Supported Keys:
 *   mode            - Operating mode: "client" or "server"
 *   tun_name        - TUN device name (e.g., "tun0")
 *   tun_address     - IPv6 address for the TUN device (e.g., "fd00::1")
 *   tun_prefixlen   - IPv6 prefix length (e.g., 64)
 *   tun_mtu         - TUN device MTU (e.g., 1500)
 *   remote_address  - Server address for client mode
 *   remote_port     - Server port for client mode
 *   bind_address    - Bind address for server mode
 *   bind_port       - Bind port for server mode
 *   log_level       - Logging level: debug, info, warn, error, fatal
 */

#ifndef PIPESIX_CONFIG_H
#define PIPESIX_CONFIG_H

#include "logger.h"

/*
 * Maximum lengths for configuration string fields.
 * These limits prevent buffer overruns and ensure consistent sizing.
 */
#define CONFIG_MAX_STR      256
#define CONFIG_MAX_MODE     16
#define CONFIG_MAX_TUN_NAME 64
#define CONFIG_MAX_ADDRESS  128
#define CONFIG_PATH_MAX     4096

/*
 * Default Configuration Values
 *
 * Sensible defaults for fields that have reasonable fallbacks.
 * The user is expected to override at least mode, tun_address,
 * and the remote/bind endpoint.
 */
#define CONFIG_DEFAULT_TUN_NAME     "tun0"
#define CONFIG_DEFAULT_TUN_PREFIX   64
#define CONFIG_DEFAULT_TUN_MTU      1500
#define CONFIG_DEFAULT_PORT         8899
#define CONFIG_DEFAULT_BIND_ADDRESS "0.0.0.0"
#define CONFIG_DEFAULT_LOG_LEVEL    LOG_INFO

/*
 * pipesix_config_t
 *
 * Complete configuration state for the pipesix application.
 * Populated by config_load() and validated by config_validate().
 */
typedef struct {
    /* Operating mode: "client" or "server" */
    char mode[CONFIG_MAX_MODE];

    /* TUN device configuration */
    char tun_name[CONFIG_MAX_TUN_NAME];    /* TUN interface name */
    char tun_address[CONFIG_MAX_ADDRESS];  /* IPv6 address with optional /prefix */
    int  tun_prefixlen;                     /* IPv6 prefix length */
    int  tun_mtu;                           /* TUN device MTU */

    /* Remote endpoint (used in client mode) */
    char remote_address[CONFIG_MAX_ADDRESS];  /* Server IPv4/IPv6 address */
    int  remote_port;                         /* Server UDP port */

    /* Local bind (used in server mode) */
    char bind_address[CONFIG_MAX_ADDRESS];  /* Local bind address */
    int  bind_port;                          /* Local UDP port */

    /* Logging configuration */
    log_level_t log_level;  /* Minimum log level */
} pipesix_config_t;

/*
 * Load configuration from a file.
 *
 * Reads the specified configuration file, parses key-value pairs,
 * and populates the provided config structure with defaults for
 * any missing fields.
 *
 * Parameters:
 *   path   - Path to the configuration file
 *   config - Pointer to config structure to populate (must not be NULL)
 *
 * Returns:
 *   0 on success, -1 on failure (with details logged)
 */
int config_load(const char *path, pipesix_config_t *config);

/*
 * Validate the loaded configuration.
 *
 * Checks that all required fields are present and have acceptable
 * values. Logs specific error messages for each validation failure.
 *
 * Parameters:
 *   config - Pointer to config structure to validate (must not be NULL)
 *
 * Returns:
 *   0 if configuration is valid, -1 if validation fails
 */
int config_validate(const pipesix_config_t *config);

/*
 * Print configuration summary to the log.
 *
 * Outputs all configuration values at INFO level for operational
 * visibility and troubleshooting.
 *
 * Parameters:
 *   config - Pointer to config structure to display
 */
void config_dump(const pipesix_config_t *config);

#endif /* PIPESIX_CONFIG_H */
