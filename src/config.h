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
 *   mode             - Operating mode: "client" or "server"
 *   tun_name         - TUN device name (e.g., "tun0")
 *   tun_address      - IPv6 address, optionally with /prefix
 *   tun_prefixlen    - IPv6 prefix length when no /prefix is given
 *   tun_mtu          - TUN device MTU
 *   remote_address   - Server address for client mode
 *   remote_port      - Server port for client mode
 *   bind_address     - Bind address for server mode
 *   bind_port        - Bind port for server mode
 *   secret           - This client's pre-shared key (client mode)
 *   client_id        - This client's identity (client mode)
 *   client           - <id>: <secret> credential (server mode, repeatable)
 *   keepalive        - Client keepalive interval in seconds (0 disables)
 *   session_timeout  - Server session idle timeout in seconds (0 disables)
 *   peer_timeout     - Client dead-peer timeout in seconds (0 disables)
 *   allow_client     - Server allow-list of client IPs (comma separated)
 *   stats_interval   - Periodic stats log interval in seconds (0 disables)
 *   log_level        - debug, info, warn, error, fatal
 *
 * SIGHUP reloads log_level, keepalive, peer_timeout, session_timeout
 * and stats_interval from the original configuration file. Changes to
 * the interface, endpoints, credentials, mode or allow_client require
 * a restart.
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
#define CONFIG_MAX_SECRET   256
#define CONFIG_PATH_MAX     4096
#define CONFIG_MAX_ALLOWED  64
#define CONFIG_MAX_CLIENTS  64
#define CONFIG_MAX_CLIENT_ID 32

/*
 * Default Configuration Values
 */
#define CONFIG_DEFAULT_TUN_NAME          "tun0"
#define CONFIG_DEFAULT_TUN_PREFIX        64
#define CONFIG_DEFAULT_TUN_MTU           1500
#define CONFIG_DEFAULT_PORT              8899
#define CONFIG_DEFAULT_BIND_ADDRESS      "0.0.0.0"
#define CONFIG_DEFAULT_LOG_LEVEL         LOG_INFO
#define CONFIG_DEFAULT_KEEPALIVE         20
#define CONFIG_DEFAULT_SESSION_TIMEOUT   120
#define CONFIG_DEFAULT_STATS_INTERVAL    60
#define CONFIG_DEFAULT_PEER_TIMEOUT      120

/*
 * Per-client credential: a stable identity plus its own pre-shared key.
 */
typedef struct {
    char id[CONFIG_MAX_CLIENT_ID];
    char secret[CONFIG_MAX_SECRET];
} pipesix_client_cred_t;

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
    char tun_address[CONFIG_MAX_ADDRESS];  /* IPv6 address (prefix split out) */
    int  tun_prefixlen;                     /* IPv6 prefix length */
    int  tun_mtu;                           /* TUN device MTU */

    /* Remote endpoint (used in client mode) */
    char remote_address[CONFIG_MAX_ADDRESS];  /* Server IPv4/IPv6 address */
    int  remote_port;                         /* Server UDP port */

    /* Local bind (used in server mode) */
    char bind_address[CONFIG_MAX_ADDRESS];  /* Local bind address */
    int  bind_port;                          /* Local UDP port */

    /* Security and session management */
    char secret[CONFIG_MAX_SECRET];         /* This client's pre-shared key */
    int  keepalive;                          /* Client keepalive interval */
    int  session_timeout;                    /* Server idle session timeout */

    /* Reliability and access control */
    int  peer_timeout;                       /* Client dead-peer timeout */
    char allow_client[CONFIG_MAX_ALLOWED][CONFIG_MAX_ADDRESS];
    int  allow_client_count;                 /* Parsed allow-list entries */

    /*
     * Per-client identity and credentials. In client mode 'client_id'
     * and 'secret' identify this host; in server mode 'clients' holds
     * one entry per admitted client, each with its own PSK.
     */
    char client_id[CONFIG_MAX_CLIENT_ID];
    pipesix_client_cred_t clients[CONFIG_MAX_CLIENTS];
    int  client_count;

    /* Observability */
    int  stats_interval;                     /* Periodic stats interval */
    log_level_t log_level;                   /* Minimum log level */

    /* Source path, used by the SIGHUP reload */
    char config_path[CONFIG_PATH_MAX];
} pipesix_config_t;

/*
 * Load configuration from a file.
 *
 * Reads the specified configuration file, parses key-value pairs,
 * and populates the provided config structure with defaults for
 * any missing fields.
 *
 * Returns:
 *   0 on success, -1 on failure (with details logged)
 */
int config_load(const char *path, pipesix_config_t *config);

/*
 * Validate the loaded configuration.
 *
 * Returns:
 *   0 if configuration is valid, -1 if validation fails
 */
int config_validate(const pipesix_config_t *config);

/*
 * Print configuration summary to the log.
 */
void config_dump(const pipesix_config_t *config);

/*
 * Re-read runtime-tunable settings from config->config_path.
 *
 * Applies log_level, keepalive, peer_timeout, session_timeout and
 * stats_interval. Interface, endpoint, secret, mode and allow-list
 * changes are ignored until the process restarts.
 *
 * Returns:
 *   0 on success, -1 if the file cannot be loaded or validated (the
 *   current configuration is left untouched)
 */
int config_reload_runtime(pipesix_config_t *config);

/*
 * Find a client credential by id.
 *
 * Returns a pointer into config->clients, or NULL when the id is not
 * configured.
 */
const pipesix_client_cred_t *config_find_client(const pipesix_config_t *config,
                                                const char *id);

/*
 * Parse a log level name (case-insensitive).
 *
 * Returns:
 *   0 on success, -1 if the name is not recognized
 */
int config_parse_log_level(const char *str, log_level_t *level);

#endif /* PIPESIX_CONFIG_H */
