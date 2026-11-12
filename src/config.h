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
 *   client_route     - <id> <ipv6[/len]> inner prefix for return traffic
 *                      (server mode, repeatable, follows its client line)
 *   client_rate_limit - <id> <kbit/s> bandwidth cap (server, repeatable)
 *   client_quota     - <id> <MiB> bytes per UTC day (server, repeatable)
 *   keepalive        - Client keepalive interval in seconds (0 disables)
 *   session_timeout  - Server session idle timeout in seconds (0 disables)
 *   peer_timeout     - Client dead-peer timeout in seconds (0 disables)
 *   allow_client     - Server allow-list of client IPs (comma separated)
 *   stats_interval   - Periodic stats log interval in seconds (0 disables)
 *   metrics_address  - Address for the Prometheus metrics endpoint
 *                      (empty disables it)
 *   metrics_port     - Port for the Prometheus metrics endpoint
 *   metrics_token    - Bearer token required by GET /metrics
 *                      (empty leaves the endpoint open)
 *   log_level        - debug, info, warn, error, fatal
 *
 * SIGHUP reloads log_level, keepalive, peer_timeout, session_timeout,
 * stats_interval and the credentials from the original configuration
 * file: the client table in server mode, this client's own client_id and
 * secret in client mode. Changes to the interface, endpoints, mode,
 * allow_client or the per-client limits require a restart.
 */

#ifndef PIPESIX_CONFIG_H
#define PIPESIX_CONFIG_H

#include "logger.h"

#include <stddef.h>
#include <stdint.h>

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
#define CONFIG_DEFAULT_METRICS_PORT      9100

/*
 * Per-client credential: a stable identity, its own pre-shared key, and
 * the inner IPv6 prefix the server routes return traffic to.
 *
 * prefix_len is 0 when no 'client_route' was configured for the client.
 */
typedef struct {
    char    id[CONFIG_MAX_CLIENT_ID];
    char    secret[CONFIG_MAX_SECRET];
    uint8_t prefix[16];
    int     prefix_len;
} pipesix_client_cred_t;

/*
 * Optional per-client limits, applied by the server in both directions.
 * rate_kbps caps bandwidth in kilobits per second and quota_mib caps the
 * bytes moved per UTC day; 0 means unlimited for either.
 */
typedef struct {
    char     id[CONFIG_MAX_CLIENT_ID];
    uint64_t rate_kbps;
    uint64_t quota_mib;
} pipesix_client_policy_t;

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

    /* Per-client limits, at most one entry per client id. */
    pipesix_client_policy_t policies[CONFIG_MAX_CLIENTS];
    int  policy_count;

    /* Observability */
    int  stats_interval;                     /* Periodic stats interval */
    log_level_t log_level;                   /* Minimum log level */

    /*
     * Prometheus endpoint. An empty metrics_address disables it; the
     * port is only used when an address is configured. Like bind_address
     * it is applied at startup, so changing it needs a restart.
     *
     * metrics_token holds a bearer token: when set, GET /metrics requires
     * 'Authorization: Bearer <token>'. GET /healthz never does, so a
     * probe needs no secret. The token is printable ASCII without
     * whitespace, since it travels in an HTTP header.
     */
    char metrics_address[CONFIG_MAX_ADDRESS];
    int  metrics_port;
    char metrics_token[CONFIG_MAX_SECRET];

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
 * Applies log_level, keepalive, peer_timeout, session_timeout,
 * stats_interval and the credentials: the per-client table in server
 * mode, this client's own client_id and secret in client mode (so a key
 * can be rotated on either end without a restart). Interface, endpoint,
 * mode and allow-list changes are ignored until the process restarts.
 *
 * Returns:
 *   0 on success, -1 if the file cannot be loaded or validated (the
 *   current configuration is left untouched)
 */
int config_reload_runtime(pipesix_config_t *config);

/*
 * Generate a fresh key for every configured client and write it into
 * the configuration file.
 *
 * Server mode only: a client owns a single key, which 'pipesix --genkey'
 * and a 'secret' edit already cover. Comments, ordering and spacing in
 * the file are preserved, the new file is re-parsed and checked before it
 * replaces the original, and on success config->clients[] holds the new
 * secrets so the caller can print them for distribution.
 *
 * Returns:
 *   0 on success, -1 on failure (no key and no file change)
 */
int config_rotate_all_keys(pipesix_config_t *config);

/*
 * Add a client to a server configuration file.
 *
 * Generates a fresh 256-bit key, appends 'client = <id>: <key>' and,
 * when prefix is not NULL, 'client_route = <id> <prefix>' to the file at
 * config->config_path. The rewritten file is parsed and validated before
 * it replaces the original, so a rejected route, a duplicate id or a
 * duplicate prefix leaves the file exactly as it was. Comments, ordering
 * and formatting of every other line are preserved.
 *
 * On success the generated key is copied to secret_out as a
 * NUL-terminated hex string, for the caller to hand to the client.
 *
 * Returns:
 *   0 on success, -1 on failure (the file is unchanged)
 */
int config_add_client(pipesix_config_t *config, const char *id,
                      const char *prefix, char *secret_out,
                      size_t secret_size);

/*
 * Remove a client and its 'client_route' line from a server
 * configuration file.
 *
 * The client's 'client' and 'client_route' lines are dropped, everything
 * else is copied through unchanged, and the result is parsed and
 * validated before it replaces the original. Removing the last client is
 * refused: a server needs at least one credential.
 *
 * The running server drops the removed client's session when it reloads.
 *
 * Returns:
 *   0 on success, -1 on failure (the file is unchanged)
 */
int config_remove_client(pipesix_config_t *config, const char *id);

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
