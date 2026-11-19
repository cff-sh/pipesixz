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
 *   remote_address   - Server address(es) for client mode; a comma
 *                      separated list is tried in order when a relay
 *                      stops answering
 *   remote_port      - Server port for client mode
 *   bind_address     - Bind address for server mode
 *   bind_port        - Bind port for server mode
 *   secret           - This client's pre-shared key (client mode)
 *   secret_file      - File holding this client's pre-shared key; wins
 *                      over 'secret' when both are set (client mode)
 *   include          - Read another configuration file at this point
 *   user / group     - POSIX account to drop to after opening the TUN
 *                      device and sockets
 *   client_id        - This client's identity (client mode)
 *   client           - <id>: <secret> credential (server mode, repeatable)
 *   client_next      - <id>: <secret> staged replacement key, accepted
 *                      alongside the current one (server, repeatable)
 *   client_route     - <id> <ipv6[/len]> inner prefix for return traffic
 *                      (server mode, repeatable, follows its client line)
 *   client_disabled  - <id> temporarily refuse this client (server)
 *   client_expires   - <id> <YYYY-MM-DD|unix-seconds> expiry (server)
 *   client_rate_limit - <id> <kbit/s> bandwidth cap in both directions
 *                      (server, repeatable)
 *   client_rate_limit_in - <id> <kbit/s> client-to-server cap
 *   client_rate_limit_out - <id> <kbit/s> server-to-client cap
 *   client_quota     - <id> <MiB> bytes per UTC period (server, repeatable)
 *   client_quota_warn - <id> <percent> warn the client at this usage
 *                      (server, repeatable)
 *   client_allow     - <id> <prefix> destination allowed for that client
 *                      (server, repeatable; an allow list is closed)
 *   client_deny      - <id> <prefix> destination denied for that client
 *                      (server, repeatable)
 *   client_isolation - Drop traffic to every other client's route
 *                      (server mode, default off)
 *   strict_source    - Drop data whose inner source is outside the
 *                      client's 'client_route' (server mode, default off)
 *   quota_period     - daily (default), weekly, monthly or custom
 *   quota_period_days - custom period length in UTC days (1-365)
 *   quota_action     - drop (default) or throttle when a quota is used up
 *   quota_grace      - Extra MiB a client may use before that action
 *   quota_throttle_kbps - Over-quota rate in kbit/s when throttling
 *   quota_state      - File that keeps quota usage across a restart
 *                      (server mode, empty disables it)
 *   usage_history    - Append-only CSV of completed quota periods
 *                      (server mode, empty disables it)
 *   client_prefix_pool - IPv6 prefix no longer than /64 that
 *                      --add-client --delegate carves /64s from
 *                      (server mode, empty disables delegation)
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
 *   audit_log        - Append-only JSONL security audit file
 *   endpoint_failback - Return to the first relay after it recovers
 *   endpoint_failback_interval - Seconds between preferred-relay probes
 *   log_level        - debug, info, warn, error, fatal
 *   log_format       - text (default) or json
 *
 * SIGHUP reloads log_level, keepalive, peer_timeout, session_timeout,
 * stats_interval, strict_source, the quota action/grace/throttle rate,
 * the credentials and the per-client limits from the original
 * configuration file: the client table, ACLs, limits and runtime paths in
 * server mode, this client's own client_id/secret and endpoints in client
 * mode. Changes to the interface, mode or user/group require a restart.
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
#define CONFIG_MAX_REMOTE_ENDPOINTS 8
#define CONFIG_MAX_REMOTE_LIST      512
#define CONFIG_MAX_USER             64
#define CONFIG_MAX_GROUP            64
#define CONFIG_MAX_INCLUDE_DEPTH    8
#define CONFIG_MAX_ACL_PREFIXES     8

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
#define CONFIG_DEFAULT_QUOTA_THROTTLE_KBPS 64

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
    /* Optional destination policy, checked after authenticating a packet. */
    uint8_t allow[CONFIG_MAX_ACL_PREFIXES][16];
    int     allow_len[CONFIG_MAX_ACL_PREFIXES];
    int     allow_count;
    uint8_t deny[CONFIG_MAX_ACL_PREFIXES][16];
    int     deny_len[CONFIG_MAX_ACL_PREFIXES];
    int     deny_count;
    /* Staged replacement key accepted during a zero-downtime rotation. */
    char    next_secret[CONFIG_MAX_SECRET];
    int     has_next_secret;
    /* Administrative state, checked before authentication and by reload. */
    int     disabled;
    int     has_expiry;
    int64_t expires_at;
} pipesix_client_cred_t;

/*
 * Optional per-client limits, applied by the server in both directions.
 * rate_kbps is the default for both directions; rate_in/out override it
 * when their corresponding _set flag is non-zero. quota_mib caps the bytes
 * moved per UTC period; 0 means unlimited for either.
 */
typedef struct {
    char     id[CONFIG_MAX_CLIENT_ID];
    uint64_t rate_kbps;
    uint64_t rate_in_kbps;
    uint64_t rate_out_kbps;
    int      rate_in_set;
    int      rate_out_set;
    uint64_t quota_mib;
    /* Percentage of the quota at which the client is warned; 0 = off. */
    uint64_t warn_percent;
} pipesix_client_policy_t;

static inline uint64_t pipesix_policy_rate_in(
    const pipesix_client_policy_t *policy)
{
    return policy->rate_in_set ? policy->rate_in_kbps : policy->rate_kbps;
}

static inline uint64_t pipesix_policy_rate_out(
    const pipesix_client_policy_t *policy)
{
    return policy->rate_out_set ? policy->rate_out_kbps : policy->rate_kbps;
}

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

    /*
     * Remote endpoints (client mode). 'remote_address' keeps the raw
     * configured value, while 'remote_endpoints' holds the parsed,
     * ordered list the client walks during failover. A single address
     * behaves exactly as before.
     */
    char remote_address[CONFIG_MAX_REMOTE_LIST];
    char remote_endpoints[CONFIG_MAX_REMOTE_ENDPOINTS][CONFIG_MAX_ADDRESS];
    int  remote_count;
    int  remote_port;                         /* Server UDP port */

    /* Local bind (used in server mode) */
    char bind_address[CONFIG_MAX_ADDRESS];  /* Local bind address */
    int  bind_port;                          /* Local UDP port */

    /* Security and session management */
    char secret[CONFIG_MAX_SECRET];         /* This client's pre-shared key */
    char secret_file[CONFIG_PATH_MAX];      /* Or a file holding that key */
    char user[CONFIG_MAX_USER];             /* POSIX account to drop to */
    char group[CONFIG_MAX_GROUP];           /* POSIX group to drop to */
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

    /*
     * Drop packets whose inner source is outside the client's route.
     * Off by default so an existing, misconfigured client keeps working;
     * an operator opts in when the routes are authoritative.
     */
    int  strict_source;

    /* Drop traffic to every other configured client's return prefix. */
    int  client_isolation;

    /*
     * Quota period: 0 = UTC day, 1 = UTC calendar month, 2 = UTC week,
     * negative = a custom number of UTC days. config_load() resolves the
     * 'custom' keyword plus 'quota_period_days' to the negative form.
     */
    int  quota_period;
    int  quota_period_days;

    /* Quota action: 0 = drop over-quota traffic, 1 = throttle it. */
    int      quota_throttle;
    uint64_t quota_grace_mib;      /* extra MiB before the action applies */
    uint64_t quota_throttle_kbps;  /* rate used when quota_throttle is set */

    /* Observability */
    int  stats_interval;                     /* Periodic stats interval */
    log_level_t log_level;                   /* Minimum log level */
    int  log_json;                           /* 1 = one JSON object per line */

    /*
     * Prometheus endpoint. An empty metrics_address disables it; the
     * port is only used when an address is configured. A SIGHUP stops the
     * old listener and starts a new one with the current settings.
     *
     * metrics_token holds a bearer token: when set, GET /metrics requires
     * 'Authorization: Bearer <token>'. GET /healthz never does, so a
     * probe needs no secret. The token is printable ASCII without
     * whitespace, since it travels in an HTTP header.
     */
    char metrics_address[CONFIG_MAX_ADDRESS];
    int  metrics_port;
    char metrics_token[CONFIG_MAX_SECRET];

    /* Append-only JSONL security audit, empty disables it. */
    char audit_log[CONFIG_PATH_MAX];

    /* Client mode: return to the first endpoint after it recovers. */
    int  endpoint_failback;
    int  endpoint_failback_interval;  /* seconds between preferred probes */

    /*
     * Per-client quota state (server mode). When set, the server restores
     * the current period's counters from this file at startup and rewrites
     * it periodically and on shutdown. Empty disables persistence. A
     * SIGHUP switches to a new path without touching the old file.
     */
    char quota_state[CONFIG_PATH_MAX];

    /*
     * Completed quota periods are appended here as CSV (server mode).
     * The path is read when a period rolls over, so an empty value keeps
     * no history. Like quota_state, a SIGHUP applies a changed path.
     */
    char usage_history[CONFIG_PATH_MAX];

    /*
     * Delegated return prefixes (server mode). When set, a /64 carved
     * from this pool can become a client's route, so that client owns a
     * whole LAN instead of a single address. The pool has to be routed
     * to the relay by the upstream. Only provisioning reads it, so it
     * needs no reload handling.
     */
    char    client_prefix_pool[CONFIG_MAX_ADDRESS];
    uint8_t prefix_pool[16];
    int     prefix_pool_len;   /* 0 = unset, otherwise 1-64 */

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
 * Applies log_level, log_format, keepalive, peer_timeout, session_timeout,
 * stats_interval, endpoint_failback, the per-client limits and the
 * credentials: the per-client table in server mode, this client's own
 * client_id and secret in client mode (so a key can be rotated on either
 * end without a restart). Interface, mode, user/group and bind_address
 * changes still require a restart.
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
                      const char *prefix,
                      const pipesix_client_policy_t *limits,
                      char *secret_out, size_t secret_size);

/*
 * Set or clear the per-client limits in a server configuration file.
 *
 * config_set_limits() drops the client's existing 'client_rate_limit',
 * 'client_quota' and 'client_quota_warn' lines and appends the ones whose
 * pointer is not NULL, so a NULL argument leaves that limit as it is.
 * config_clear_limits() removes all three lines and fails when the client
 * has no limits configured. Both keep every other line untouched, re-parse
 * and validate the rewritten file, and only then replace the original.
 *
 * On success config is reloaded from the replaced file, so the caller can
 * print the effective values.
 *
 * Returns:
 *   0 on success, -1 on failure (the file is unchanged)
 */
int config_set_limits(pipesix_config_t *config, const char *id,
                      const uint64_t *rate_kbps,
                      const uint64_t *rate_in_kbps,
                      const uint64_t *rate_out_kbps,
                      const uint64_t *quota_mib,
                      const uint64_t *warn_percent);

int config_clear_limits(pipesix_config_t *config, const char *id);

/*
 * Stage, promote or discard a replacement key for one client.
 *
 * Staging writes 'client_next = <id>: <key>' and leaves the current key
 * valid, so old and new clients can both handshake during the rollout.
 * Promote makes the staged key current and removes the staged line;
 * abort removes the staged line without changing the current key. Each
 * command rewrites the file atomically and re-parses it first. On success
 * config is reloaded from disk and the caller may print the key.
 */
int config_stage_key(pipesix_config_t *config, const char *id,
                     char *secret_out, size_t secret_size);
int config_promote_key(pipesix_config_t *config, const char *id);
int config_abort_key(pipesix_config_t *config, const char *id);

/*
 * Enable or disable a configured client, or set/clear its UTC expiry.
 * Disabled and expired clients keep their route and usage but cannot
 * handshake; a live session is dropped by the next reload/expiry scan.
 * 'when' accepts YYYY-MM-DD or a Unix timestamp. Pass NULL to clear it.
 */
int config_set_client_disabled(pipesix_config_t *config, const char *id,
                               int disabled);
int config_set_client_expiry(pipesix_config_t *config, const char *id,
                             const char *when);

/*
 * Allocate the lowest free /64 in 'client_prefix_pool'.
 *
 * A block is free when no configured 'client_route' overlaps it and it
 * does not contain the relay's own 'tun_address'. Explicit routes always
 * win, so a host route carved out of a delegated prefix makes that /64
 * unavailable. The allocation is not recorded here: the caller writes
 * the prefix as the client's 'client_route', which is what makes it
 * stable across restarts.
 *
 * On success prefix holds the 16 address bytes and 0 is returned.
 * Returns -1 when no pool is configured or every /64 is taken.
 */
int config_delegate_prefix(const pipesix_config_t *config, uint8_t prefix[16]);

/*
 * Format a 16-byte IPv6 address and prefix length as "<addr>/<len>".
 *
 * Returns 0 on success, -1 when the address cannot be formatted or the
 * result does not fit in out.
 */
int config_format_prefix(const uint8_t addr[16], int prefix_len,
                         char *out, size_t size);

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
 * Find a client's limits by id.
 *
 * Returns a pointer into config->policies, or NULL when the client has no
 * 'client_rate_limit' or 'client_quota' line.
 */
const pipesix_client_policy_t *config_find_policy(const pipesix_config_t *config,
                                                  const char *id);

/*
 * Parse a log level name (case-insensitive).
 *
 * Returns:
 *   0 on success, -1 if the name is not recognized
 */
int config_parse_log_level(const char *str, log_level_t *level);

#endif /* PIPESIX_CONFIG_H */
