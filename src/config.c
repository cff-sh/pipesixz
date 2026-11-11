/*
 * config.c - pipesix Configuration Implementation
 *
 * Implements a flat key-value configuration file parser. The format
 * is simple and human-readable:
 *
 *   # This is a comment
 *   key = value
 *
 * Leading and trailing whitespace is stripped from keys and values.
 * Values are length-checked so typos fail early instead of being
 * silently truncated. Required fields are validated after loading.
 */

#include "config.h"
#include "crypto.h"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#else
#include <arpa/inet.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Flush a rewritten configuration to disk.
 *
 * POSIX uses fsync(); the Windows CRT spells the same operation _commit()
 * on a descriptor. Windows also has no fchmod(), so permission
 * preservation is POSIX-only there (it uses ACLs, not mode bits).
 */
static int sync_file(FILE *fp)
{
#if defined(_WIN32)
    return _commit(_fileno(fp));
#else
    return fsync(fileno(fp));
#endif
}

/*
 * Trim leading and trailing whitespace from a string in place.
 */
static char *str_trim(char *str)
{
    char *end;

    while (isspace((unsigned char)*str)) {
        str++;
    }

    end = str + strlen(str);
    while (end > str && isspace((unsigned char)*(end - 1))) {
        end--;
    }

    *end = '\0';
    return str;
}

static int copy_string(char *dst, size_t size, const char *value)
{
    size_t len = strlen(value);

    if (len >= size) {
        return -1;
    }

    memcpy(dst, value, len + 1);
    return 0;
}

static int parse_int(const char *value, int *out)
{
    char *end = NULL;
    long parsed;

    if (value == NULL || out == NULL) {
        return -1;
    }

    errno = 0;
    parsed = strtol(value, &end, 10);

    if (errno != 0 || end == value || *end != '\0') {
        return -1;
    }
    if (parsed < INT_MIN || parsed > INT_MAX) {
        return -1;
    }

    *out = (int)parsed;
    return 0;
}

static int set_int_range(int *dst, const char *value, int min, int max)
{
    int parsed;

    if (parse_int(value, &parsed) != 0 || parsed < min || parsed > max) {
        return -1;
    }

    *dst = parsed;
    return 0;
}

/*
 * Set default values for all configuration fields.
 */
static void config_set_defaults(pipesix_config_t *config)
{
    memset(config, 0, sizeof(*config));

    memcpy(config->tun_name, CONFIG_DEFAULT_TUN_NAME,
           sizeof(CONFIG_DEFAULT_TUN_NAME));
    config->tun_prefixlen  = CONFIG_DEFAULT_TUN_PREFIX;
    config->tun_mtu        = CONFIG_DEFAULT_TUN_MTU;
    config->remote_port    = CONFIG_DEFAULT_PORT;
    memcpy(config->bind_address, CONFIG_DEFAULT_BIND_ADDRESS,
           sizeof(CONFIG_DEFAULT_BIND_ADDRESS));
    config->bind_port      = CONFIG_DEFAULT_PORT;
    config->keepalive      = CONFIG_DEFAULT_KEEPALIVE;
    config->session_timeout = CONFIG_DEFAULT_SESSION_TIMEOUT;
    config->peer_timeout   = CONFIG_DEFAULT_PEER_TIMEOUT;
    config->stats_interval = CONFIG_DEFAULT_STATS_INTERVAL;
    config->log_level      = CONFIG_DEFAULT_LOG_LEVEL;
}

int config_parse_log_level(const char *str, log_level_t *level)
{
    if (str == NULL || level == NULL) {
        return -1;
    }

    if (strcasecmp(str, "debug") == 0) { *level = LOG_DEBUG; return 0; }
    if (strcasecmp(str, "info") == 0)  { *level = LOG_INFO;  return 0; }
    if (strcasecmp(str, "warn") == 0)  { *level = LOG_WARN;  return 0; }
    if (strcasecmp(str, "error") == 0) { *level = LOG_ERROR; return 0; }
    if (strcasecmp(str, "fatal") == 0) { *level = LOG_FATAL; return 0; }
    return -1;
}

/*
 * Accept tun_address with or without an explicit /prefix.
 */
static int set_tun_address(pipesix_config_t *config, const char *value)
{
    const char *slash = strchr(value, '/');

    if (slash != NULL) {
        size_t addr_len = (size_t)(slash - value);
        int prefix;

        if (addr_len == 0 || addr_len >= CONFIG_MAX_ADDRESS) {
            return -1;
        }
        if (parse_int(slash + 1, &prefix) != 0 || prefix < 0 || prefix > 128) {
            return -1;
        }

        memcpy(config->tun_address, value, addr_len);
        config->tun_address[addr_len] = '\0';
        config->tun_prefixlen = prefix;
        return 0;
    }

    return copy_string(config->tun_address, CONFIG_MAX_ADDRESS, value);
}

/*
 * Parse a comma/space separated allow-list of numeric client IPs.
 */
static int set_allow_client(pipesix_config_t *config, const char *value)
{
    char work[CONFIG_MAX_ALLOWED * CONFIG_MAX_ADDRESS];
    struct in_addr v4;
    struct in6_addr v6;
    char *saveptr = NULL;
    char *token;
    int count = 0;

    if (strlen(value) >= sizeof(work)) {
        return -1;
    }
    memcpy(work, value, strlen(value) + 1);

    for (token = strtok_r(work, ", \t", &saveptr);
         token != NULL;
         token = strtok_r(NULL, ", \t", &saveptr)) {
        size_t len = strlen(token);

        if (count >= CONFIG_MAX_ALLOWED) {
            return -1;
        }
        if (len == 0 || len >= CONFIG_MAX_ADDRESS) {
            return -1;
        }
        if (inet_pton(AF_INET, token, &v4) != 1 &&
            inet_pton(AF_INET6, token, &v6) != 1) {
            return -1;
        }

        memcpy(config->allow_client[count], token, len + 1);
        count++;
    }

    if (count == 0) {
        return -1;
    }

    config->allow_client_count = count;
    return 0;
}

/*
 * Client ids appear in logs and are matched byte for byte, so keep them
 * to a conservative character set.
 */
static int valid_client_id(const char *id)
{
    size_t i;
    size_t len;

    if (id == NULL) return 0;

    len = strlen(id);
    if (len == 0 || len >= CONFIG_MAX_CLIENT_ID) return 0;

    for (i = 0; i < len; i++) {
        char c = id[i];

        if (!(isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.')) {
            return 0;
        }
    }

    return 1;
}

/*
 * Parse "client = <id>: <secret>" and append it to the credential table.
 */
static int set_client_cred(pipesix_config_t *config, const char *value)
{
    const char *sep;
    const char *start;
    const char *end;
    const char *secret;
    char id[CONFIG_MAX_CLIENT_ID];
    size_t id_len;
    size_t secret_len;
    size_t i;

    if (value == NULL) return -1;

    sep = strchr(value, ':');
    if (sep == NULL) return -1;

    start = value;
    end = sep;
    while (start < end && isspace((unsigned char)*start)) start++;
    while (end > start && isspace((unsigned char)*(end - 1))) end--;

    id_len = (size_t)(end - start);
    if (id_len == 0 || id_len >= sizeof(id)) return -1;

    memcpy(id, start, id_len);
    id[id_len] = '\0';

    if (!valid_client_id(id)) return -1;

    secret = sep + 1;
    while (*secret != '\0' && isspace((unsigned char)*secret)) secret++;

    secret_len = strlen(secret);
    while (secret_len > 0 &&
           isspace((unsigned char)secret[secret_len - 1])) {
        secret_len--;
    }

    if (secret_len == 0 || secret_len >= CONFIG_MAX_SECRET) return -1;
    if (config->client_count >= CONFIG_MAX_CLIENTS) return -1;

    for (i = 0; i < (size_t)config->client_count; i++) {
        if (strcmp(config->clients[i].id, id) == 0) {
            return -1; /* Duplicate ids would make identity ambiguous. */
        }
    }

    memcpy(config->clients[config->client_count].id, id, id_len + 1);
    memcpy(config->clients[config->client_count].secret, secret, secret_len);
    config->clients[config->client_count].secret[secret_len] = '\0';
    config->client_count++;

    return 0;
}

/*
 * Parse "client_route = <id> <ipv6-prefix>" and attach the prefix to
 * the named client's credential.
 *
 * A bare address means a /128 host route. The 'client' line for that id
 * must come first, so the route is rejected rather than silently
 * dropped when the id is not known yet.
 */
static int set_client_route(pipesix_config_t *config, const char *value)
{
    pipesix_client_cred_t *cred = NULL;
    struct in6_addr parsed;
    char work[CONFIG_MAX_CLIENT_ID + CONFIG_MAX_ADDRESS + 2];
    char *id;
    char *prefix;
    char *slash;
    size_t len;
    int prefix_len = 128;
    int i;

    if (value == NULL) return -1;

    len = strlen(value);
    if (len == 0 || len >= sizeof(work)) return -1;
    memcpy(work, value, len + 1);

    id = work;
    while (isspace((unsigned char)*id)) id++;

    prefix = id;
    while (*prefix != '\0' && !isspace((unsigned char)*prefix)) prefix++;
    if (*prefix == '\0') return -1; /* Missing prefix. */
    *prefix = '\0';
    prefix++;
    while (isspace((unsigned char)*prefix)) prefix++;

    len = strlen(prefix);
    while (len > 0 && isspace((unsigned char)prefix[len - 1])) {
        prefix[--len] = '\0';
    }

    if (!valid_client_id(id)) return -1;

    slash = strchr(prefix, '/');
    if (slash != NULL) {
        *slash = '\0';
        if (parse_int(slash + 1, &prefix_len) != 0) {
            return -1;
        }
    }

    /* /0 is not expressible: prefix_len 0 means "no route configured". */
    if (prefix_len < 1 || prefix_len > 128) return -1;

    for (i = 0; i < config->client_count; i++) {
        if (strcmp(config->clients[i].id, id) == 0) {
            cred = &config->clients[i];
            break;
        }
    }

    if (cred == NULL) {
        log_error("client_route: unknown client '%s' (the 'client' line "
                  "must come before its 'client_route')", id);
        return -1;
    }

    if (cred->prefix_len != 0) {
        log_error("client_route: client '%s' already has a route", id);
        return -1;
    }

    if (inet_pton(AF_INET6, prefix, &parsed) != 1) {
        return -1;
    }

    memcpy(cred->prefix, &parsed, sizeof(cred->prefix));
    cred->prefix_len = prefix_len;

    return 0;
}

const pipesix_client_cred_t *config_find_client(const pipesix_config_t *config,
                                                const char *id)
{
    int i;

    if (config == NULL || id == NULL) return NULL;

    for (i = 0; i < config->client_count; i++) {
        if (strcmp(config->clients[i].id, id) == 0) {
            return &config->clients[i];
        }
    }

    return NULL;
}

/*
 * Process a single key=value line and update the configuration.
 *
 * Returns 0 on success, -1 if the value is invalid or too long.
 */
static int config_set_value(pipesix_config_t *config, const char *key,
                            const char *value)
{
    if (strcmp(key, "mode") == 0) {
        return copy_string(config->mode, CONFIG_MAX_MODE, value);
    }
    if (strcmp(key, "tun_name") == 0) {
        return copy_string(config->tun_name, CONFIG_MAX_TUN_NAME, value);
    }
    if (strcmp(key, "tun_address") == 0) {
        return set_tun_address(config, value);
    }
    if (strcmp(key, "tun_prefixlen") == 0) {
        return set_int_range(&config->tun_prefixlen, value, 0, 128);
    }
    if (strcmp(key, "tun_mtu") == 0) {
        return set_int_range(&config->tun_mtu, value, 0, 65535);
    }
    if (strcmp(key, "remote_address") == 0) {
        return copy_string(config->remote_address, CONFIG_MAX_ADDRESS, value);
    }
    if (strcmp(key, "remote_port") == 0) {
        return set_int_range(&config->remote_port, value, 1, 65535);
    }
    if (strcmp(key, "bind_address") == 0) {
        return copy_string(config->bind_address, CONFIG_MAX_ADDRESS, value);
    }
    if (strcmp(key, "bind_port") == 0) {
        return set_int_range(&config->bind_port, value, 1, 65535);
    }
    if (strcmp(key, "secret") == 0) {
        return copy_string(config->secret, CONFIG_MAX_SECRET, value);
    }
    if (strcmp(key, "keepalive") == 0) {
        return set_int_range(&config->keepalive, value, 0, 3600);
    }
    if (strcmp(key, "session_timeout") == 0) {
        return set_int_range(&config->session_timeout, value, 0, 86400);
    }
    if (strcmp(key, "peer_timeout") == 0) {
        return set_int_range(&config->peer_timeout, value, 0, 86400);
    }
    if (strcmp(key, "allow_client") == 0) {
        return set_allow_client(config, value);
    }
    if (strcmp(key, "stats_interval") == 0) {
        return set_int_range(&config->stats_interval, value, 0, 86400);
    }
    if (strcmp(key, "client_id") == 0) {
        if (!valid_client_id(value)) {
            return -1;
        }
        return copy_string(config->client_id, sizeof(config->client_id),
                           value);
    }
    if (strcmp(key, "client") == 0) {
        return set_client_cred(config, value);
    }
    if (strcmp(key, "client_route") == 0) {
        return set_client_route(config, value);
    }
    if (strcmp(key, "log_level") == 0) {
        log_level_t level;

        if (config_parse_log_level(value, &level) != 0) {
            return -1;
        }
        config->log_level = level;
        return 0;
    }

    log_warn("Configuration: ignoring unknown key '%s'", key);
    return 0;
}

int config_load(const char *path, pipesix_config_t *config)
{
    FILE *fp;
    char line[4096];
    unsigned int line_num = 0;

    if (config == NULL || path == NULL) {
        fprintf(stderr, "config_load: invalid parameters\n");
        return -1;
    }

    config_set_defaults(config);

    if (copy_string(config->config_path, sizeof(config->config_path),
                    path) != 0) {
        config->config_path[0] = '\0';
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        fprintf(stderr, "config_load: cannot open '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *ptr, *key, *value;

        line_num++;

        /* Detect lines too long for the buffer before trimming. */
        if (strchr(line, '\n') == NULL && !feof(fp)) {
            fprintf(stderr, "config_load: %s:%u: line too long\n",
                    path, line_num);
            fclose(fp);
            return -1;
        }

        /* Remove trailing newline/carriage return */
        ptr = line + strlen(line);
        while (ptr > line && (*(ptr - 1) == '\n' || *(ptr - 1) == '\r')) {
            *(--ptr) = '\0';
        }

        /* Skip empty lines and comments */
        ptr = line;
        while (isspace((unsigned char)*ptr)) ptr++;
        if (*ptr == '\0' || *ptr == '#') {
            continue;
        }

        /* Find the '=' separator */
        value = strchr(line, '=');
        if (value == NULL) {
            fprintf(stderr, "config_load: %s:%u: malformed line (no '=')\n",
                    path, line_num);
            fclose(fp);
            return -1;
        }

        *value = '\0';
        key = str_trim(line);
        value = str_trim(value + 1);

        if (*key == '\0') {
            fprintf(stderr, "config_load: %s:%u: empty key\n",
                    path, line_num);
            fclose(fp);
            return -1;
        }

        if (config_set_value(config, key, value) != 0) {
            fprintf(stderr,
                    "config_load: %s:%u: invalid value for '%s'\n",
                    path, line_num, key);
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

int config_validate(const pipesix_config_t *config)
{
    struct in6_addr parsed_addr;

    if (config == NULL) {
        return -1;
    }

    if (strlen(config->mode) == 0) {
        log_error("Configuration validation failed: 'mode' is required (client or server)");
        return -1;
    }

    if (strcmp(config->mode, "client") != 0 &&
        strcmp(config->mode, "server") != 0) {
        log_error("Configuration validation failed: 'mode' must be 'client' or 'server' (got '%s')",
                  config->mode);
        return -1;
    }

    if (strlen(config->tun_address) == 0) {
        log_error("Configuration validation failed: 'tun_address' is required");
        return -1;
    }

    if (inet_pton(AF_INET6, config->tun_address, &parsed_addr) != 1) {
        log_error("Configuration validation failed: 'tun_address' is not a valid IPv6 address (got '%s')",
                  config->tun_address);
        return -1;
    }

    if (config->tun_prefixlen < 0 || config->tun_prefixlen > 128) {
        log_error("Configuration validation failed: 'tun_prefixlen' must be 0-128 (got %d)",
                  config->tun_prefixlen);
        return -1;
    }

    if (config->tun_mtu != 0 &&
        (config->tun_mtu < 576 || config->tun_mtu > 65535)) {
        log_error("Configuration validation failed: 'tun_mtu' must be 576-65535 or 0 to leave it unchanged (got %d)",
                  config->tun_mtu);
        return -1;
    }

    if (config->peer_timeout < 0 || config->peer_timeout > 86400) {
        log_error("Configuration validation failed: 'peer_timeout' must be 0-86400 (got %d)",
                  config->peer_timeout);
        return -1;
    }

    if (strcmp(config->mode, "client") == 0) {
        if (strlen(config->remote_address) == 0) {
            log_error("Configuration validation failed: 'remote_address' is required in client mode");
            return -1;
        }
        if (config->remote_port < 1 || config->remote_port > 65535) {
            log_error("Configuration validation failed: 'remote_port' must be 1-65535 (got %d)",
                      config->remote_port);
            return -1;
        }
        if (strlen(config->client_id) == 0) {
            log_error("Configuration validation failed: 'client_id' is required in client mode");
            return -1;
        }
        if (config->secret[0] == '\0') {
            log_error("Configuration validation failed: 'secret' (this client's pre-shared key) is required in client mode");
            return -1;
        }
    }

    if (strcmp(config->mode, "server") == 0) {
        if (strlen(config->bind_address) == 0) {
            log_error("Configuration validation failed: 'bind_address' is required in server mode");
            return -1;
        }
        if (config->bind_port < 1 || config->bind_port > 65535) {
            log_error("Configuration validation failed: 'bind_port' must be 1-65535 (got %d)",
                      config->bind_port);
            return -1;
        }
        if (config->client_count == 0) {
            log_error("Configuration validation failed: at least one "
                      "'client = <id>: <secret>' entry is required in "
                      "server mode");
            return -1;
        }
        if (config->secret[0] != '\0') {
            log_warn("Server 'secret' is ignored: each client authenticates "
                     "with its own credential from 'client = <id>: <secret>'");
        }

        /*
         * Two clients claiming the same prefix would make return routing
         * ambiguous, so reject that instead of picking one at random.
         */
        {
            int i;
            int j;
            int routed = 0;

            for (i = 0; i < config->client_count; i++) {
                if (config->clients[i].prefix_len > 0) {
                    routed++;
                }
            }

            for (i = 0; i < config->client_count; i++) {
                if (config->clients[i].prefix_len <= 0) {
                    continue;
                }

                for (j = i + 1; j < config->client_count; j++) {
                    if (config->clients[j].prefix_len !=
                        config->clients[i].prefix_len) {
                        continue;
                    }
                    if (memcmp(config->clients[j].prefix,
                               config->clients[i].prefix,
                               sizeof(config->clients[i].prefix)) != 0) {
                        continue;
                    }

                    log_error("Configuration validation failed: clients "
                              "'%s' and '%s' are configured with the same "
                              "route prefix",
                              config->clients[i].id,
                              config->clients[j].id);
                    return -1;
                }
            }

            if (config->client_count > 1 && routed < config->client_count) {
                log_warn("%d client(s) have no 'client_route'; return "
                         "traffic to them is dropped unless it is the "
                         "only connected client",
                         config->client_count - routed);
            }
        }
    }

    if (strcmp(config->mode, "client") == 0 &&
        config->secret[0] != '\0' && strlen(config->secret) < 16) {
        log_warn("Configured 'secret' is short; generate one with 'pipesix --genkey'");
    }

    {
        int i;

        for (i = 0; i < config->client_count; i++) {
            if (strlen(config->clients[i].secret) < 16) {
                log_warn("Client '%s' uses a short secret; generate one "
                         "with 'pipesix --genkey'", config->clients[i].id);
            }
        }
    }

    return 0;
}

void config_dump(const pipesix_config_t *config)
{
    const char *level_str = "UNKNOWN";

    if (config == NULL) return;

    switch (config->log_level) {
        case LOG_DEBUG: level_str = "debug"; break;
        case LOG_INFO:  level_str = "info";  break;
        case LOG_WARN:  level_str = "warn";  break;
        case LOG_ERROR: level_str = "error"; break;
        case LOG_FATAL: level_str = "fatal"; break;
    }

    log_info("Configuration:");
    log_info("  mode            = %s", config->mode);
    log_info("  tun_name        = %s", config->tun_name);
    log_info("  tun_address     = %s/%d", config->tun_address,
             config->tun_prefixlen);
    log_info("  tun_mtu         = %d", config->tun_mtu);

    if (strcmp(config->mode, "client") == 0) {
        log_info("  remote_address  = %s", config->remote_address);
        log_info("  remote_port     = %d", config->remote_port);
    }

    if (strcmp(config->mode, "server") == 0) {
        log_info("  bind_address    = %s", config->bind_address);
        log_info("  bind_port       = %d", config->bind_port);
        log_info("  allow_client    = %d configured",
                 config->allow_client_count);
    }

    log_info("  secret          = %s",
             (config->secret[0] != '\0') ? "(set)" : "(not set)");
    log_info("  client_id       = %s",
             (config->client_id[0] != '\0') ? config->client_id : "(not set)");

    if (strcmp(config->mode, "server") == 0) {
        int i;

        log_info("  clients         = %d configured", config->client_count);
        for (i = 0; i < config->client_count; i++) {
            char prefix_str[INET6_ADDRSTRLEN];

            if (config->clients[i].prefix_len <= 0) {
                log_info("    client: %s (no route)", config->clients[i].id);
                continue;
            }

            if (inet_ntop(AF_INET6, config->clients[i].prefix, prefix_str,
                          sizeof(prefix_str)) == NULL) {
                memcpy(prefix_str, "?", sizeof("?"));
            }

            log_info("    client: %s route %s/%d", config->clients[i].id,
                     prefix_str, config->clients[i].prefix_len);
        }
    }
    log_info("  keepalive       = %d s", config->keepalive);
    log_info("  peer_timeout    = %d s", config->peer_timeout);
    log_info("  session_timeout = %d s", config->session_timeout);
    log_info("  stats_interval  = %d s", config->stats_interval);
    log_info("  log_level       = %s", level_str);
}

int config_reload_runtime(pipesix_config_t *config)
{
    pipesix_config_t fresh;

    if (config == NULL || config->config_path[0] == '\0') {
        return -1;
    }

    if (config_load(config->config_path, &fresh) != 0) {
        return -1;
    }

    if (config_validate(&fresh) != 0) {
        return -1;
    }

    if (strcmp(fresh.mode, config->mode) != 0) {
        log_error("Configuration reload rejected: 'mode' cannot change at runtime");
        return -1;
    }

    config->log_level       = fresh.log_level;
    config->keepalive       = fresh.keepalive;
    config->peer_timeout    = fresh.peer_timeout;
    config->session_timeout = fresh.session_timeout;
    config->stats_interval  = fresh.stats_interval;

    /*
     * In server mode the credential table is reloadable too: this is how
     * an operator rotates a client's key without restarting the relay.
     * The caller (the server) decides which live sessions that affects.
     */
    if (strcmp(config->mode, "server") == 0) {
        config->client_count = fresh.client_count;
        memcpy(config->clients, fresh.clients, sizeof(config->clients));
    } else {
        /*
         * A client's own identity and key are reloadable as well; the
         * caller compares them and re-handshakes when they changed, which
         * is how a client rotates its key without a restart.
         */
        memcpy(config->client_id, fresh.client_id, sizeof(config->client_id));
        memcpy(config->secret, fresh.secret, sizeof(config->secret));
    }

    return 0;
}

/* One generated key as a NUL-terminated hex string. */
#define ROTATE_KEY_STRIDE (PIPESIX_KEY_LEN * 2 + 1)

/*
 * Rewrite the 'client = <id>: <secret>' lines of path with new_keys.
 *
 * Every other byte of the file is copied through unchanged, so comments,
 * blank lines, ordering and the spacing around '=' and ':' survive a
 * rotation and the diff shows nothing but the secrets.
 *
 * The replacement is written to a temporary file in the same directory,
 * parsed back and compared entry by entry, and only then renamed over the
 * original: a bad rewrite can never replace a working configuration.
 *
 * Returns:
 *   0 on success, -1 on failure (the original file is left alone)
 */
static int rewrite_client_keys(const char *path,
                               const pipesix_config_t *config,
                               const char *new_keys)
{
    char tmp_path[CONFIG_PATH_MAX + 32];
    char buf[4096];
    struct stat st;
    FILE *in;
    FILE *out = NULL;
    int fd;
    int rc = -1;
    int i;

    if (path == NULL || config == NULL) {
        return -1;
    }

    if (strlen(path) + sizeof(".pipesix.XXXXXX") > sizeof(tmp_path)) {
        return -1;
    }

    if (stat(path, &st) != 0) {
        return -1;
    }

    snprintf(tmp_path, sizeof(tmp_path), "%s.pipesix.XXXXXX", path);

    in = fopen(path, "r");
    if (in == NULL) {
        return -1;
    }

    fd = mkstemp(tmp_path);
    if (fd < 0) {
        fclose(in);
        return -1;
    }

    /* Keep the permissions the operator set on the original file. */
#if !defined(_WIN32)
    if (fchmod(fd, st.st_mode & (mode_t)07777) != 0) {
        close(fd);
        unlink(tmp_path);
        fclose(in);
        return -1;
    }
#endif

    out = fdopen(fd, "w");
    if (out == NULL) {
        close(fd);
        unlink(tmp_path);
        fclose(in);
        return -1;
    }

    while (fgets(buf, sizeof(buf), in) != NULL) {
        const char *key = buf;
        const char *eq;
        const char *colon;
        const char *secret;
        const char *tail;
        const char *id;
        const char *id_end;
        size_t key_len = 0;
        size_t id_len;
        size_t secret_len;
        int idx = -1;

        /* config_load() refused longer lines, so this is not a split. */
        if (strchr(buf, '\n') == NULL && !feof(in)) {
            goto cleanup;
        }

        while (isspace((unsigned char)*key)) {
            key++;
        }

        /* Comments, blank lines and every other key are copied verbatim. */
        if (*key == '\0' || *key == '#') {
            fputs(buf, out);
            continue;
        }

        while (key[key_len] != '\0' && key[key_len] != '=' &&
               !isspace((unsigned char)key[key_len])) {
            key_len++;
        }

        /* 'client_id' and 'client_route' must not be mistaken for 'client'. */
        if (key_len != 6u || memcmp(key, "client", 6) != 0) {
            fputs(buf, out);
            continue;
        }

        eq = strchr(key, '=');
        colon = (eq != NULL) ? strchr(eq + 1, ':') : NULL;
        if (colon == NULL) {
            goto cleanup;
        }

        /* Locate the id between '=' and ':', trimmed at both ends. */
        id = eq + 1;
        id_end = colon;
        while (id < id_end && isspace((unsigned char)*id)) {
            id++;
        }
        while (id_end > id && isspace((unsigned char)*(id_end - 1))) {
            id_end--;
        }
        id_len = (size_t)(id_end - id);

        for (i = 0; i < config->client_count; i++) {
            if (strlen(config->clients[i].id) == id_len &&
                memcmp(config->clients[i].id, id, id_len) == 0) {
                idx = i;
                break;
            }
        }

        /* An id the loaded table does not know means the file changed. */
        if (idx < 0) {
            goto cleanup;
        }

        secret = colon + 1;
        while (*secret != '\0' && isspace((unsigned char)*secret)) {
            secret++;
        }

        tail = secret;
        while (*tail != '\0' && !isspace((unsigned char)*tail)) {
            tail++;
        }
        secret_len = (size_t)(secret - buf);

        /* Prefix through the colon's whitespace, new key, then the rest. */
        if (fwrite(buf, 1, secret_len, out) != secret_len) {
            goto cleanup;
        }
        if (fputs(new_keys + ((size_t)idx * ROTATE_KEY_STRIDE), out) == EOF ||
            fputs(tail, out) == EOF) {
            goto cleanup;
        }
    }

    if (ferror(in)) {
        goto cleanup;
    }

    if (fflush(out) != 0 || sync_file(out) != 0) {
        goto cleanup;
    }

    if (fclose(out) != 0) {
        out = NULL;
        goto cleanup;
    }
    out = NULL;

    /* Re-parse the replacement before it is allowed to replace anything. */
    {
        pipesix_config_t check;

        if (config_load(tmp_path, &check) != 0 ||
            config_validate(&check) != 0) {
            unlink(tmp_path);
            fclose(in);
            return -1;
        }

        for (i = 0; i < config->client_count; i++) {
            const pipesix_client_cred_t *cred =
                config_find_client(&check, config->clients[i].id);

            if (cred == NULL ||
                strcmp(cred->secret,
                       new_keys + ((size_t)i * ROTATE_KEY_STRIDE)) != 0) {
                unlink(tmp_path);
                fclose(in);
                return -1;
            }
        }
    }

    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        fclose(in);
        return -1;
    }

    rc = 0;

cleanup:
    if (out != NULL) {
        fclose(out);
    }
    fclose(in);

    if (rc != 0) {
        unlink(tmp_path);
    }

    return rc;
}

int config_rotate_all_keys(pipesix_config_t *config)
{
    char new_keys[(size_t)CONFIG_MAX_CLIENTS * ROTATE_KEY_STRIDE];
    uint8_t key[PIPESIX_KEY_LEN];
    int i;

    if (config == NULL) {
        return -1;
    }

    if (strcmp(config->mode, "server") != 0) {
        log_error("--rotate-all rewrites a server's client table; on a "
                  "client generate a key with 'pipesix --genkey' and set "
                  "'secret' by hand");
        return -1;
    }

    if (config->client_count <= 0) {
        log_error("--rotate-all: no 'client' entries are configured");
        return -1;
    }

    if (config->config_path[0] == '\0') {
        log_error("--rotate-all: the configuration file path is unknown");
        return -1;
    }

    /*
     * Generate every key before touching the file, so a failure to read
     * randomness leaves the configuration exactly as it was.
     */
    for (i = 0; i < config->client_count; i++) {
        if (pipesix_random_bytes(key, sizeof(key)) != 0) {
            log_error("--rotate-all: cannot read random bytes: %s",
                      strerror(errno));
            return -1;
        }

        pipesix_hex_encode(key, sizeof(key),
                           new_keys + ((size_t)i * ROTATE_KEY_STRIDE));
    }

    memset(key, 0, sizeof(key));

    if (rewrite_client_keys(config->config_path, config, new_keys) != 0) {
        log_error("--rotate-all: cannot rewrite '%s'; the existing keys "
                  "are unchanged", config->config_path);
        return -1;
    }

    /* The caller prints these, so the new keys can be handed out. */
    for (i = 0; i < config->client_count; i++) {
        memcpy(config->clients[i].secret,
               new_keys + ((size_t)i * ROTATE_KEY_STRIDE),
               ROTATE_KEY_STRIDE);
    }

    return 0;
}

/*
 * Does this configuration line define or route 'id'?
 *
 * Matches 'client = <id>: <secret>' and 'client_route = <id> <prefix>'.
 * The same conservative parser as the rest of the file: the key token is
 * read up to '=' or whitespace, and the id up to ':' or whitespace.
 */
static int line_belongs_to_client(const char *line, const char *id)
{
    const char *p = line;
    const char *eq;
    const char *start;
    const char *end;
    size_t key_len = 0;
    size_t id_len = strlen(id);

    while (isspace((unsigned char)*p)) {
        p++;
    }

    if (*p == '\0' || *p == '#') {
        return 0;
    }

    while (p[key_len] != '\0' && p[key_len] != '=' &&
           !isspace((unsigned char)p[key_len])) {
        key_len++;
    }

    if (!((key_len == 6u && memcmp(p, "client", 6) == 0) ||
          (key_len == 12u && memcmp(p, "client_route", 12) == 0))) {
        return 0;
    }

    eq = strchr(p, '=');
    if (eq == NULL) {
        return 0;
    }

    start = eq + 1;
    while (isspace((unsigned char)*start)) {
        start++;
    }

    end = start;
    while (*end != '\0' && *end != ':' && !isspace((unsigned char)*end)) {
        end++;
    }

    return (size_t)(end - start) == id_len &&
           memcmp(start, id, id_len) == 0;
}

/*
 * Open a temporary file next to path that will replace it.
 *
 * Returns the temp path and an open stream, or -1. Keeps the original
 * file's permissions so a 0600 configuration stays 0600.
 */
static int open_replacement(const char *path, char *tmp_path,
                            size_t tmp_size, FILE **out)
{
    struct stat st;
    int fd;

    if (strlen(path) + sizeof(".pipesix.XXXXXX") > tmp_size) {
        return -1;
    }

    if (stat(path, &st) != 0) {
        return -1;
    }

    snprintf(tmp_path, tmp_size, "%s.pipesix.XXXXXX", path);

    fd = mkstemp(tmp_path);
    if (fd < 0) {
        return -1;
    }

#if !defined(_WIN32)
    if (fchmod(fd, st.st_mode & (mode_t)07777) != 0) {
        close(fd);
        unlink(tmp_path);
        return -1;
    }
#endif

    *out = fdopen(fd, "w");
    if (*out == NULL) {
        close(fd);
        unlink(tmp_path);
        return -1;
    }

    return 0;
}

int config_add_client(pipesix_config_t *config, const char *id,
                      const char *prefix, char *secret_out,
                      size_t secret_size)
{
    char key_hex[ROTATE_KEY_STRIDE];
    char tmp_path[CONFIG_PATH_MAX + 32];
    char line[CONFIG_MAX_CLIENT_ID + CONFIG_MAX_ADDRESS + 32];
    char buf[4096];
    uint8_t key[PIPESIX_KEY_LEN];
    FILE *in = NULL;
    FILE *out = NULL;
    size_t nread;
    int last = '\n';
    int rc = -1;

    if (config == NULL || id == NULL || config->config_path[0] == '\0') {
        return -1;
    }

    if (strcmp(config->mode, "server") != 0) {
        log_error("clients can only be added to a server configuration");
        return -1;
    }

    if (!valid_client_id(id)) {
        log_error("invalid client id '%s' (letters, digits, '.', '_' and "
                  "'-' only, at most %d characters)",
                  id, CONFIG_MAX_CLIENT_ID - 1);
        return -1;
    }

    if (config_find_client(config, id) != NULL) {
        log_error("client '%s' already exists in '%s'", id,
                  config->config_path);
        return -1;
    }

    if (config->client_count >= CONFIG_MAX_CLIENTS) {
        log_error("the configuration already holds %d clients",
                  CONFIG_MAX_CLIENTS);
        return -1;
    }

    if (prefix != NULL && prefix[0] == '\0') {
        prefix = NULL;
    }

    if (secret_out != NULL && secret_size > 0) {
        secret_out[0] = '\0';
    }

    if (pipesix_random_bytes(key, sizeof(key)) != 0) {
        log_error("cannot read random bytes: %s", strerror(errno));
        return -1;
    }
    pipesix_hex_encode(key, sizeof(key), key_hex);
    memset(key, 0, sizeof(key));

    in = fopen(config->config_path, "r");
    if (in == NULL) {
        return -1;
    }

    if (open_replacement(config->config_path, tmp_path, sizeof(tmp_path),
                         &out) != 0) {
        fclose(in);
        return -1;
    }

    while ((nread = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, nread, out) != nread) {
            goto cleanup;
        }
        last = buf[nread - 1];
    }

    if (ferror(in)) {
        goto cleanup;
    }

    /* Appending after the last line keeps 'client_route' after 'client'. */
    if (last != '\n' && fputc('\n', out) == EOF) {
        goto cleanup;
    }

    if (snprintf(line, sizeof(line), "client = %s: %s\n", id, key_hex) >=
        (int)sizeof(line)) {
        goto cleanup;
    }
    if (fputs(line, out) == EOF) {
        goto cleanup;
    }

    if (prefix != NULL) {
        if (snprintf(line, sizeof(line), "client_route = %s %s\n", id,
                     prefix) >= (int)sizeof(line)) {
            goto cleanup;
        }
        if (fputs(line, out) == EOF) {
            goto cleanup;
        }
    }

    if (fflush(out) != 0 || sync_file(out) != 0) {
        goto cleanup;
    }
    if (fclose(out) != 0) {
        out = NULL;
        goto cleanup;
    }
    out = NULL;

    /* Never let a rewrite replace a configuration that does not parse. */
    {
        pipesix_config_t check;
        const pipesix_client_cred_t *cred;

        if (config_load(tmp_path, &check) != 0 ||
            config_validate(&check) != 0) {
            log_error("the rewritten configuration is invalid; '%s' is "
                      "unchanged", config->config_path);
            goto cleanup;
        }

        cred = config_find_client(&check, id);
        if (cred == NULL || strcmp(cred->secret, key_hex) != 0) {
            log_error("the rewritten configuration does not hold client "
                      "'%s'; '%s' is unchanged", id,
                      config->config_path);
            goto cleanup;
        }
        if (prefix != NULL && cred->prefix_len == 0) {
            log_error("the route for client '%s' was not accepted; '%s' "
                      "is unchanged", id, config->config_path);
            goto cleanup;
        }
    }

    if (rename(tmp_path, config->config_path) != 0) {
        log_error("cannot replace '%s': %s", config->config_path,
                  strerror(errno));
        goto cleanup;
    }

    if (secret_out != NULL && secret_size > 0) {
        snprintf(secret_out, secret_size, "%s", key_hex);
    }

    rc = 0;

cleanup:
    if (out != NULL) {
        fclose(out);
    }
    fclose(in);

    if (rc != 0) {
        unlink(tmp_path);
    }

    return rc;
}

int config_remove_client(pipesix_config_t *config, const char *id)
{
    char tmp_path[CONFIG_PATH_MAX + 32];
    char buf[4096];
    FILE *in = NULL;
    FILE *out = NULL;
    int removed = 0;
    int rc = -1;

    if (config == NULL || id == NULL || config->config_path[0] == '\0') {
        return -1;
    }

    if (strcmp(config->mode, "server") != 0) {
        log_error("clients can only be removed from a server configuration");
        return -1;
    }

    if (config_find_client(config, id) == NULL) {
        log_error("client '%s' is not configured in '%s'", id,
                  config->config_path);
        return -1;
    }

    if (config->client_count <= 1) {
        log_error("'%s' is the last client; a server needs at least one "
                  "credential", id);
        return -1;
    }

    in = fopen(config->config_path, "r");
    if (in == NULL) {
        return -1;
    }

    if (open_replacement(config->config_path, tmp_path, sizeof(tmp_path),
                         &out) != 0) {
        fclose(in);
        return -1;
    }

    while (fgets(buf, sizeof(buf), in) != NULL) {
        if (line_belongs_to_client(buf, id)) {
            removed++;
            continue;
        }
        if (fputs(buf, out) == EOF) {
            goto cleanup;
        }
    }

    if (ferror(in) || removed == 0) {
        goto cleanup;
    }

    if (fflush(out) != 0 || sync_file(out) != 0) {
        goto cleanup;
    }
    if (fclose(out) != 0) {
        out = NULL;
        goto cleanup;
    }
    out = NULL;

    {
        pipesix_config_t check;

        if (config_load(tmp_path, &check) != 0 ||
            config_validate(&check) != 0 ||
            config_find_client(&check, id) != NULL) {
            log_error("the rewritten configuration is invalid; '%s' is "
                      "unchanged", config->config_path);
            goto cleanup;
        }
    }

    if (rename(tmp_path, config->config_path) != 0) {
        log_error("cannot replace '%s': %s", config->config_path,
                  strerror(errno));
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (out != NULL) {
        fclose(out);
    }
    fclose(in);

    if (rc != 0) {
        unlink(tmp_path);
    }

    return rc;
}
