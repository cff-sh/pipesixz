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
#include "policy.h"

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

static int resolve_relative(const char *base, const char *value,
                            char *out, size_t out_size);
static int set_client_secret_file(pipesix_config_t *config, const char *value,
                                  const char *base);
static int set_client_next_file(pipesix_config_t *config, const char *value,
                                const char *base);

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

/*
 * Replace a key file atomically with one secret on its own line.
 *
 * The temporary file is created with mode 0600 rather than inheriting the
 * old file's mode: a server key is a credential, not configuration. The
 * write is synced and renamed, so a crash cannot leave a truncated key
 * that would lock a client out.
 */
static int write_secret_file(const char *path, const char *secret)
{
    char tmp_path[CONFIG_PATH_MAX + 32];
    FILE *fp;
    int fd;

    if (path == NULL || path[0] == '\0' || secret == NULL ||
        secret[0] == '\0' || strlen(secret) >= CONFIG_MAX_SECRET) {
        return -1;
    }
    if (strlen(path) + sizeof(".pipesix.XXXXXX") > sizeof(tmp_path)) {
        return -1;
    }

    snprintf(tmp_path, sizeof(tmp_path), "%s.pipesix.XXXXXX", path);
    fd = mkstemp(tmp_path);
    if (fd < 0) {
        return -1;
    }
#if !defined(_WIN32)
    if (fchmod(fd, 0600) != 0) {
        close(fd);
        unlink(tmp_path);
        return -1;
    }
#endif

    fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        unlink(tmp_path);
        return -1;
    }

    if (fprintf(fp, "%s\n", secret) < 0 || fflush(fp) != 0 ||
        sync_file(fp) != 0) {
        fclose(fp);
        unlink(tmp_path);
        return -1;
    }
    if (fclose(fp) != 0) {
        unlink(tmp_path);
        return -1;
    }

    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        return -1;
    }

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

static int set_u64_range(uint64_t *dst, const char *value,
                         uint64_t min, uint64_t max)
{
    int parsed;

    if (parse_int(value, &parsed) != 0 || parsed < 0 ||
        (uint64_t)parsed < min || (uint64_t)parsed > max) {
        return -1;
    }

    *dst = (uint64_t)parsed;
    return 0;
}

/*
 * Accept the usual spellings for a boolean configuration value.
 */
static int set_bool(int *dst, const char *value)
{
    if (strcasecmp(value, "on") == 0 ||
        strcasecmp(value, "true") == 0 ||
        strcasecmp(value, "yes") == 0 ||
        strcmp(value, "1") == 0) {
        *dst = 1;
        return 0;
    }

    if (strcasecmp(value, "off") == 0 ||
        strcasecmp(value, "false") == 0 ||
        strcasecmp(value, "no") == 0 ||
        strcmp(value, "0") == 0) {
        *dst = 0;
        return 0;
    }

    return -1;
}

/*
 * Split 'remote_address' into ordered endpoints.
 *
 * A comma separated list is accepted; whitespace around each entry is
 * ignored. Keeping the order matters: the client tries them in the order
 * written and only moves on when one stops answering.
 */
static int split_remote_endpoints(pipesix_config_t *config)
{
    char work[CONFIG_MAX_REMOTE_LIST];
    char *p;
    size_t len;

    config->remote_count = 0;

    if (config->remote_address[0] == '\0') {
        return 0;
    }

    len = strlen(config->remote_address);
    if (len >= sizeof(work)) {
        return -1;
    }
    memcpy(work, config->remote_address, len + 1);

    p = work;
    while (*p != '\0') {
        char *start = p;
        char *end;

        while (*p != '\0' && *p != ',') {
            p++;
        }
        if (*p == ',') {
            *p = '\0';
            p++;
        }

        start = str_trim(start);
        end = start + strlen(start);
        while (end > start && isspace((unsigned char)end[-1])) {
            *--end = '\0';
        }

        if (*start == '\0' || strlen(start) >= CONFIG_MAX_ADDRESS) {
            return -1;
        }
        if (config->remote_count >= CONFIG_MAX_REMOTE_ENDPOINTS) {
            return -1;
        }

        memcpy(config->remote_endpoints[config->remote_count], start,
               strlen(start) + 1);
        config->remote_count++;
    }

    return config->remote_count > 0 ? 0 : -1;
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
    config->metrics_port   = CONFIG_DEFAULT_METRICS_PORT;
    config->endpoint_failback_interval = 60;
    config->quota_throttle_kbps = CONFIG_DEFAULT_QUOTA_THROTTLE_KBPS;
    config->log_level      = CONFIG_DEFAULT_LOG_LEVEL;
    config->policy_count   = 0;
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
static int parse_client_secret(const char *value, char *id, size_t id_size,
                               char *secret, size_t secret_size)
{
    const char *sep;
    const char *start;
    const char *end;
    size_t id_len;
    size_t secret_len;

    if (value == NULL) return -1;

    sep = strchr(value, ':');
    if (sep == NULL) return -1;

    start = value;
    end = sep;
    while (start < end && isspace((unsigned char)*start)) start++;
    while (end > start && isspace((unsigned char)*(end - 1))) end--;

    id_len = (size_t)(end - start);
    if (id_len == 0 || id_len >= id_size) return -1;

    memcpy(id, start, id_len);
    id[id_len] = '\0';
    if (!valid_client_id(id)) return -1;

    start = sep + 1;
    while (*start != '\0' && isspace((unsigned char)*start)) start++;
    secret_len = strlen(start);
    while (secret_len > 0 &&
           isspace((unsigned char)start[secret_len - 1])) {
        secret_len--;
    }

    if (secret_len == 0 || secret_len >= secret_size) return -1;
    memcpy(secret, start, secret_len);
    secret[secret_len] = '\0';
    return 0;
}

static int set_client_cred(pipesix_config_t *config, const char *value)
{
    char id[CONFIG_MAX_CLIENT_ID];
    char secret[CONFIG_MAX_SECRET];
    size_t i;

    if (parse_client_secret(value, id, sizeof(id), secret, sizeof(secret)) !=
        0) {
        return -1;
    }

    if (config->client_count >= CONFIG_MAX_CLIENTS) return -1;

    for (i = 0; i < (size_t)config->client_count; i++) {
        if (strcmp(config->clients[i].id, id) == 0) {
            return -1; /* Duplicate ids would make identity ambiguous. */
        }
    }

    memcpy(config->clients[config->client_count].id, id, strlen(id) + 1);
    memcpy(config->clients[config->client_count].secret, secret,
           strlen(secret) + 1);
    config->client_count++;

    return 0;
}

/* Parse '<id>: <secret>' for a staged key. */
static int set_client_next(pipesix_config_t *config, const char *value)
{
    pipesix_client_cred_t *cred;
    char id[CONFIG_MAX_CLIENT_ID];
    char secret[CONFIG_MAX_SECRET];

    if (parse_client_secret(value, id, sizeof(id), secret, sizeof(secret)) !=
        0) {
        return -1;
    }

    cred = (pipesix_client_cred_t *)config_find_client(config, id);
    if (cred == NULL || cred->has_next_secret) {
        return -1;
    }

    memcpy(cred->next_secret, secret, strlen(secret) + 1);
    cred->has_next_secret = 1;
    return 0;
}

/*
 * Parse a UTC date or Unix timestamp into an expiry instant. A date means
 * the first second of that UTC day, which is the usual "expires at the end
 * of the previous day" interpretation.
 */
static int64_t days_from_civil(int year, unsigned int month,
                               unsigned int day)
{
    int era;
    unsigned int yoe;
    unsigned int doy;
    unsigned int doe;

    year -= month <= 2;
    era = (year >= 0 ? year : year - 399) / 400;
    yoe = (unsigned int)(year - era * 400);
    doy = (153u * (month + (month > 2 ? (unsigned int)-3 : 9u)) + 2u) / 5u +
          day - 1u;
    doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    return (int64_t)era * 146097 + (int64_t)doe - 719468;
}

static int parse_expiry_value(const char *value, int64_t *out)
{
    int year;
    int month;
    int day;
    int consumed = 0;

    if (value == NULL || out == NULL || value[0] == '\0') return -1;

    if (strchr(value, '-') == NULL) {
        char *end = NULL;
        long long seconds;

        errno = 0;
        seconds = strtoll(value, &end, 10);
        if (errno != 0 || end == value || *end != '\0' || seconds <= 0) {
            return -1;
        }
        *out = (int64_t)seconds;
        return 0;
    }

    if (sscanf(value, "%4d-%2d-%2d%n", &year, &month, &day, &consumed) != 3 ||
        consumed != (int)strlen(value) || month < 1 || month > 12 ||
        day < 1 || day > 31 || year < 1970 || year > 9999) {
        return -1;
    }

    *out = days_from_civil(year, (unsigned int)month, (unsigned int)day) *
           86400;
    return *out > 0 ? 0 : -1;
}

static int set_client_disabled(pipesix_config_t *config, const char *value)
{
    pipesix_client_cred_t *cred;
    char id[CONFIG_MAX_CLIENT_ID];
    const char *end;
    size_t len;

    if (value == NULL) return -1;

    while (isspace((unsigned char)*value)) value++;
    end = value + strlen(value);
    while (end > value && isspace((unsigned char)*(end - 1))) end--;
    len = (size_t)(end - value);
    if (len == 0 || len >= sizeof(id)) return -1;

    memcpy(id, value, len);
    id[len] = '\0';
    if (!valid_client_id(id)) return -1;

    cred = (pipesix_client_cred_t *)config_find_client(config, id);
    if (cred == NULL || cred->disabled) return -1;
    cred->disabled = 1;
    return 0;
}

static int set_client_expiry(pipesix_config_t *config, const char *value)
{
    pipesix_client_cred_t *cred;
    char work[CONFIG_MAX_CLIENT_ID + 64];
    char *id;
    char *when;
    size_t len;
    int64_t expires;

    if (value == NULL) return -1;
    len = strlen(value);
    if (len == 0 || len >= sizeof(work)) return -1;
    memcpy(work, value, len + 1);

    id = work;
    while (isspace((unsigned char)*id)) id++;
    when = id;
    while (*when != '\0' && !isspace((unsigned char)*when)) when++;
    if (*when == '\0') return -1;
    *when++ = '\0';
    while (isspace((unsigned char)*when)) when++;

    len = strlen(when);
    while (len > 0 && isspace((unsigned char)when[len - 1])) {
        when[--len] = '\0';
    }

    if (!valid_client_id(id) || parse_expiry_value(when, &expires) != 0) {
        return -1;
    }

    cred = (pipesix_client_cred_t *)config_find_client(config, id);
    if (cred == NULL || cred->has_expiry) return -1;

    cred->has_expiry = 1;
    cred->expires_at = expires;
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

/*
 * Parse "client_allow = <id> <prefix>" or "client_deny = <id> <prefix>".
 *
 * An allow list is closed: once a client has one entry, destinations
 * outside it are dropped. The deny list is checked first, so a specific
 * deny can carve a hole out of a broader allow. The 'client' line must
 * come first, like client_route.
 */
static int set_client_acl(pipesix_config_t *config, const char *value,
                          int deny)
{
    char work[CONFIG_MAX_CLIENT_ID + CONFIG_MAX_ADDRESS + 2];
    pipesix_client_cred_t *cred = NULL;
    struct in6_addr parsed;
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
    if (*prefix == '\0') return -1;
    *prefix = '\0';
    prefix++;
    while (isspace((unsigned char)*prefix)) prefix++;

    len = strlen(prefix);
    while (len > 0 && isspace((unsigned char)prefix[len - 1])) {
        prefix[--len] = '\0';
    }

    if (!valid_client_id(id) || prefix[0] == '\0') return -1;

    slash = strchr(prefix, '/');
    if (slash != NULL) {
        *slash = '\0';
        if (parse_int(slash + 1, &prefix_len) != 0) return -1;
    }
    if (prefix_len < 1 || prefix_len > 128) return -1;

    for (i = 0; i < config->client_count; i++) {
        if (strcmp(config->clients[i].id, id) == 0) {
            cred = &config->clients[i];
            break;
        }
    }
    if (cred == NULL) {
        log_error("client_allow/client_deny: unknown client '%s' (the "
                  "'client' line must come first)", id);
        return -1;
    }

    if (inet_pton(AF_INET6, prefix, &parsed) != 1) return -1;

    if (deny) {
        if (cred->deny_count >= CONFIG_MAX_ACL_PREFIXES) return -1;
        memcpy(cred->deny[cred->deny_count], &parsed, sizeof(parsed));
        cred->deny_len[cred->deny_count] = prefix_len;
        cred->deny_count++;
    } else {
        if (cred->allow_count >= CONFIG_MAX_ACL_PREFIXES) return -1;
        memcpy(cred->allow[cred->allow_count], &parsed, sizeof(parsed));
        cred->allow_len[cred->allow_count] = prefix_len;
        cred->allow_count++;
    }

    return 0;
}

/*
 * Read and write the first 64 bits of an IPv6 address in network order.
 */
static uint64_t load_be64(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | (uint64_t)p[7];
}

static void store_be64(uint8_t *p, uint64_t value)
{
    p[0] = (uint8_t)(value >> 56);
    p[1] = (uint8_t)(value >> 48);
    p[2] = (uint8_t)(value >> 40);
    p[3] = (uint8_t)(value >> 32);
    p[4] = (uint8_t)(value >> 24);
    p[5] = (uint8_t)(value >> 16);
    p[6] = (uint8_t)(value >> 8);
    p[7] = (uint8_t)value;
}

/*
 * Do two IPv6 prefixes cover any common address?
 */
static int prefixes_overlap(const uint8_t *a, int a_len,
                            const uint8_t *b, int b_len)
{
    int bits;
    int full;
    int rem;
    uint8_t mask;

    if (a_len <= 0 || b_len <= 0) {
        return 0;
    }

    bits = (a_len < b_len) ? a_len : b_len;
    full = bits / 8;
    rem = bits % 8;

    if (full > 0 && memcmp(a, b, (size_t)full) != 0) {
        return 0;
    }
    if (rem == 0) {
        return 1;
    }

    mask = (uint8_t)(0xFFu << (8 - rem));
    return (a[full] & mask) == (b[full] & mask);
}

/*
 * Parse "client_prefix_pool = <ipv6>/<len>" with a length of 1-64.
 *
 * The address must already be the network address: host bits below the
 * prefix are rejected, so a pool always names a real block. Delegated
 * prefixes are always /64, which is why the pool cannot be longer.
 */
static int set_prefix_pool(pipesix_config_t *config, const char *value)
{
    const char *slash;
    char addr[CONFIG_MAX_ADDRESS];
    struct in6_addr parsed;
    size_t addr_len;
    int prefix_len;
    int i;

    if (value == NULL) return -1;

    slash = strchr(value, '/');
    if (slash == NULL) return -1;

    addr_len = (size_t)(slash - value);
    if (addr_len == 0 || addr_len >= sizeof(addr)) return -1;

    if (parse_int(slash + 1, &prefix_len) != 0 ||
        prefix_len < 1 || prefix_len > 64) {
        return -1;
    }

    memcpy(addr, value, addr_len);
    addr[addr_len] = '\0';

    if (inet_pton(AF_INET6, addr, &parsed) != 1) return -1;
    if (IN6_IS_ADDR_UNSPECIFIED(&parsed) ||
        IN6_IS_ADDR_MULTICAST(&parsed) ||
        IN6_IS_ADDR_LINKLOCAL(&parsed) ||
        IN6_IS_ADDR_LOOPBACK(&parsed)) {
        return -1;
    }

    for (i = 0; i < 16; i++) {
        int keep = prefix_len - i * 8;

        if (keep >= 8) {
            continue;
        }
        if (keep <= 0) {
            if (parsed.s6_addr[i] != 0) return -1;
        } else {
            uint8_t mask = (uint8_t)(0xFFu << (8 - keep));

            if ((parsed.s6_addr[i] & (uint8_t)~mask) != 0) return -1;
        }
    }

    memcpy(config->prefix_pool, &parsed, sizeof(config->prefix_pool));
    config->prefix_pool_len = prefix_len;

    return copy_string(config->client_prefix_pool, CONFIG_MAX_ADDRESS,
                       value);
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
 * Find or create the policy entry for a client id.
 *
 * Returns NULL when the table is full.
 */
static pipesix_client_policy_t *policy_find(const pipesix_config_t *config,
                                            const char *id)
{
    int i;

    for (i = 0; i < config->policy_count; i++) {
        if (strcmp(config->policies[i].id, id) == 0) {
            return (pipesix_client_policy_t *)&config->policies[i];
        }
    }

    return NULL;
}

const pipesix_client_policy_t *config_find_policy(
    const pipesix_config_t *config, const char *id)
{
    return policy_find(config, id);
}

static pipesix_client_policy_t *policy_entry(pipesix_config_t *config,
                                             const char *id)
{
    pipesix_client_policy_t *existing = policy_find(config, id);
    int i;

    if (existing != NULL) {
        return existing;
    }

    if (config->policy_count >= CONFIG_MAX_CLIENTS) {
        log_error("At most %d clients can have per-client limits",
                  CONFIG_MAX_CLIENTS);
        return NULL;
    }

    i = config->policy_count++;
    memset(&config->policies[i], 0, sizeof(config->policies[i]));
    snprintf(config->policies[i].id, sizeof(config->policies[i].id), "%s",
             id);

    return &config->policies[i];
}

/* Which limit a 'client_*' line sets. */
#define POLICY_RATE      0
#define POLICY_QUOTA     1
#define POLICY_WARN      2
#define POLICY_RATE_IN   3
#define POLICY_RATE_OUT  4

/*
 * Parse "client_rate_limit = <id> <kbit/s>",
 * "client_quota = <id> <MiB per UTC period>" or
 * "client_quota_warn = <id> <percent>".
 *
 * The 'client' line must come first, like 'client_route', so a typo in the
 * id is an error instead of a limit that silently never applies.
 */
static int set_client_policy(pipesix_config_t *config, const char *value,
                             int kind)
{
    static const char *const names[] = {
        "client_rate_limit", "client_quota", "client_quota_warn",
        "client_rate_limit_in", "client_rate_limit_out"
    };
    pipesix_client_policy_t *policy;
    char work[CONFIG_MAX_CLIENT_ID + 32];
    char *id;
    char *number;
    size_t len;
    int parsed;

    if (value == NULL) return -1;

    len = strlen(value);
    if (len == 0 || len >= sizeof(work)) return -1;
    memcpy(work, value, len + 1);

    id = work;
    while (isspace((unsigned char)*id)) id++;

    number = id;
    while (*number != '\0' && !isspace((unsigned char)*number)) number++;
    if (*number == '\0') return -1; /* Missing value. */
    *number = '\0';
    number++;
    while (isspace((unsigned char)*number)) number++;

    len = strlen(number);
    while (len > 0 && isspace((unsigned char)number[len - 1])) {
        number[--len] = '\0';
    }

    if (!valid_client_id(id)) return -1;
    if (parse_int(number, &parsed) != 0 || parsed < 0) return -1;

    if (kind == POLICY_QUOTA) {
        if (parsed > 1048576) {         /* 1 TiB per period */
            log_error("client_quota: '%d' MiB is too large", parsed);
            return -1;
        }
    } else if (kind == POLICY_RATE || kind == POLICY_RATE_IN ||
               kind == POLICY_RATE_OUT) {
        if (parsed > 100000000) {       /* 100 Gbit/s */
            log_error("%s: '%d' kbit/s is too large", names[kind], parsed);
            return -1;
        }
    } else if (parsed > 99) {
        log_error("client_quota_warn: '%d'%% is not between 1 and 99",
                  parsed);
        return -1;
    }

    if (config_find_client(config, id) == NULL) {
        log_error("%s: unknown client '%s' (the 'client' line must come "
                  "before its limits)", names[kind], id);
        return -1;
    }

    policy = policy_entry(config, id);
    if (policy == NULL) return -1;

    if (kind == POLICY_RATE) {
        if (policy->rate_kbps != 0) {
            log_error("client_rate_limit: client '%s' already has a rate",
                      id);
            return -1;
        }
        policy->rate_kbps = (uint64_t)parsed;
    } else if (kind == POLICY_RATE_IN) {
        if (policy->rate_in_set) {
            log_error("client_rate_limit_in: client '%s' already has an "
                      "inbound rate", id);
            return -1;
        }
        policy->rate_in_set = 1;
        policy->rate_in_kbps = (uint64_t)parsed;
    } else if (kind == POLICY_RATE_OUT) {
        if (policy->rate_out_set) {
            log_error("client_rate_limit_out: client '%s' already has an "
                      "outbound rate", id);
            return -1;
        }
        policy->rate_out_set = 1;
        policy->rate_out_kbps = (uint64_t)parsed;
    } else if (kind == POLICY_QUOTA) {
        if (policy->quota_mib != 0) {
            log_error("client_quota: client '%s' already has a quota", id);
            return -1;
        }
        policy->quota_mib = (uint64_t)parsed;
    } else {
        if (policy->warn_percent != 0) {
            log_error("client_quota_warn: client '%s' already has a "
                      "warning", id);
            return -1;
        }
        policy->warn_percent = (uint64_t)parsed;
    }

    return 0;
}

/*
 * Process a single key=value line and update the configuration.
 *
 * Returns 0 on success, -1 if the value is invalid or too long.
 */
static int config_set_value(pipesix_config_t *config, const char *key,
                            const char *value, const char *base)
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
        return copy_string(config->remote_address, CONFIG_MAX_REMOTE_LIST,
                           value);
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
    if (strcmp(key, "secret_file") == 0) {
        return copy_string(config->secret_file, CONFIG_PATH_MAX, value);
    }
    if (strcmp(key, "user") == 0) {
        return copy_string(config->user, CONFIG_MAX_USER, value);
    }
    if (strcmp(key, "group") == 0) {
        return copy_string(config->group, CONFIG_MAX_GROUP, value);
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
    if (strcmp(key, "metrics_address") == 0) {
        return copy_string(config->metrics_address, CONFIG_MAX_ADDRESS,
                           value);
    }
    if (strcmp(key, "metrics_port") == 0) {
        return set_int_range(&config->metrics_port, value, 1, 65535);
    }
    if (strcmp(key, "metrics_token") == 0) {
        return copy_string(config->metrics_token, CONFIG_MAX_SECRET, value);
    }
    if (strcmp(key, "audit_log") == 0) {
        return copy_string(config->audit_log, CONFIG_PATH_MAX, value);
    }
    if (strcmp(key, "endpoint_failback") == 0) {
        return set_bool(&config->endpoint_failback, value);
    }
    if (strcmp(key, "endpoint_failback_interval") == 0) {
        return set_int_range(&config->endpoint_failback_interval, value, 1,
                             86400);
    }
    if (strcmp(key, "quota_state") == 0) {
        return copy_string(config->quota_state, CONFIG_PATH_MAX, value);
    }
    if (strcmp(key, "usage_history") == 0) {
        return copy_string(config->usage_history, CONFIG_PATH_MAX, value);
    }
    if (strcmp(key, "client_prefix_pool") == 0) {
        return set_prefix_pool(config, value);
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
    if (strcmp(key, "client_secret_file") == 0) {
        return set_client_secret_file(config, value, base);
    }
    if (strcmp(key, "client_next") == 0) {
        return set_client_next(config, value);
    }
    if (strcmp(key, "client_next_file") == 0) {
        return set_client_next_file(config, value, base);
    }
    if (strcmp(key, "client_disabled") == 0) {
        return set_client_disabled(config, value);
    }
    if (strcmp(key, "client_expires") == 0) {
        return set_client_expiry(config, value);
    }
    if (strcmp(key, "client_route") == 0) {
        return set_client_route(config, value);
    }
    if (strcmp(key, "client_rate_limit") == 0) {
        return set_client_policy(config, value, POLICY_RATE);
    }
    if (strcmp(key, "client_rate_limit_in") == 0) {
        return set_client_policy(config, value, POLICY_RATE_IN);
    }
    if (strcmp(key, "client_rate_limit_out") == 0) {
        return set_client_policy(config, value, POLICY_RATE_OUT);
    }
    if (strcmp(key, "client_quota") == 0) {
        return set_client_policy(config, value, POLICY_QUOTA);
    }
    if (strcmp(key, "client_quota_warn") == 0) {
        return set_client_policy(config, value, POLICY_WARN);
    }
    if (strcmp(key, "client_allow") == 0) {
        return set_client_acl(config, value, 0);
    }
    if (strcmp(key, "client_deny") == 0) {
        return set_client_acl(config, value, 1);
    }
    if (strcmp(key, "strict_source") == 0) {
        return set_bool(&config->strict_source, value);
    }
    if (strcmp(key, "client_isolation") == 0) {
        return set_bool(&config->client_isolation, value);
    }
    if (strcmp(key, "quota_period") == 0) {
        if (strcasecmp(value, "daily") == 0) {
            config->quota_period = POLICY_PERIOD_DAILY;
            return 0;
        }
        if (strcasecmp(value, "monthly") == 0) {
            config->quota_period = POLICY_PERIOD_MONTHLY;
            return 0;
        }
        if (strcasecmp(value, "weekly") == 0) {
            config->quota_period = POLICY_PERIOD_WEEKLY;
            return 0;
        }
        if (strcasecmp(value, "custom") == 0) {
            config->quota_period = 3; /* resolved after parsing */
            return 0;
        }
        return -1;
    }
    if (strcmp(key, "quota_period_days") == 0) {
        if (set_int_range(&config->quota_period_days, value, 1, 365) != 0) {
            return -1;
        }
        config->quota_period = 3; /* custom; resolved after parsing */
        return 0;
    }
    if (strcmp(key, "quota_action") == 0) {
        if (strcasecmp(value, "drop") == 0) {
            config->quota_throttle = 0;
            return 0;
        }
        if (strcasecmp(value, "throttle") == 0) {
            config->quota_throttle = 1;
            return 0;
        }
        return -1;
    }
    if (strcmp(key, "quota_grace") == 0) {
        return set_u64_range(&config->quota_grace_mib, value, 0, 1048576);
    }
    if (strcmp(key, "quota_throttle_kbps") == 0) {
        return set_u64_range(&config->quota_throttle_kbps, value, 1,
                             100000000);
    }
    if (strcmp(key, "log_level") == 0) {
        log_level_t level;

        if (config_parse_log_level(value, &level) != 0) {
            return -1;
        }
        config->log_level = level;
        return 0;
    }
    if (strcmp(key, "log_format") == 0) {
        if (strcasecmp(value, "text") == 0) {
            config->log_json = 0;
            return 0;
        }
        if (strcasecmp(value, "json") == 0) {
            config->log_json = 1;
            return 0;
        }
        return -1;
    }

    log_warn("Configuration: ignoring unknown key '%s'", key);
    return 0;
}

/*
 * Resolve an include path relative to the file that named it, so a
 * configuration tree works regardless of the daemon's working directory.
 */
static int resolve_relative(const char *base, const char *value,
                            char *out, size_t out_size)
{
    const char *slash;
    size_t dir_len;

    if (value == NULL || value[0] == '\0' || out == NULL || out_size == 0) {
        return -1;
    }

    if (value[0] == '/' || base == NULL || strchr(base, '/') == NULL) {
        return copy_string(out, out_size, value);
    }

    slash = strrchr(base, '/');
    dir_len = (size_t)(slash - base) + 1;
    if (dir_len >= out_size || strlen(value) >= out_size - dir_len) {
        return -1;
    }

    memcpy(out, base, dir_len);
    memcpy(out + dir_len, value, strlen(value) + 1);
    return 0;
}

/*
 * Split '<id> <value>' where value is the remainder of the line. Paths may
 * contain spaces, so only the id ends at whitespace.
 */
static int parse_id_and_rest(const char *value, char *id, size_t id_size,
                             char *rest, size_t rest_size)
{
    const char *p;
    const char *end;
    size_t len;

    if (value == NULL) return -1;

    p = value;
    while (isspace((unsigned char)*p)) p++;
    end = p;
    while (*end != '\0' && !isspace((unsigned char)*end)) end++;
    len = (size_t)(end - p);
    if (len == 0 || len >= id_size) return -1;

    memcpy(id, p, len);
    id[len] = '\0';
    if (!valid_client_id(id)) return -1;

    while (isspace((unsigned char)*end)) end++;
    p = end + strlen(end);
    while (p > end && isspace((unsigned char)*(p - 1))) p--;
    len = (size_t)(p - end);
    if (len == 0 || len >= rest_size) return -1;

    memcpy(rest, end, len);
    rest[len] = '\0';
    return 0;
}

/*
 * Read one secret from a key file: the first non-empty, non-comment line.
 * The path is already resolved relative to the file that named it.
 */
static int read_secret_line(const char *path, char *out, size_t out_size,
                            const char *key, const char *id)
{
    char line[CONFIG_MAX_SECRET + 2];
    FILE *fp;
    struct stat st;

    fp = fopen(path, "r");
    if (fp == NULL) {
        log_error("%s: cannot open '%s' for client '%s': %s", key, path, id,
                  strerror(errno));
        return -1;
    }

    if (stat(path, &st) == 0 &&
        (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        log_warn("%s '%s' is readable by group or other; use mode 0600",
                 key, path);
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *p;

        if (strchr(line, '\n') == NULL && !feof(fp)) {
            log_error("%s '%s': line is too long", key, path);
            fclose(fp);
            return -1;
        }

        p = str_trim(line);
        if (*p == '\0' || *p == '#') {
            continue;
        }
        if (strlen(p) >= out_size) {
            log_error("%s '%s': secret is too long", key, path);
            fclose(fp);
            return -1;
        }

        snprintf(out, out_size, "%s", p);
        fclose(fp);
        return 0;
    }

    fclose(fp);
    log_error("%s '%s' is empty", key, path);
    return -1;
}

/*
 * Add a credential whose current key lives in a separate file. The file
 * is parsed at load time, just like a client-mode 'secret_file', so a
 * missing or empty file is a configuration error rather than a server
 * that silently cannot authenticate the client.
 */
static int set_client_secret_file(pipesix_config_t *config, const char *value,
                                  const char *base)
{
    pipesix_client_cred_t *cred;
    char id[CONFIG_MAX_CLIENT_ID];
    char path[CONFIG_CLIENT_SECRET_PATH];
    char resolved[CONFIG_CLIENT_SECRET_PATH];
    char secret[CONFIG_MAX_SECRET];

    if (parse_id_and_rest(value, id, sizeof(id), path, sizeof(path)) != 0) {
        return -1;
    }
    if (config_find_client(config, id) != NULL) {
        return -1;
    }
    if (config->client_count >= CONFIG_MAX_CLIENTS) {
        return -1;
    }
    if (resolve_relative(base, path, resolved, sizeof(resolved)) != 0) {
        log_error("client_secret_file: path is too long");
        return -1;
    }
    if (read_secret_line(resolved, secret, sizeof(secret),
                         "client_secret_file", id) != 0) {
        return -1;
    }

    cred = &config->clients[config->client_count];
    memset(cred, 0, sizeof(*cred));
    snprintf(cred->id, sizeof(cred->id), "%s", id);
    snprintf(cred->secret, sizeof(cred->secret), "%s", secret);
    snprintf(cred->secret_file, sizeof(cred->secret_file), "%s", resolved);
    config->client_count++;
    return 0;
}

/*
 * Add a staged key read from a separate file. This is what --stage-key
 * writes when the current key came from client_secret_file, so a staged
 * rotation never puts the new secret in the main configuration either.
 */
static int set_client_next_file(pipesix_config_t *config, const char *value,
                                const char *base)
{
    pipesix_client_cred_t *cred;
    char id[CONFIG_MAX_CLIENT_ID];
    char path[CONFIG_CLIENT_SECRET_PATH];
    char resolved[CONFIG_CLIENT_SECRET_PATH];
    char secret[CONFIG_MAX_SECRET];

    if (parse_id_and_rest(value, id, sizeof(id), path, sizeof(path)) != 0) {
        return -1;
    }
    cred = (pipesix_client_cred_t *)config_find_client(config, id);
    if (cred == NULL || cred->has_next_secret) {
        return -1;
    }
    if (resolve_relative(base, path, resolved, sizeof(resolved)) != 0) {
        log_error("client_next_file: path is too long");
        return -1;
    }
    if (read_secret_line(resolved, secret, sizeof(secret),
                         "client_next_file", id) != 0) {
        return -1;
    }

    snprintf(cred->next_secret, sizeof(cred->next_secret), "%s", secret);
    snprintf(cred->next_file, sizeof(cred->next_file), "%s", resolved);
    cred->has_next_secret = 1;
    return 0;
}

static int config_parse_file(pipesix_config_t *config, const char *path,
                             int depth);

/*
 * Read the first non-empty, non-comment line of secret_file into the
 * configuration's secret. A file is used instead of the config line so
 * the credential can live in a 0600 file owned by the service account.
 */
static int load_secret_file(pipesix_config_t *config)
{
    char path[CONFIG_PATH_MAX];
    char line[CONFIG_MAX_SECRET];
    FILE *fp;
    struct stat st;

    if (config->secret_file[0] == '\0') {
        return 0;
    }

    if (resolve_relative(config->config_path, config->secret_file, path,
                         sizeof(path)) != 0) {
        fprintf(stderr, "config_load: secret_file path is too long\n");
        return -1;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        fprintf(stderr, "config_load: cannot open secret_file '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    if (stat(path, &st) == 0 &&
        (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        log_warn("'secret_file' %s is readable by group or other; use "
                 "mode 0600", path);
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *p = str_trim(line);

        if (*p == '\0' || *p == '#') {
            continue;
        }
        if (strlen(p) >= CONFIG_MAX_SECRET) {
            fclose(fp);
            fprintf(stderr, "config_load: secret_file '%s' line is too "
                            "long\n", path);
            return -1;
        }

        if (config->secret[0] != '\0' &&
            strcmp(config->secret, p) != 0) {
            log_warn("'secret_file' wins over the inline 'secret'");
        }
        snprintf(config->secret, sizeof(config->secret), "%s", p);
        fclose(fp);
        return 0;
    }

    fclose(fp);
    fprintf(stderr, "config_load: secret_file '%s' is empty\n", path);
    return -1;
}

static int config_parse_file(pipesix_config_t *config, const char *path,
                             int depth)
{
    FILE *fp;
    char line[4096];
    unsigned int line_num = 0;

    if (depth > CONFIG_MAX_INCLUDE_DEPTH) {
        fprintf(stderr, "config_load: include nesting exceeds %d levels\n",
                CONFIG_MAX_INCLUDE_DEPTH);
        return -1;
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

        if (strcmp(key, "include") == 0) {
            char included[CONFIG_PATH_MAX];

            if (resolve_relative(path, value, included,
                                 sizeof(included)) != 0) {
                fprintf(stderr, "config_load: %s:%u: include path is too "
                                "long\n", path, line_num);
                fclose(fp);
                return -1;
            }
            if (config_parse_file(config, included, depth + 1) != 0) {
                fclose(fp);
                return -1;
            }
            continue;
        }

        if (config_set_value(config, key, value, path) != 0) {
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

int config_load(const char *path, pipesix_config_t *config)
{
    if (config == NULL || path == NULL) {
        fprintf(stderr, "config_load: invalid parameters\n");
        return -1;
    }

    config_set_defaults(config);

    if (copy_string(config->config_path, sizeof(config->config_path),
                    path) != 0) {
        config->config_path[0] = '\0';
    }

    if (config_parse_file(config, path, 0) != 0) {
        return -1;
    }

    if (strcmp(config->mode, "client") == 0 &&
        load_secret_file(config) != 0) {
        return -1;
    }

    if (config->quota_period == 3) {
        if (config->quota_period_days <= 0) {
            fprintf(stderr, "config_load: %s: 'quota_period = custom' "
                            "needs 'quota_period_days'\n", path);
            return -1;
        }
        config->quota_period = -config->quota_period_days;
    }

    if (split_remote_endpoints(config) != 0) {
        fprintf(stderr,
                "config_load: %s: invalid 'remote_address' list (at most "
                "%d comma separated endpoints)\n", path,
                CONFIG_MAX_REMOTE_ENDPOINTS);
        return -1;
    }

    return 0;
}

/*
 * A bearer token travels in an HTTP header, so it must be printable ASCII
 * without whitespace: anything else could never match a request and would
 * silently leave the endpoint open.
 */
static int valid_metrics_token(const char *token)
{
    const unsigned char *p = (const unsigned char *)token;

    if (token[0] == '\0') {
        return 1;
    }

    for (; *p != '\0'; p++) {
        if (*p <= 0x20 || *p >= 0x7f) {
            return 0;
        }
    }

    return 1;
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

    if (config->metrics_address[0] != '\0' &&
        (config->metrics_port < 1 || config->metrics_port > 65535)) {
        log_error("Configuration validation failed: 'metrics_port' must be 1-65535 (got %d)",
                  config->metrics_port);
        return -1;
    }

    if (!valid_metrics_token(config->metrics_token)) {
        log_error("Configuration validation failed: 'metrics_token' must be "
                  "printable ASCII without spaces");
        return -1;
    }

    if (config->quota_period > POLICY_PERIOD_WEEKLY ||
        config->quota_period == 3 || config->quota_period < -365) {
        log_error("Configuration validation failed: 'quota_period' is "
                  "invalid");
        return -1;
    }

    if (config->endpoint_failback_interval < 1 ||
        config->endpoint_failback_interval > 86400) {
        log_error("Configuration validation failed: "
                  "'endpoint_failback_interval' must be 1-86400 seconds");
        return -1;
    }

    {
        int i;

        for (i = 0; i < config->policy_count; i++) {
            if (config->policies[i].warn_percent > 0 &&
                config->policies[i].quota_mib == 0) {
                log_error("Configuration validation failed: client '%s' "
                          "sets 'client_quota_warn' without a "
                          "'client_quota'", config->policies[i].id);
                return -1;
            }
        }
    }

    {
        int i;

        for (i = 0; i < config->client_count; i++) {
            if (config->clients[i].has_next_secret &&
                strlen(config->clients[i].next_secret) < 16) {
                log_warn("Client '%s' has a short staged key; generate one "
                         "with 'pipesix --genkey'", config->clients[i].id);
            }
            if (config->clients[i].has_expiry &&
                config->clients[i].expires_at <= 0) {
                log_error("Configuration validation failed: client '%s' "
                          "has an invalid expiry", config->clients[i].id);
                return -1;
            }
        }
    }

    if (config->group[0] != '\0' && config->user[0] == '\0') {
        log_error("Configuration validation failed: 'group' needs 'user'");
        return -1;
    }

#if defined(_WIN32)
    if (config->user[0] != '\0' || config->group[0] != '\0') {
        log_error("Configuration validation failed: 'user'/'group' are "
                  "only supported on POSIX");
        return -1;
    }
#endif

    if (strcmp(config->mode, "client") == 0) {
        if (strlen(config->remote_address) == 0) {
            log_error("Configuration validation failed: 'remote_address' is required in client mode");
            return -1;
        }
        if (config->remote_count < 1 ||
            config->remote_count > CONFIG_MAX_REMOTE_ENDPOINTS) {
            log_error("Configuration validation failed: "
                      "'remote_address' must name 1-%d endpoints",
                      CONFIG_MAX_REMOTE_ENDPOINTS);
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
        if (config->client_prefix_pool[0] != '\0') {
            log_error("Configuration validation failed: "
                      "'client_prefix_pool' is only valid in server mode");
            return -1;
        }
        if (config->usage_history[0] != '\0') {
            log_error("Configuration validation failed: "
                      "'usage_history' is only valid in server mode");
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
                      "'client = <id>: <secret>' or "
                      "'client_secret_file = <id> <path>' entry is required "
                      "in server mode");
            return -1;
        }
        if (config->secret[0] != '\0') {
            log_warn("Server 'secret' is ignored: each client authenticates "
                     "with its own credential from 'client = <id>: <secret>'");
        }

        if (config->client_prefix_pool[0] != '\0' &&
            (config->prefix_pool_len < 1 || config->prefix_pool_len > 64)) {
            log_error("Configuration validation failed: "
                      "'client_prefix_pool' must be an IPv6 prefix no "
                      "longer than /64");
            return -1;
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

int config_delegate_prefix(const pipesix_config_t *config, uint8_t prefix[16])
{
    struct in6_addr tun;
    uint64_t base;
    uint64_t blocks;
    uint64_t index;
    int free_bits;
    int tun_len = 0;
    int have_tun = 0;
    int i;

    if (config == NULL || prefix == NULL) return -1;
    if (config->prefix_pool_len < 1 || config->prefix_pool_len > 64) {
        return -1;
    }

    free_bits = 64 - config->prefix_pool_len;
    /*
     * At most one route per client plus the relay's own /64 can be
     * unavailable, so scanning two blocks past the client table always
     * finds a free one when the pool has it. A smaller pool is scanned
     * in full.
     */
    blocks = (free_bits >= 7)
                 ? (uint64_t)(CONFIG_MAX_CLIENTS + 2)
                 : (1ULL << (unsigned)free_bits);

    if (config->tun_prefixlen > 0 &&
        inet_pton(AF_INET6, config->tun_address, &tun) == 1) {
        have_tun = 1;
        tun_len = (config->tun_prefixlen > 64) ? 64 : config->tun_prefixlen;
    }

    base = load_be64(config->prefix_pool);

    for (index = 0; index < blocks; index++) {
        uint8_t candidate[16];
        int used = 0;

        memcpy(candidate, config->prefix_pool, sizeof(candidate));
        store_be64(candidate, base | index);
        memset(candidate + 8, 0, 8);

        for (i = 0; i < config->client_count; i++) {
            const pipesix_client_cred_t *cred = &config->clients[i];

            if (cred->prefix_len > 0 &&
                prefixes_overlap(candidate, 64, cred->prefix,
                                 cred->prefix_len)) {
                used = 1;
                break;
            }
        }

        if (used) {
            continue;
        }
        if (have_tun &&
            prefixes_overlap(candidate, 64, tun.s6_addr, tun_len)) {
            continue;
        }

        memcpy(prefix, candidate, sizeof(candidate));
        return 0;
    }

    return -1;
}

int config_format_prefix(const uint8_t addr[16], int prefix_len,
                         char *out, size_t size)
{
    char text[INET6_ADDRSTRLEN];

    if (addr == NULL || out == NULL || size == 0) {
        return -1;
    }
    if (inet_ntop(AF_INET6, addr, text, sizeof(text)) == NULL) {
        return -1;
    }
    if (snprintf(out, size, "%s/%d", text, prefix_len) >= (int)size) {
        return -1;
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

    char quota_name[24];

    policy_period_name(config->quota_period, quota_name, sizeof(quota_name));

    log_info("Configuration:");
    log_info("  mode            = %s", config->mode);
    log_info("  tun_name        = %s", config->tun_name);
    log_info("  tun_address     = %s/%d", config->tun_address,
             config->tun_prefixlen);
    log_info("  tun_mtu         = %d", config->tun_mtu);

    if (strcmp(config->mode, "client") == 0) {
        int i;

        log_info("  remote_address  = %s", config->remote_address);
        for (i = 0; i < config->remote_count; i++) {
            log_info("    endpoint %d: %s", i + 1,
                     config->remote_endpoints[i]);
        }
        log_info("  remote_port     = %d", config->remote_port);
        log_info("  endpoint_failback = %s (%d s)",
                 config->endpoint_failback ? "on" : "off",
                 config->endpoint_failback_interval);
    }

    if (strcmp(config->mode, "server") == 0) {
        log_info("  bind_address    = %s", config->bind_address);
        log_info("  bind_port       = %d", config->bind_port);
        log_info("  allow_client    = %d configured",
                 config->allow_client_count);
    }

    log_info("  secret          = %s",
             (config->secret[0] != '\0') ? "(set)" : "(not set)");
    if (config->secret_file[0] != '\0') {
        log_info("  secret_file     = %s", config->secret_file);
    }
    if (config->user[0] != '\0') {
        log_info("  user            = %s", config->user);
    }
    if (config->group[0] != '\0') {
        log_info("  group           = %s", config->group);
    }
    log_info("  client_id       = %s",
             (config->client_id[0] != '\0') ? config->client_id : "(not set)");

    if (strcmp(config->mode, "server") == 0) {
        int i;

        log_info("  clients         = %d configured", config->client_count);
        for (i = 0; i < config->client_count; i++) {
            char prefix_str[INET6_ADDRSTRLEN];

            if (config->clients[i].secret_file[0] != '\0') {
                log_info("      key file: %s",
                         config->clients[i].secret_file);
            }
            if (config->clients[i].next_file[0] != '\0') {
                log_info("      staged file: %s",
                         config->clients[i].next_file);
            }

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
            if (config->clients[i].allow_count > 0 ||
                config->clients[i].deny_count > 0) {
                log_info("      acl: %d allow, %d deny",
                         config->clients[i].allow_count,
                         config->clients[i].deny_count);
            }
            if (config->clients[i].has_next_secret) {
                log_info("      staged key: yes");
            }
            if (config->clients[i].disabled) {
                log_info("      state: disabled");
            }
            if (config->clients[i].has_expiry) {
                log_info("      expires: %lld",
                         (long long)config->clients[i].expires_at);
            }
        }

        log_info("  strict_source   = %s",
                 config->strict_source ? "on" : "off");
        log_info("  client_isolation = %s",
                 config->client_isolation ? "on" : "off");
        log_info("  quota_period    = %s", quota_name);
        log_info("  quota_action    = %s (grace %llu MiB, throttle %llu "
                 "kbit/s)",
                 config->quota_throttle ? "throttle" : "drop",
                 (unsigned long long)config->quota_grace_mib,
                 (unsigned long long)config->quota_throttle_kbps);

        for (i = 0; i < config->policy_count; i++) {
            char warn[48];

            if (config->policies[i].warn_percent > 0) {
                snprintf(warn, sizeof(warn), ", warn at %llu%%",
                         (unsigned long long)config->policies[i]
                             .warn_percent);
            } else {
                warn[0] = '\0';
            }

            log_info("    limits: %s rate in %llu / out %llu kbit/s, "
                     "quota %llu MiB/%s%s",
                     config->policies[i].id,
                     (unsigned long long)pipesix_policy_rate_in(
                         &config->policies[i]),
                     (unsigned long long)pipesix_policy_rate_out(
                         &config->policies[i]),
                     (unsigned long long)config->policies[i].quota_mib,
                     quota_name, warn);
        }
    }
    log_info("  keepalive       = %d s", config->keepalive);
    log_info("  peer_timeout    = %d s", config->peer_timeout);
    log_info("  session_timeout = %d s", config->session_timeout);
    log_info("  stats_interval  = %d s", config->stats_interval);
    if (config->metrics_address[0] != '\0') {
        log_info("  metrics         = %s:%d (%s)", config->metrics_address,
                 config->metrics_port,
                 config->metrics_token[0] != '\0' ? "token required"
                                                  : "no authentication");
    } else {
        log_info("  metrics         = disabled");
    }
    log_info("  audit_log       = %s",
             config->audit_log[0] != '\0' ? config->audit_log : "disabled");
    if (strcmp(config->mode, "server") == 0) {
        if (config->quota_state[0] != '\0') {
            log_info("  quota_state     = %s", config->quota_state);
        } else {
            log_info("  quota_state     = disabled");
        }
        if (config->usage_history[0] != '\0') {
            log_info("  usage_history   = %s", config->usage_history);
        }
        if (config->client_prefix_pool[0] != '\0') {
            log_info("  client_prefix_pool = %s",
                     config->client_prefix_pool);
        }
    }
    log_info("  log_level       = %s", level_str);
    log_info("  log_format      = %s", config->log_json ? "json" : "text");
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
    config->log_json        = fresh.log_json;
    config->keepalive       = fresh.keepalive;
    config->peer_timeout    = fresh.peer_timeout;
    config->session_timeout = fresh.session_timeout;
    config->stats_interval  = fresh.stats_interval;
    config->endpoint_failback = fresh.endpoint_failback;
    config->endpoint_failback_interval = fresh.endpoint_failback_interval;
    copy_string(config->audit_log, sizeof(config->audit_log),
                fresh.audit_log);

    /*
     * In server mode the credential table is reloadable too: this is how
     * an operator rotates a client's key without restarting the relay.
     * The caller (the server) decides which live sessions that affects.
     */
    if (strcmp(config->mode, "server") == 0) {
        config->client_count = fresh.client_count;
        memcpy(config->clients, fresh.clients, sizeof(config->clients));

        /*
         * Limits are reloadable too, so a cap can be raised, lowered or
         * lifted on a live tunnel. The server re-indexes its accounting
         * and buckets from the new table.
         */
        config->policy_count = fresh.policy_count;
        memcpy(config->policies, fresh.policies, sizeof(config->policies));

        config->strict_source = fresh.strict_source;
        config->client_isolation = fresh.client_isolation;
        config->quota_throttle = fresh.quota_throttle;
        config->quota_grace_mib = fresh.quota_grace_mib;
        config->quota_throttle_kbps = fresh.quota_throttle_kbps;
        config->quota_period = fresh.quota_period;
        config->quota_period_days = fresh.quota_period_days;

        config->allow_client_count = fresh.allow_client_count;
        memcpy(config->allow_client, fresh.allow_client,
               sizeof(config->allow_client));

        copy_string(config->quota_state, sizeof(config->quota_state),
                    fresh.quota_state);
        copy_string(config->usage_history, sizeof(config->usage_history),
                    fresh.usage_history);
    } else {
        /*
         * A client's own identity and key are reloadable as well; the
         * caller compares them and re-handshakes when they changed, which
         * is how a client rotates its key without a restart.
         */
        memcpy(config->client_id, fresh.client_id, sizeof(config->client_id));
        memcpy(config->secret, fresh.secret, sizeof(config->secret));

        copy_string(config->remote_address, sizeof(config->remote_address),
                    fresh.remote_address);
        config->remote_count = fresh.remote_count;
        memcpy(config->remote_endpoints, fresh.remote_endpoints,
               sizeof(config->remote_endpoints));
        config->remote_port = fresh.remote_port;
    }

    copy_string(config->metrics_address, sizeof(config->metrics_address),
                fresh.metrics_address);
    config->metrics_port = fresh.metrics_port;
    copy_string(config->metrics_token, sizeof(config->metrics_token),
                fresh.metrics_token);

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

        /* A full rotation retires any staged replacement key. */
        if ((key_len == 11u && memcmp(key, "client_next", 11) == 0) ||
            (key_len == 16u && memcmp(key, "client_next_file", 16) == 0)) {
            continue;
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
    char old_secrets[CONFIG_MAX_CLIENTS][CONFIG_MAX_SECRET];
    int written[CONFIG_MAX_CLIENTS] = { 0 };
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

        snprintf(old_secrets[i], sizeof(old_secrets[i]), "%s",
                 config->clients[i].secret);
        pipesix_hex_encode(key, sizeof(key),
                           new_keys + ((size_t)i * ROTATE_KEY_STRIDE));
    }

    memset(key, 0, sizeof(key));

    /*
     * File-backed credentials have no 'client' line to rewrite. Write
     * their key files first, then rewrite the configuration; if the
     * rewrite fails, restore every file before returning so the server is
     * never left half-rotated.
     */
    for (i = 0; i < config->client_count; i++) {
        const pipesix_client_cred_t *cred = &config->clients[i];

        if (cred->secret_file[0] == '\0') {
            continue;
        }
        if (write_secret_file(cred->secret_file,
                              new_keys + ((size_t)i * ROTATE_KEY_STRIDE)) !=
            0) {
            log_error("--rotate-all: cannot write key file '%s': %s",
                      cred->secret_file, strerror(errno));
            goto restore;
        }
        written[i] = 1;
    }

    if (rewrite_client_keys(config->config_path, config, new_keys) != 0) {
        log_error("--rotate-all: cannot rewrite '%s'; the existing keys "
                  "are unchanged", config->config_path);
        goto restore;
    }

    /* The caller prints these, so the new keys can be handed out. */
    for (i = 0; i < config->client_count; i++) {
        char staged[CONFIG_CLIENT_SECRET_PATH];

        snprintf(staged, sizeof(staged), "%s", config->clients[i].next_file);
        memcpy(config->clients[i].secret,
               new_keys + ((size_t)i * ROTATE_KEY_STRIDE),
               ROTATE_KEY_STRIDE);
        memset(config->clients[i].next_secret, 0,
               sizeof(config->clients[i].next_secret));
        memset(config->clients[i].next_file, 0,
               sizeof(config->clients[i].next_file));
        config->clients[i].has_next_secret = 0;
        if (staged[0] != '\0') {
            (void)unlink(staged);
        }
    }

    return 0;

restore:
    for (i = 0; i < config->client_count; i++) {
        if (written[i] &&
            write_secret_file(config->clients[i].secret_file,
                              old_secrets[i]) != 0) {
            log_error("--rotate-all: cannot restore key file '%s': %s",
                      config->clients[i].secret_file, strerror(errno));
        }
    }
    return -1;
}

/*
 * Does this configuration line define, route or limit 'id'?
 *
 * Matches 'client = <id>: <secret>', 'client_route = <id> <prefix>',
 * 'client_rate_limit = <id> <kbit/s>' and 'client_quota = <id> <MiB>'.
 * The same conservative parser as the rest of the file: the key token is
 * read up to '=' or whitespace, and the id up to ':' or whitespace.
 */
static int line_names_client(const char *line, const char *id,
                             int limits_only)
{
    const char *p = line;
    const char *eq;
    const char *start;
    const char *end;
    size_t key_len = 0;
    size_t id_len = strlen(id);
    int is_client;
    int is_route;
    int is_limit;

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

    is_client = key_len == 6u && memcmp(p, "client", 6) == 0;
    is_route = key_len == 12u && memcmp(p, "client_route", 12) == 0;
    is_limit = (key_len == 12u && memcmp(p, "client_allow", 12) == 0) ||
               (key_len == 11u && memcmp(p, "client_deny", 11) == 0) ||
               (key_len == 12u && memcmp(p, "client_quota", 12) == 0) ||
               (key_len == 17u &&
                memcmp(p, "client_rate_limit", 17) == 0) ||
               (key_len == 20u &&
                memcmp(p, "client_rate_limit_in", 20) == 0) ||
               (key_len == 21u &&
                memcmp(p, "client_rate_limit_out", 21) == 0) ||
               (key_len == 17u &&
                memcmp(p, "client_quota_warn", 17) == 0);

    if ((!is_client && !is_route && !is_limit) ||
        (limits_only && !is_limit)) {
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
 * Match one exact key and client id. Unlike line_names_client() this can
 * identify auxiliary lines such as 'client_next' whose value does not use
 * the same separator convention as the main client table.
 */
static int line_is_key_for(const char *line, const char *key,
                           const char *id)
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
    if (key_len != strlen(key) || memcmp(p, key, key_len) != 0) {
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

static int line_is_aux_for(const char *line, const char *id)
{
    return line_is_key_for(line, "client_secret_file", id) ||
           line_is_key_for(line, "client_next", id) ||
           line_is_key_for(line, "client_next_file", id) ||
           line_is_key_for(line, "client_disabled", id) ||
           line_is_key_for(line, "client_expires", id);
}

static int line_belongs_to_client(const char *line, const char *id)
{
    return line_names_client(line, id, 0) || line_is_aux_for(line, id);
}

static int line_is_limit_for(const char *line, const char *id)
{
    return line_names_client(line, id, 1);
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
                      const char *prefix,
                      const pipesix_client_policy_t *limits,
                      char *secret_out, size_t secret_size)
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

    if (limits != NULL) {
        if (limits->rate_kbps > 0) {
            if (snprintf(line, sizeof(line),
                         "client_rate_limit = %s %llu\n", id,
                         (unsigned long long)limits->rate_kbps) >=
                (int)sizeof(line)) {
                goto cleanup;
            }
            if (fputs(line, out) == EOF) {
                goto cleanup;
            }
        }

        if (limits->rate_in_set) {
            if (snprintf(line, sizeof(line),
                         "client_rate_limit_in = %s %llu\n", id,
                         (unsigned long long)limits->rate_in_kbps) >=
                (int)sizeof(line)) {
                goto cleanup;
            }
            if (fputs(line, out) == EOF) {
                goto cleanup;
            }
        }

        if (limits->rate_out_set) {
            if (snprintf(line, sizeof(line),
                         "client_rate_limit_out = %s %llu\n", id,
                         (unsigned long long)limits->rate_out_kbps) >=
                (int)sizeof(line)) {
                goto cleanup;
            }
            if (fputs(line, out) == EOF) {
                goto cleanup;
            }
        }

        if (limits->quota_mib > 0) {
            if (snprintf(line, sizeof(line),
                         "client_quota = %s %llu\n", id,
                         (unsigned long long)limits->quota_mib) >=
                (int)sizeof(line)) {
                goto cleanup;
            }
            if (fputs(line, out) == EOF) {
                goto cleanup;
            }
        }

        if (limits->warn_percent > 0) {
            if (snprintf(line, sizeof(line),
                         "client_quota_warn = %s %llu\n", id,
                         (unsigned long long)limits->warn_percent) >=
                (int)sizeof(line)) {
                goto cleanup;
            }
            if (fputs(line, out) == EOF) {
                goto cleanup;
            }
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

        if (limits != NULL &&
            (limits->rate_kbps > 0 || limits->rate_in_set ||
             limits->rate_out_set || limits->quota_mib > 0 ||
             limits->warn_percent > 0)) {
            const pipesix_client_policy_t *policy =
                config_find_policy(&check, id);

            if (policy == NULL ||
                policy->rate_kbps != limits->rate_kbps ||
                policy->rate_in_set != limits->rate_in_set ||
                policy->rate_in_kbps != limits->rate_in_kbps ||
                policy->rate_out_set != limits->rate_out_set ||
                policy->rate_out_kbps != limits->rate_out_kbps ||
                policy->quota_mib != limits->quota_mib ||
                policy->warn_percent != limits->warn_percent) {
                log_error("the limits for client '%s' were not accepted; "
                          "'%s' is unchanged", id, config->config_path);
                goto cleanup;
            }
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

/*
 * Replace one client's limit lines and reload the result.
 *
 * 'append' holds the replacement lines, or NULL to remove every limit for
 * the client. Every other line is copied through unchanged, and the
 * rewritten file is parsed and validated before it replaces the original.
 */
static int rewrite_limits(pipesix_config_t *config, const char *id,
                          const char *append)
{
    char path[CONFIG_PATH_MAX];
    char tmp_path[CONFIG_PATH_MAX + 32];
    char buf[4096];
    FILE *in = NULL;
    FILE *out = NULL;
    int last = '\n';
    int rc = -1;

    /*
     * config_load() clears the destination before parsing, so it must
     * never receive its own config->config_path buffer as the path.
     */
    snprintf(path, sizeof(path), "%s", config->config_path);

    in = fopen(path, "r");
    if (in == NULL) {
        return -1;
    }

    if (open_replacement(path, tmp_path, sizeof(tmp_path), &out) != 0) {
        fclose(in);
        return -1;
    }

    while (fgets(buf, sizeof(buf), in) != NULL) {
        if (line_is_limit_for(buf, id)) {
            continue;
        }
        if (fputs(buf, out) == EOF) {
            goto cleanup;
        }
        last = buf[strlen(buf) - 1];
    }

    if (ferror(in)) {
        goto cleanup;
    }

    if (append != NULL) {
        if (last != '\n' && fputc('\n', out) == EOF) {
            goto cleanup;
        }
        if (fputs(append, out) == EOF) {
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

    {
        pipesix_config_t check;

        if (config_load(tmp_path, &check) != 0 ||
            config_validate(&check) != 0) {
            log_error("the rewritten configuration is invalid; '%s' is "
                      "unchanged", config->config_path);
            goto cleanup;
        }

        if (append == NULL) {
            if (config_find_policy(&check, id) != NULL) {
                log_error("the limits for client '%s' were not removed; "
                          "'%s' is unchanged", id, config->config_path);
                goto cleanup;
            }
        } else if (append[0] != '\0' &&
                   config_find_policy(&check, id) == NULL) {
            log_error("the rewritten configuration has no limits for "
                      "client '%s'; '%s' is unchanged", id,
                      config->config_path);
            goto cleanup;
        }
    }

    if (rename(tmp_path, path) != 0) {
        log_error("cannot replace '%s': %s", path, strerror(errno));
        goto cleanup;
    }

    if (config_load(path, config) != 0) {
        log_error("cannot reload '%s' after the rewrite", path);
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

int config_set_limits(pipesix_config_t *config, const char *id,
                      const uint64_t *rate_kbps,
                      const uint64_t *rate_in_kbps,
                      const uint64_t *rate_out_kbps,
                      const uint64_t *quota_mib,
                      const uint64_t *warn_percent)
{
    const pipesix_client_policy_t *current;
    char append[768];
    size_t used = 0;
    uint64_t rate;
    uint64_t rate_in;
    uint64_t rate_out;
    uint64_t quota;
    uint64_t warn;
    int have_in;
    int have_out;

    if (config == NULL || id == NULL || config->config_path[0] == '\0') {
        return -1;
    }

    if (strcmp(config->mode, "server") != 0) {
        log_error("limits can only be set on a server configuration");
        return -1;
    }

    if (config_find_client(config, id) == NULL) {
        log_error("client '%s' is not configured in '%s'", id,
                  config->config_path);
        return -1;
    }

    if (rate_kbps == NULL && rate_in_kbps == NULL &&
        rate_out_kbps == NULL && quota_mib == NULL && warn_percent == NULL) {
        log_error("--set-limit needs --rate, --rate-in, --rate-out, "
                  "--quota or --quota-warn");
        return -1;
    }

    if (rate_kbps != NULL && *rate_kbps > 100000000u) {
        log_error("--rate: '%llu' kbit/s is too large",
                  (unsigned long long)*rate_kbps);
        return -1;
    }
    if (rate_in_kbps != NULL && *rate_in_kbps > 100000000u) {
        log_error("--rate-in: '%llu' kbit/s is too large",
                  (unsigned long long)*rate_in_kbps);
        return -1;
    }
    if (rate_out_kbps != NULL && *rate_out_kbps > 100000000u) {
        log_error("--rate-out: '%llu' kbit/s is too large",
                  (unsigned long long)*rate_out_kbps);
        return -1;
    }

    if (quota_mib != NULL && *quota_mib > 1048576u) {
        log_error("--quota: '%llu' MiB is too large",
                  (unsigned long long)*quota_mib);
        return -1;
    }

    if (warn_percent != NULL && *warn_percent > 99u) {
        log_error("--quota-warn: '%llu'%% is not between 0 and 99",
                  (unsigned long long)*warn_percent);
        return -1;
    }

    /* Unspecified limits keep whatever the file already has. */
    current = config_find_policy(config, id);
    rate = (rate_kbps != NULL) ? *rate_kbps
                               : (current != NULL ? current->rate_kbps : 0);
    quota = (quota_mib != NULL) ? *quota_mib
                                : (current != NULL ? current->quota_mib : 0);
    warn = (warn_percent != NULL)
               ? *warn_percent
               : (current != NULL ? current->warn_percent : 0);

    have_in = rate_in_kbps != NULL ||
              (current != NULL && current->rate_in_set);
    rate_in = (rate_in_kbps != NULL)
                  ? *rate_in_kbps
                  : (current != NULL ? current->rate_in_kbps : 0);
    have_out = rate_out_kbps != NULL ||
               (current != NULL && current->rate_out_set);
    rate_out = (rate_out_kbps != NULL)
                   ? *rate_out_kbps
                   : (current != NULL ? current->rate_out_kbps : 0);

    if (warn > 0 && quota == 0) {
        log_error("--quota-warn needs a quota: set --quota first");
        return -1;
    }

    append[0] = '\0';

    if (rate > 0) {
        int n = snprintf(append + used, sizeof(append) - used,
                         "client_rate_limit = %s %llu\n", id,
                         (unsigned long long)rate);

        if (n < 0 || (size_t)n >= sizeof(append) - used) {
            return -1;
        }
        used += (size_t)n;
    }

    /* An explicit 0 overrides the shared rate in that direction. */
    if (have_in) {
        int n = snprintf(append + used, sizeof(append) - used,
                         "client_rate_limit_in = %s %llu\n", id,
                         (unsigned long long)rate_in);

        if (n < 0 || (size_t)n >= sizeof(append) - used) {
            return -1;
        }
        used += (size_t)n;
    }

    if (have_out) {
        int n = snprintf(append + used, sizeof(append) - used,
                         "client_rate_limit_out = %s %llu\n", id,
                         (unsigned long long)rate_out);

        if (n < 0 || (size_t)n >= sizeof(append) - used) {
            return -1;
        }
        used += (size_t)n;
    }

    if (quota > 0) {
        int n = snprintf(append + used, sizeof(append) - used,
                         "client_quota = %s %llu\n", id,
                         (unsigned long long)quota);

        if (n < 0 || (size_t)n >= sizeof(append) - used) {
            return -1;
        }
        used += (size_t)n;
    }

    if (warn > 0) {
        int n = snprintf(append + used, sizeof(append) - used,
                         "client_quota_warn = %s %llu\n", id,
                         (unsigned long long)warn);

        if (n < 0 || (size_t)n >= sizeof(append) - used) {
            return -1;
        }
        used += (size_t)n;
    }

    return rewrite_limits(config, id, append);
}

int config_clear_limits(pipesix_config_t *config, const char *id)
{
    if (config == NULL || id == NULL || config->config_path[0] == '\0') {
        return -1;
    }

    if (strcmp(config->mode, "server") != 0) {
        log_error("limits can only be cleared on a server configuration");
        return -1;
    }

    if (config_find_client(config, id) == NULL) {
        log_error("client '%s' is not configured in '%s'", id,
                  config->config_path);
        return -1;
    }

    if (config_find_policy(config, id) == NULL) {
        log_error("client '%s' has no limits configured", id);
        return -1;
    }

    return rewrite_limits(config, id, NULL);
}

/*
 * Remove one auxiliary client line and optionally append its replacement.
 * The caller verifies the resulting in-memory state after the reload.
 */
static int rewrite_client_aux_keys(pipesix_config_t *config, const char *id,
                                   const char *const *keys, int key_count,
                                   const char *append)
{
    char path[CONFIG_PATH_MAX];
    char tmp_path[CONFIG_PATH_MAX + 32];
    char buf[4096];
    FILE *in = NULL;
    FILE *out = NULL;
    int last = '\n';
    int rc = -1;
    int i;

    snprintf(path, sizeof(path), "%s", config->config_path);
    in = fopen(path, "r");
    if (in == NULL) {
        return -1;
    }
    if (open_replacement(path, tmp_path, sizeof(tmp_path), &out) != 0) {
        fclose(in);
        return -1;
    }

    while (fgets(buf, sizeof(buf), in) != NULL) {
        int remove = 0;

        for (i = 0; i < key_count; i++) {
            if (line_is_key_for(buf, keys[i], id)) {
                remove = 1;
                break;
            }
        }
        if (remove) {
            last = buf[strlen(buf) - 1];
            continue;
        }
        if (fputs(buf, out) == EOF) {
            goto cleanup;
        }
        last = buf[strlen(buf) - 1];
    }

    if (ferror(in)) {
        goto cleanup;
    }
    if (append != NULL) {
        if (last != '\n' && fputc('\n', out) == EOF) {
            goto cleanup;
        }
        if (fputs(append, out) == EOF) {
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

    {
        pipesix_config_t check;

        if (config_load(tmp_path, &check) != 0 ||
            config_validate(&check) != 0) {
            log_error("the rewritten configuration is invalid; '%s' is "
                      "unchanged", config->config_path);
            goto cleanup;
        }
    }

    if (rename(tmp_path, path) != 0) {
        log_error("cannot replace '%s': %s", path, strerror(errno));
        goto cleanup;
    }
    if (config_load(path, config) != 0) {
        log_error("cannot reload '%s' after the rewrite", path);
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

static int rewrite_client_aux(pipesix_config_t *config, const char *id,
                              const char *key, const char *append)
{
    const char *keys[1];

    keys[0] = key;
    return rewrite_client_aux_keys(config, id, keys, 1, append);
}

int config_stage_key(pipesix_config_t *config, const char *id,
                     char *secret_out, size_t secret_size)
{
    const pipesix_client_cred_t *cred;
    char key_hex[ROTATE_KEY_STRIDE];
    char line[CONFIG_MAX_CLIENT_ID + CONFIG_CLIENT_SECRET_PATH + 40];
    char next_path[CONFIG_CLIENT_SECRET_PATH + 8];
    uint8_t key[PIPESIX_KEY_LEN];
    int file_backed = 0;

    if (config == NULL || id == NULL || config->config_path[0] == '\0') {
        return -1;
    }
    if (strcmp(config->mode, "server") != 0) {
        log_error("keys can only be staged on a server configuration");
        return -1;
    }
    cred = config_find_client(config, id);
    if (cred == NULL) {
        log_error("client '%s' is not configured in '%s'", id,
                  config->config_path);
        return -1;
    }
    if (cred->has_next_secret) {
        log_error("client '%s' already has a staged key; promote or abort "
                  "it first", id);
        return -1;
    }
    if (pipesix_random_bytes(key, sizeof(key)) != 0) {
        log_error("cannot read random bytes: %s", strerror(errno));
        return -1;
    }
    pipesix_hex_encode(key, sizeof(key), key_hex);
    memset(key, 0, sizeof(key));

    file_backed = cred->secret_file[0] != '\0';
    if (file_backed) {
        if (snprintf(next_path, sizeof(next_path), "%s.next",
                     cred->secret_file) >= (int)sizeof(next_path)) {
            return -1;
        }
        if (write_secret_file(next_path, key_hex) != 0) {
            log_error("cannot write the staged key file '%s': %s",
                      next_path, strerror(errno));
            return -1;
        }
        if (snprintf(line, sizeof(line), "client_next_file = %s %s\n", id,
                     next_path) >= (int)sizeof(line)) {
            unlink(next_path);
            return -1;
        }
    } else if (snprintf(line, sizeof(line), "client_next = %s: %s\n", id,
                        key_hex) >= (int)sizeof(line)) {
        return -1;
    }

    if (rewrite_client_aux(config, id,
                           file_backed ? "client_next_file"
                                       : "client_next", line) != 0) {
        if (file_backed) {
            unlink(next_path);
        }
        return -1;
    }

    cred = config_find_client(config, id);
    if (cred == NULL || !cred->has_next_secret ||
        strcmp(cred->next_secret, key_hex) != 0 ||
        (file_backed && strcmp(cred->next_file, next_path) != 0)) {
        log_error("the staged key for client '%s' was not accepted", id);
        if (file_backed) {
            unlink(next_path);
        }
        return -1;
    }
    if (secret_out != NULL && secret_size > 0) {
        snprintf(secret_out, secret_size, "%s", key_hex);
    }
    return 0;
}

int config_abort_key(pipesix_config_t *config, const char *id)
{
    static const char *const keys[] = { "client_next", "client_next_file" };
    const pipesix_client_cred_t *cred;
    char next_file[CONFIG_CLIENT_SECRET_PATH];

    if (config == NULL || id == NULL || config->config_path[0] == '\0') {
        return -1;
    }
    cred = config_find_client(config, id);
    if (cred == NULL || !cred->has_next_secret) {
        log_error("client '%s' has no staged key", id);
        return -1;
    }
    snprintf(next_file, sizeof(next_file), "%s", cred->next_file);
    if (rewrite_client_aux_keys(config, id, keys, 2, NULL) != 0) {
        return -1;
    }
    cred = config_find_client(config, id);
    if (cred == NULL || cred->has_next_secret) {
        log_error("the staged key for client '%s' was not removed", id);
        return -1;
    }
    if (next_file[0] != '\0') {
        (void)unlink(next_file);
    }
    return 0;
}

int config_promote_key(pipesix_config_t *config, const char *id)
{
    static const char *const next_keys[] = {
        "client_next", "client_next_file"
    };
    const pipesix_client_cred_t *cred;
    char path[CONFIG_PATH_MAX];
    char tmp_path[CONFIG_PATH_MAX + 32];
    char buf[4096];
    char line[CONFIG_MAX_CLIENT_ID + CONFIG_MAX_SECRET + 32];
    char new_secret[CONFIG_MAX_SECRET];
    char old_secret[CONFIG_MAX_SECRET];
    char current_file[CONFIG_CLIENT_SECRET_PATH];
    char next_file[CONFIG_CLIENT_SECRET_PATH];
    FILE *in = NULL;
    FILE *out = NULL;
    int found = 0;
    int rc = -1;

    if (config == NULL || id == NULL || config->config_path[0] == '\0') {
        return -1;
    }
    cred = config_find_client(config, id);
    if (cred == NULL || !cred->has_next_secret) {
        log_error("client '%s' has no staged key to promote", id);
        return -1;
    }
    snprintf(new_secret, sizeof(new_secret), "%s", cred->next_secret);
    snprintf(old_secret, sizeof(old_secret), "%s", cred->secret);
    snprintf(current_file, sizeof(current_file), "%s", cred->secret_file);
    snprintf(next_file, sizeof(next_file), "%s", cred->next_file);

    /*
     * A file-backed key has no 'client' line to rewrite. Put the staged
     * secret into the current key file first, then remove the staged line
     * from the configuration. If the second step fails, both the new
     * current key and the staged line still authenticate the client, so a
     * retry is safe.
     */
    if (current_file[0] != '\0') {
        if (write_secret_file(current_file, new_secret) != 0) {
            log_error("cannot update the key file '%s': %s", current_file,
                      strerror(errno));
            return -1;
        }
        if (rewrite_client_aux_keys(config, id, next_keys, 2, NULL) != 0) {
            /* The config was not replaced; undo the key file change. */
            if (write_secret_file(current_file, old_secret) != 0) {
                log_error("cannot restore key file '%s': %s", current_file,
                          strerror(errno));
            }
            return -1;
        }
        cred = config_find_client(config, id);
        if (cred == NULL || cred->has_next_secret ||
            strcmp(cred->secret, new_secret) != 0) {
            log_error("the promoted key for client '%s' was not accepted",
                      id);
            return -1;
        }
        if (next_file[0] != '\0') {
            (void)unlink(next_file);
        }
        return 0;
    }

    snprintf(path, sizeof(path), "%s", config->config_path);

    in = fopen(path, "r");
    if (in == NULL) {
        return -1;
    }
    if (open_replacement(path, tmp_path, sizeof(tmp_path), &out) != 0) {
        fclose(in);
        return -1;
    }

    while (fgets(buf, sizeof(buf), in) != NULL) {
        if (line_is_key_for(buf, "client", id)) {
            if (snprintf(line, sizeof(line), "client = %s: %s\n", id,
                         new_secret) >= (int)sizeof(line)) {
                goto cleanup;
            }
            if (fputs(line, out) == EOF) {
                goto cleanup;
            }
            found = 1;
            continue;
        }
        if (line_is_key_for(buf, "client_next", id) ||
            line_is_key_for(buf, "client_next_file", id)) {
            continue;
        }
        if (fputs(buf, out) == EOF) {
            goto cleanup;
        }
    }

    if (ferror(in) || !found) {
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
            config_validate(&check) != 0) {
            log_error("the promoted configuration is invalid; '%s' is "
                      "unchanged", config->config_path);
            goto cleanup;
        }
        cred = config_find_client(&check, id);
        if (cred == NULL || strcmp(cred->secret, new_secret) != 0 ||
            cred->has_next_secret) {
            log_error("the promoted key for client '%s' was not accepted",
                      id);
            goto cleanup;
        }
    }

    if (rename(tmp_path, path) != 0) {
        log_error("cannot replace '%s': %s", path, strerror(errno));
        goto cleanup;
    }
    if (config_load(path, config) != 0) {
        log_error("cannot reload '%s' after the rewrite", path);
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

int config_set_client_disabled(pipesix_config_t *config, const char *id,
                               int disabled)
{
    const pipesix_client_cred_t *cred;
    char line[CONFIG_MAX_CLIENT_ID + 32];

    if (config == NULL || id == NULL || config->config_path[0] == '\0') {
        return -1;
    }
    cred = config_find_client(config, id);
    if (cred == NULL) {
        log_error("client '%s' is not configured in '%s'", id,
                  config->config_path);
        return -1;
    }
    if (cred->disabled == (disabled != 0)) {
        return 0;
    }

    if (disabled) {
        if (snprintf(line, sizeof(line), "client_disabled = %s\n", id) >=
            (int)sizeof(line)) {
            return -1;
        }
        if (rewrite_client_aux(config, id, "client_disabled", line) != 0) {
            return -1;
        }
    } else if (rewrite_client_aux(config, id, "client_disabled", NULL) != 0) {
        return -1;
    }

    cred = config_find_client(config, id);
    if (cred == NULL || cred->disabled != (disabled != 0)) {
        log_error("the state for client '%s' was not updated", id);
        return -1;
    }
    return 0;
}

int config_set_client_expiry(pipesix_config_t *config, const char *id,
                             const char *when)
{
    const pipesix_client_cred_t *cred;
    char line[CONFIG_MAX_CLIENT_ID + 64];
    int64_t expires;

    if (config == NULL || id == NULL || config->config_path[0] == '\0') {
        return -1;
    }
    cred = config_find_client(config, id);
    if (cred == NULL) {
        log_error("client '%s' is not configured in '%s'", id,
                  config->config_path);
        return -1;
    }

    if (when == NULL || strcasecmp(when, "never") == 0) {
        if (!cred->has_expiry) {
            return 0;
        }
        if (rewrite_client_aux(config, id, "client_expires", NULL) != 0) {
            return -1;
        }
        cred = config_find_client(config, id);
        if (cred == NULL || cred->has_expiry) {
            log_error("the expiry for client '%s' was not cleared", id);
            return -1;
        }
        return 0;
    }

    if (parse_expiry_value(when, &expires) != 0) {
        log_error("expiry must be YYYY-MM-DD or a Unix timestamp");
        return -1;
    }
    if (snprintf(line, sizeof(line), "client_expires = %s %s\n", id,
                 when) >= (int)sizeof(line)) {
        return -1;
    }
    if (rewrite_client_aux(config, id, "client_expires", line) != 0) {
        return -1;
    }
    cred = config_find_client(config, id);
    if (cred == NULL || !cred->has_expiry || cred->expires_at != expires) {
        log_error("the expiry for client '%s' was not accepted", id);
        return -1;
    }
    return 0;
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
