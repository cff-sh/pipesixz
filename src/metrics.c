/*
 * metrics.c - Prometheus Metrics Endpoint
 *
 * Serves GET /metrics over TCP on the configured address, plus GET
 * /healthz for a liveness probe. One request per connection with a short
 * receive timeout and a bounded request buffer, so a stuck or hostile
 * client cannot park the thread.
 *
 * Nothing here changes state, but the body exposes client ids and traffic
 * counters, so 'metrics_token' can require 'Authorization: Bearer <token>'
 * on /metrics. /healthz is deliberately never authenticated: a probe
 * should not have to hold the scrape secret.
 */

#include "metrics.h"
#include "logger.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)

/*
 * Windows has no endpoint: the tunnel is a client there, and the named
 * events in control.c already cover reload and statistics.
 */
int metrics_start(const pipesix_config_t *config, metrics_body_fn body,
                  void *arg)
{
    (void)config;
    (void)body;
    (void)arg;
    return 0;
}

void metrics_stop(void)
{
}

int metrics_running(void)
{
    return 0;
}

#else

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define METRICS_POLL_MS     500
#define METRICS_TIMEOUT_SEC 5
#define METRICS_BODY_MAX    65536u
#define METRICS_REQUEST_MAX 1024u

static int            s_listen_fd = -1;
static pthread_t      s_thread;
static atomic_int     s_stopping;
static int            s_started;
static metrics_body_fn s_body;
static void           *s_body_arg;
static char           s_token[CONFIG_MAX_SECRET];

static void metrics_write_all(int fd, const char *buf, size_t len)
{
    size_t written = 0;

    while (written < len) {
        ssize_t n = write(fd, buf + written, len - written);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (n == 0) {
            return;
        }
        written += (size_t)n;
    }
}

static void metrics_respond(int fd, const char *status, const char *extra,
                            const char *body)
{
    char header[512];
    int header_len;

    header_len = snprintf(header, sizeof(header),
                          "HTTP/1.1 %s\r\n"
                          "Content-Type: text/plain; version=0.0.4; "
                          "charset=utf-8\r\n"
                          "Content-Length: %zu\r\n"
                          "%s"
                          "Connection: close\r\n"
                          "\r\n",
                          status, (body != NULL) ? strlen(body) : 0u,
                          (extra != NULL) ? extra : "");

    if (header_len < 0 || (size_t)header_len >= sizeof(header)) {
        return;
    }

    metrics_write_all(fd, header, (size_t)header_len);
    if (body != NULL) {
        metrics_write_all(fd, body, strlen(body));
    }
}

/*
 * Non-zero once the whole header block has arrived.
 */
static int head_complete(const char *request)
{
    return strstr(request, "\r\n\r\n") != NULL ||
           strstr(request, "\n\n") != NULL;
}

/*
 * Non-zero when c ends the request path (HTTP version, query or nothing).
 */
static int path_delimiter(char c)
{
    return c == ' ' || c == '?' || c == '\0';
}

/*
 * Compare a header name at the start of line, case-insensitively.
 * HTTP header names are not case-sensitive and nothing else here needs a
 * full header parser.
 */
static int header_name_matches(const char *line, const char *name)
{
    size_t i;

    for (i = 0; name[i] != '\0'; i++) {
        unsigned char got = (unsigned char)line[i];

        if (got == ':' || got == '\0') {
            return 0;
        }
        if (tolower((int)got) != tolower((int)(unsigned char)name[i])) {
            return 0;
        }
    }

    return line[i] == ':';
}

/*
 * Return the value of a header (after the colon and any spaces), or NULL.
 *
 * The value runs to the end of its line inside the request buffer, so a
 * caller must stop at the first CR, LF or NUL.
 */
static const char *find_header_value(const char *request, const char *name)
{
    const char *line = strchr(request, '\n');

    while (line != NULL) {
        line++;
        if (*line == '\r' || *line == '\n' || *line == '\0') {
            return NULL;   /* blank line: the header is not there */
        }

        if (header_name_matches(line, name)) {
            const char *value = line + strlen(name) + 1;

            while (*value == ' ' || *value == '\t') {
                value++;
            }
            return value;
        }

        line = strchr(line, '\n');
    }

    return NULL;
}

/*
 * Does the request carry 'Authorization: Bearer <token>'?
 *
 * The token bytes are compared without an early exit, so a caller cannot
 * learn the secret one prefix at a time from response timing. The length
 * of a wrong token is observable, which is true of every bearer check of
 * this shape and reveals nothing usable.
 */
static int authorized(const char *request, const char *token)
{
    const char *value = find_header_value(request, "authorization");
    size_t token_len;
    size_t i;
    unsigned char diff = 0;

    if (value == NULL || strlen(value) < 7) {
        return 0;
    }

    for (i = 0; i < 7; i++) {
        if (tolower((int)(unsigned char)value[i]) !=
            tolower((int)(unsigned char)"Bearer "[i])) {
            return 0;
        }
    }

    value += 7;
    token_len = strlen(token);

    for (i = 0; i < token_len; i++) {
        unsigned char got = (unsigned char)value[i];

        if (got == '\r' || got == '\n' || got == '\0') {
            return 0;
        }
        diff |= (unsigned char)(got ^ (unsigned char)token[i]);
    }

    if (value[i] != '\r' && value[i] != '\n' && value[i] != '\0') {
        return 0;   /* trailing junk: not this token */
    }

    return diff == 0;
}

/*
 * Read the request head, route it, and answer it.
 */
static void metrics_serve_connection(int fd)
{
    /* One server thread, so a static body buffer needs no locking. */
    static char body[METRICS_BODY_MAX];
    char request[METRICS_REQUEST_MAX];
    struct timeval timeout;
    size_t used = 0;
    ssize_t nread;
    const char *method;
    int is_get;

    timeout.tv_sec = METRICS_TIMEOUT_SEC;
    timeout.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
               (socklen_t)sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
               (socklen_t)sizeof(timeout));

    /*
     * The whole header block is needed: the request line picks the route,
     * but the bearer token lives in a header.
     */
    while (used + 1 < sizeof(request)) {
        nread = read(fd, request + used, sizeof(request) - 1 - used);

        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (nread == 0) {
            break;
        }

        used += (size_t)nread;
        request[used] = '\0';

        if (head_complete(request)) {
            break;
        }
    }

    request[used] = '\0';

    method = request;
    is_get = (strncmp(method, "GET ", 4) == 0) ? 1 : 0;

    if (!is_get) {
        metrics_respond(fd, "405 Method Not Allowed", NULL, NULL);
        return;
    }

    /*
     * A liveness probe wants a status code and nothing else, so it stays
     * cheap and never requires the token.
     */
    if (strncmp(method + 4, "/healthz", 8) == 0 &&
        path_delimiter(method[12])) {
        metrics_respond(fd, "200 OK", NULL, "ok\n");
        return;
    }

    /*
     * Accept the path up to the query string or the HTTP version: "/metrics",
     * "/metrics?x=1" and "/metrics HTTP/1.1" all scrape, anything else is
     * a 404 so a wrong URL is obvious instead of an empty scrape.
     */
    if (strncmp(method + 4, "/metrics", 8) != 0 ||
        !path_delimiter(method[12])) {
        metrics_respond(fd, "404 Not Found", NULL, NULL);
        return;
    }

    if (s_token[0] != '\0' && !authorized(request, s_token)) {
        metrics_respond(fd, "401 Unauthorized",
                        "WWW-Authenticate: Bearer realm=\"pipesix\"\r\n",
                        NULL);
        return;
    }

    body[0] = '\0';
    if (s_body == NULL || s_body(body, sizeof(body), s_body_arg) != 0) {
        metrics_respond(fd, "500 Internal Server Error", NULL, NULL);
        return;
    }

    metrics_respond(fd, "200 OK", NULL, body);
}

static void *metrics_loop(void *arg)
{
    (void)arg;

    while (!atomic_load(&s_stopping)) {
        struct pollfd pfd;
        int ready;
        int fd;

        pfd.fd = s_listen_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        ready = poll(&pfd, 1, METRICS_POLL_MS);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (ready == 0) {
            continue;
        }

        fd = accept(s_listen_fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (atomic_load(&s_stopping)) {
                break;
            }
            continue;
        }

        metrics_serve_connection(fd);
        close(fd);
    }

    return NULL;
}

int metrics_start(const pipesix_config_t *config, metrics_body_fn body,
                  void *arg)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp;
    char port[16];
    int gai;
    int fd = -1;

    if (config == NULL) {
        return -1;
    }

    /* No address means the operator did not ask for an endpoint. */
    if (config->metrics_address[0] == '\0') {
        if (config->metrics_token[0] != '\0') {
            log_warn("metrics_token is set but metrics_address is empty; "
                     "the metrics endpoint stays disabled");
        }
        return 0;
    }

    if (s_started) {
        return 0;
    }

    snprintf(port, sizeof(port), "%d", config->metrics_port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    gai = getaddrinfo(config->metrics_address, port, &hints, &result);
    if (gai != 0) {
        log_warn("Cannot resolve metrics_address '%s': %s",
                 config->metrics_address, gai_strerror(gai));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        int optval = 1;

        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }

        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(result);

    if (fd < 0) {
        log_warn("Cannot bind the metrics endpoint to %s:%d: %s",
                 config->metrics_address, config->metrics_port,
                 strerror(errno));
        return -1;
    }

    if (listen(fd, 8) != 0) {
        log_warn("Cannot listen on the metrics endpoint: %s",
                 strerror(errno));
        close(fd);
        return -1;
    }

    s_listen_fd = fd;
    s_body = body;
    s_body_arg = arg;
    snprintf(s_token, sizeof(s_token), "%s", config->metrics_token);
    atomic_store(&s_stopping, 0);

    if (pthread_create(&s_thread, NULL, metrics_loop, NULL) != 0) {
        log_warn("Cannot start the metrics thread: %s", strerror(errno));
        close(fd);
        s_listen_fd = -1;
        s_body = NULL;
        s_body_arg = NULL;
        return -1;
    }

    s_started = 1;
    log_info("Metrics endpoint on http://%s:%d/metrics (%s)",
             config->metrics_address, config->metrics_port,
             s_token[0] != '\0' ? "bearer token required"
                                : "no authentication");
    return 0;
}

void metrics_stop(void)
{
    if (!s_started) {
        return;
    }

    atomic_store(&s_stopping, 1);
    pthread_join(s_thread, NULL);
    s_started = 0;

    if (s_listen_fd >= 0) {
        close(s_listen_fd);
        s_listen_fd = -1;
    }

    s_body = NULL;
    s_body_arg = NULL;
    memset(s_token, 0, sizeof(s_token));
}

int metrics_running(void)
{
    return s_started;
}

#endif /* _WIN32 */
