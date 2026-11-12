/*
 * metrics.c - Prometheus Metrics Endpoint
 *
 * Serves GET /metrics over TCP on the configured address. One request
 * per connection with a short receive timeout and a bounded request
 * buffer: a stuck or hostile client cannot park the thread, and nothing
 * here changes state, so no authentication is needed. Bind the endpoint
 * to 127.0.0.1 or a private interface rather than to the internet.
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

static void metrics_respond(int fd, const char *status, const char *body)
{
    char header[256];
    int header_len;

    header_len = snprintf(header, sizeof(header),
                          "HTTP/1.1 %s\r\n"
                          "Content-Type: text/plain; version=0.0.4; "
                          "charset=utf-8\r\n"
                          "Content-Length: %zu\r\n"
                          "Connection: close\r\n"
                          "\r\n",
                          status, (body != NULL) ? strlen(body) : 0u);

    if (header_len < 0 || (size_t)header_len >= sizeof(header)) {
        return;
    }

    metrics_write_all(fd, header, (size_t)header_len);
    if (body != NULL) {
        metrics_write_all(fd, body, strlen(body));
    }
}

/*
 * Read the request head, keep only the request line, and answer it.
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

        /* The request line is all that matters; headers end the input. */
        if (strchr(request, '\n') != NULL) {
            break;
        }
    }

    request[used] = '\0';

    method = request;
    is_get = (strncmp(method, "GET ", 4) == 0) ? 1 : 0;

    if (!is_get) {
        metrics_respond(fd, "405 Method Not Allowed", NULL);
        return;
    }

    /*
     * Accept the path up to the query string or the HTTP version: "/metrics",
     * "/metrics?x=1" and "/metrics HTTP/1.1" all scrape, anything else is
     * a 404 so a wrong URL is obvious instead of an empty scrape.
     */
    if (strncmp(method + 4, "/metrics", 8) != 0) {
        metrics_respond(fd, "404 Not Found", NULL);
        return;
    }

    if (method[12] != ' ' && method[12] != '?' && method[12] != '\0') {
        metrics_respond(fd, "404 Not Found", NULL);
        return;
    }

    body[0] = '\0';
    if (s_body == NULL || s_body(body, sizeof(body), s_body_arg) != 0) {
        metrics_respond(fd, "500 Internal Server Error", NULL);
        return;
    }

    metrics_respond(fd, "200 OK", body);
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
    log_info("Metrics endpoint on http://%s:%d/metrics",
             config->metrics_address, config->metrics_port);
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
}

int metrics_running(void)
{
    return s_started;
}

#endif /* _WIN32 */
