/*
 * control.c - Implementation of the Out-of-Band Control Channel
 *
 * On Windows the channel is a pair of auto-reset named events whose names
 * are derived from the absolute path of the configuration file, so a
 * client and a server on the same machine never address each other:
 *
 *   Local\pipe-six-<hash of config path>-reload
 *   Local\pipe-six-<hash of config path>-stats
 *
 * The events live in the "Local" namespace, which is per logon session:
 * an unelevated 'pipesix --reload' can therefore reach a pipesix started
 * by the same user, and nothing is shared with other sessions.
 *
 * A small thread waits on both events and turns them into the same
 * runtime requests the POSIX signal handlers make, so the rest of the
 * program is unaware of the difference.
 *
 * On POSIX the whole file is a set of stubs: main.c uses the signals.
 */

#include "control.h"

#if defined(_WIN32)

#include "logger.h"
#include "platform.h"
#include "runtime.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONTROL_EVENT_PREFIX "Local\\pipe-six-"

static HANDLE s_reload_event = NULL;
static HANDLE s_stats_event = NULL;
static HANDLE s_stop_event = NULL;
static HANDLE s_thread = NULL;

/*
 * Build the event name for one configuration file and request kind.
 *
 * The configuration path is made absolute first, so 'pipesix --reload -c
 * .\client.conf' reaches an instance started with the full path. The path
 * is lowercased because Windows compares file names case-insensitively,
 * then hashed so the name stays short and contains no characters that a
 * legal file name could break.
 */
static int build_event_name(const char *config_path, const char *kind,
                            WCHAR *name, size_t count)
{
    char full[_MAX_PATH];
    char ascii[128];
    uint32_t hash = 2166136261u;
    size_t i;

    if (config_path == NULL || kind == NULL || _fullpath(full, config_path,
                                                         sizeof(full)) == NULL) {
        if (config_path == NULL || strlen(config_path) >= sizeof(full)) {
            return -1;
        }
        memcpy(full, config_path, strlen(config_path) + 1);
    }

    for (i = 0; full[i] != '\0'; i++) {
        hash ^= (uint32_t)tolower((unsigned char)full[i]);
        /* FNV-1a: 16777619 = 2^24 + 403. */
        hash *= 16777619u;
    }

    if (snprintf(ascii, sizeof(ascii), "%s%08lx-%s", CONTROL_EVENT_PREFIX,
                 (unsigned long)hash, kind) >= (int)sizeof(ascii)) {
        return -1;
    }

    return psix_utf8_to_wide(ascii, name, count);
}

/*
 * The control thread: wait for either request until control_stop().
 *
 * WaitForMultipleObjects() is used rather than two threads because both
 * requests are handled by the same runtime flags the signal handlers set.
 */
static DWORD WINAPI control_thread(LPVOID unused)
{
    HANDLE events[3];
    (void)unused;

    events[0] = s_stop_event;
    events[1] = s_reload_event;
    events[2] = s_stats_event;

    for (;;) {
        DWORD ready = WaitForMultipleObjects(3, events, FALSE, INFINITE);

        if (ready == WAIT_OBJECT_0) {
            break;
        }
        if (ready == WAIT_OBJECT_0 + 1) {
            log_info("Control request: reload configuration");
            runtime_request_reload();
        } else if (ready == WAIT_OBJECT_0 + 2) {
            runtime_request_stats();
        } else {
            break;
        }
    }

    return 0;
}

static void close_handles(void)
{
    if (s_thread != NULL) {
        CloseHandle(s_thread);
        s_thread = NULL;
    }
    if (s_stop_event != NULL) {
        CloseHandle(s_stop_event);
        s_stop_event = NULL;
    }
    if (s_reload_event != NULL) {
        CloseHandle(s_reload_event);
        s_reload_event = NULL;
    }
    if (s_stats_event != NULL) {
        CloseHandle(s_stats_event);
        s_stats_event = NULL;
    }
}

void control_start(const char *config_path)
{
    WCHAR name[128];

    if (s_thread != NULL) {
        return;
    }

    if (build_event_name(config_path, "reload", name,
                         sizeof(name) / sizeof(name[0])) != 0) {
        log_warn("Cannot derive a control channel name from '%s'",
                 config_path != NULL ? config_path : "(null)");
        return;
    }
    s_reload_event = CreateEventW(NULL, FALSE, FALSE, name);

    if (build_event_name(config_path, "stats", name,
                         sizeof(name) / sizeof(name[0])) != 0) {
        close_handles();
        return;
    }
    s_stats_event = CreateEventW(NULL, FALSE, FALSE, name);

    s_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (s_reload_event == NULL || s_stats_event == NULL ||
        s_stop_event == NULL) {
        log_warn("Cannot create the control channel (error %lu)",
                 (unsigned long)GetLastError());
        close_handles();
        return;
    }

    s_thread = CreateThread(NULL, 0, control_thread, NULL, 0, NULL);
    if (s_thread == NULL) {
        log_warn("Cannot start the control thread (error %lu)",
                 (unsigned long)GetLastError());
        close_handles();
    }
}

void control_stop(void)
{
    if (s_thread == NULL) {
        return;
    }

    SetEvent(s_stop_event);
    WaitForSingleObject(s_thread, INFINITE);
    CloseHandle(s_thread);
    s_thread = NULL;

    if (s_stop_event != NULL) {
        CloseHandle(s_stop_event);
        s_stop_event = NULL;
    }
    if (s_reload_event != NULL) {
        CloseHandle(s_reload_event);
        s_reload_event = NULL;
    }
    if (s_stats_event != NULL) {
        CloseHandle(s_stats_event);
        s_stats_event = NULL;
    }
}

/*
 * Signal a running instance by name.
 *
 * Returns 1 when an instance was listening, 0 when none was (which is
 * almost always a wrong configuration path).
 */
static int raise_event(const char *config_path, const char *kind)
{
    WCHAR name[128];
    HANDLE event;

    if (build_event_name(config_path, kind, name,
                         sizeof(name) / sizeof(name[0])) != 0) {
        return -1;
    }

    event = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
    if (event == NULL) {
        return 0;
    }

    if (!SetEvent(event)) {
        CloseHandle(event);
        return -1;
    }

    CloseHandle(event);
    return 1;
}

int control_request_reload(const char *config_path)
{
    return raise_event(config_path, "reload");
}

int control_request_stats(const char *config_path)
{
    return raise_event(config_path, "stats");
}

void control_set_handler(control_handler_fn handler, void *arg)
{
    (void)handler;
    (void)arg;
}

int control_request(const char *config_path, const char *request,
                    char *reply, size_t reply_size)
{
    (void)config_path;
    (void)request;
    (void)reply;
    (void)reply_size;
    errno = ENOTSUP;
    return -1;
}

#else /* POSIX: a UNIX socket carries the same requests */

#include "logger.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define CONTROL_MAX_REQUEST  256u
#define CONTROL_POLL_MS      200
#define CONTROL_TIMEOUT_SEC  3

static pthread_t          s_thread;
static int                s_thread_started;
static int                s_listen_fd = -1;
static char               s_socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
static _Atomic int        s_stopping = 1;

static pthread_mutex_t    s_handler_lock = PTHREAD_MUTEX_INITIALIZER;
static control_handler_fn s_handler;
static void              *s_handler_arg;

/*
 * FNV-1a over the absolute configuration path, so two instances with
 * different configurations never share a socket.
 */
static unsigned long socket_name_hash(const char *path)
{
    const unsigned char *p = (const unsigned char *)path;
    unsigned long hash = 2166136261ul;

    while (*p != '\0') {
        hash ^= (unsigned long)*p;
        hash *= 16777619ul;
        p++;
    }

    return hash & 0xfffffffful;
}

/*
 * Pick the directory that holds the control socket.
 *
 * /run/pipesix is used when it exists (or can be created) and is
 * writable; both the server and the CLI call this same function, so they
 * agree on the path. When /run is not writable - an unprivileged run -
 * both fall back to /tmp.
 */
static void control_directory(char *out, size_t out_size)
{
    struct stat st;

    if (stat("/run/pipesix", &st) == 0 && S_ISDIR(st.st_mode) &&
        access("/run/pipesix", W_OK) == 0) {
        snprintf(out, out_size, "%s", "/run/pipesix");
        return;
    }

    if (stat("/run", &st) == 0 && S_ISDIR(st.st_mode) &&
        mkdir("/run/pipesix", 0700) == 0 &&
        access("/run/pipesix", W_OK) == 0) {
        snprintf(out, out_size, "%s", "/run/pipesix");
        return;
    }

    snprintf(out, out_size, "%s", "/tmp");
}

static int control_socket_path(const char *config_path, char *out,
                               size_t out_size)
{
    char resolved[PATH_MAX];
    char dir[64];
    const char *key;
    int n;

    if (config_path == NULL || config_path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    key = realpath(config_path, resolved) != NULL ? resolved : config_path;
    control_directory(dir, sizeof(dir));

    n = snprintf(out, out_size, "%s/pipesix-%lu-%08lx.sock", dir,
                 (unsigned long)getuid(), socket_name_hash(key));
    if (n < 0 || (size_t)n >= out_size) {
        errno = ENAMETOOLONG;
        return -1;
    }

    return 0;
}

static void write_all(int fd, const char *buf, size_t len)
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

/*
 * Serve one request: read a line, let the handler fill the reply, write
 * it and close. One request per connection keeps the protocol trivial.
 */
static void control_serve_connection(int fd)
{
    char request[CONTROL_MAX_REQUEST];
    char reply[CONTROL_MAX_REPLY];
    struct timeval timeout;
    control_handler_fn handler;
    void *handler_arg;
    size_t used = 0;
    size_t start;
    size_t end;
    size_t len;
    ssize_t nread;

    timeout.tv_sec = CONTROL_TIMEOUT_SEC;
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
        if (memchr(request, '\n', used) != NULL) {
            break;
        }
    }

    request[used] = '\0';

    /* Trim the line: a request is one line of plain text. */
    start = 0;
    while (request[start] != '\0' &&
           isspace((unsigned char)request[start])) {
        start++;
    }
    end = strlen(request + start);
    while (end > 0 && isspace((unsigned char)request[start + end - 1])) {
        end--;
    }
    memmove(request, request + start, end);
    request[end] = '\0';

    pthread_mutex_lock(&s_handler_lock);
    handler = s_handler;
    handler_arg = s_handler_arg;
    pthread_mutex_unlock(&s_handler_lock);

    reply[0] = '\0';
    if (handler == NULL) {
        snprintf(reply, sizeof(reply),
                 "ERR the control channel is not ready\n");
    } else if (handler(request, reply, sizeof(reply), handler_arg) != 0 &&
               reply[0] == '\0') {
        snprintf(reply, sizeof(reply), "ERR request failed\n");
    } else if (reply[0] == '\0') {
        snprintf(reply, sizeof(reply), "OK\n");
    }

    len = strlen(reply);
    if (len == 0 || reply[len - 1] != '\n') {
        if (len + 1 < sizeof(reply)) {
            reply[len++] = '\n';
            reply[len] = '\0';
        }
    }

    write_all(fd, reply, len);
}

static void *control_loop(void *arg)
{
    (void)arg;

    while (!atomic_load(&s_stopping)) {
        struct pollfd pfd;
        int ready;
        int fd;

        pfd.fd = s_listen_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        ready = poll(&pfd, 1, CONTROL_POLL_MS);
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

        control_serve_connection(fd);
        close(fd);
    }

    return NULL;
}

void control_start(const char *config_path)
{
    struct sockaddr_un addr;
    int fd;

    if (s_thread_started) {
        return;
    }

    if (control_socket_path(config_path, s_socket_path,
                            sizeof(s_socket_path)) != 0) {
        log_warn("Cannot derive a control socket path from '%s'",
                 config_path != NULL ? config_path : "(null)");
        s_socket_path[0] = '\0';
        return;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        log_warn("Cannot create the control socket: %s", strerror(errno));
        s_socket_path[0] = '\0';
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, s_socket_path, strlen(s_socket_path) + 1);

    /* A socket left behind by a killed instance must not block startup. */
    unlink(s_socket_path);

    if (bind(fd, (struct sockaddr *)(void *)&addr,
             (socklen_t)sizeof(addr)) != 0) {
        log_warn("Cannot bind the control socket '%s': %s", s_socket_path,
                 strerror(errno));
        close(fd);
        s_socket_path[0] = '\0';
        return;
    }

    /* Only the owner may ask; the requests can drop a client. */
    chmod(s_socket_path, 0600);
    listen(fd, 8);

    s_listen_fd = fd;
    atomic_store(&s_stopping, 0);

    if (pthread_create(&s_thread, NULL, control_loop, NULL) != 0) {
        log_warn("Cannot start the control thread: %s", strerror(errno));
        close(fd);
        s_listen_fd = -1;
        unlink(s_socket_path);
        s_socket_path[0] = '\0';
        atomic_store(&s_stopping, 1);
        return;
    }

    s_thread_started = 1;
    log_info("Control socket '%s'", s_socket_path);
}

void control_stop(void)
{
    if (!s_thread_started) {
        return;
    }

    atomic_store(&s_stopping, 1);
    pthread_join(s_thread, NULL);
    s_thread_started = 0;

    if (s_listen_fd >= 0) {
        close(s_listen_fd);
        s_listen_fd = -1;
    }

    if (s_socket_path[0] != '\0') {
        unlink(s_socket_path);
        s_socket_path[0] = '\0';
    }
}

void control_set_handler(control_handler_fn handler, void *arg)
{
    pthread_mutex_lock(&s_handler_lock);
    s_handler = handler;
    s_handler_arg = arg;
    pthread_mutex_unlock(&s_handler_lock);
}

int control_request(const char *config_path, const char *request,
                    char *reply, size_t reply_size)
{
    struct sockaddr_un addr;
    struct timeval timeout;
    char path[sizeof(addr.sun_path)];
    char line[CONTROL_MAX_REQUEST];
    size_t total = 0;
    ssize_t nread;
    int fd;
    int len;

    if (config_path == NULL || request == NULL || reply == NULL ||
        reply_size == 0) {
        errno = EINVAL;
        return -1;
    }

    if (control_socket_path(config_path, path, sizeof(path)) != 0) {
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, strlen(path) + 1);

    if (connect(fd, (struct sockaddr *)(void *)&addr,
                (socklen_t)sizeof(addr)) != 0) {
        int saved = errno;

        close(fd);
        errno = saved;
        return -1;
    }

    timeout.tv_sec = CONTROL_TIMEOUT_SEC;
    timeout.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
               (socklen_t)sizeof(timeout));

    len = snprintf(line, sizeof(line), "%s\n", request);
    if (len < 0 || (size_t)len >= sizeof(line)) {
        close(fd);
        errno = EINVAL;
        return -1;
    }

    write_all(fd, line, (size_t)len);
    shutdown(fd, SHUT_WR);

    while (total + 1 < reply_size) {
        nread = read(fd, reply + total, reply_size - 1 - total);

        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (nread == 0) {
            break;
        }

        total += (size_t)nread;
    }

    reply[total] = '\0';
    close(fd);

    if (total == 0) {
        errno = EPROTO;
        return -1;
    }

    return 0;
}

int control_request_reload(const char *config_path)
{
    (void)config_path;
    return -1;
}

int control_request_stats(const char *config_path)
{
    (void)config_path;
    return -1;
}

#endif /* _WIN32 */

int control_json_escape(const char *in, char *out, size_t out_size)
{
    static const char hex[] = "0123456789abcdef";
    size_t used = 0;

    if (out == NULL || out_size == 0) {
        return -1;
    }

    out[0] = '\0';

    if (in == NULL) {
        return 0;
    }

    for (; *in != '\0'; in++) {
        unsigned char c = (unsigned char)*in;
        const char *esc = NULL;
        char unicode[7];

        switch (c) {
            case '"':  esc = "\\\""; break;
            case '\\': esc = "\\\\"; break;
            case '\b': esc = "\\b";  break;
            case '\f': esc = "\\f";  break;
            case '\n': esc = "\\n";  break;
            case '\r': esc = "\\r";  break;
            case '\t': esc = "\\t";  break;
            default:   break;
        }

        if (esc == NULL && c < 0x20u) {
            unicode[0] = '\\';
            unicode[1] = 'u';
            unicode[2] = '0';
            unicode[3] = '0';
            unicode[4] = hex[c >> 4];
            unicode[5] = hex[c & 0x0fu];
            unicode[6] = '\0';
            esc = unicode;
        }

        if (esc != NULL) {
            size_t len = strlen(esc);

            if (used + len >= out_size) {
                out[0] = '\0';
                return -1;
            }
            memcpy(out + used, esc, len);
            used += len;
        } else {
            if (used + 1 >= out_size) {
                out[0] = '\0';
                return -1;
            }
            out[used++] = (char)c;
        }
    }

    out[used] = '\0';
    return 0;
}
