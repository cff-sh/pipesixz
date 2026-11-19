/*
 * audit.c - Append-only security audit records
 */

#include "audit.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if defined(_WIN32)
#include <io.h>
#else
#include <sys/stat.h>
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

static pthread_mutex_t audit_lock = PTHREAD_MUTEX_INITIALIZER;
static int audit_fd = -1;

int audit_open(const char *path)
{
    int fd = -1;

    if (path != NULL && path[0] != '\0') {
        fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_BINARY,
                  (mode_t)0600);
        if (fd < 0) {
            return -1;
        }
#if !defined(_WIN32)
        (void)fchmod(fd, (mode_t)0600);
#endif
    }

    pthread_mutex_lock(&audit_lock);
    if (audit_fd >= 0) {
        close(audit_fd);
    }
    audit_fd = fd;
    pthread_mutex_unlock(&audit_lock);

    return 0;
}

void audit_close(void)
{
    pthread_mutex_lock(&audit_lock);
    if (audit_fd >= 0) {
        close(audit_fd);
        audit_fd = -1;
    }
    pthread_mutex_unlock(&audit_lock);
}

/*
 * Escape one string for a JSON value. Truncation is allowed (audit records
 * are bounded), but never in the middle of an escape sequence.
 */
static int json_escape(char *dst, size_t size, const char *src)
{
    size_t used = 0;
    const unsigned char *p = (const unsigned char *)(src != NULL ? src : "");

    while (*p != '\0') {
        const char *escape = NULL;
        char unicode[7];
        size_t need;

        switch (*p) {
            case '"':  escape = "\\\""; break;
            case '\\': escape = "\\\\"; break;
            case '\b': escape = "\\b"; break;
            case '\f': escape = "\\f"; break;
            case '\n': escape = "\\n"; break;
            case '\r': escape = "\\r"; break;
            case '\t': escape = "\\t"; break;
            default:
                if (*p < 0x20) {
                    snprintf(unicode, sizeof(unicode), "\\u%04x", *p);
                    escape = unicode;
                }
                break;
        }

        if (escape != NULL) {
            need = strlen(escape);
            if (used + need + 1 >= size) {
                break;
            }
            memcpy(dst + used, escape, need);
            used += need;
        } else {
            if (used + 2 >= size) {
                break;
            }
            dst[used++] = (char)*p;
        }
        p++;
    }

    dst[used] = '\0';
    return 0;
}

void audit_event(const char *event, const char *client, const char *peer,
                 const char *fmt, ...)
{
    char message[768];
    char event_esc[96];
    char client_esc[160];
    char peer_esc[224];
    char message_esc[1600];
    char line[4096];
    char stamp[32];
    struct tm tm_now;
    time_t now;
    va_list ap;
    int n;
    size_t used = 0;
    int fd;

    pthread_mutex_lock(&audit_lock);
    fd = audit_fd;
    if (fd < 0) {
        pthread_mutex_unlock(&audit_lock);
        return;
    }

    va_start(ap, fmt);
    vsnprintf(message, sizeof(message), fmt, ap);
    va_end(ap);

    now = time(NULL);
#if defined(_WIN32)
    {
        struct tm *tmp = gmtime(&now);
        if (tmp != NULL) {
            tm_now = *tmp;
        } else {
            memset(&tm_now, 0, sizeof(tm_now));
        }
    }
#else
    if (gmtime_r(&now, &tm_now) == NULL) {
        memset(&tm_now, 0, sizeof(tm_now));
    }
#endif

    if (strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &tm_now) == 0) {
        snprintf(stamp, sizeof(stamp), "1970-01-01T00:00:00Z");
    }

    json_escape(event_esc, sizeof(event_esc), event);
    json_escape(client_esc, sizeof(client_esc), client);
    json_escape(peer_esc, sizeof(peer_esc), peer);
    json_escape(message_esc, sizeof(message_esc), message);

    n = snprintf(line, sizeof(line),
                 "{\"time\":\"%s\",\"event\":\"%s\",\"client\":\"%s\","
                 "\"peer\":\"%s\",\"msg\":\"%s\"}\n",
                 stamp, event_esc, client_esc, peer_esc, message_esc);
    if (n < 0 || (size_t)n >= sizeof(line)) {
        pthread_mutex_unlock(&audit_lock);
        return;
    }

    while (used < (size_t)n) {
        ssize_t written = write(fd, line + used, (size_t)n - used);

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            audit_fd = -1;
            break;
        }
        used += (size_t)written;
    }

    pthread_mutex_unlock(&audit_lock);
}
