/*
 * platform.h - Thin Portability Layer
 *
 * pipesix is written against POSIX sockets, poll() and threads. Windows
 * offers the same concepts under different names and, in two places, with
 * different semantics that would break the callers if used directly:
 *
 *   - A socket is a SOCKET (an unsigned pointer-sized handle), not an int,
 *     so it cannot be stored in an int or compared with 0.
 *   - Socket calls do not set errno; they report through WSAGetLastError()
 *     with a completely different set of error numbers.
 *
 * Everything else the client needs (pthreads, getaddrinfo, inet_ntop,
 * time_t, C11 atomics) is provided by MinGW-w64, so only sockets, a
 * readiness wait, close() and sleeping are wrapped here.
 *
 * The POSIX side of this header is a set of inline forwarders, so the
 * Linux and macOS builds keep their existing behaviour and incur no call
 * overhead.
 */

#ifndef PIPESIX_PLATFORM_H
#define PIPESIX_PLATFORM_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>

/* A socket handle. Never an int: SOCKET is pointer-sized on Win64. */
typedef SOCKET psix_socket_t;

#define PSIX_INVALID_SOCKET INVALID_SOCKET

/* Windows spells the process id with a leading underscore. */
#define getpid _getpid

/*
 * Translate the last Winsock error into the nearest POSIX value and store
 * it in errno, so the callers' existing errno/strerror() handling keeps
 * working unchanged.
 */
static inline int psix_map_wsa_error(int wsa)
{
    int mapped;

    switch (wsa) {
        case WSAEINTR:         mapped = EINTR;         break;
        case WSAEWOULDBLOCK:   mapped = EWOULDBLOCK;   break;
        case WSAEINPROGRESS:   mapped = EINPROGRESS;   break;
        case WSAEALREADY:      mapped = EALREADY;      break;
        case WSAENOTSOCK:      mapped = ENOTSOCK;      break;
        case WSAEDESTADDRREQ:  mapped = EDESTADDRREQ;  break;
        case WSAEMSGSIZE:      mapped = EMSGSIZE;      break;
        case WSAEPROTOTYPE:    mapped = EPROTOTYPE;    break;
        case WSAENOPROTOOPT:   mapped = ENOPROTOOPT;   break;
        case WSAEPROTONOSUPPORT: mapped = EPROTONOSUPPORT; break;
        case WSAEAFNOSUPPORT:  mapped = EAFNOSUPPORT;  break;
        case WSAEADDRINUSE:    mapped = EADDRINUSE;    break;
        case WSAEADDRNOTAVAIL: mapped = EADDRNOTAVAIL; break;
        case WSAENETDOWN:      mapped = ENETDOWN;      break;
        case WSAENETUNREACH:   mapped = ENETUNREACH;   break;
        case WSAENETRESET:     mapped = ENETRESET;     break;
        case WSAECONNABORTED:  mapped = ECONNABORTED;  break;
        case WSAECONNRESET:    mapped = ECONNRESET;    break;
        case WSAENOBUFS:       mapped = ENOBUFS;       break;
        case WSAEISCONN:       mapped = EISCONN;       break;
        case WSAENOTCONN:      mapped = ENOTCONN;      break;
        case WSAETIMEDOUT:     mapped = ETIMEDOUT;     break;
        case WSAECONNREFUSED:  mapped = ECONNREFUSED;  break;
        case WSAEHOSTUNREACH:  mapped = EHOSTUNREACH;  break;
        case WSAEINVAL:        mapped = EINVAL;        break;
        case WSAEFAULT:        mapped = EFAULT;        break;
        default:               mapped = EIO;           break;
    }

    errno = mapped;
    return mapped;
}

/*
 * Convert a UTF-8 string to a NUL-terminated wide string.
 *
 * Returns 0 on success, -1 if the destination is too small.
 */
static inline int psix_utf8_to_wide(const char *src, WCHAR *dst, size_t count)
{
    int needed;

    if (src == NULL || dst == NULL || count == 0 || count > 0x7FFFFFFFu) {
        return -1;
    }

    needed = MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, (int)count);
    return needed > 0 ? 0 : -1;
}

int psix_net_init(void);
void psix_net_shutdown(void);
int psix_close(psix_socket_t sock);
ssize_t psix_send(psix_socket_t sock, const void *buf, size_t len, int flags);
ssize_t psix_recv(psix_socket_t sock, void *buf, size_t len, int flags);
int psix_connect(psix_socket_t sock, const struct sockaddr *addr,
                 socklen_t addrlen);
int psix_socket_wait(psix_socket_t sock, int timeout_ms);
void psix_sleep(unsigned int seconds);

#else /* POSIX */

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

typedef int psix_socket_t;

#define PSIX_INVALID_SOCKET (-1)

static inline int psix_net_init(void)
{
    return 0;
}

static inline void psix_net_shutdown(void)
{
}

static inline int psix_close(psix_socket_t sock)
{
    return close(sock);
}

static inline ssize_t psix_send(psix_socket_t sock, const void *buf,
                                size_t len, int flags)
{
    return send(sock, buf, len, flags);
}

static inline ssize_t psix_recv(psix_socket_t sock, void *buf,
                                size_t len, int flags)
{
    return recv(sock, buf, len, flags);
}

static inline int psix_connect(psix_socket_t sock, const struct sockaddr *addr,
                               socklen_t addrlen)
{
    return connect(sock, addr, addrlen);
}

/*
 * Wait until the socket has data to read.
 *
 * Returns >0 when readable, 0 on timeout and -1 on error, matching
 * poll() so callers need no platform conditionals.
 */
static inline int psix_socket_wait(psix_socket_t sock, int timeout_ms)
{
    struct pollfd pfd;

    pfd.fd = sock;
    pfd.events = POLLIN;
    pfd.revents = 0;

    return poll(&pfd, 1, timeout_ms);
}

static inline void psix_sleep(unsigned int seconds)
{
    struct timespec delay;

    delay.tv_sec = (time_t)seconds;
    delay.tv_nsec = 0;
    (void)nanosleep(&delay, NULL);
}

#endif /* _WIN32 */

#endif /* PIPESIX_PLATFORM_H */
