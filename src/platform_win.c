/*
 * platform_win.c - Windows Implementations of the Portability Layer
 *
 * Sockets, readiness waits and sleeps for the Windows client:
 *
 *   - WSAStartup() has to run before any socket call, and WSACleanup()
 *     after the last one.
 *   - closesocket() replaces close(); closing a socket with close() is a
 *     handle leak on Windows.
 *   - WSAPoll() is the equivalent of poll(), available on Vista and
 *     later.
 *   - Socket calls report errors through WSAGetLastError(), which
 *     platform.h maps back onto errno so call sites stay unchanged.
 */

#include "platform.h"
#include "logger.h"

#include <string.h>

/*
 * Reference count of psix_net_init() calls, so a second initialisation
 * (there is none today, but the tunnel code may grow one) cannot tear the
 * stack down under the first user.
 */
static int s_net_users = 0;

int psix_net_init(void)
{
    WSADATA data;
    int rc;

    if (s_net_users > 0) {
        s_net_users++;
        return 0;
    }

    rc = WSAStartup(MAKEWORD(2, 2), &data);
    if (rc != 0) {
        log_error("WSAStartup failed with error %d", rc);
        return -1;
    }

    s_net_users = 1;
    return 0;
}

void psix_net_shutdown(void)
{
    if (s_net_users <= 0) {
        return;
    }

    s_net_users--;
    if (s_net_users == 0) {
        (void)WSACleanup();
    }
}

int psix_close(psix_socket_t sock)
{
    if (sock == PSIX_INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (closesocket(sock) == SOCKET_ERROR) {
        psix_map_wsa_error(WSAGetLastError());
        return -1;
    }

    return 0;
}

ssize_t psix_send(psix_socket_t sock, const void *buf, size_t len, int flags)
{
    int sent;

    if (len > 0x7FFFFFFFu) {
        errno = EMSGSIZE;
        return -1;
    }

    sent = send(sock, (const char *)buf, (int)len, flags);
    if (sent == SOCKET_ERROR) {
        psix_map_wsa_error(WSAGetLastError());
        return -1;
    }

    return (ssize_t)sent;
}

ssize_t psix_recv(psix_socket_t sock, void *buf, size_t len, int flags)
{
    int received;

    if (len > 0x7FFFFFFFu) {
        errno = EMSGSIZE;
        return -1;
    }

    received = recv(sock, (char *)buf, (int)len, flags);
    if (received == SOCKET_ERROR) {
        psix_map_wsa_error(WSAGetLastError());
        return -1;
    }

    return (ssize_t)received;
}

int psix_connect(psix_socket_t sock, const struct sockaddr *addr,
                 socklen_t addrlen)
{
    if (connect(sock, addr, (int)addrlen) == SOCKET_ERROR) {
        psix_map_wsa_error(WSAGetLastError());
        return -1;
    }

    return 0;
}

int psix_socket_wait(psix_socket_t sock, int timeout_ms)
{
    WSAPOLLFD pfd;
    int ready;

    if (sock == PSIX_INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    pfd.fd = sock;
    pfd.events = POLLRDNORM;
    pfd.revents = 0;

    ready = WSAPoll(&pfd, 1, timeout_ms);
    if (ready == SOCKET_ERROR) {
        psix_map_wsa_error(WSAGetLastError());
        return -1;
    }

    return ready;
}

void psix_sleep(unsigned int seconds)
{
    /* Sleep() takes milliseconds and returns immediately on a signal. */
    Sleep(seconds * 1000u);
}
