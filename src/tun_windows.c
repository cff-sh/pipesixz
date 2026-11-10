/*
 * tun_windows.c - Windows TUN Backend (Wintun)
 *
 * Windows has no /dev/net/tun and no utun. The Layer 3 adapter comes from
 * Wintun, the driver the WireGuard project publishes: wintun.dll creates
 * the adapter and hands out packet buffers, the driver itself is
 * installed by Windows on first use.
 *
 * The DLL is loaded at run time with LoadLibrary() rather than linked, so
 * pipesix.exe still starts (and explains itself) when wintun.dll is
 * missing, and so no import library or SDK is needed to build.
 *
 * Wintun's read path is not a file descriptor: a packet arrives as a
 * pointer donated by the driver, valid until it is released, and its
 * arrival is announced by a waitable event. That shape is mapped back
 * onto tun.h's read/write interface:
 *
 *   tun_wait()  waits on the read event, like poll() on a tun fd
 *   tun_read()  copies the packet out and releases the driver's buffer
 *   tun_write() allocates a send buffer, copies, and sends
 *
 * Address, MTU and route configuration keeps the approach tun.c uses on
 * Linux and macOS: shell out. On Windows that is netsh, invoked through
 * CreateProcess() with an argument vector (never system(), so an
 * interface name cannot reach a command interpreter) after both the name
 * and the address have been validated.
 *
 * Building requires MinGW-w64 (see 'make windows').
 */

#include "platform.h"
#include "tun.h"
#include "logger.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <winerror.h>

#define WINTUN_RING_CAPACITY  0x400000u   /* 4 MiB, the documented default */
#define DEFAULT_ADAPTER_NAME  "pipesix"
#define MAX_ADAPTER_NAME      127

/*
 * The subset of wintun.h the tunnel needs.
 *
 * These are declared here instead of including the SDK so the build does
 * not depend on Wintun headers being present; the symbols are resolved
 * from the DLL at start-up.
 */
typedef void *wintun_adapter_handle;
typedef void *wintun_session_handle;

typedef wintun_adapter_handle (*wintun_create_adapter_fn)(const WCHAR *,
                                                          const WCHAR *,
                                                          const GUID *);
typedef wintun_adapter_handle (*wintun_open_adapter_fn)(const WCHAR *);
typedef void (*wintun_close_adapter_fn)(wintun_adapter_handle);
typedef wintun_session_handle (*wintun_start_session_fn)(wintun_adapter_handle,
                                                         DWORD);
typedef void (*wintun_end_session_fn)(wintun_session_handle);
typedef HANDLE (*wintun_read_wait_event_fn)(wintun_session_handle);
typedef BYTE *(*wintun_receive_packet_fn)(wintun_session_handle, DWORD *);
typedef void (*wintun_release_receive_packet_fn)(wintun_session_handle,
                                                 const BYTE *);
typedef BYTE *(*wintun_allocate_send_packet_fn)(wintun_session_handle, DWORD);
typedef void (*wintun_send_packet_fn)(wintun_session_handle, const BYTE *);

typedef struct {
    HMODULE                        dll;
    wintun_create_adapter_fn       create_adapter;
    wintun_open_adapter_fn         open_adapter;
    wintun_close_adapter_fn        close_adapter;
    wintun_start_session_fn        start_session;
    wintun_end_session_fn          end_session;
    wintun_read_wait_event_fn      read_wait_event;
    wintun_receive_packet_fn       receive_packet;
    wintun_release_receive_packet_fn release_receive_packet;
    wintun_allocate_send_packet_fn allocate_send_packet;
    wintun_send_packet_fn          send_packet;
} wintun_api_t;

static wintun_api_t s_api;
static int s_api_loaded = 0;

/*
 * Resolve every entry point once.
 *
 * A partially loaded DLL is treated as no DLL at all: half of Wintun is
 * useless, and freeing the module keeps the failure recoverable.
 */
static int wintun_load(void)
{
    if (s_api_loaded) {
        return s_api.dll != NULL ? 0 : -1;
    }
    s_api_loaded = 1;

    s_api.dll = LoadLibraryW(L"wintun.dll");
    if (s_api.dll == NULL) {
        log_error("Cannot load wintun.dll (error %lu); put it next to "
                  "pipesix.exe", (unsigned long)GetLastError());
        return -1;
    }

    /*
     * GetProcAddress() returns FARPROC. Casting that straight to the type
     * we want is the standard loader idiom; routing the cast through
     * void * would trip -Wpedantic, which forbids converting between
     * object and function pointers.
     */
    s_api.create_adapter = (wintun_create_adapter_fn)
        GetProcAddress(s_api.dll, "WintunCreateAdapter");
    s_api.open_adapter = (wintun_open_adapter_fn)
        GetProcAddress(s_api.dll, "WintunOpenAdapter");
    s_api.close_adapter = (wintun_close_adapter_fn)
        GetProcAddress(s_api.dll, "WintunCloseAdapter");
    s_api.start_session = (wintun_start_session_fn)
        GetProcAddress(s_api.dll, "WintunStartSession");
    s_api.end_session = (wintun_end_session_fn)
        GetProcAddress(s_api.dll, "WintunEndSession");
    s_api.read_wait_event = (wintun_read_wait_event_fn)
        GetProcAddress(s_api.dll, "WintunGetReadWaitEvent");
    s_api.receive_packet = (wintun_receive_packet_fn)
        GetProcAddress(s_api.dll, "WintunReceivePacket");
    s_api.release_receive_packet = (wintun_release_receive_packet_fn)
        GetProcAddress(s_api.dll, "WintunReleaseReceivePacket");
    s_api.allocate_send_packet = (wintun_allocate_send_packet_fn)
        GetProcAddress(s_api.dll, "WintunAllocateSendPacket");
    s_api.send_packet = (wintun_send_packet_fn)
        GetProcAddress(s_api.dll, "WintunSendPacket");

    if (s_api.create_adapter == NULL || s_api.open_adapter == NULL ||
        s_api.close_adapter == NULL || s_api.start_session == NULL ||
        s_api.end_session == NULL || s_api.read_wait_event == NULL ||
        s_api.receive_packet == NULL || s_api.release_receive_packet == NULL ||
        s_api.allocate_send_packet == NULL || s_api.send_packet == NULL) {
        log_error("wintun.dll does not export the expected functions; "
                  "it is probably the wrong architecture or too old");
        FreeLibrary(s_api.dll);
        memset(&s_api, 0, sizeof(s_api));
        return -1;
    }

    return 0;
}

/*
 * Copy an interface name, always NUL-terminating and never writing more
 * than size - 1 bytes.
 */
static void copy_name(char *dst, size_t size, const char *src)
{
    size_t len;

    if (dst == NULL || size == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    len = strlen(src);
    if (len >= size) {
        len = size - 1;
    }

    memcpy(dst, src, len);
    dst[len] = '\0';
}

/*
 * Reject interface names that could confuse netsh's own argument parsing.
 *
 * The name is passed as one quoted argument, so the only characters that
 * matter are the quote itself, backslashes and control characters; a
 * space is fine and common ("Local Area Connection").
 */
static int valid_adapter_name(const char *name)
{
    size_t i;
    size_t len;

    if (name == NULL) {
        return 0;
    }

    len = strlen(name);
    if (len == 0 || len > MAX_ADAPTER_NAME) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];

        if (c < 0x20 || c == 0x7F || c == '"' || c == '\\') {
            return 0;
        }
    }

    return 1;
}

/*
 * Append one argument to a command line, quoting it.
 *
 * Returns the new length, or 0 when the buffer cannot hold it.
 */
static size_t append_argument(WCHAR *line, size_t used, size_t capacity,
                              const WCHAR *arg)
{
    size_t need = used;

    if (need + 4 > capacity) {
        return 0;
    }

    line[need++] = L' ';
    line[need++] = L'"';

    while (*arg != L'\0') {
        if (need + 4 > capacity) {
            return 0;
        }
        if (*arg == L'"') {
            line[need++] = L'\\';
        }
        line[need++] = *arg++;
    }

    line[need++] = L'"';
    line[need] = L'\0';

    return need;
}

/*
 * Run netsh.exe with the given arguments.
 *
 * The command line is built from an argument vector and CreateProcess()
 * is given netsh.exe explicitly, so no shell ever parses the interface
 * name or the address.
 *
 * Returns:
 *   0 on success, the exit status of netsh on failure, -1 if netsh could
 *   not be started at all.
 */
static int run_netsh(const char *const *args, size_t count)
{
    WCHAR line[1024];
    WCHAR wide[256];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD status = 0;
    size_t used;
    size_t i;

    memcpy(line, L"netsh.exe", sizeof(L"netsh.exe"));
    used = wcslen(line);

    for (i = 0; i < count; i++) {
        if (psix_utf8_to_wide(args[i], wide,
                              sizeof(wide) / sizeof(wide[0])) != 0) {
            log_warn("netsh argument %zu is too long", i);
            return -1;
        }

        used = append_argument(line, used, sizeof(line) / sizeof(line[0]),
                               wide);
        if (used == 0) {
            log_warn("netsh command line too long");
            return -1;
        }
    }

    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    if (!CreateProcessW(L"netsh.exe", line, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        log_warn("Cannot run netsh (error %lu)", (unsigned long)GetLastError());
        return -1;
    }

    (void)WaitForSingleObject(pi.hProcess, INFINITE);
    (void)GetExitCodeProcess(pi.hProcess, &status);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return (int)status;
}

/*
 * Configure the adapter: bring it up, set the MTU and add the IPv6
 * address, in that order.
 *
 * Every step is idempotent: 'set' overwrites, and a failing 'add address'
 * for an address that already exists is not an error worth stopping for.
 */
static int configure_adapter(const char *name, const char *address,
                             int prefixlen, int mtu)
{
    char address_option[80];
    char mtu_option[32];

    /*
     * 'set' is idempotent. A failure here is not fatal: assigning the
     * address below also enables the interface, so this is only a head
     * start for the MTU step.
     */
    {
        const char *args[] = { "interface", "ipv6", "set", "interface",
                               name, "admin=enabled", "store=active" };

        if (run_netsh(args, sizeof(args) / sizeof(args[0])) != 0) {
            log_info("Interface '%s' was already enabled or could not be "
                     "enabled yet; continuing", name);
        }
    }

    if (mtu > 0) {
        const char *args[6];

        if (snprintf(mtu_option, sizeof(mtu_option), "mtu=%d", mtu) >=
            (int)sizeof(mtu_option)) {
            log_warn("MTU option too long");
        } else {
            args[0] = "interface";
            args[1] = "ipv6";
            args[2] = "set";
            args[3] = "subinterface";
            args[4] = name;
            args[5] = mtu_option;

            if (run_netsh(args, 6) != 0) {
                log_warn("Failed to set MTU %d on '%s'", mtu, name);
            } else {
                log_info("TUN device MTU set to %d", mtu);
            }
        }
    }

    if (address != NULL && address[0] != '\0') {
        const char *args[6];
        struct in6_addr parsed;

        if (InetPtonA(AF_INET6, address, &parsed) != 1) {
            log_error("'%s' is not a valid IPv6 address", address);
            return -1;
        }
        if (snprintf(address_option, sizeof(address_option), "%s/%d",
                     address, prefixlen) >= (int)sizeof(address_option)) {
            log_error("IPv6 address option too long");
            return -1;
        }

        args[0] = "interface";
        args[1] = "ipv6";
        args[2] = "add";
        args[3] = "address";
        args[4] = name;
        args[5] = address_option;

        if (run_netsh(args, 6) != 0) {
            /* netsh refuses a duplicate address, which is not an error. */
            log_info("netsh did not add %s to '%s' (it may already exist)",
                     address_option, name);
        } else {
            log_info("Assigned %s to '%s'", address_option, name);
        }
    }

    return 0;
}

void tun_init(tun_device_t *tun)
{
    if (tun == NULL) return;

    tun->fd = -1;
    tun->name[0] = '\0';
    tun->mtu = 0;
    tun->adapter = NULL;
    tun->session = NULL;
    tun->read_event = NULL;
}

/*
 * Open (or reuse) the Wintun adapter and configure it.
 *
 * Returns 0 on success, -1 on failure with errno set.
 */
int tun_open(tun_device_t *tun, const char *name,
             const char *address, int prefixlen, int mtu)
{
    WCHAR wname[128];
    const char *adapter_name;
    wintun_adapter_handle adapter;
    wintun_session_handle session;

    if (tun == NULL) {
        errno = EINVAL;
        return -1;
    }

    adapter_name = (name != NULL && name[0] != '\0') ? name
                                                    : DEFAULT_ADAPTER_NAME;

    if (!valid_adapter_name(adapter_name)) {
        log_error("Invalid TUN device name '%s' on Windows", adapter_name);
        errno = EINVAL;
        return -1;
    }
    if (address != NULL && address[0] != '\0') {
        struct in6_addr parsed;

        if (InetPtonA(AF_INET6, address, &parsed) != 1) {
            log_error("'%s' is not a valid IPv6 address", address);
            errno = EINVAL;
            return -1;
        }
    }
    if (prefixlen < 0 || prefixlen > 128) {
        log_error("Invalid prefix length %d", prefixlen);
        errno = EINVAL;
        return -1;
    }

    if (psix_utf8_to_wide(adapter_name, wname,
                          sizeof(wname) / sizeof(wname[0])) != 0) {
        log_error("TUN device name is too long");
        errno = EINVAL;
        return -1;
    }

    if (wintun_load() != 0) {
        errno = ENOENT;
        return -1;
    }

    /*
     * Reuse an adapter left behind by a previous run instead of creating
     * a second one; Wintun keeps it alive while any session is open, but
     * a crashed process can still leave the adapter registered.
     */
    adapter = s_api.open_adapter(wname);
    if (adapter != NULL) {
        log_info("Reusing Wintun adapter '%s'", adapter_name);
    } else {
        adapter = s_api.create_adapter(wname, L"pipesix", NULL);
        if (adapter == NULL) {
            log_error("Cannot create the Wintun adapter '%s' (error %lu). "
                      "Run pipesix as an administrator and keep wintun.dll "
                      "next to pipesix.exe", adapter_name,
                      (unsigned long)GetLastError());
            errno = EACCES;
            return -1;
        }
        log_info("Created Wintun adapter '%s'", adapter_name);
    }

    session = s_api.start_session(adapter, WINTUN_RING_CAPACITY);
    if (session == NULL) {
        log_error("Cannot start the Wintun session (error %lu)",
                  (unsigned long)GetLastError());
        s_api.close_adapter(adapter);
        errno = EIO;
        return -1;
    }

    tun->adapter = adapter;
    tun->session = session;
    tun->read_event = s_api.read_wait_event(session);
    tun->fd = -1;
    copy_name(tun->name, sizeof(tun->name), adapter_name);
    tun->mtu = mtu > 0 ? mtu : 1500;

    if (tun->read_event == NULL) {
        log_error("Wintun did not provide a read wait event");
        s_api.end_session(session);
        s_api.close_adapter(adapter);
        tun->adapter = NULL;
        tun->session = NULL;
        errno = EIO;
        return -1;
    }

    if (configure_adapter(adapter_name, address, prefixlen, mtu) != 0) {
        tun_close(tun);
        return -1;
    }

    log_info("TUN device '%s' ready (Wintun, mtu %d)", tun->name, tun->mtu);
    return 0;
}

/*
 * Wait until a packet can be read from the adapter.
 *
 * Returns 1 when readable, 0 on timeout, -1 on error, so client.c can use
 * it exactly like poll() on the POSIX backends.
 */
int tun_wait(tun_device_t *tun, int timeout_ms)
{
    DWORD rc;

    if (tun == NULL || tun->read_event == NULL) {
        errno = EBADF;
        return -1;
    }

    rc = WaitForSingleObject((HANDLE)tun->read_event,
                            timeout_ms < 0 ? INFINITE : (DWORD)timeout_ms);

    if (rc == WAIT_OBJECT_0) {
        return 1;
    }
    if (rc == WAIT_TIMEOUT) {
        return 0;
    }

    errno = EIO;
    return -1;
}

/*
 * Read one packet from the adapter.
 *
 * Wintun donates a buffer that stays valid only until it is released, so
 * the packet is copied into the caller's buffer and released at once. A
 * packet larger than the caller's buffer is dropped: the caller's buffer
 * is PIPESIX_MAX_PACKET, which is larger than any frame the protocol
 * accepts.
 */
ssize_t tun_read(tun_device_t *tun, void *buf, size_t size)
{
    DWORD packet_size = 0;
    BYTE *packet;

    if (tun == NULL || tun->session == NULL || buf == NULL) {
        errno = EBADF;
        return -1;
    }

    packet = s_api.receive_packet(tun->session, &packet_size);
    if (packet == NULL) {
        if (GetLastError() == ERROR_NO_MORE_ITEMS) {
            return 0; /* Nothing queued right now. */
        }
        log_error("Wintun receive failed (error %lu)",
                  (unsigned long)GetLastError());
        errno = EIO;
        return -1;
    }

    if ((size_t)packet_size > size) {
        log_warn("Dropping an oversized packet (%lu bytes)", 
                 (unsigned long)packet_size);
        s_api.release_receive_packet(tun->session, packet);
        errno = EMSGSIZE;
        return -1;
    }

    memcpy(buf, packet, (size_t)packet_size);
    s_api.release_receive_packet(tun->session, packet);

    return (ssize_t)packet_size;
}

/*
 * Write one packet to the adapter.
 *
 * The send ring can be temporarily full, which is not an error: retry
 * briefly before giving up so a burst is not reported as a failure.
 */
ssize_t tun_write(tun_device_t *tun, const void *buf, size_t length)
{
    int attempt;

    if (tun == NULL || tun->session == NULL || buf == NULL) {
        errno = EBADF;
        return -1;
    }
    if (length == 0 || length > 0xFFFFFFFFu) {
        errno = EINVAL;
        return -1;
    }

    for (attempt = 0; attempt < 10; attempt++) {
        BYTE *packet = s_api.allocate_send_packet(tun->session,
                                                  (DWORD)length);

        if (packet != NULL) {
            memcpy(packet, buf, length);
            s_api.send_packet(tun->session, packet);
            return (ssize_t)length;
        }

        Sleep(1);
    }

    log_warn("Wintun send ring is full; dropping a %zu-byte packet", length);
    errno = ENOBUFS;
    return -1;
}

void tun_close(tun_device_t *tun)
{
    if (tun == NULL) return;

    if (tun->session != NULL) {
        log_info("Closing TUN device '%s'", tun->name);
        s_api.end_session(tun->session);
        tun->session = NULL;
    }
    if (tun->adapter != NULL) {
        s_api.close_adapter(tun->adapter);
        tun->adapter = NULL;
    }

    tun->read_event = NULL;
    tun->fd = -1;
    tun->name[0] = '\0';
    tun->mtu = 0;
}
