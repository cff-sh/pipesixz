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

#else /* POSIX: signals carry these requests already */

void control_start(const char *config_path)
{
    (void)config_path;
}

void control_stop(void)
{
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
