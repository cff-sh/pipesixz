/*
 * admin.c - Administrative roles and command authorization
 */

/* struct ucred and SO_PEERCRED are GNU extensions on glibc. */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "admin.h"
#include "logger.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(_WIN32)
#include <grp.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#define ADMIN_MAX_GROUPS 128

static int s_configured;
static int s_invalid;
static int s_have_access;
static int s_have_admin;
static int s_have_operator;
static unsigned long s_access_gid;
static unsigned long s_admin_gid;
static unsigned long s_operator_gid;

#if !defined(_WIN32)
#if defined(__APPLE__)
typedef int admin_gid_t;
#else
typedef gid_t admin_gid_t;
#endif

static int resolve_group(const char *name, unsigned long *gid)
{
    struct group *group;

    if (name == NULL || name[0] == '\0' || gid == NULL) {
        return -1;
    }

    group = getgrnam(name);
    if (group == NULL) {
        return -1;
    }

    *gid = (unsigned long)group->gr_gid;
    return 0;
}

static int uid_in_group(unsigned long uid, unsigned long gid)
{
    struct passwd pw;
    struct passwd *result = NULL;
    admin_gid_t groups[ADMIN_MAX_GROUPS];
    char buf[4096];
    int ngroups = ADMIN_MAX_GROUPS;
    int i;
    int rc;

    rc = getpwuid_r((uid_t)uid, &pw, buf, sizeof(buf), &result);
    if (rc != 0 || result == NULL) {
        return 0;
    }

    groups[0] = (admin_gid_t)pw.pw_gid;
    ngroups = ADMIN_MAX_GROUPS;
    if (getgrouplist(pw.pw_name, (admin_gid_t)pw.pw_gid, groups,
                     &ngroups) < 0) {
        return 0;
    }

    for (i = 0; i < ngroups; i++) {
        if ((unsigned long)groups[i] == gid) {
            return 1;
        }
    }

    return 0;
}
#endif

int admin_configure(const char *access_group, const char *admin_group,
                    const char *operator_group)
{
    s_configured = 1;
    s_invalid = 0;
    s_have_access = 0;
    s_have_admin = 0;
    s_have_operator = 0;
    s_access_gid = 0;
    s_admin_gid = 0;
    s_operator_gid = 0;

    if (access_group == NULL || access_group[0] == '\0') {
        if ((admin_group != NULL && admin_group[0] != '\0') ||
            (operator_group != NULL && operator_group[0] != '\0')) {
            log_error("control_admin_group and control_operator_group "
                      "require control_group");
            s_invalid = 1;
            return -1;
        }
        return 0;
    }

#if defined(_WIN32)
    (void)admin_group;
    (void)operator_group;
    log_error("control_group is not supported on Windows: the control "
              "channel is not available");
    s_invalid = 1;
    return -1;
#else
    if (resolve_group(access_group, &s_access_gid) != 0) {
        log_error("control_group '%s' does not exist", access_group);
        s_invalid = 1;
        return -1;
    }
    s_have_access = 1;

    if (admin_group != NULL && admin_group[0] != '\0') {
        if (resolve_group(admin_group, &s_admin_gid) != 0) {
            log_error("control_admin_group '%s' does not exist", admin_group);
            s_invalid = 1;
            return -1;
        }
        s_have_admin = 1;
    }

    if (operator_group != NULL && operator_group[0] != '\0') {
        if (resolve_group(operator_group, &s_operator_gid) != 0) {
            log_error("control_operator_group '%s' does not exist",
                      operator_group);
            s_invalid = 1;
            return -1;
        }
        s_have_operator = 1;
    }

    return 0;
#endif
}

int admin_control_gid(unsigned long *gid)
{
    if (!s_have_access || gid == NULL) {
        return 0;
    }

    *gid = s_access_gid;
    return 1;
}

int admin_role_for_uid(unsigned long uid, admin_role_t *role)
{
    if (role == NULL || s_invalid) {
        return -1;
    }

    /*
     * No access group means the historical owner-only control socket and
     * CLI. The filesystem still decides who can reach the socket or write
     * the configuration; this preserves existing installations.
     */
    if (!s_have_access) {
        *role = ADMIN_ROLE_ADMIN;
        return 0;
    }

    if (uid == 0) {
        *role = ADMIN_ROLE_ADMIN;
        return 0;
    }

#if defined(_WIN32)
    (void)uid;
    return -1;
#else
    if (!uid_in_group(uid, s_access_gid)) {
        return -1;
    }

    if (s_have_admin && uid_in_group(uid, s_admin_gid)) {
        *role = ADMIN_ROLE_ADMIN;
        return 0;
    }

    if (s_have_operator && uid_in_group(uid, s_operator_gid)) {
        *role = ADMIN_ROLE_OPERATOR;
        return 0;
    }

    *role = ADMIN_ROLE_VIEWER;
    return 0;
#endif
}

int admin_current_role(admin_role_t *role)
{
#if defined(_WIN32)
    return admin_role_for_uid(0, role);
#else
    return admin_role_for_uid((unsigned long)getuid(), role);
#endif
}

int admin_peer_role(int fd, admin_role_t *role, unsigned long *uid,
                    unsigned long *pid)
{
#if defined(_WIN32)
    (void)fd;
    (void)role;
    (void)uid;
    (void)pid;
    errno = ENOTSUP;
    return -1;
#else
    unsigned long peer_uid;
    unsigned long peer_pid = 0;

#if defined(SO_PEERCRED)
    struct ucred cred;
    socklen_t len = (socklen_t)sizeof(cred);

    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
        return -1;
    }
    peer_uid = (unsigned long)cred.uid;
    peer_pid = (unsigned long)cred.pid;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__)
    uid_t peer_uid_native;
    gid_t peer_gid_native;

    if (getpeereid(fd, &peer_uid_native, &peer_gid_native) != 0) {
        return -1;
    }
    (void)peer_gid_native;
    peer_uid = (unsigned long)peer_uid_native;
#else
    (void)fd;
    (void)role;
    (void)uid;
    (void)pid;
    errno = ENOTSUP;
    return -1;
#endif

    if (peer_uid == 0) {
        if (role != NULL) {
            *role = ADMIN_ROLE_ADMIN;
        }
        if (uid != NULL) {
            *uid = peer_uid;
        }
        if (pid != NULL) {
            *pid = peer_pid;
        }
        return 0;
    }

    if (role == NULL || admin_role_for_uid(peer_uid, role) != 0) {
        return -1;
    }

    if (uid != NULL) {
        *uid = peer_uid;
    }
    if (pid != NULL) {
        *pid = peer_pid;
    }
    return 0;
#endif
}

int admin_user_name(unsigned long uid, char *out, size_t out_size)
{
    if (out == NULL || out_size == 0) {
        return -1;
    }

#if defined(_WIN32)
    (void)uid;
    snprintf(out, out_size, "%s",
             getenv("USERNAME") != NULL ? getenv("USERNAME") : "unknown");
    return 0;
#else
    struct passwd pw;
    struct passwd *result = NULL;
    char buf[4096];
    int rc;

    rc = getpwuid_r((uid_t)uid, &pw, buf, sizeof(buf), &result);
    if (rc == 0 && result != NULL) {
        snprintf(out, out_size, "%s", result->pw_name);
    } else {
        snprintf(out, out_size, "uid:%lu", uid);
    }
    return 0;
#endif
}

const char *admin_role_name(admin_role_t role)
{
    switch (role) {
        case ADMIN_ROLE_ADMIN:    return "admin";
        case ADMIN_ROLE_OPERATOR: return "operator";
        case ADMIN_ROLE_VIEWER:   return "viewer";
        default:                  return "none";
    }
}

int admin_role_satisfies(admin_role_t have, admin_role_t need)
{
    return have != ADMIN_ROLE_NONE && need != ADMIN_ROLE_NONE && have >= need;
}

int admin_request_allowed(admin_role_t role, const char *request)
{
    if (request == NULL || role == ADMIN_ROLE_NONE) {
        return 0;
    }

    if (role == ADMIN_ROLE_ADMIN) {
        return 1;
    }

    if (strcmp(request, "status") == 0 ||
        strcmp(request, "status json") == 0 ||
        strcmp(request, "stats") == 0 ||
        strcmp(request, "metrics") == 0 ||
        strcmp(request, "usage") == 0 ||
        strcmp(request, "usage json") == 0 ||
        strcmp(request, "usage csv") == 0) {
        return 1;
    }

    if (role == ADMIN_ROLE_OPERATOR &&
        (strcmp(request, "reload") == 0 ||
         strncmp(request, "kick ", 5) == 0)) {
        return 1;
    }

    return 0;
}

int admin_request_is_mutation(const char *request)
{
    if (request == NULL) {
        return 0;
    }

    return strcmp(request, "reload") == 0 ||
           strncmp(request, "kick ", 5) == 0 ||
           strncmp(request, "usage-reset ", 12) == 0 ||
           strncmp(request, "usage-credit ", 13) == 0 ||
           strncmp(request, "usage-add ", 10) == 0;
}
