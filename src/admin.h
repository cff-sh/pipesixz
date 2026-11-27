/*
 * admin.h - Administrative roles and command authorization
 *
 * The control channel and the provisioning CLI share one role model:
 *
 *   viewer    read-only status, usage, metrics and statistics
 *   operator  viewer plus session kick and configuration reload
 *   admin     full configuration, credential and accounting changes
 *
 * Roles are assigned with POSIX groups. 'control_group' grants access to
 * the UNIX control socket; members of 'control_admin_group' and
 * 'control_operator_group' are elevated, and every other member of
 * 'control_group' is a viewer. Root is always an administrator. Without
 * any control_* setting the socket remains owner-only and the process
 * owner is the administrator, preserving existing installations.
 *
 * All group names are resolved when admin_configure() is called. A
 * missing group is an error rather than a silent fallback, because a
 * typo must not quietly widen access.
 */

#ifndef PIPESIX_ADMIN_H
#define PIPESIX_ADMIN_H

#include <stddef.h>

#define ADMIN_MAX_GROUP 64

typedef enum {
    ADMIN_ROLE_NONE = -1,
    ADMIN_ROLE_VIEWER = 0,
    ADMIN_ROLE_OPERATOR = 1,
    ADMIN_ROLE_ADMIN = 2
} admin_role_t;

/*
 * Resolve the three configured groups. Any argument may be NULL or empty.
 * Calling this again replaces the previous role table.
 *
 * Returns 0 on success, -1 when a configured group does not exist or an
 * elevated group is configured without 'control_group'.
 */
int admin_configure(const char *access_group, const char *admin_group,
                    const char *operator_group);

/*
 * Return the configured control-socket group, if any.
 *
 * Returns 1 and stores the numeric gid when access is group-based, 0 when
 * the socket stays owner-only.
 */
int admin_control_gid(unsigned long *gid);

/*
 * Resolve one uid to a role.
 *
 * Without a configured access group the legacy owner-only model applies
 * and every caller is an administrator; the caller must still pass the
 * control socket's filesystem permissions. With groups configured, root
 * and members of the access group are admitted, and the role groups
 * elevate them.
 *
 * Returns 0 on success, -1 when the uid is not allowed.
 */
int admin_role_for_uid(unsigned long uid, admin_role_t *role);

/* Resolve the current process uid. */
int admin_current_role(admin_role_t *role);

/*
 * Read the peer credentials of a connected UNIX socket and resolve the
 * peer's role. Returns 0 on success, -1 when credentials are unavailable
 * or the peer is not authorized.
 *
 * uid and pid may be NULL when the caller does not need them. pid is 0 on
 * platforms that expose only uid/gid peer credentials.
 */
int admin_peer_role(int fd, admin_role_t *role, unsigned long *uid,
                    unsigned long *pid);

/* Resolve a uid to a printable account name, or "uid:<number>". */
int admin_user_name(unsigned long uid, char *out, size_t out_size);

/* Stable role name for logs and audit records. */
const char *admin_role_name(admin_role_t role);

/* Whether 'have' is at least 'need'. */
int admin_role_satisfies(admin_role_t have, admin_role_t need);

/*
 * Whether a control request is allowed for a role.
 *
 * Viewer requests are status, usage, metrics and statistics. Operator
 * requests additionally include kick and reload. Accounting adjustments
 * and unknown commands are administrator-only.
 */
int admin_request_allowed(admin_role_t role, const char *request);

/* Whether a control request changes state and should be audited. */
int admin_request_is_mutation(const char *request);

#endif /* PIPESIX_ADMIN_H */
