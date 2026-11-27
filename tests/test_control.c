/*
 * test_control.c - Control Channel Tests
 *
 * Exercises the UNIX-socket control channel end to end: a handler stands
 * in for the server, so the test needs no TUN device and no privileges.
 *
 * Covered:
 *   - the request/reply round trip over the derived socket path
 *   - a handler that accepts a request (reply starts with "OK")
 *   - a handler that rejects a request (reply starts with "ERR")
 *   - unknown requests reach the handler unchanged
 */

#include "control.h"
#include "admin.h"
#include "audit.h"
#include "logger.h"

#include <errno.h>
#if !defined(_WIN32)
#include <grp.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int s_handled;

static int test_handler(const char *request, char *reply, size_t reply_size,
                        void *arg)
{
    (void)arg;
    s_handled++;

    if (strcmp(request, "status") == 0) {
        snprintf(reply, reply_size, "OK\nmode: test\n");
        return 0;
    }

    if (strcmp(request, "stats") == 0) {
        snprintf(reply, reply_size, "OK\nstats[test]: uptime=0s\n");
        return 0;
    }

    if (strcmp(request, "fail") == 0) {
        snprintf(reply, reply_size, "ERR deliberate\n");
        return -1;
    }

    snprintf(reply, reply_size, "ERR unknown request '%s'\n", request);
    return -1;
}

/*
 * Send a request and check the reply contains needle and, when
 * expect_ok is set, starts with "OK".
 */
static int check_reply(const char *path, const char *request,
                       const char *needle, int expect_ok)
{
    char reply[1024];

    if (control_request(path, request, reply, sizeof(reply)) != 0) {
        fprintf(stderr, "control: request '%s' failed: %s\n",
                request, strerror(errno));
        return -1;
    }

    if (strstr(reply, needle) == NULL) {
        fprintf(stderr, "control: request '%s': expected '%s' in '%s'\n",
                request, needle, reply);
        return -1;
    }

    if ((strncmp(reply, "OK", 2) == 0) != expect_ok) {
        fprintf(stderr, "control: request '%s': unexpected status in '%s'\n",
                request, reply);
        return -1;
    }

    return 0;
}

static int test_admin_matrix(void)
{
    int failed = 0;

    if (!admin_request_allowed(ADMIN_ROLE_VIEWER, "status") ||
        !admin_request_allowed(ADMIN_ROLE_VIEWER, "usage json") ||
        !admin_request_allowed(ADMIN_ROLE_VIEWER, "metrics") ||
        !admin_request_allowed(ADMIN_ROLE_VIEWER, "stats")) {
        fprintf(stderr, "admin: viewer read commands were denied\n");
        failed = 1;
    }
    if (admin_request_allowed(ADMIN_ROLE_VIEWER, "kick alice") ||
        admin_request_allowed(ADMIN_ROLE_VIEWER, "reload") ||
        admin_request_allowed(ADMIN_ROLE_VIEWER, "usage-reset alice")) {
        fprintf(stderr, "admin: viewer was allowed to change state\n");
        failed = 1;
    }
    if (!admin_request_allowed(ADMIN_ROLE_OPERATOR, "kick alice") ||
        !admin_request_allowed(ADMIN_ROLE_OPERATOR, "reload")) {
        fprintf(stderr, "admin: operator was denied kick or reload\n");
        failed = 1;
    }
    if (admin_request_allowed(ADMIN_ROLE_OPERATOR, "usage-reset alice")) {
        fprintf(stderr, "admin: operator was allowed an accounting change\n");
        failed = 1;
    }
    if (!admin_request_allowed(ADMIN_ROLE_ADMIN, "usage-reset alice")) {
        fprintf(stderr, "admin: administrator was denied an accounting change\n");
        failed = 1;
    }
    if (strcmp(admin_role_name(ADMIN_ROLE_ADMIN), "admin") != 0 ||
        strcmp(admin_role_name(ADMIN_ROLE_OPERATOR), "operator") != 0 ||
        strcmp(admin_role_name(ADMIN_ROLE_VIEWER), "viewer") != 0) {
        fprintf(stderr, "admin: role names changed\n");
        failed = 1;
    }
    if (!admin_role_satisfies(ADMIN_ROLE_ADMIN, ADMIN_ROLE_OPERATOR) ||
        admin_role_satisfies(ADMIN_ROLE_VIEWER, ADMIN_ROLE_OPERATOR)) {
        fprintf(stderr, "admin: role ordering is wrong\n");
        failed = 1;
    }

    return failed;
}

static int test_audit_actor(void)
{
    char path[] = "/tmp/pipesix-audit-test-XXXXXX";
    char body[2048];
    FILE *fp;
    int fd;
    int failed = 0;
    size_t used;

    fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    close(fd);

    if (audit_open(path) != 0) {
        fprintf(stderr, "audit: cannot open test file: %s\n",
                strerror(errno));
        unlink(path);
        return 1;
    }

    audit_set_actor("alice", 1000, "admin", "req-1");
    audit_event("test", "client", "peer", "hello");
    audit_close();
    audit_clear_actor();

    fp = fopen(path, "r");
    used = (fp != NULL) ? fread(body, 1, sizeof(body) - 1, fp) : 0;
    if (fp != NULL) {
        fclose(fp);
    }
    body[used] = '\0';

    if (strstr(body, "\"actor\":\"alice\"") == NULL ||
        strstr(body, "\"actor_uid\":1000") == NULL ||
        strstr(body, "\"role\":\"admin\"") == NULL ||
        strstr(body, "\"request_id\":\"req-1\"") == NULL) {
        fprintf(stderr, "audit: actor fields missing from '%s'\n", body);
        failed = 1;
    }

    unlink(path);
    return failed;
}

static int test_control_config(void)
{
    int failed = 0;

    if (control_configure("pipesix-no-such-control-group", NULL, NULL) == 0) {
        fprintf(stderr, "admin: a missing control group was accepted\n");
        failed = 1;
    }
    if (control_configure(NULL, NULL, NULL) != 0) {
        fprintf(stderr, "admin: clearing the role table failed\n");
        failed = 1;
    }

    return failed;
}

/*
 * With an access group configured but no elevation group, the current
 * non-root user is a viewer. This exercises the real peer-credential path
 * rather than only the request matrix.
 */
static int test_viewer_socket(const char *path)
{
#if !defined(_WIN32)
    struct group *group;
    int before;
    int failed = 0;

    if (getuid() == 0) {
        return 0;
    }

    group = getgrgid(getgid());
    if (group == NULL) {
        return 0;
    }

    if (control_configure(group->gr_name, NULL, NULL) != 0) {
        fprintf(stderr, "admin: cannot configure the viewer group\n");
        return 1;
    }

    control_start(path);
    before = s_handled;

    if (check_reply(path, "status", "mode: test", 1) != 0) failed = 1;
    if (check_reply(path, "kick alice", "permission denied", 0) != 0) {
        failed = 1;
    }
    if (check_reply(path, "usage-reset alice", "permission denied", 0) != 0) {
        failed = 1;
    }
    if (s_handled != before + 1) {
        fprintf(stderr, "admin: a denied request reached the handler\n");
        failed = 1;
    }

    control_stop();
    if (control_configure(NULL, NULL, NULL) != 0) {
        failed = 1;
    }

    return failed;
#else
    (void)path;
    return 0;
#endif
}

/*
 * JSON escaping: quotes, backslashes, control bytes and truncation.
 */
static int test_json_escape(void)
{
    char out[64];
    int failed = 0;

    if (control_json_escape("plain", out, sizeof(out)) != 0 ||
        strcmp(out, "plain") != 0) {
        fprintf(stderr, "json: plain string changed\n");
        failed = 1;
    }

    if (control_json_escape("a\"b\\c\nd", out, sizeof(out)) != 0 ||
        strcmp(out, "a\\\"b\\\\c\\nd") != 0) {
        fprintf(stderr, "json: quote/backslash escaping failed: '%s'\n", out);
        failed = 1;
    }

    if (control_json_escape("tab\there", out, sizeof(out)) != 0 ||
        strcmp(out, "tab\\there") != 0) {
        fprintf(stderr, "json: tab escaping failed: '%s'\n", out);
        failed = 1;
    }

    if (control_json_escape("\x01", out, sizeof(out)) != 0 ||
        strcmp(out, "\\u0001") != 0) {
        fprintf(stderr, "json: control byte escaping failed: '%s'\n", out);
        failed = 1;
    }

    /* A partial escape is worse than none: report failure and clear. */
    if (control_json_escape("\"", out, 2) == 0 || out[0] != '\0') {
        fprintf(stderr, "json: truncation not reported\n");
        failed = 1;
    }

    return failed;
}

int main(void)
{
    char path[] = "/tmp/pipesix-control-test-XXXXXX";
    int fd;
    int failed = 0;

    fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        return EXIT_FAILURE;
    }
    close(fd);

    logger_init(NULL);
    logger_set_level(LOG_ERROR);

    if (test_json_escape() != 0) failed = 1;
    if (test_admin_matrix() != 0) failed = 1;
    if (test_audit_actor() != 0) failed = 1;
    if (test_control_config() != 0) failed = 1;

    control_set_handler(test_handler, NULL);
    control_start(path);

    if (check_reply(path, "status", "mode: test", 1) != 0) failed = 1;
    if (check_reply(path, "stats", "stats[test]", 1) != 0) failed = 1;
    if (check_reply(path, "fail", "ERR deliberate", 0) != 0) failed = 1;
    if (check_reply(path, "nonsense", "unknown request 'nonsense'", 0) != 0) {
        failed = 1;
    }

    if (s_handled != 4) {
        fprintf(stderr, "control: handler saw %d request(s), expected 4\n",
                s_handled);
        failed = 1;
    }

    control_stop();
    if (test_viewer_socket(path) != 0) failed = 1;
    unlink(path);

    if (failed) {
        return EXIT_FAILURE;
    }

    printf("control channel: OK\n");
    return EXIT_SUCCESS;
}
