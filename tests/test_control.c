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
#include "logger.h"

#include <errno.h>
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
    unlink(path);

    if (failed) {
        return EXIT_FAILURE;
    }

    printf("control channel: OK\n");
    return EXIT_SUCCESS;
}
