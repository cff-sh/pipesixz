/*
 * audit.h - Append-only security audit records
 *
 * The normal log is for operators watching the process. The audit log is
 * a separate JSONL file for events that need to survive log rotation and
 * be correlated later: handshakes, credential changes, ACL drops, quota
 * exhaustion and administrative client-state changes.
 *
 * Records are one JSON object per line and are written with O_APPEND, so
 * several processes (a running server and a provisioning command) can
 * append to the same file without overwriting one another. An empty path
 * disables auditing.
 */

#ifndef PIPESIX_AUDIT_H
#define PIPESIX_AUDIT_H

#include <stddef.h>

/*
 * Open or replace the audit file. A path of NULL or "" disables auditing
 * and closes the previous file. The file is created with mode 0600 on
 * POSIX when it does not exist.
 *
 * Returns 0 on success, -1 on failure (auditing remains disabled).
 */
int audit_open(const char *path);

/* Close the audit file. Safe to call more than once. */
void audit_close(void);

/*
 * Append one audit event. event should be a stable short identifier such
 * as "handshake" or "acl_denied"; client and peer may be NULL or empty.
 * The remaining arguments are a printf-style message.
 *
 * A missing audit file is a no-op. A write failure disables auditing
 * until the next audit_open() rather than recursing through the logger.
 */
void audit_event(const char *event, const char *client, const char *peer,
                 const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 4, 5)))
#endif
    ;

#endif /* PIPESIX_AUDIT_H */
