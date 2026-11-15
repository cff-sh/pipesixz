/*
 * policy.h - Per-client Rate and Quota Enforcement
 *
 * Two independent limits, both optional and both applied by the server
 * data path:
 *
 *   - a token bucket that caps a client's rate in bytes per second;
 *   - a byte quota for a UTC day or a UTC calendar month.
 *
 * Every configured client is accounted for, with or without a quota, so
 * 'pipesix --usage' can report the bytes a client moved this period and a
 * limit added later does not start from zero.
 *
 * Neither structure knows about clients, sockets or configuration, and
 * the time is passed in rather than read, so both can be unit-tested
 * without a clock, a tunnel or root privileges.
 */

#ifndef PIPESIX_POLICY_H
#define PIPESIX_POLICY_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* Smallest bucket that can still pass one full frame. */
#define POLICY_MIN_BURST 1600u

/* Longest client id accepted by the state file, including the NUL. */
#define POLICY_MAX_ID 33

/* Quota period selectors, matching the 'quota_period' configuration key. */
#define POLICY_PERIOD_DAILY   0
#define POLICY_PERIOD_MONTHLY 1

/*
 * Token bucket. A rate of 0 means unlimited, and the bucket functions
 * then always allow the packet without touching the counters.
 */
typedef struct {
    uint64_t rate_bps;  /* bytes per second, 0 = unlimited */
    uint64_t burst;     /* bucket size in bytes, 0 when unlimited */
    uint64_t tokens;    /* bytes available right now */
    uint64_t last_ms;   /* timestamp of the last refill */
} pipesix_bucket_t;

/*
 * Start a bucket with a one-second burst, or one full frame when the
 * configured rate is slower than that. Without the floor a 1 kbit/s cap
 * would never let a single 1500-byte packet through.
 */
void policy_bucket_init(pipesix_bucket_t *bucket, uint64_t rate_bps,
                        uint64_t now_ms);

/*
 * Charge one packet against the bucket.
 *
 * Returns 1 when it fits, 0 when it has to be dropped. A dropped packet
 * is not charged, so a client that keeps sending does not build up a
 * debt it could clear by staying quiet for a moment.
 */
int policy_bucket_allow(pipesix_bucket_t *bucket, size_t bytes,
                        uint64_t now_ms);

/*
 * Per-client usage for the current period, and the quota that may cap it.
 *
 * 'used' and 'period' are atomic because the receiver charges traffic the
 * client sent and the sender charges traffic the client received, and
 * those run in different threads.
 */
typedef struct {
    uint64_t limit;          /* bytes per period, 0 = unlimited */
    _Atomic uint64_t used;   /* bytes charged for 'period' */
    _Atomic int      period; /* period index, -1 = unset */
} pipesix_quota_t;

void policy_quota_init(pipesix_quota_t *quota, uint64_t limit_bytes);

/*
 * Charge bytes against the quota for 'period'.
 *
 * Returns 1 while the client is within its budget, 0 once it is not.
 * The bytes are charged either way, so exceeding the quota does not let
 * the next packet through, and a quota of 0 still counts usage instead of
 * letting it pass unseen. The counter resets when 'period' changes; two
 * threads racing across a period boundary may lose a handful of bytes from
 * the count, which is deliberate: the data path must not take a lock to
 * account for a policy.
 */
int policy_quota_charge(pipesix_quota_t *quota, size_t bytes, int period);

/*
 * Bytes still available in the quota for 'period'.
 *
 * Returns 0 when the client has no quota or has used it all. Read-only:
 * a scrape must not reset the counter, so a new period is reported as a
 * full budget without storing anything.
 */
uint64_t policy_quota_remaining(const pipesix_quota_t *quota, int period);

/*
 * Bytes charged for 'period'.
 *
 * Returns 0 when the counter belongs to another period. Unlike
 * policy_quota_remaining() this works for a client without a quota, which
 * is what 'pipesix --usage' reports.
 */
uint64_t policy_quota_used(const pipesix_quota_t *quota, int period);

/*
 * Put a counter back to a value read from the state file.
 *
 * Only meaningful at startup or under the server's session lock: it
 * replaces the counter without charging anything.
 */
void policy_quota_restore(pipesix_quota_t *quota, uint64_t used, int period);

/*
 * Index of the quota period that contains 'now'.
 *
 * Daily periods count days since the epoch; monthly periods count calendar
 * months since January 1970 (year * 12 + month - 1). Both are pure
 * arithmetic, so the data path can call this from several threads without
 * touching gmtime()'s shared state.
 */
int policy_period(time_t now, int monthly);

/* Unix timestamp of the first second of 'period'. */
time_t policy_period_start(int period, int monthly);

/* Unix timestamp of the first second after 'period'. */
time_t policy_period_end(int period, int monthly);

/*
 * One client's persisted usage.
 */
typedef struct {
    char     id[POLICY_MAX_ID];
    int64_t  period; /* period index, as policy_period() */
    uint64_t used;   /* bytes charged that period */
} policy_usage_t;

/*
 * Write usage to 'path', replacing it atomically.
 *
 * The file carries the period kind, so state saved under a daily quota is
 * not mistaken for monthly usage (or the other way round). It is written
 * to '<path>.tmp', flushed, and renamed over the destination, so a crash
 * mid-write leaves the previous state file intact. It is created with
 * mode 0600.
 *
 * Returns:
 *   0 on success, -1 on failure (the previous file is left alone)
 */
int policy_state_save(const char *path, int monthly,
                      const policy_usage_t *usage, int count);

/*
 * Read usage lines from 'path'.
 *
 * A missing file is not an error: it means the server has not saved any
 * state yet, so *count is 0 and the call returns 0. *monthly reports the
 * period kind the file was written with (daily when the file predates the
 * period support). Malformed or overlong lines are skipped, and at most
 * max entries are stored.
 *
 * Returns:
 *   0 on success (including a missing file), -1 when the file exists but
 *   cannot be read
 */
int policy_state_load(const char *path, int *monthly,
                      policy_usage_t *usage, int max, int *count);

/*
 * Monotonic milliseconds, for the token buckets. Monotonic matters: a
 * wall-clock step must not freeze a bucket or hand a client a burst it
 * did not earn.
 */
uint64_t policy_now_ms(void);

#endif /* PIPESIX_POLICY_H */
