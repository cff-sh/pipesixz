/*
 * policy.h - Per-client Rate and Quota Enforcement
 *
 * Two independent limits, both optional and both applied by the server
 * data path:
 *
 *   - a token bucket that caps a client's rate in bytes per second;
 *   - a UTC-day byte quota shared by both directions.
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
 * Per-client daily quota.
 *
 * 'used' and 'day' are atomic because the receiver charges traffic the
 * client sent and the sender charges traffic the client received, and
 * those run in different threads.
 */
typedef struct {
    uint64_t limit;         /* bytes per UTC day, 0 = unlimited */
    _Atomic uint64_t used;  /* bytes charged for 'day' */
    _Atomic int      day;   /* UTC day the counter belongs to, -1 = unset */
} pipesix_quota_t;

void policy_quota_init(pipesix_quota_t *quota, uint64_t limit_bytes);

/*
 * Charge bytes against the quota for 'day'.
 *
 * Returns 1 while the client is within its budget, 0 once it is not.
 * The bytes are charged either way, so exceeding the quota does not let
 * the next packet through. The counter resets when 'day' changes; two
 * threads racing across midnight may lose a handful of bytes from the
 * count, which is deliberate: the data path must not take a lock to
 * account for a policy.
 */
int policy_quota_charge(pipesix_quota_t *quota, size_t bytes, int day);

/*
 * Bytes still available in the quota for 'day'.
 *
 * Returns 0 when the client has no quota or has used it all. Read-only:
 * a scrape must not reset the counter, so a new day is reported as a full
 * budget without storing anything.
 */
uint64_t policy_quota_remaining(const pipesix_quota_t *quota, int day);

/*
 * Monotonic milliseconds, for the token buckets. Monotonic matters: a
 * wall-clock step must not freeze a bucket or hand a client a burst it
 * did not earn.
 */
uint64_t policy_now_ms(void);

/* UTC day number (days since the epoch) for a Unix timestamp. */
int policy_day(time_t now);

#endif /* PIPESIX_POLICY_H */
