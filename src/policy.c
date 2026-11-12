/*
 * policy.c - Per-client Rate and Quota Enforcement
 *
 * The bucket refills from a wall-clock timestamp instead of a timer
 * thread: one subtraction per packet is cheaper than waking up every
 * client's bucket on a schedule, and it needs no state outside the
 * session. A clock that jumps backwards simply refills nothing until it
 * catches up, because elapsed time is clamped to zero.
 *
 * The quota is per client id and per UTC day. Keeping the counter out of
 * the session is what stops a reconnect (or a key rotation) from resetting
 * the budget.
 */

#include "policy.h"

#include <stdatomic.h>
#include <stdint.h>
#include <time.h>

void policy_bucket_init(pipesix_bucket_t *bucket, uint64_t rate_bps,
                        uint64_t now_ms)
{
    if (bucket == NULL) {
        return;
    }

    bucket->rate_bps = rate_bps;
    bucket->last_ms = now_ms;
    bucket->burst = 0;
    bucket->tokens = 0;

    if (rate_bps == 0) {
        return;
    }

    bucket->burst = rate_bps;
    if (bucket->burst < POLICY_MIN_BURST) {
        bucket->burst = POLICY_MIN_BURST;
    }
    bucket->tokens = bucket->burst;
}

int policy_bucket_allow(pipesix_bucket_t *bucket, size_t bytes,
                        uint64_t now_ms)
{
    uint64_t elapsed;
    uint64_t needed;

    if (bucket == NULL || bucket->rate_bps == 0) {
        return 1;
    }

    if (now_ms < bucket->last_ms) {
        now_ms = bucket->last_ms;
    }
    elapsed = now_ms - bucket->last_ms;
    bucket->last_ms = now_ms;

    if (elapsed > 0) {
        uint64_t added;

        if (elapsed > UINT64_MAX / bucket->rate_bps) {
            added = bucket->burst;
        } else {
            added = (elapsed * bucket->rate_bps) / 1000u;
        }

        if (added >= bucket->burst - bucket->tokens) {
            bucket->tokens = bucket->burst;
        } else {
            bucket->tokens += added;
        }
    }

    needed = (uint64_t)bytes;
    if (needed > bucket->tokens) {
        return 0;
    }

    bucket->tokens -= needed;
    return 1;
}

void policy_quota_init(pipesix_quota_t *quota, uint64_t limit_bytes)
{
    if (quota == NULL) {
        return;
    }

    quota->limit = limit_bytes;
    atomic_init(&quota->used, 0);
    atomic_init(&quota->day, -1);
}

int policy_quota_charge(pipesix_quota_t *quota, size_t bytes, int day)
{
    uint64_t used;

    if (quota == NULL || quota->limit == 0) {
        return 1;
    }

    if (atomic_load_explicit(&quota->day, memory_order_relaxed) != day) {
        atomic_store_explicit(&quota->day, day, memory_order_relaxed);
        atomic_store_explicit(&quota->used, 0, memory_order_relaxed);
    }

    used = atomic_fetch_add_explicit(&quota->used, (uint64_t)bytes,
                                     memory_order_relaxed) + (uint64_t)bytes;

    return used <= quota->limit;
}

uint64_t policy_quota_remaining(const pipesix_quota_t *quota, int day)
{
    uint64_t used;

    if (quota == NULL || quota->limit == 0) {
        return 0;
    }

    if (atomic_load_explicit(&quota->day, memory_order_relaxed) != day) {
        return quota->limit;
    }

    used = atomic_load_explicit(&quota->used, memory_order_relaxed);
    if (used >= quota->limit) {
        return 0;
    }

    return quota->limit - used;
}

uint64_t policy_now_ms(void)
{
    struct timespec ts;

    if (timespec_get(&ts, TIME_UTC) != TIME_UTC) {
        return (uint64_t)time(NULL) * 1000u;
    }

    return (uint64_t)ts.tv_sec * 1000u +
           ((uint64_t)ts.tv_nsec / 1000000u);
}

int policy_day(time_t now)
{
    return (int)((int64_t)now / 86400);
}
