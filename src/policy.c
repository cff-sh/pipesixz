/*
 * policy.c - Per-client Rate and Quota Enforcement
 *
 * The bucket refills from a monotonic timestamp instead of a timer
 * thread: one subtraction per packet is cheaper than waking up every
 * client's bucket on a schedule, and it needs no state outside the
 * session. A clock that jumps backwards simply refills nothing until it
 * catches up, because elapsed time is clamped to zero.
 *
 * The quota is per client id and per UTC day. Keeping the counter out of
 * the session is what stops a reconnect (or a key rotation) from resetting
 * the budget, and the same counter feeds 'pipesix --usage' and the
 * optional state file, so a restart does not reset the day either.
 */

#include "policy.h"

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#endif

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Suffix of the temporary file policy_state_save() renames into place. */
#define POLICY_STATE_SUFFIX ".tmp"

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

    if (quota == NULL) {
        return 1;
    }

    if (atomic_load_explicit(&quota->day, memory_order_relaxed) != day) {
        atomic_store_explicit(&quota->day, day, memory_order_relaxed);
        atomic_store_explicit(&quota->used, 0, memory_order_relaxed);
    }

    used = atomic_fetch_add_explicit(&quota->used, (uint64_t)bytes,
                                     memory_order_relaxed) + (uint64_t)bytes;

    if (quota->limit == 0) {
        return 1;
    }

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

uint64_t policy_quota_used(const pipesix_quota_t *quota, int day)
{
    if (quota == NULL) {
        return 0;
    }

    if (atomic_load_explicit(&quota->day, memory_order_relaxed) != day) {
        return 0;
    }

    return atomic_load_explicit(&quota->used, memory_order_relaxed);
}

void policy_quota_restore(pipesix_quota_t *quota, uint64_t used, int day)
{
    if (quota == NULL) {
        return;
    }

    atomic_store_explicit(&quota->used, used, memory_order_relaxed);
    atomic_store_explicit(&quota->day, day, memory_order_relaxed);
}

int policy_state_save(const char *path, const policy_usage_t *usage,
                      int count)
{
    char tmp_path[4096 + sizeof(POLICY_STATE_SUFFIX)];
    FILE *fp;
    int i;
    int rc = -1;

    if (path == NULL || path[0] == '\0' || usage == NULL || count < 0) {
        errno = EINVAL;
        return -1;
    }

    if (strlen(path) + sizeof(POLICY_STATE_SUFFIX) > sizeof(tmp_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    snprintf(tmp_path, sizeof(tmp_path), "%s" POLICY_STATE_SUFFIX, path);

    fp = fopen(tmp_path, "w");
    if (fp == NULL) {
        return -1;
    }

    if (fprintf(fp, "# pipesix quota state v1\n") < 0) {
        goto close;
    }

    for (i = 0; i < count; i++) {
        if (fprintf(fp, "%lld %llu %s\n", (long long)usage[i].day,
                    (unsigned long long)usage[i].used,
                    usage[i].id) < 0) {
            goto close;
        }
    }

    if (fflush(fp) != 0) {
        goto close;
    }

#if !defined(_WIN32)
    if (fsync(fileno(fp)) != 0) {
        goto close;
    }
#endif

    if (fclose(fp) != 0) {
        fp = NULL;
        goto fail;
    }
    fp = NULL;

#if !defined(_WIN32)
    /* The counters are worth keeping private even on a shared /tmp. */
    (void)chmod(tmp_path, 0600);
#else
    /* Windows rename() refuses to replace an existing destination. */
    (void)remove(path);
#endif

    if (rename(tmp_path, path) != 0) {
        goto fail;
    }

    return 0;

close:
    fclose(fp);

fail:
    (void)remove(tmp_path);
    return rc;
}

int policy_state_load(const char *path, policy_usage_t *usage, int max,
                      int *count)
{
    char line[256];
    FILE *fp;
    int n = 0;

    if (path == NULL || path[0] == '\0' || usage == NULL || max < 0 ||
        count == NULL) {
        errno = EINVAL;
        return -1;
    }

    *count = 0;

    fp = fopen(path, "r");
    if (fp == NULL) {
        return (errno == ENOENT) ? 0 : -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *p = line;
        char id[POLICY_MAX_ID];
        long long day;
        unsigned long long used;

        while (*p == ' ' || *p == '\t') {
            p++;
        }

        if (*p == '\0' || *p == '\n' || *p == '#') {
            continue;
        }

        if (sscanf(p, "%lld %llu %32s", &day, &used, id) != 3) {
            continue;
        }

        if (day < 0 || n >= max) {
            continue;
        }

        memset(&usage[n], 0, sizeof(usage[n]));
        snprintf(usage[n].id, sizeof(usage[n].id), "%s", id);
        usage[n].day = (int64_t)day;
        usage[n].used = (uint64_t)used;
        n++;
    }

    if (ferror(fp)) {
        fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0) {
        return -1;
    }

    *count = n;
    return 0;
}

uint64_t policy_now_ms(void)
{
#if defined(_WIN32)
    /* Server mode is not built for Windows, but the module still links. */
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return (uint64_t)time(NULL) * 1000u;
    }

    return (uint64_t)ts.tv_sec * 1000u +
           ((uint64_t)ts.tv_nsec / 1000000u);
#endif
}

int policy_day(time_t now)
{
    return (int)((int64_t)now / 86400);
}
