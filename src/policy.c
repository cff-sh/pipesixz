/*
 * policy.c - Per-client Rate and Quota Enforcement
 *
 * The bucket refills from a monotonic timestamp instead of a timer
 * thread: one subtraction per packet is cheaper than waking up every
 * client's bucket on a schedule, and it needs no state outside the
 * session. A clock that jumps backwards simply refills nothing until it
 * catches up, because elapsed time is clamped to zero.
 *
 * The quota is per client id and per UTC period (a day, or a calendar
 * month). Keeping the counter out of the session is what stops a
 * reconnect (or a key rotation) from resetting the budget, and the same
 * counter feeds 'pipesix --usage' and the optional state file, so a
 * restart does not reset the period either.
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
    atomic_init(&quota->period, -1);
}

int policy_quota_charge(pipesix_quota_t *quota, size_t bytes, int period)
{
    uint64_t used;

    if (quota == NULL) {
        return 1;
    }

    if (atomic_load_explicit(&quota->period, memory_order_relaxed) != period) {
        atomic_store_explicit(&quota->period, period, memory_order_relaxed);
        atomic_store_explicit(&quota->used, 0, memory_order_relaxed);
    }

    used = atomic_fetch_add_explicit(&quota->used, (uint64_t)bytes,
                                     memory_order_relaxed) + (uint64_t)bytes;

    if (quota->limit == 0) {
        return 1;
    }

    return used <= quota->limit;
}

uint64_t policy_quota_remaining(const pipesix_quota_t *quota, int period)
{
    uint64_t used;

    if (quota == NULL || quota->limit == 0) {
        return 0;
    }

    if (atomic_load_explicit(&quota->period, memory_order_relaxed) != period) {
        return quota->limit;
    }

    used = atomic_load_explicit(&quota->used, memory_order_relaxed);
    if (used >= quota->limit) {
        return 0;
    }

    return quota->limit - used;
}

uint64_t policy_quota_used(const pipesix_quota_t *quota, int period)
{
    if (quota == NULL) {
        return 0;
    }

    if (atomic_load_explicit(&quota->period, memory_order_relaxed) != period) {
        return 0;
    }

    return atomic_load_explicit(&quota->used, memory_order_relaxed);
}

void policy_quota_restore(pipesix_quota_t *quota, uint64_t used, int period)
{
    if (quota == NULL) {
        return;
    }

    atomic_store_explicit(&quota->used, used, memory_order_relaxed);
    atomic_store_explicit(&quota->period, period, memory_order_relaxed);
}

/*
 * Days since 1970-01-01 for a proleptic Gregorian date, and the inverse.
 *
 * The algorithms are Howard Hinnant's 'days_from_civil' and
 * 'civil_from_days'. They are here so the monthly period is a pure
 * function of a timestamp: gmtime() keeps one static result buffer, and
 * both data-path threads call into this module at once.
 */
static int64_t days_from_civil(int y, unsigned m, unsigned d)
{
    int64_t era;
    unsigned yoe;
    unsigned doy;
    unsigned doe;

    y -= (m <= 2u);
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = (unsigned)((int64_t)y - era * 400);
    doy = (153u * (m > 2u ? m - 3u : m + 9u) + 2u) / 5u + d - 1u;
    doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;

    return era * 146097 + (int64_t)doe - 719468;
}

static void civil_from_days(int64_t z, int *y, unsigned *m, unsigned *d)
{
    int64_t era;
    int64_t yr;
    unsigned doe;
    unsigned yoe;
    unsigned doy;
    unsigned mp;

    z += 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = (unsigned)(z - era * 146097);
    yoe = (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u;
    yr = (int64_t)yoe + era * 400;
    doy = doe - (365u * yoe + yoe / 4u - yoe / 100u);
    mp = (5u * doy + 2u) / 153u;

    *d = doy - (153u * mp + 2u) / 5u + 1u;
    *m = (mp < 10u) ? mp + 3u : mp - 9u;
    *y = (int)(yr + (*m <= 2u));
}

int policy_period(time_t now, int monthly)
{
    int64_t days = (int64_t)now / 86400;

    if (!monthly) {
        return (int)days;
    }

    {
        int year;
        unsigned month;
        unsigned day;

        civil_from_days(days, &year, &month, &day);
        return year * 12 + (int)month - 1;
    }
}

time_t policy_period_start(int period, int monthly)
{
    if (!monthly) {
        return (time_t)((int64_t)period * 86400);
    }

    {
        int year = period / 12;
        int month = period % 12;

        /* Keep the arithmetic correct either side of the epoch. */
        if (month < 0) {
            month += 12;
            year -= 1;
        }

        return (time_t)(days_from_civil(year, (unsigned)month + 1u, 1u) *
                        86400);
    }
}

time_t policy_period_end(int period, int monthly)
{
    return policy_period_start(period + 1, monthly);
}

int policy_format_date(time_t t, char *out, size_t size)
{
    struct tm *tmp;
    struct tm tm;

    if (out == NULL || size == 0) {
        return -1;
    }

    tmp = gmtime(&t);
    if (tmp == NULL) {
        return -1;
    }
    tm = *tmp;

    return (strftime(out, size, "%Y-%m-%d", &tm) == 0) ? -1 : 0;
}

#define POLICY_HISTORY_HEADER \
    "client_id,period_start,period_end,period_kind,used_bytes\n"

int policy_history_append(const char *path, int monthly,
                          const policy_usage_t *usage, int count)
{
    FILE *fp;
    long size;
    int i;

    if (path == NULL || path[0] == '\0' || usage == NULL || count < 0) {
        errno = EINVAL;
        return -1;
    }

    if (count == 0) {
        return 0;
    }

    fp = fopen(path, "a");
    if (fp == NULL) {
        return -1;
    }

#if !defined(_WIN32)
    (void)chmod(path, 0600);
#endif

    if (fseek(fp, 0, SEEK_END) != 0 || (size = ftell(fp)) < 0) {
        fclose(fp);
        return -1;
    }

    if (size == 0 && fputs(POLICY_HISTORY_HEADER, fp) == EOF) {
        fclose(fp);
        return -1;
    }

    for (i = 0; i < count; i++) {
        time_t start = policy_period_start((int)usage[i].period, monthly);
        time_t end = policy_period_end((int)usage[i].period, monthly);

        if (fprintf(fp, "%s,%lld,%lld,%s,%llu\n", usage[i].id,
                    (long long)start, (long long)end,
                    monthly ? "monthly" : "daily",
                    (unsigned long long)usage[i].used) < 0) {
            fclose(fp);
            return -1;
        }
    }

    if (fflush(fp) != 0) {
        fclose(fp);
        return -1;
    }

    return fclose(fp);
}

int policy_history_load(const char *path, policy_history_t *out, int max,
                        int *count, int *total)
{
    char line[512];
    FILE *fp;
    int n = 0;
    int seen = 0;

    if (path == NULL || path[0] == '\0' || out == NULL || max < 0 ||
        count == NULL || total == NULL) {
        errno = EINVAL;
        return -1;
    }

    *count = 0;
    *total = 0;

    fp = fopen(path, "r");
    if (fp == NULL) {
        return (errno == ENOENT) ? 0 : -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *p = line;
        char id[POLICY_MAX_ID];
        char kind[16];
        long long start;
        long long end;
        unsigned long long used;

        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '\0' || *p == '\n' || *p == '#' ||
            strncmp(p, "client_id,", 10) == 0) {
            continue;
        }

        if (sscanf(p, "%32[^,],%lld,%lld,%15[^,],%llu", id, &start, &end,
                   kind, &used) != 5) {
            continue;
        }

        seen++;
        if (n >= max) {
            continue;
        }

        memset(&out[n], 0, sizeof(out[n]));
        snprintf(out[n].id, sizeof(out[n].id), "%s", id);
        out[n].start_unix = (int64_t)start;
        out[n].end_unix = (int64_t)end;
        out[n].monthly = (strcmp(kind, "monthly") == 0);
        out[n].used = (uint64_t)used;
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
    *total = seen;
    return 0;
}

int policy_state_save(const char *path, int monthly,
                      const policy_usage_t *usage, int count)
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

    if (fprintf(fp, "# pipesix quota state v2\nperiod %s\n",
                monthly ? "monthly" : "daily") < 0) {
        goto close;
    }

    for (i = 0; i < count; i++) {
        if (fprintf(fp, "%lld %llu %s\n", (long long)usage[i].period,
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

int policy_state_load(const char *path, int *monthly,
                      policy_usage_t *usage, int max, int *count)
{
    char line[256];
    FILE *fp;
    int n = 0;

    if (path == NULL || path[0] == '\0' || monthly == NULL ||
        usage == NULL || max < 0 || count == NULL) {
        errno = EINVAL;
        return -1;
    }

    *count = 0;
    *monthly = 0;

    fp = fopen(path, "r");
    if (fp == NULL) {
        return (errno == ENOENT) ? 0 : -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *p = line;
        char id[POLICY_MAX_ID];
        long long period;
        unsigned long long used;

        while (*p == ' ' || *p == '\t') {
            p++;
        }

        if (*p == '\0' || *p == '\n' || *p == '#') {
            continue;
        }

        if (strncmp(p, "period ", 7) == 0) {
            *monthly = (strncmp(p + 7, "monthly", 7) == 0);
            continue;
        }

        if (sscanf(p, "%lld %llu %32s", &period, &used, id) != 3) {
            continue;
        }

        if (period < 0 || n >= max) {
            continue;
        }

        memset(&usage[n], 0, sizeof(usage[n]));
        snprintf(usage[n].id, sizeof(usage[n].id), "%s", id);
        usage[n].period = (int64_t)period;
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
