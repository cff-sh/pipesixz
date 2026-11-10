/*
 * runtime.c - Process-wide Runtime State
 */

#include "runtime.h"

#include <stdatomic.h>

static _Atomic int s_stop_requested = 0;
static _Atomic int s_stats_requested = 0;
static _Atomic int s_reload_requested = 0;

void runtime_init(void)
{
    atomic_store(&s_stop_requested, 0);
    atomic_store(&s_stats_requested, 0);
    atomic_store(&s_reload_requested, 0);
}

int runtime_should_stop(void)
{
    return atomic_load_explicit(&s_stop_requested, memory_order_relaxed) != 0;
}

void runtime_request_stop(void)
{
    atomic_store_explicit(&s_stop_requested, 1, memory_order_relaxed);
}

void runtime_request_stats(void)
{
    atomic_store_explicit(&s_stats_requested, 1, memory_order_relaxed);
}

int runtime_take_stats_request(void)
{
    return atomic_exchange_explicit(&s_stats_requested, 0,
                                    memory_order_relaxed) != 0;
}

void runtime_request_reload(void)
{
    atomic_store_explicit(&s_reload_requested, 1, memory_order_relaxed);
}

int runtime_take_reload_request(void)
{
    return atomic_exchange_explicit(&s_reload_requested, 0,
                                    memory_order_relaxed) != 0;
}
