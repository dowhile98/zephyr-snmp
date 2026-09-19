/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 *
 * Standalone Zephyr kernel stub for unit testing without Zephyr RTOS.
 * Provides minimal type definitions and mock implementations needed
 * to compile and test the SNMP BER/MIB code in a native environment.
 */

#ifndef ZEPHYR_KERNEL_STUB_H_
#define ZEPHYR_KERNEL_STUB_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

/* --- Basic Types --- */
typedef int32_t k_timeout_t;
typedef struct {
    void *unused;
} k_mutex;

/* --- Mutex Stubs --- */
#define K_MUTEX_DEFINE(name) k_mutex name = {0}
#define K_FOREVER ((k_timeout_t)-1)

static inline int k_mutex_lock(k_mutex *mutex, k_timeout_t timeout)
{
    (void)mutex;
    (void)timeout;
    return 0;
}

static inline void k_mutex_unlock(k_mutex *mutex)
{
    (void)mutex;
}

/* --- Time Stubs --- */
static inline int64_t k_uptime_get(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

#endif /* ZEPHYR_KERNEL_STUB_H_ */
