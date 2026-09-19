/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 *
 * Standalone Zephyr atomic operations stub for unit testing.
 * Provides atomic operations needed to compile the MIB counter code.
 */

#ifndef ZEPHYR_SYS_ATOMIC_STUB_H_
#define ZEPHYR_SYS_ATOMIC_STUB_H_

#include <stdint.h>

typedef uint32_t atomic_t;

static inline void atomic_inc(atomic_t *target)
{
    (*target)++;
}

#endif /* ZEPHYR_SYS_ATOMIC_STUB_H_ */
