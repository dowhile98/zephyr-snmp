/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_SERVICE_H_
#define ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_SERVICE_H_

#include <zephyr/kernel.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_SNMP_AGENT

/**
 * @brief Initialize UDP socket on port 161 and register with Zephyr Socket Service API.
 *
 * @return 0 on success, negative errno on failure.
 */
int snmp_service_init(void);

#endif /* CONFIG_SNMP_AGENT */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_SERVICE_H_ */
