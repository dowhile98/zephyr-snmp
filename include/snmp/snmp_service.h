/*
 * Copyright (c) 2026 StructCore Embedded
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_SERVICE_H_
#define ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_SERVICE_H_

#include <zephyr/kernel.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_SNMP_AGENT

/*
 * There is no process-wide transport entry point any more. The socket-service adapter is
 * per instance and is driven exclusively by the lifecycle API:
 *
 *   snmp_agent_init(agent, cfg)        -> reserves nothing yet
 *   snmp_agent_start(agent)            -> binds agent->port / agent->bound_iface and
 *                                         attaches one socket-service descriptor slot
 *   snmp_agent_stop(agent)             -> deregisters, quiesces, closes, frees the slot
 *
 * The adapter itself (snmp_service_attach/snmp_service_detach) is module-internal and
 * declared in src/snmp_internal.h, so including this header is no longer required by
 * applications.
 *
 * @deprecated Kept only so existing #includes still compile; the no-parameter facades
 *             this header once documented were removed in sub-phase 8c. Delete the file
 *             in sub-phase 8d after auditing that nothing includes it.
 */

#endif /* CONFIG_SNMP_AGENT */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_SERVICE_H_ */
