/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_TRAP_H_
#define ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_TRAP_H_

#include <zephyr/kernel.h>
#include <snmp/snmp_ber.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_SNMP_AGENT

#ifndef CONFIG_SNMP_TRAP_DEST_COUNT
#define CONFIG_SNMP_TRAP_DEST_COUNT 3
#endif

/* Forward declaration of agent instance */
struct snmp_agent_inst;

/* ---- Instance-based APIs ---- */

/**
 * @brief Add a destination IP address for trap notifications on a specific agent instance.
 */
int snmp_trap_add_destination_inst(struct snmp_agent_inst *inst, const char *addr);

/**
 * @brief Send an SNMP Trap or Inform notification from a specific agent instance.
 */
int snmp_trap_send_inst(struct snmp_agent_inst *inst, const struct snmp_oid *trap_oid,
			const struct snmp_varbind *varbinds, uint8_t varbind_cnt,
			bool is_inform);

/**
 * @brief Send standard Cold Start Trap from a specific agent instance.
 */
int snmp_trap_send_coldstart_inst(struct snmp_agent_inst *inst);

/**
 * @brief Send standard Authentication Failure Trap from a specific agent instance.
 */
int snmp_trap_send_auth_failure_inst(struct snmp_agent_inst *inst);

/* ---- Legacy API Facade (delegates to default agent) ---- */

int snmp_trap_add_destination(const char *addr);
int snmp_trap_send(const struct snmp_oid *trap_oid,
		   const struct snmp_varbind *varbinds,
		   uint8_t varbind_cnt,
		   bool is_inform);
#if defined(CONFIG_SNMP_VERSION_3)
int snmp_trap_send_v3(const struct snmp_oid *trap_oid,
		      const struct snmp_varbind *varbinds,
		      uint8_t varbind_cnt,
		      bool is_inform);
#endif
int snmp_trap_send_coldstart(void);
int snmp_trap_send_auth_failure(void);

#endif /* CONFIG_SNMP_AGENT */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_TRAP_H_ */
