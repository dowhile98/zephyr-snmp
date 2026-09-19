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

#if defined(CONFIG_SNMP_AGENT) && defined(CONFIG_SNMP_TRAP_ENABLED)

/**
 * @brief Send an SNMP Trap or Inform notification to all configured trap destinations.
 *
 * @param trap_oid Pointer to the Trap OID identifying the event.
 * @param varbinds Pointer to array of additional variable bindings (may be NULL if cnt == 0).
 * @param varbind_cnt Number of variable bindings.
 * @param is_inform True to send InformRequest requiring ACK, false for Trap.
 *
 * @return 0 on success, negative errno on failure.
 */
int snmp_trap_send(const struct snmp_oid *trap_oid,
                   const struct snmp_varbind *varbinds,
                   uint8_t varbind_cnt,
                   bool is_inform);

#if defined(CONFIG_SNMP_VERSION_3)
/**
 * @brief Send an SNMPv3 Trap or Inform notification to all configured trap destinations.
 *
 * @param trap_oid Pointer to the Trap OID identifying the event.
 * @param varbinds Pointer to array of additional variable bindings (may be NULL if cnt == 0).
 * @param varbind_cnt Number of variable bindings.
 * @param is_inform True to send InformRequest requiring ACK, false for Trap.
 *
 * @return 0 on success, negative errno on failure.
 */
int snmp_trap_send_v3(const struct snmp_oid *trap_oid,
                     const struct snmp_varbind *varbinds,
                     uint8_t varbind_cnt,
                     bool is_inform);
#endif

/**
 * @brief Add a destination IP address for trap notifications.
 *
 * @param addr IPv4 address string (e.g. "192.168.1.100").
 * @return 0 on success, negative errno on failure.
 */
int snmp_trap_add_destination(const char *addr);

/**
 * @brief Send standard Cold Start Trap (1.3.6.1.6.3.1.1.5.1).
 */
int snmp_trap_send_coldstart(void);

/**
 * @brief Send standard Authentication Failure Trap (1.3.6.1.6.3.1.1.5.5).
 */
int snmp_trap_send_auth_failure(void);

#endif /* CONFIG_SNMP_AGENT && CONFIG_SNMP_TRAP_ENABLED */



#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_TRAP_H_ */
