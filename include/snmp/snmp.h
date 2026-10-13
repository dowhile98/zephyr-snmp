/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 *
 * @file snmp.h
 * @brief Public API for the SNMP agent module (v1 / v2c / v3).
 *
 * ## Architecture
 *
 * The SNMP agent is a layered, self-contained module within the application:
 *
 *   ┌─────────────────────────────────────────────────┐
 *   │ snmp.h            Public API (this file)        │
 *   ├─────────────────────────────────────────────────┤
 *   │ snmp_service.c    UDP :161, Socket Service      │
 *   │ snmp_core.c       Version dispatch, auth        │
 *   │ snmp_mib.c        MIB tree, Get/GetNext/Set/    │
 *   │                   GetBulk, system+snmp MIB-II   │
 *   │ snmp_ber.c        ASN.1 BER encode/decode       │
 *   ├─────────────────────────────────────────────────┤
 *   │ snmp_usm.c        HMAC-SHA1/MD5, AES-CFB  (v3) │
 *   │ snmp_vacm.c       View-based access control(v3) │
 *   │ snmp_trap.c       Trap/Inform UDP :162          │
 *   └─────────────────────────────────────────────────┘
 *
 * Build-time configuration via Kconfig (prj.conf):
 *   CONFIG_SNMP_AGENT=y          enable the agent
 *   CONFIG_SNMP_VERSION_1=y      SNMPv1
 *   CONFIG_SNMP_VERSION_2C=y     SNMPv2c
 *   CONFIG_SNMP_VERSION_3=y      SNMPv3 (+mbedtls/PSA Crypto)
 *   CONFIG_SNMP_TRAP_ENABLED=y   Traps and Informs
 *
 * ## Quick Start
 *
 * The agent has no default instance: the application owns one @ref struct snmp_agent
 * per SNMP endpoint (static storage, zero dynamic allocation) and drives it through
 * the instance API.
 *
 * @code
 * #include <snmp/snmp.h>
 *
 * static struct snmp_agent g_agent_lan;            // caller-owned storage (BSS)
 *
 * int main(void)
 * {
 *     struct snmp_agent_cfg cfg = {
 *         .port           = 161,
 *         .read_community = "public",
 *         .write_community = "secret",
 *         .sys_name       = "MyDevice",
 *         .sys_location   = "Rack 3",
 *     };
 *
 *     // 1. Create the domain state (MIB-II system + snmp groups included)
 *     snmp_agent_init(&g_agent_lan, &cfg);
 *
 *     // 2. Register enterprise MIB nodes on this agent
 *     struct snmp_mib_node my_nodes[] = {
 *         { .oid = {11, {1,3,6,1,4,1,54321,1,1,1,0}},
 *           .type = SNMP_TAG_GAUGE32,
 *           .get_cb = my_sensor_get, .set_cb = NULL },
 *     };
 *     snmp_mib_register_nodes(&g_agent_lan, my_nodes, ARRAY_SIZE(my_nodes));
 *
 *     // 3. Configure trap destinations (optional), then open UDP :161
 *     snmp_trap_add_destination(&g_agent_lan, "192.168.1.100");
 *     snmp_agent_start(&g_agent_lan);
 *
 *     // ... snmp_agent_stop(&g_agent_lan) to detach the transport ...
 *     return 0;
 * }
 * @endcode
 *
 * A second agent on the same interface only needs its own storage, another port
 * (@c cfg.port) and its own @c cfg.sys_name — every API takes the instance to act
 * on. Lifecycle: init -> start -> stop -> deinit; calling an API in the wrong state
 * returns @c -EPERM. Every entry point except @ref snmp_agent_get_counters and
 * @ref snmp_usm_get_engine_boots takes @c agent->lock: call them from thread
 * context, never from an ISR, and never from inside a MIB callback.
 *
 * ## Testing (Linux host)
 *
 * @code
 * snmpget   -v2c -c public <IP> 1.3.6.1.2.1.1.1.0        # sysDescr
 * snmpwalk  -v2c -c public <IP> 1.3.6.1.2.1               # full MIB-II
 * snmpbulkwalk -v2c -c public <IP> 1.3.6.1                 # bulk walk
 * snmpset   -v2c -c private <IP> sysContact.0 s "admin@corp.com"
 * snmpwalk  -v3 -u admin -l authNoPriv -a SHA -A authpass123 <IP> 1.3.6.1
 * snmptrapd -f -Lo                                           # receive traps
 * @endcode
 *
 * ## RFC References
 *
 * - RFC 3412  Message Processing and Dispatching
 * - RFC 3414  User-based Security Model (USM)
 * - RFC 3415  View-based Access Control Model (VACM)
 * - RFC 3416  Protocol Operations for SNMPv2
 * - RFC 3418  MIB for SNMP (MIB-II snmp group)
 * - RFC 1213  MIB-II (system, interfaces, IP, ICMP, TCP, UDP)
 */

#ifndef ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_H_
#define ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_H_

#include <zephyr/kernel.h>
#include <snmp/snmp_ber.h>
#include <snmp/snmp_mib.h>
#include <snmp/snmp_core.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_SNMP_AGENT
/*
 * All public entry points are declared in the component headers included above:
 * lifecycle and communities in snmp_core.h, MIB and identity setters in snmp_mib.h,
 * traps in snmp_trap.h, v3 security in snmp_usm.h / snmp_vacm.h. There is no
 * default instance to facade any more: every call names the agent it acts on.
 */
#endif /* CONFIG_SNMP_AGENT */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_H_ */
