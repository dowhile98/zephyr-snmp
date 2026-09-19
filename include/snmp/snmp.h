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
 * @code
 * #include <snmp/snmp.h>
 *
 * // 1. Init agent (registra MIB-II system + snmp groups, abre UDP :161)
 * snmp_agent_init();
 *
 * // 2. Configure identity
 * snmp_mib2_set_sysname("MyDevice");
 * snmp_mib2_set_syslocation("Rack 3");
 * snmp_set_read_community("public");
 * snmp_set_write_community("secret");
 *
 * // 3. Register enterprise MIB nodes
 * struct snmp_mib_node my_nodes[] = {
 *     { .oid = {11, {1,3,6,1,4,1,54321,1,1,1,0}},
 *       .type = SNMP_TAG_GAUGE32,
 *       .get_cb = my_sensor_get, .set_cb = NULL },
 * };
 * snmp_mib_register_nodes(my_nodes, ARRAY_SIZE(my_nodes));
 *
 * // 4. Configure trap destinations (optional)
 * snmp_trap_add_destination("192.168.1.100");
 * @endcode
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

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_SNMP_AGENT

/**
 * @brief Initialize the SNMP agent subsystem, MIB tree, and UDP socket service on port 161.
 *
 * @return 0 on success, negative errno on failure.
 */
int snmp_agent_init(void);

/**
 * @brief Deinitialize the SNMP agent subsystem and close network sockets.
 *
 * @return 0 on success, negative errno on failure.
 */
int snmp_agent_deinit(void);

/**
 * @brief Register standard MIB-II objects (system group + snmp group counters).
 *        Called automatically by snmp_agent_init(). Application code may call
 *        this directly if using a custom init sequence.
 *
 * @return 0 on success, negative errno on failure.
 */
int snmp_mib_register_defaults(void);

/**
 * @brief Register a single MIB node. Nodes are kept lexicographically sorted.
 *
 * @param node Pointer to the MIB node definition to register.
 * @return 0 on success, negative errno on failure.
 */
int snmp_mib_register(const struct snmp_mib_node *node);

/**
 * @brief Register an array of MIB nodes in bulk (application-defined MIB).
 *        All nodes are inserted into the same sorted tree.
 *
 * @param nodes Pointer to array of MIB node definitions.
 * @param count Number of nodes in the array.
 * @return 0 on success, negative errno on failure.
 */
int snmp_mib_register_nodes(const struct snmp_mib_node *nodes, size_t count);

/**
 * @brief Configure the read community string for SNMP v1/v2c (default: "public").
 *
 * @param community String pointer.
 * @return 0 on success, negative errno on failure.
 */
int snmp_set_read_community(const char *community);

/**
 * @brief Configure the write community string for SNMP v1/v2c (default: "private").
 *
 * @param community String pointer.
 * @return 0 on success, negative errno on failure.
 */
int snmp_set_write_community(const char *community);

/**
 * @brief Configure the Enterprise OID (used for sysObjectID and Traps).
 *
 * @param oid Pointer to enterprise OID.
 * @return 0 on success, negative errno on failure.
 */
int snmp_set_device_enterprise_oid(const struct snmp_oid *oid);

/**
 * @brief Configure the MIB-II System description string (sysDescr).
 *
 * @param descr Null-terminated description string (max 127 chars).
 * @return 0 on success, negative errno on failure.
 */
int snmp_mib2_set_sysdescr(const char *descr);

/**
 * @brief Configure the MIB-II System contact person (sysContact).
 *
 * @param contact Null-terminated contact string (max 63 chars).
 * @return 0 on success, negative errno on failure.
 */
int snmp_mib2_set_syscontact(const char *contact);

/**
 * @brief Configure the MIB-II System host name (sysName).
 *
 * @param name Null-terminated system name string (max 63 chars).
 * @return 0 on success, negative errno on failure.
 */
int snmp_mib2_set_sysname(const char *name);

/**
 * @brief Configure the MIB-II System physical location (sysLocation).
 *
 * @param location Null-terminated location string (max 63 chars).
 * @return 0 on success, negative errno on failure.
 */
int snmp_mib2_set_syslocation(const char *location);

#endif /* CONFIG_SNMP_AGENT */




#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_H_ */
