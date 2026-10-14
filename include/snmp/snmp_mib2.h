/*
 * Copyright (c) 2026 StructCore Embedded
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_MIB2_H_
#define ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_MIB2_H_

#include <snmp/snmp_core.h>
#include <snmp/snmp_mib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Register MIB-II Interfaces group (ifNumber, ifTable) per RFC 1213 / RFC 2863.
 *
 * @param agent Target agent instance.
 * @return 0 on success, negative errno on failure.
 */
int snmp_mib2_register_interfaces(struct snmp_agent *agent);

/**
 * @brief Register MIB-II IP group per RFC 1213.
 *
 * @param agent Target agent instance.
 * @return 0 on success, negative errno on failure.
 */
int snmp_mib2_register_ip(struct snmp_agent *agent);

/**
 * @brief Register MIB-II ICMP group per RFC 1213.
 *
 * @param agent Target agent instance.
 * @return 0 on success, negative errno on failure.
 */
int snmp_mib2_register_icmp(struct snmp_agent *agent);

/**
 * @brief Register MIB-II TCP group per RFC 1213.
 *
 * @param agent Target agent instance.
 * @return 0 on success, negative errno on failure.
 */
int snmp_mib2_register_tcp(struct snmp_agent *agent);

/**
 * @brief Register MIB-II UDP group per RFC 1213.
 *
 * @param agent Target agent instance.
 * @return 0 on success, negative errno on failure.
 */
int snmp_mib2_register_udp(struct snmp_agent *agent);

/**
 * @brief Register all MIB-II network subsystem groups (interfaces, ip, icmp, tcp, udp).
 *
 * @param agent Target agent instance.
 * @return 0 on success, negative errno on failure.
 */
int snmp_mib2_register_all(struct snmp_agent *agent);

#if !defined(__ZEPHYR__)
struct snmp_mock_iface {
	uint32_t index;
	const char *descr;
	uint32_t type;
	uint32_t mtu;
	uint32_t speed;
	uint8_t mac[6];
	uint32_t admin_status;
	uint32_t oper_status;
	uint32_t in_octets;
	uint32_t in_ucast;
	uint32_t in_errors;
	uint32_t out_octets;
	uint32_t out_ucast;
	uint32_t out_errors;
};

void snmp_mib2_mock_set_ifaces(const struct snmp_mock_iface *ifaces, size_t count);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_MIB2_H_ */
