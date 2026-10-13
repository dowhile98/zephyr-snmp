/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_CORE_H_
#define ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_CORE_H_

#include <zephyr/kernel.h>
#include <snmp/snmp_ber.h>
#include <snmp/snmp_mib.h>
#include <snmp/snmp_vacm.h>
#include <snmp/snmp_usm.h>
#include <snmp/snmp_trap.h>

#if defined(__ZEPHYR__)
#include <zephyr/net/socket.h>
#else
#include <netinet/in.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_SNMP_AGENT

/**
 * @brief Complete SNMP agent instance state handle encapsulating all configuration,
 *        MIB tree, USM credentials, VACM access rules, traps, and buffers.
 *        Supports zero-singleton multi-instance deployment.
 */
struct snmp_agent_inst {
	/* Communities */
	char read_community[64];
	char write_community[64];

	/* USM engine */
	uint8_t engine_id[SNMP_V3_ENGINE_ID_MAX_LEN];
	uint8_t engine_id_len;
	uint32_t engine_boots;
	struct snmp_usm_user users[CONFIG_SNMP_V3_MAX_USERS];
	uint8_t user_cnt;

	/* VACM engine */
	struct vacm_context_entry contexts[CONFIG_SNMP_VACM_MAX_CONTEXTS];
	uint8_t context_cnt;
	struct vacm_group_mapping_entry groups[CONFIG_SNMP_VACM_MAX_GROUPS];
	uint8_t group_cnt;
	struct vacm_access_rule_entry access_rules[CONFIG_SNMP_VACM_MAX_ACCESS_RULES];
	uint8_t access_rule_cnt;
	struct vacm_view_tree_entry views[CONFIG_SNMP_VACM_MAX_VIEW_TREES];
	uint8_t view_cnt;

	/* MIB engine */
	struct snmp_mib_node mib_nodes[CONFIG_SNMP_MAX_MIB_NODES];
	size_t mib_node_cnt;
	struct snmp_mib_table *mib_tables[CONFIG_SNMP_MAX_TABLES];
	size_t mib_table_cnt;
	char sys_descr[128];
	char sys_contact[64];
	char sys_name[64];
	char sys_location[64];
	struct snmp_oid sys_object_id;
	struct k_mutex mib_lock;

	/* Trap engine */
	struct sockaddr_in trap_dests[CONFIG_SNMP_TRAP_DEST_COUNT];
	uint8_t trap_dest_cnt;

	/* Transport/Service */
	int sock_v4;
	int sock_v6;
	uint16_t port;
	void *bound_iface;

	/* Processing */
	struct snmp_pdu current_pdu;
	uint8_t rx_buf[CONFIG_SNMP_MAX_PDU_SIZE];
	uint8_t tx_buf[CONFIG_SNMP_MAX_PDU_SIZE];
	struct snmp_mib2_counters counters;

	/* User data pointer */
	void *user_data;
};

/**
 * @brief Initialize an SNMP agent instance with default values, MIB tree, and security state.
 *
 * @param inst Pointer to agent instance structure.
 * @return 0 on success, -EINVAL if inst is NULL.
 */
int snmp_agent_inst_init(struct snmp_agent_inst *inst);

/**
 * @brief Process raw SNMP packet payload using an explicit agent instance context.
 *
 * @param inst Pointer to target agent instance.
 * @param req_buf Pointer to incoming raw UDP payload.
 * @param req_len Length of incoming payload.
 * @param resp_buf Pointer to output buffer for SNMP response.
 * @param max_resp_len Capacity of output buffer.
 * @param out_resp_len Pointer where output response length will be stored.
 *
 * @return 0 on success (or silent drop with out_resp_len=0), negative errno on error.
 */
int snmp_agent_inst_process_pdu(struct snmp_agent_inst *inst,
				const uint8_t *req_buf, size_t req_len,
				uint8_t *resp_buf, size_t max_resp_len,
				size_t *out_resp_len);

/**
 * @brief Set read community string for a specific agent instance.
 *
 * @param inst Pointer to agent instance.
 * @param community Null-terminated community string (max 63 chars).
 * @return 0 on success, -EINVAL on invalid parameter.
 */
int snmp_agent_inst_set_read_community(struct snmp_agent_inst *inst, const char *community);

/**
 * @brief Set write community string for a specific agent instance.
 *
 * @param inst Pointer to agent instance.
 * @param community Null-terminated community string (max 63 chars).
 * @return 0 on success, -EINVAL on invalid parameter.
 */
int snmp_agent_inst_set_write_community(struct snmp_agent_inst *inst, const char *community);

/**
 * @brief Retrieve pointer to default global agent instance (for legacy facade APIs).
 *
 * @return Pointer to global default struct snmp_agent_inst.
 */
struct snmp_agent_inst *snmp_agent_get_default(void);

/**
 * @brief Process raw UDP packet payload through the default global SNMP agent.
 *
 * @param req_buf Pointer to incoming raw UDP payload.
 * @param req_len Length of incoming payload.
 * @param resp_buf Pointer to output buffer for SNMP response.
 * @param max_resp_len Capacity of output buffer.
 * @param out_resp_len Pointer where output response length will be stored.
 *
 * @return 0 on success (or silent drop with out_resp_len=0), negative errno on error.
 */
int snmp_core_process_pdu(const uint8_t *req_buf, size_t req_len,
			  uint8_t *resp_buf, size_t max_resp_len,
			  size_t *out_resp_len);

#endif /* CONFIG_SNMP_AGENT */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_CORE_H_ */
