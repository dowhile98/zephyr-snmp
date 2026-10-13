/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_CORE_H_
#define ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_CORE_H_

#include <zephyr/kernel.h>
#include <snmp/snmp_ber.h>
#include <snmp/snmp_mib.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_SNMP_AGENT

/**
 * @brief SNMP agent instance state handle for multi-instance support.
 */
struct snmp_agent_inst {
	char read_community[64];
	char write_community[64];
	struct snmp_pdu current_pdu;
	struct snmp_mib2_counters counters;
	/* Future extension fields for USM, VACM, transport */
	void *user_data;
};

/**
 * @brief Initialize an SNMP agent instance with default community strings and zeroed counters.
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
