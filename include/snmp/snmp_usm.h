/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_USM_H_
#define ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_USM_H_

#include <zephyr/kernel.h>
#include <snmp/snmp_ber.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_SNMP_AGENT

#ifndef CONFIG_SNMP_V3_MAX_USERS
#define CONFIG_SNMP_V3_MAX_USERS 4
#endif

/* Forward declaration of agent instance */
struct snmp_agent_inst;

struct snmp_usm_user {
	char        user_name[32];
	uint8_t     auth_protocol;  /* 0=none, 1=SHA, 2=MD5 */
	char        auth_pass[64];
	uint8_t     priv_protocol;  /* 0=none, 1=AES, 2=DES */
	char        priv_pass[64];

	/* Localized keys (derived at init) */
	uint8_t  auth_key[20];       /* SHA1=20, MD5=16 */
	uint16_t auth_key_len;
	uint8_t  priv_key[20];       /* AES=16, DES=16 */
	uint16_t priv_key_len;
	bool     in_use;
};

/* ---- Instance-based APIs ---- */

/**
 * @brief Initialize USM engine inside an agent instance.
 */
int snmp_usm_init_inst(struct snmp_agent_inst *inst);

/**
 * @brief Add a user to an agent instance's USM engine.
 */
int snmp_usm_add_user_inst(struct snmp_agent_inst *inst, const struct snmp_usm_user *user);

/**
 * @brief Verify incoming v3 message against an agent instance.
 */
int snmp_usm_verify_incoming_inst(struct snmp_agent_inst *inst, struct snmp_v3_msg *msg,
				  const uint8_t *raw_buf, size_t raw_len);

/**
 * @brief Prepare outgoing v3 message using an agent instance's USM engine.
 */
int snmp_usm_build_outgoing_inst(struct snmp_agent_inst *inst, struct snmp_v3_msg *msg);

/**
 * @brief Get engine ID for an agent instance.
 */
int snmp_usm_get_engine_id_inst(struct snmp_agent_inst *inst, uint8_t *engine_id, uint8_t *len);

/**
 * @brief Set engine boots for an agent instance.
 */
int snmp_usm_set_engine_boots_inst(struct snmp_agent_inst *inst, uint32_t boots);

/**
 * @brief Get engine boots for an agent instance.
 */
uint32_t snmp_usm_get_engine_boots_inst(struct snmp_agent_inst *inst);

/* ---- Legacy API Facade (delegates to default agent) ---- */

int snmp_usm_init(void);
int snmp_usm_add_user(const struct snmp_usm_user *user);
int snmp_usm_get_engine_id(uint8_t *engine_id, uint8_t *len);
int snmp_usm_verify_incoming(struct snmp_v3_msg *msg, const uint8_t *raw_buf, size_t raw_len);
int snmp_usm_build_outgoing(struct snmp_v3_msg *msg);
int snmp_usm_set_engine_boots(uint32_t boots);
uint32_t snmp_usm_get_engine_boots(void);

#endif /* CONFIG_SNMP_AGENT */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_USM_H_ */
