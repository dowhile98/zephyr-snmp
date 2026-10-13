/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_VACM_H_
#define ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_VACM_H_

#include <zephyr/kernel.h>
#include <snmp/snmp_ber.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_SNMP_AGENT

/* ---- VACM Access Types ---- */
#define SNMP_VACM_ACCESS_READ   1
#define SNMP_VACM_ACCESS_WRITE  2
#define SNMP_VACM_ACCESS_NOTIFY 3

/* ---- VACM Security Levels (RFC 3411 §3.4.3 / RFC 3415) ---- */
#define SNMP_SEC_LEVEL_NOAUTH_NOPRIV 1
#define SNMP_SEC_LEVEL_AUTH_NOPRIV   2
#define SNMP_SEC_LEVEL_AUTH_PRIV     3

/* ---- VACM Security Models ---- */
#define SNMP_SEC_MODEL_ANY  0
#define SNMP_SEC_MODEL_V1   1
#define SNMP_SEC_MODEL_V2C  2
#define SNMP_SEC_MODEL_USM  3

/* ---- VACM View Tree Family Types (RFC 3415 §4) ---- */
#define SNMP_VACM_VIEW_INCLUDED 1
#define SNMP_VACM_VIEW_EXCLUDED 2

/* ---- Table Capacities & Limits ---- */
#ifndef CONFIG_SNMP_VACM_MAX_CONTEXTS
#define CONFIG_SNMP_VACM_MAX_CONTEXTS 8
#endif

#ifndef CONFIG_SNMP_VACM_MAX_GROUPS
#define CONFIG_SNMP_VACM_MAX_GROUPS 16
#endif

#ifndef CONFIG_SNMP_VACM_MAX_ACCESS_RULES
#define CONFIG_SNMP_VACM_MAX_ACCESS_RULES 16
#endif

#ifndef CONFIG_SNMP_VACM_MAX_VIEW_TREES
#define CONFIG_SNMP_VACM_MAX_VIEW_TREES 32
#endif

#define SNMP_VACM_NAME_MAX_LEN 32
#define SNMP_VACM_MASK_MAX_LEN 16

/* Forward declaration of agent instance */
struct snmp_agent;

/* ---- Table Entry Structures ---- */

struct vacm_context_entry {
	char name[SNMP_VACM_NAME_MAX_LEN];
	bool in_use;
};

struct vacm_group_mapping_entry {
	int  security_model;
	char security_name[SNMP_VACM_NAME_MAX_LEN];
	char group_name[SNMP_VACM_NAME_MAX_LEN];
	bool in_use;
};

struct vacm_access_rule_entry {
	char group_name[SNMP_VACM_NAME_MAX_LEN];
	char context_prefix[SNMP_VACM_NAME_MAX_LEN];
	int  security_model;
	int  min_sec_level;
	char read_view[SNMP_VACM_NAME_MAX_LEN];
	char write_view[SNMP_VACM_NAME_MAX_LEN];
	char notify_view[SNMP_VACM_NAME_MAX_LEN];
	bool in_use;
};

struct vacm_view_tree_entry {
	char            view_name[SNMP_VACM_NAME_MAX_LEN];
	struct snmp_oid subtree;
	uint8_t         mask[SNMP_VACM_MASK_MAX_LEN];
	size_t          mask_len;
	int             type; /* SNMP_VACM_VIEW_INCLUDED or SNMP_VACM_VIEW_EXCLUDED */
	bool            in_use;
};

/* ---- Instance-based APIs ---- */

/**
 * @brief Initialize VACM state inside an agent instance with default RFC 3415 configuration.
 */
int snmp_vacm_init_inst(struct snmp_agent *inst);

/**
 * @brief Register a context name in vacmContextTable for an agent instance.
 */
int snmp_vacm_add_context_inst(struct snmp_agent *inst, const char *context_name);

/**
 * @brief Map a security model and security name to a group name for an agent instance.
 */
int snmp_vacm_add_group_mapping_inst(struct snmp_agent *inst, int security_model,
				     const char *security_name, const char *group_name);

/**
 * @brief Add an access rule in vacmAccessTable for an agent instance.
 */
int snmp_vacm_add_access_rule_inst(struct snmp_agent *inst, const char *group_name,
				   const char *context_prefix, int security_model,
				   int min_sec_level, const char *read_view, const char *write_view,
				   const char *notify_view);

/**
 * @brief Add a view tree family entry in vacmViewTreeFamilyTable for an agent instance.
 */
int snmp_vacm_add_view_tree_inst(struct snmp_agent *inst, const char *view_name,
				 const struct snmp_oid *subtree, const uint8_t *mask,
				 size_t mask_len, int type_included);

/**
 * @brief Check access for a specific target OID per RFC 3415 §4 for an agent instance.
 */
int snmp_vacm_check_access_ex_inst(struct snmp_agent *inst, const char *context_name,
				   int security_model, const char *security_name, int sec_level,
				   int access_type, const struct snmp_oid *target_oid);

/**
 * @brief Check access for incoming SNMPv3 message varbinds for an agent instance.
 */
int snmp_vacm_check_access_inst(struct snmp_agent *inst, const struct snmp_v3_msg *msg,
				bool is_write);

/* ---- Legacy API Facade (delegates to default agent) ---- */

int snmp_vacm_init(void);
int snmp_vacm_add_context(const char *context_name);
int snmp_vacm_add_group_mapping(int security_model, const char *security_name,
				const char *group_name);
int snmp_vacm_add_access_rule(const char *group_name, const char *context_prefix,
			      int security_model, int min_sec_level,
			      const char *read_view, const char *write_view,
			      const char *notify_view);
int snmp_vacm_add_view_tree(const char *view_name, const struct snmp_oid *subtree,
			    const uint8_t *mask, size_t mask_len, int type_included);
int snmp_vacm_check_access_ex(const char *context_name, int security_model,
			      const char *security_name, int sec_level,
			      int access_type, const struct snmp_oid *target_oid);
int snmp_vacm_check_access(const struct snmp_v3_msg *msg, bool is_write);
int snmp_vacm_add_user(const char *user_name, const char *group_name);

#endif /* CONFIG_SNMP_AGENT */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_VACM_H_ */
