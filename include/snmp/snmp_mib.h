/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_MIB_H_
#define ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_MIB_H_

#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>
#include <snmp/snmp_ber.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_SNMP_AGENT

#ifndef CONFIG_SNMP_MAX_MIB_NODES
#define CONFIG_SNMP_MAX_MIB_NODES 128
#endif

#ifndef CONFIG_SNMP_MAX_TABLES
#define CONFIG_SNMP_MAX_TABLES 8
#endif

struct snmp_mib_node;
struct snmp_agent;

/**
 * @brief Two-Phase Commit (2PC) SET transaction action phases per RFC 3416 §4.2.5.
 */
enum snmp_set_action {
	SNMP_SET_RESERVE,  /**< Phase 1: validate types, values, and reserve resources */
	SNMP_SET_COMMIT,   /**< Phase 2: apply modifications */
	SNMP_SET_UNDO,     /**< Phase 3: rollback on partial failure */
	SNMP_SET_CLEANUP   /**< Phase 4: release transaction resources */
};

/* RFC 3416 Protocol Error Status Codes */
#define SNMP_ERR_NO_ERROR              0
#define SNMP_ERR_TOO_BIG               1
#define SNMP_ERR_NO_SUCH_NAME          2
#define SNMP_ERR_BAD_VALUE             3
#define SNMP_ERR_READ_ONLY             4
#define SNMP_ERR_GEN_ERR               5
#define SNMP_ERR_NO_ACCESS             6
#define SNMP_ERR_WRONG_TYPE            7
#define SNMP_ERR_WRONG_LENGTH          8
#define SNMP_ERR_WRONG_ENCODING        9
#define SNMP_ERR_WRONG_VALUE           10
#define SNMP_ERR_NO_CREATION           11
#define SNMP_ERR_INCONSISTENT_VALUE    12
#define SNMP_ERR_RESOURCE_UNAVAILABLE  13
#define SNMP_ERR_COMMIT_FAILED         14
#define SNMP_ERR_UNDO_FAILED           15
#define SNMP_ERR_AUTHORIZATION_ERR     16
#define SNMP_ERR_NOT_WRITABLE          17
#define SNMP_ERR_INCONSISTENT_NAME     18

typedef int (*snmp_mib_get_cb_t)(const struct snmp_mib_node *node, struct snmp_varbind *vb);
typedef int (*snmp_mib_set_cb_t)(struct snmp_mib_node *node, const struct snmp_varbind *vb);
typedef int (*snmp_mib_set_tx_cb_t)(struct snmp_mib_node *node, const struct snmp_varbind *vb,
				    enum snmp_set_action action, void **tx_ctx);

struct snmp_mib_node {
	struct snmp_oid oid;
	uint8_t type;
	snmp_mib_get_cb_t get_cb;
	snmp_mib_set_cb_t set_cb;
	snmp_mib_set_tx_cb_t set_tx_cb;
	void *user_data;
};

/* --- Global SNMP MIB-II Group (1.3.6.1.2.1.11) Counters --- */
struct snmp_mib2_counters {
	uint32_t snmpInPkts;               /* 11.1.0 */
	uint32_t snmpOutPkts;              /* 11.2.0 */
	uint32_t snmpInBadVersions;        /* 11.3.0 */
	uint32_t snmpInBadCommunityNames;  /* 11.4.0 */
	uint32_t snmpInBadCommunityUses;   /* 11.5.0 */
	uint32_t snmpInASNParseErrs;       /* 11.6.0 */
	uint32_t snmpInTooBigs;            /* 11.8.0 */
	uint32_t snmpInNoSuchNames;        /* 11.9.0 */
	uint32_t snmpInBadValues;          /* 11.10.0 */
	uint32_t snmpInReadOnlys;          /* 11.11.0 */
	uint32_t snmpInGenErrs;            /* 11.12.0 */
	uint32_t snmpInTotalReqVars;       /* 11.13.0 */
	uint32_t snmpInTotalSetVars;       /* 11.14.0 */
	uint32_t snmpInGetRequests;        /* 11.15.0 */
	uint32_t snmpInGetNexts;           /* 11.16.0 */
	uint32_t snmpInSetRequests;        /* 11.17.0 */
	uint32_t snmpInGetResponses;       /* 11.18.0 */
	uint32_t snmpInTraps;              /* 11.19.0 */
	uint32_t snmpOutTooBigs;           /* 11.20.0 */
	uint32_t snmpOutNoSuchNames;       /* 11.21.0 */
	uint32_t snmpOutBadValues;         /* 11.22.0 */
	uint32_t snmpOutGenErrs;           /* 11.24.0 */
	uint32_t snmpOutGetRequests;       /* 11.25.0 */
	uint32_t snmpOutGetNexts;          /* 11.26.0 */
	uint32_t snmpOutSetRequests;       /* 11.27.0 */
	uint32_t snmpOutGetResponses;      /* 11.28.0 */
	uint32_t snmpOutTraps;             /* 11.29.0 */
	int32_t  snmpEnableAuthenTraps;    /* 11.30.0 (1=enabled, 2=disabled) */
	uint32_t snmpSilentDrops;          /* 11.31.0 */
	uint32_t snmpProxyDrops;           /* 11.32.0 */
};

extern struct snmp_mib2_counters g_snmp_counters;

static inline void snmp_counter_inc(uint32_t *counter)
{
#if defined(CONFIG_ATOMIC_OPERATIONS)
	atomic_inc((atomic_t *)counter);
#else
	(*counter)++;
#endif
}

/* --- MIB Table Support --- */

struct snmp_table_row;

typedef int (*snmp_table_get_cb_t)(const struct snmp_table_row *row, uint8_t column, struct snmp_varbind *vb);
typedef int (*snmp_table_set_cb_t)(struct snmp_table_row *row, uint8_t column, const struct snmp_varbind *vb);

struct snmp_table_row {
	uint32_t index;
	struct snmp_table_row *next;
	void *user_data;
};

struct snmp_mib_table {
	struct snmp_oid table_oid;
	uint8_t column_cnt;
	const uint8_t *column_subids;
	const uint8_t *column_types;
	snmp_table_get_cb_t *get_cbs;
	snmp_table_set_cb_t *set_cbs;
	struct snmp_table_row *rows;
	void *user_data;
};

int snmp_mib_table_add_row(struct snmp_mib_table *table, struct snmp_table_row *row);
int snmp_mib_table_remove_row(struct snmp_mib_table *table, uint32_t index);

/* --- Instance-based MIB APIs --- */

/**
 * @brief Reset the agent's MIB tree and table registry.
 * @param inst Target agent instance.
 * @return 0 on success, -EINVAL if @p inst is NULL.
 */
int snmp_mib_init(struct snmp_agent *inst);

/**
 * @brief Register the MIB-II system group and snmp (1.3.6.1.2.1.11) counter group
 *        into the agent's own tree.
 * @param inst Target agent instance.
 * @return 0 on success, -EINVAL if @p inst is NULL, -ENOMEM if the tree is full.
 */
int snmp_mib_register_defaults(struct snmp_agent *inst);

/**
 * @brief Register a single MIB node in the agent's tree (lexicographically sorted).
 * @param inst Target agent instance.
 * @param node Node definition to copy in.
 * @return 0 on success, -EINVAL on bad arguments, -ENOMEM if the tree is full.
 */
int snmp_mib_register_inst(struct snmp_agent *inst, const struct snmp_mib_node *node);

/**
 * @brief Register an array of MIB nodes in bulk.
 * @param inst Target agent instance.
 * @param nodes Node array.
 * @param count Number of nodes.
 * @return 0 on success, -EINVAL on bad arguments, -ENOMEM if the tree is full.
 */
int snmp_mib_register_nodes(struct snmp_agent *inst, const struct snmp_mib_node *nodes,
			    size_t count);

/**
 * @brief Look up one OID in the agent's tree (scalar node or table cell).
 * @param inst Target agent instance.
 * @param oid OID to resolve.
 * @param vb Output variable binding.
 * @return 0 on success, -EINVAL on bad arguments, negative errno from the node callback.
 */
int snmp_mib_get(struct snmp_agent *inst, const struct snmp_oid *oid, struct snmp_varbind *vb);

/**
 * @brief Return the lexicographically next OID present in the agent's tree.
 * @param inst Target agent instance.
 * @param oid Reference OID.
 * @param vb Output variable binding (endOfMibView when nothing is larger).
 * @return 0 on success, -EINVAL on bad arguments.
 */
int snmp_mib_get_next(struct snmp_agent *inst, const struct snmp_oid *oid, struct snmp_varbind *vb);

/**
 * @brief Write one variable binding (reserve/commit/cleanup runs inline).
 * @param inst Target agent instance.
 * @param oid Target OID.
 * @param vb Value to write.
 * @return 0 on success, -EINVAL on bad arguments, -ENOENT/-EACCES per RFC 3416.
 */
int snmp_mib_set(struct snmp_agent *inst, const struct snmp_oid *oid,
		 const struct snmp_varbind *vb);

/**
 * @brief Execute a PDU (GET/GETNEXT/GETBULK/SET) against the agent's tree.
 *
 * Runs the two-phase-commit SET pipeline of RFC 3416 section 4.2.5 atomically under
 * the agent lock. @p inst is mandatory: pass the agent that received the message.
 *
 * @param inst Target agent instance.
 * @param pdu PDU to process in place (error_status/error_index and response type set).
 * @return 0 on success, -EINVAL if @p inst or @p pdu is NULL.
 */
int snmp_mib_dispatch(struct snmp_agent *inst, struct snmp_pdu *pdu);

/**
 * @brief Register an SNMP table in the agent's tree.
 * @param inst Target agent instance.
 * @param table Application-owned table descriptor (pointer is stored, not copied).
 * @return 0 on success, -EINVAL on bad arguments, -ENOMEM if the table registry is full.
 */
int snmp_mib_register_table_inst(struct snmp_agent *inst, struct snmp_mib_table *table);

/**
 * @brief Lock the agent's shared state (MIB tree, tables, sys strings, communities,
 *        engine config and rx/tx/current_pdu scratch). Same mutex as @c inst->lock.
 * @param inst Target agent instance.
 */
void snmp_mib_lock(struct snmp_agent *inst);

/** @brief Release the lock taken by snmp_mib_lock(). @param inst Target agent. */
void snmp_mib_unlock(struct snmp_agent *inst);

int snmp_set_device_enterprise_oid_inst(struct snmp_agent *inst, const struct snmp_oid *oid);
int snmp_mib2_set_sysdescr_inst(struct snmp_agent *inst, const char *descr);
int snmp_mib2_set_syscontact_inst(struct snmp_agent *inst, const char *contact);
int snmp_mib2_set_sysname_inst(struct snmp_agent *inst, const char *name);
int snmp_mib2_set_syslocation_inst(struct snmp_agent *inst, const char *location);

/*
 * --- Transitional legacy facades (removed in sub-phase 8c) ---------------------
 *
 * These no-parameter entry points delegate to snmp_agent_get_default(). They only
 * survive because samples/snmp_agent still calls them; the identifier cannot be
 * reclaimed by the instance API until the sample migrates, since C has no
 * overloading. Do not use in new code.
 */
int snmp_mib_register(const struct snmp_mib_node *node);
int snmp_mib_register_table(struct snmp_mib_table *table);
int snmp_set_device_enterprise_oid(const struct snmp_oid *oid);
int snmp_mib2_set_sysdescr(const char *descr);
int snmp_mib2_set_syscontact(const char *contact);
int snmp_mib2_set_sysname(const char *name);
int snmp_mib2_set_syslocation(const char *location);

#endif /* CONFIG_SNMP_AGENT */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_MIB_H_ */
