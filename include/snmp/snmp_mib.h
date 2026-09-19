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

#ifndef CONFIG_SNMP_MAX_TABLES
#define CONFIG_SNMP_MAX_TABLES 8
#endif

struct snmp_mib_node;

typedef int (*snmp_mib_get_cb_t)(const struct snmp_mib_node *node, struct snmp_varbind *vb);
typedef int (*snmp_mib_set_cb_t)(struct snmp_mib_node *node, const struct snmp_varbind *vb);

struct snmp_mib_node {
	struct snmp_oid oid;
	uint8_t type;
	snmp_mib_get_cb_t get_cb;
	snmp_mib_set_cb_t set_cb;
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

/* Counter increment helper — uses atomic ops when CONFIG_ATOMIC_OPERATIONS
 * is enabled, otherwise plain increment. Counters are best-effort stats;
 * minor races are acceptable per RFC 1907.
 */
static inline void snmp_counter_inc(uint32_t *counter)
{
#if defined(CONFIG_ATOMIC_OPERATIONS)
	atomic_inc((atomic_t *)counter);
#else
	(*counter)++;
#endif
}

/* --- MIB Public APIs --- */

/**
 * @brief Initialize the MIB tree. Must be called once before any other MIB operation.
 *        The tree starts empty; register nodes with snmp_mib_register() or
 *        snmp_mib_register_defaults().
 *
 * @return 0 on success, negative errno on failure.
 */
int snmp_mib_init(void);

/**
 * @brief Register the standard MIB-II system group (1.3.6.1.2.1.1) and
 *        snmp group (1.3.6.1.2.1.11) counters. Call after snmp_mib_init()
 *        if standard MIB-II objects are needed.
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
 * @brief Register an array of MIB nodes in bulk (equivalent to lwIP's snmp_set_mibs).
 *        All nodes are inserted into the same sorted tree.
 *
 * @param nodes Pointer to array of MIB node definitions.
 * @param count Number of nodes in the array.
 * @return 0 on success, negative errno on failure.
 */
int snmp_mib_register_nodes(const struct snmp_mib_node *nodes, size_t count);

int snmp_mib_get(const struct snmp_oid *oid, struct snmp_varbind *vb);
int snmp_mib_get_next(const struct snmp_oid *oid, struct snmp_varbind *vb);
int snmp_mib_set(const struct snmp_oid *oid, const struct snmp_varbind *vb);
int snmp_mib_dispatch(struct snmp_pdu *pdu);

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

int snmp_mib_register_table(struct snmp_mib_table *table);
int snmp_mib_table_add_row(struct snmp_mib_table *table, struct snmp_table_row *row);
int snmp_mib_table_remove_row(struct snmp_mib_table *table, uint32_t index);

/* Thread safety mutex lock helpers */
void snmp_mib_lock(void);
void snmp_mib_unlock(void);

/* --- MIB-II System Group Convenience Setters --- */
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
