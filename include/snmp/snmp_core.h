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

struct net_if; /* forward declaration: host (non-Zephyr) builds keep it incomplete */

/**
 * @brief Lifecycle states of a &ref agent_instance "struct snmp_agent".
 *
 * Legal transitions:
 * @code
 *   UNINIT --snmp_agent_inst_init()--> INITIALIZED --snmp_agent_start()--> RUNNING
 *      ^                                  ^   |                              |
 *      |                                  |   +--------snmp_agent_deinit()---+
 *      |                                  |                              |
 *   snmp_agent_deinit()             snmp_agent_stop()<-- STOPPING <-------+
 * @endcode
 *
 * Any API invoked in the wrong state returns @c -EPERM.
 */
enum snmp_agent_state {
	SNMP_AGENT_UNINIT = 0,	/**< Zero-filled storage; snmp_agent_inst_init() not called. */
	SNMP_AGENT_INITIALIZED, /**< Domain state ready, transport not listening. */
	SNMP_AGENT_RUNNING,	/**< Sockets bound and registered with the socket service. */
	SNMP_AGENT_STOPPING,	/**< Deregistration in progress (quiesce barrier). */
	SNMP_AGENT_STOPPED,	/**< Transport closed; may be started again or deinitialized. */
};

/** Value of struct snmp_agent::svc_slot when the agent owns no socket-service slot. */
#define SNMP_SLOT_NONE 0xFF

/**
 * @brief Optional creation-time configuration for snmp_agent_inst_init().
 *
 * Every member is optional: a NULL string / NULL pointer / zero value selects the
 * Kconfig default. Passing @ NULL for the whole structure is legal and yields the
 * Kconfig defaults for all fields.
 */
struct snmp_agent_cfg {
	uint16_t port;			      /**< 0 = CONFIG_SNMP_AGENT_PORT (default port). */
	struct net_if *iface;		      /**< NULL = any interface (routing default). */
	const char *read_community;	      /**< NULL = CONFIG_SNMP_COMMUNITY_READ. */
	const char *write_community;	      /**< NULL = CONFIG_SNMP_COMMUNITY_WRITE. */
	const uint8_t *engine_id;	      /**< v3; NULL = derived USM default. */
	uint8_t engine_id_len;		      /**< v3; length of engine_id. */
	const char *sys_descr;		      /**< NULL = built-in default. */
	const char *sys_contact;	      /**< NULL = built-in default. */
	const char *sys_name;		      /**< NULL = built-in default. */
	const char *sys_location;	      /**< NULL = built-in default. */
	const struct snmp_oid *sys_object_id; /**< NULL = keep default enterprise OID. */
	uint32_t engine_boots;		      /**< v3; 0 = CONFIG_SNMP_V3_ENGINE_BOOTS. */
	const char *settings_prefix;	      /**< e.g. "snmp/lan"; NULL = no persistence. */
	const void *user_data;		      /**< Opaque pointer returned to the application. */
};

/**
 * @brief Complete SNMP agent instance state handle, encapsulating all configuration,
 *        MIB tree, USM credentials, VACM access rules, traps, transport and buffers.
 *
 * @note PRIVATE FIELDS: this structure is visible only so that the application can own
 *       the storage (static allocation, zero dynamic memory). Fields must not be read or
 *       written by application code except through the public @c snmp_agent_* / @c snmp_*
 *       APIs — they are module-internal and may change without notice.
 *
 * @note Storage may be zero-filled (BSS): state @c 0 is #SNMP_AGENT_UNINIT and
 *       snmp_agent_inst_init() zero-fills and initialises everything itself.
 */
struct snmp_agent {
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
	/**
	 * @brief Serialises the MIB tree, the identity strings, communities, engine
	 *        configuration, the rx/tx/current_pdu scratch and the rate state.
	 */
	struct k_mutex lock;

	/* Trap engine */
	struct sockaddr_in trap_dests[CONFIG_SNMP_TRAP_DEST_COUNT];
	uint8_t trap_dest_cnt;

	/* Transport/Service */
	int sock_v4;
	int sock_v6;
	uint16_t port;
	struct net_if *bound_iface;

	/* Processing */
	struct snmp_pdu current_pdu;
	uint8_t rx_buf[CONFIG_SNMP_MAX_PDU_SIZE];
	uint8_t tx_buf[CONFIG_SNMP_MAX_PDU_SIZE];
	struct snmp_mib2_counters counters;

#ifdef CONFIG_SNMP_RATE_LIMIT
	/* Per-instance token bucket (protected by lock) */
	uint32_t rate_tokens;
	int64_t rate_last_refill;
#endif

	/* Module-internal lifecycle bookkeeping (see @note above) */
	enum snmp_agent_state state;
	uint8_t svc_slot;

	/* User data pointer */
	void *user_data;
};

/**
 * @brief Initialize an SNMP agent instance with the Kconfig defaults, overridden by
 *        the optional creation-time configuration.
 *
 * Zero-fills @p agent, initialises its mutex, registers the MIB-II default groups and
 * (when SNMPv3 is enabled) initialises USM and VACM. May be re-run after
 * snmp_agent_deinit() on the same storage.
 *
 * @param agent Pointer to caller-owned agent storage.
 * @param cfg   Optional creation-time configuration; @ NULL selects Kconfig defaults.
 * @return 0 on success, -EINVAL if @p agent is NULL.
 */
int snmp_agent_inst_init(struct snmp_agent *agent, const struct snmp_agent_cfg *cfg);

/**
 * @brief Deinitialize an agent instance: reset MIB tree, counters and security state.
 *
 * Caller-owned storage is never freed. Safe to call on an instance that was never
 * started. The instance returns to #SNMP_AGENT_INITIALIZED.
 *
 * @param agent Pointer to agent instance.
 * @return 0 on success, -EINVAL if @p agent is NULL, -EPERM if never initialized.
 */
int snmp_agent_deinit(struct snmp_agent *agent);

/**
 * @brief Process raw SNMP packet payload using an explicit agent instance context.
 *
 * This is the protocol entry point: it is used by the transport adapter and is also
 * usable by tests and applications to inject frames without sockets.
 *
 * @param agent Pointer to target agent instance.
 * @param req_buf Pointer to incoming raw UDP payload.
 * @param req_len Length of incoming payload.
 * @param resp_buf Pointer to output buffer for SNMP response.
 * @param max_resp_len Capacity of output buffer.
 * @param out_resp_len Pointer where output response length will be stored.
 *
 * @return 0 on success (or silent drop with out_resp_len=0), -EINVAL on bad arguments,
 *         -EPERM if the instance was never initialized, negative errno on protocol error.
 */
int snmp_agent_process_pdu(struct snmp_agent *agent, const uint8_t *req_buf, size_t req_len,
			   uint8_t *resp_buf, size_t max_resp_len, size_t *out_resp_len);

/**
 * @brief Set read community string for a specific agent instance.
 *
 * @param agent Pointer to agent instance.
 * @param community Null-terminated community string (max 63 chars).
 * @return 0 on success, -EINVAL on invalid parameter.
 */
int snmp_agent_set_read_community(struct snmp_agent *agent, const char *community);

/**
 * @brief Set write community string for a specific agent instance.
 *
 * @param agent Pointer to agent instance.
 * @param community Null-terminated community string (max 63 chars).
 * @return 0 on success, -EINVAL on invalid parameter.
 */
int snmp_agent_set_write_community(struct snmp_agent *agent, const char *community);

/**
 * @brief Retrieve pointer to the default global agent instance.
 *
 * @deprecated Facade retained only while the no-parameter API exists. It is removed in
 *             sub-phase 8c together with every other legacy entry point; new code must
 *             own its @ref struct snmp_agent storage and call the instance API.
 *
 * @return Pointer to the module-owned default agent instance (lazily initialized).
 */
struct snmp_agent *snmp_agent_get_default(void);

/**
 * @brief Retrieve pointer to default global agent instance (legacy facade support).
 *
 * @deprecated The default-instance facade is removed in sub-phase 8c; applications must
 *             own their @c struct snmp_agent storage and pass it to the instance API.
 * @return Pointer to the module-owned default struct snmp_agent.
 */
struct snmp_agent *snmp_agent_get_default(void);

#endif /* CONFIG_SNMP_AGENT */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_CORE_H_ */
