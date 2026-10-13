/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 */

#include <snmp/snmp_mib.h>
#include <snmp/snmp_core.h>
#include <zephyr/sys/atomic.h>
#include <string.h>
#include <errno.h>

#ifdef CONFIG_SNMP_AGENT

struct snmp_mib2_counters g_snmp_counters = {
	.snmpEnableAuthenTraps = 1 /* 1 = enabled per RFC 1907 */
};

void snmp_mib_lock(struct snmp_agent *inst)
{
	if (inst) {
		k_mutex_lock(&inst->lock, K_FOREVER);
	}
}

void snmp_mib_unlock(struct snmp_agent *inst)
{
	if (inst) {
		k_mutex_unlock(&inst->lock);
	}
}

/* Callbacks for snmp MIB-II group counters */
static int mib2_counter_get(struct snmp_agent *agent, const struct snmp_mib_node *node,
			    struct snmp_varbind *vb)
{
	(void)agent;
	if (!node || !vb || !node->user_data)
		return -EINVAL;
	uint32_t *counter_ptr = (uint32_t *)node->user_data;
	vb->type = SNMP_TAG_COUNTER32;
	vb->val.uint_val = *counter_ptr;
	return 0;
}

static int mib2_enable_authen_traps_get(struct snmp_agent *agent, const struct snmp_mib_node *node,
					struct snmp_varbind *vb)
{
	(void)agent;
	if (!node || !vb)
		return -EINVAL;
	int32_t *val_ptr = (int32_t *)node->user_data;
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = val_ptr ? *val_ptr : g_snmp_counters.snmpEnableAuthenTraps;
	return 0;
}

static int mib2_enable_authen_traps_set(struct snmp_agent *agent, struct snmp_mib_node *node,
					const struct snmp_varbind *vb)
{
	(void)agent;
	if (!node || !vb)
		return -EINVAL;
	if (vb->type != ASN1_TAG_INTEGER)
		return -EINVAL;
	if (vb->val.int_val != 1 && vb->val.int_val != 2)
		return -EINVAL;
	int32_t *val_ptr = (int32_t *)node->user_data;
	if (val_ptr) {
		*val_ptr = vb->val.int_val;
	}
	g_snmp_counters.snmpEnableAuthenTraps = vb->val.int_val;
	return 0;
}

int snmp_set_device_enterprise_oid_inst(struct snmp_agent *inst, const struct snmp_oid *oid)
{
	if (!inst || !oid || oid->len == 0 || oid->len > CONFIG_SNMP_MAX_OID_LEN)
		return -EINVAL;
	snmp_mib_lock(inst);
	inst->sys_object_id = *oid;
	snmp_mib_unlock(inst);
	return 0;
}

int snmp_set_device_enterprise_oid(const struct snmp_oid *oid)
{
	return snmp_set_device_enterprise_oid_inst(snmp_agent_get_default(), oid);
}

int snmp_mib2_set_sysdescr_inst(struct snmp_agent *inst, const char *descr)
{
	if (!inst || !descr || strlen(descr) >= sizeof(inst->sys_descr))
		return -EINVAL;
	snmp_mib_lock(inst);
	strncpy(inst->sys_descr, descr, sizeof(inst->sys_descr) - 1);
	inst->sys_descr[sizeof(inst->sys_descr) - 1] = '\0';
	snmp_mib_unlock(inst);
	return 0;
}

int snmp_mib2_set_sysdescr(const char *descr)
{
	return snmp_mib2_set_sysdescr_inst(snmp_agent_get_default(), descr);
}

int snmp_mib2_set_syscontact_inst(struct snmp_agent *inst, const char *contact)
{
	if (!inst || !contact || strlen(contact) >= sizeof(inst->sys_contact))
		return -EINVAL;
	snmp_mib_lock(inst);
	strncpy(inst->sys_contact, contact, sizeof(inst->sys_contact) - 1);
	inst->sys_contact[sizeof(inst->sys_contact) - 1] = '\0';
	snmp_mib_unlock(inst);
	return 0;
}

int snmp_mib2_set_syscontact(const char *contact)
{
	return snmp_mib2_set_syscontact_inst(snmp_agent_get_default(), contact);
}

int snmp_mib2_set_sysname_inst(struct snmp_agent *inst, const char *name)
{
	if (!inst || !name || strlen(name) >= sizeof(inst->sys_name))
		return -EINVAL;
	snmp_mib_lock(inst);
	strncpy(inst->sys_name, name, sizeof(inst->sys_name) - 1);
	inst->sys_name[sizeof(inst->sys_name) - 1] = '\0';
	snmp_mib_unlock(inst);
	return 0;
}

int snmp_mib2_set_sysname(const char *name)
{
	return snmp_mib2_set_sysname_inst(snmp_agent_get_default(), name);
}

int snmp_mib2_set_syslocation_inst(struct snmp_agent *inst, const char *location)
{
	if (!inst || !location || strlen(location) >= sizeof(inst->sys_location))
		return -EINVAL;
	snmp_mib_lock(inst);
	strncpy(inst->sys_location, location, sizeof(inst->sys_location) - 1);
	inst->sys_location[sizeof(inst->sys_location) - 1] = '\0';
	snmp_mib_unlock(inst);
	return 0;
}

int snmp_mib2_set_syslocation(const char *location)
{
	return snmp_mib2_set_syslocation_inst(snmp_agent_get_default(), location);
}

/* System Group Callbacks */
static int sys_descr_get(struct snmp_agent *agent, const struct snmp_mib_node *node,
			 struct snmp_varbind *vb)
{
	(void)agent;
	if (!node || !vb || !node->user_data)
		return -EINVAL;
	const char *descr = (const char *)node->user_data;
	vb->type = ASN1_TAG_OCTET_STRING;
	vb->val.octet_str.len = strlen(descr);
	memcpy(vb->val.octet_str.data, descr, vb->val.octet_str.len);
	return 0;
}

static int sys_object_id_get(struct snmp_agent *agent, const struct snmp_mib_node *node,
			     struct snmp_varbind *vb)
{
	(void)agent;
	if (!node || !vb || !node->user_data)
		return -EINVAL;
	const struct snmp_oid *oid_ptr = (const struct snmp_oid *)node->user_data;
	vb->type = ASN1_TAG_OID;
	vb->val.oid = *oid_ptr;
	return 0;
}

static int sys_uptime_get(struct snmp_agent *agent, const struct snmp_mib_node *node,
			  struct snmp_varbind *vb)
{
	(void)node;
	(void)agent;
	if (!vb)
		return -EINVAL;
	vb->type = SNMP_TAG_TIMETICKS;
	vb->val.uint_val = (uint32_t)(k_uptime_get() / 10);
	return 0;
}

static int sys_string_get(struct snmp_agent *agent, const struct snmp_mib_node *node,
			  struct snmp_varbind *vb)
{
	(void)agent;
	if (!node || !vb || !node->user_data)
		return -EINVAL;
	const char *str = (const char *)node->user_data;
	vb->type = ASN1_TAG_OCTET_STRING;
	vb->val.octet_str.len = strlen(str);
	memcpy(vb->val.octet_str.data, str, vb->val.octet_str.len);
	return 0;
}

static int sys_string_set(struct snmp_agent *agent, struct snmp_mib_node *node,
			  const struct snmp_varbind *vb)
{
	(void)agent;
	if (!node || !vb || !node->user_data)
		return -EINVAL;
	if (vb->type != ASN1_TAG_OCTET_STRING)
		return -EINVAL;
	char *dst = (char *)node->user_data;
	/* Assume buffer capacity of at least 64 bytes */
	size_t max_len = 64;

	if (vb->val.octet_str.len >= max_len)
		return -EINVAL;
	memcpy(dst, vb->val.octet_str.data, vb->val.octet_str.len);
	dst[vb->val.octet_str.len] = '\0';
	return 0;
}

static int sys_services_get(struct snmp_agent *agent, const struct snmp_mib_node *node,
			    struct snmp_varbind *vb)
{
	(void)node;
	(void)agent;
	if (!vb)
		return -EINVAL;
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = 72; /* Application + Link layer service */
	return 0;
}

static void register_mib2_counter_inst(struct snmp_agent *inst, const uint32_t *subids, uint8_t len,
				       uint32_t *counter_ptr)
{
	struct snmp_mib_node node;
	memset(&node, 0, sizeof(node));
	node.oid.len = len;
	memcpy(node.oid.ids, subids, len * sizeof(uint32_t));
	node.type = SNMP_TAG_COUNTER32;
	node.get_cb = mib2_counter_get;
	node.set_cb = NULL;
	node.user_data = (void *)counter_ptr;
	snmp_mib_register_inst(inst, &node);
}

int snmp_mib_init(struct snmp_agent *inst)
{
	if (!inst)
		return -EINVAL;

	snmp_mib_lock(inst);
	inst->mib_node_cnt = 0;
	inst->mib_table_cnt = 0;
	memset(inst->mib_nodes, 0, sizeof(inst->mib_nodes));
	memset(inst->mib_tables, 0, sizeof(inst->mib_tables));
	snmp_mib_unlock(inst);
	return 0;
}

int snmp_mib_register_defaults(struct snmp_agent *inst)
{
	if (!inst)
		return -EINVAL;

	/* Register standard snmp group (1.3.6.1.2.1.11.x.0) */
	static const uint32_t base_oid[9] = {1, 3, 6, 1, 2, 1, 11, 0, 0};

#define REG_COUNTER_INST(subid, field)                                     \
	do {                                                               \
		uint32_t oid_buf[10];                                      \
		memcpy(oid_buf, base_oid, 8 * sizeof(uint32_t));           \
		oid_buf[7] = subid;                                        \
		oid_buf[8] = 0;                                            \
		register_mib2_counter_inst(inst, oid_buf, 9,               \
					   &inst->counters.field);         \
	} while (0)

	REG_COUNTER_INST(1, snmpInPkts);
	REG_COUNTER_INST(2, snmpOutPkts);
	REG_COUNTER_INST(3, snmpInBadVersions);
	REG_COUNTER_INST(4, snmpInBadCommunityNames);
	REG_COUNTER_INST(5, snmpInBadCommunityUses);
	REG_COUNTER_INST(6, snmpInASNParseErrs);
	REG_COUNTER_INST(8, snmpInTooBigs);
	REG_COUNTER_INST(9, snmpInNoSuchNames);
	REG_COUNTER_INST(10, snmpInBadValues);
	REG_COUNTER_INST(11, snmpInReadOnlys);
	REG_COUNTER_INST(12, snmpInGenErrs);
	REG_COUNTER_INST(13, snmpInTotalReqVars);
	REG_COUNTER_INST(14, snmpInTotalSetVars);
	REG_COUNTER_INST(15, snmpInGetRequests);
	REG_COUNTER_INST(16, snmpInGetNexts);
	REG_COUNTER_INST(17, snmpInSetRequests);
	REG_COUNTER_INST(18, snmpInGetResponses);
	REG_COUNTER_INST(19, snmpInTraps);
	REG_COUNTER_INST(20, snmpOutTooBigs);
	REG_COUNTER_INST(21, snmpOutNoSuchNames);
	REG_COUNTER_INST(22, snmpOutBadValues);
	REG_COUNTER_INST(24, snmpOutGenErrs);
	REG_COUNTER_INST(25, snmpOutGetRequests);
	REG_COUNTER_INST(26, snmpOutGetNexts);
	REG_COUNTER_INST(27, snmpOutSetRequests);
	REG_COUNTER_INST(28, snmpOutGetResponses);
	REG_COUNTER_INST(29, snmpOutTraps);
	REG_COUNTER_INST(31, snmpSilentDrops);
	REG_COUNTER_INST(32, snmpProxyDrops);

	/* Register snmpEnableAuthenTraps (1.3.6.1.2.1.11.30.0) */
	struct snmp_mib_node authen_node;
	memset(&authen_node, 0, sizeof(authen_node));
	authen_node.oid.len = 9;
	memcpy(authen_node.oid.ids, base_oid, 8 * sizeof(uint32_t));
	authen_node.oid.ids[7] = 30;
	authen_node.oid.ids[8] = 0;
	authen_node.type = ASN1_TAG_INTEGER;
	authen_node.get_cb = mib2_enable_authen_traps_get;
	authen_node.set_cb = mib2_enable_authen_traps_set;
	authen_node.user_data = &inst->counters.snmpEnableAuthenTraps;
	snmp_mib_register_inst(inst, &authen_node);

	/* Register MIB-II System group (1.3.6.1.2.1.1.x.0) */
	static const uint32_t sys_base[7] = {1, 3, 6, 1, 2, 1, 1};

#define REG_SYS_NODE_INST(subid, tag_val, g_cb, s_cb, u_data)              \
	do {                                                               \
		struct snmp_mib_node n;                                    \
		memset(&n, 0, sizeof(n));                                  \
		n.oid.len = 9;                                             \
		memcpy(n.oid.ids, sys_base, 7 * sizeof(uint32_t));         \
		n.oid.ids[7] = subid;                                      \
		n.oid.ids[8] = 0;                                          \
		n.type = tag_val;                                          \
		n.get_cb = g_cb;                                           \
		n.set_cb = s_cb;                                           \
		n.user_data = (void *)u_data;                              \
		snmp_mib_register_inst(inst, &n);                          \
	} while (0)

	REG_SYS_NODE_INST(1, ASN1_TAG_OCTET_STRING, sys_descr_get, NULL, inst->sys_descr);
	REG_SYS_NODE_INST(2, ASN1_TAG_OID, sys_object_id_get, NULL, &inst->sys_object_id);
	REG_SYS_NODE_INST(3, SNMP_TAG_TIMETICKS, sys_uptime_get, NULL, NULL);
	REG_SYS_NODE_INST(4, ASN1_TAG_OCTET_STRING, sys_string_get, sys_string_set, inst->sys_contact);
	REG_SYS_NODE_INST(5, ASN1_TAG_OCTET_STRING, sys_string_get, sys_string_set, inst->sys_name);
	REG_SYS_NODE_INST(6, ASN1_TAG_OCTET_STRING, sys_string_get, sys_string_set, inst->sys_location);
	REG_SYS_NODE_INST(7, ASN1_TAG_INTEGER, sys_services_get, NULL, NULL);

	return 0;
}

int snmp_mib_register_inst(struct snmp_agent *inst, const struct snmp_mib_node *node)
{
	if (!inst || !node || node->oid.len == 0 || node->oid.len > CONFIG_SNMP_MAX_OID_LEN)
		return -EINVAL;

	snmp_mib_lock(inst);

	for (size_t k = 0; k < inst->mib_node_cnt; k++) {
		if (snmp_oid_equal(&inst->mib_nodes[k].oid, &node->oid)) {
			inst->mib_nodes[k] = *node;
			snmp_mib_unlock(inst);
			return 0;
		}
	}

	if (inst->mib_node_cnt >= CONFIG_SNMP_MAX_MIB_NODES) {
		snmp_mib_unlock(inst);
		return -ENOMEM;
	}

	/* Insertion sort keeping inst->mib_nodes ordered lexicographically */
	size_t i = inst->mib_node_cnt;
	while (i > 0 && snmp_oid_compare(&inst->mib_nodes[i - 1].oid, &node->oid) > 0) {
		inst->mib_nodes[i] = inst->mib_nodes[i - 1];
		i--;
	}

	inst->mib_nodes[i] = *node;
	inst->mib_node_cnt++;

	snmp_mib_unlock(inst);
	return 0;
}

int snmp_mib_register(const struct snmp_mib_node *node)
{
	return snmp_mib_register_inst(snmp_agent_get_default(), node);
}

int snmp_mib_register_nodes(struct snmp_agent *inst, const struct snmp_mib_node *nodes,
			    size_t count)
{
	if (!inst || !nodes || count == 0)
		return -EINVAL;

	snmp_mib_lock(inst);

	if (inst->mib_node_cnt + count > CONFIG_SNMP_MAX_MIB_NODES) {
		snmp_mib_unlock(inst);
		return -ENOMEM;
	}

	for (size_t j = 0; j < count; j++) {
		inst->mib_nodes[inst->mib_node_cnt + j] = nodes[j];
	}
	inst->mib_node_cnt += count;

	/* Insertion sort to re-establish lexicographic order */
	for (size_t i = 0; i < inst->mib_node_cnt; i++) {
		for (size_t j = i + 1; j < inst->mib_node_cnt; j++) {
			if (snmp_oid_compare(&inst->mib_nodes[i].oid, &inst->mib_nodes[j].oid) > 0) {
				struct snmp_mib_node tmp = inst->mib_nodes[i];
				inst->mib_nodes[i] = inst->mib_nodes[j];
				inst->mib_nodes[j] = tmp;
			}
		}
	}

	snmp_mib_unlock(inst);
	return 0;
}

static bool snmp_table_find_next_entry(const struct snmp_mib_table *tbl,
				       const struct snmp_oid *oid,
				       uint8_t *best_col_idx,
				       struct snmp_table_row **best_row_ptr,
				       struct snmp_oid *best_entry_oid)
{
	if (!tbl || !tbl->rows || tbl->column_cnt == 0)
		return false;

	bool found = false;
	struct snmp_oid best_oid;
	uint8_t best_c = 0;
	struct snmp_table_row *best_r = NULL;

	for (uint8_t c = 0; c < tbl->column_cnt; c++) {
		uint8_t col_subid = tbl->column_subids[c];
		for (struct snmp_table_row *r = tbl->rows; r; r = r->next) {
			struct snmp_oid entry_oid;
			entry_oid.len = tbl->table_oid.len + 2;
			for (uint8_t k = 0; k < tbl->table_oid.len; k++) {
				entry_oid.ids[k] = tbl->table_oid.ids[k];
			}
			entry_oid.ids[tbl->table_oid.len] = col_subid;
			entry_oid.ids[tbl->table_oid.len + 1] = r->index;

			if (snmp_oid_compare(&entry_oid, oid) > 0) {
				if (!found || snmp_oid_compare(&entry_oid, &best_oid) < 0) {
					best_oid = entry_oid;
					best_c = c;
					best_r = r;
					found = true;
				}
			}
		}
	}

	if (found) {
		*best_col_idx = best_c;
		*best_row_ptr = best_r;
		*best_entry_oid = best_oid;
		return true;
	}
	return false;
}

int snmp_mib_get(struct snmp_agent *inst, const struct snmp_oid *oid, struct snmp_varbind *vb)
{
	if (!inst || !oid || !vb)
		return -EINVAL;

	snmp_mib_lock(inst);

	for (size_t t = 0; t < inst->mib_table_cnt; t++) {
		struct snmp_mib_table *tbl = inst->mib_tables[t];

		if (oid->len != tbl->table_oid.len + 2)
			continue;

		bool match = true;
		for (uint8_t i = 0; i < tbl->table_oid.len; i++) {
			if (oid->ids[i] != tbl->table_oid.ids[i]) {
				match = false;
				break;
			}
		}
		if (!match)
			continue;

		uint8_t col_subid = (uint8_t)oid->ids[tbl->table_oid.len];
		uint32_t row_idx = (uint32_t)oid->ids[tbl->table_oid.len + 1];

		for (uint8_t c = 0; c < tbl->column_cnt; c++) {
			if (tbl->column_subids[c] != col_subid)
				continue;

			for (struct snmp_table_row *r = tbl->rows; r; r = r->next) {
				if (r->index == row_idx) {
					vb->oid = *oid;
					int ret = tbl->get_cbs[c](inst, r, c, vb);
					snmp_mib_unlock(inst);
					return ret;
				}
			}

			vb->oid = *oid;
			vb->type = SNMP_TAG_EXCEPT_NO_SUCH_INST;
			snmp_mib_unlock(inst);
			return 0;
		}
	}

	for (size_t i = 0; i < inst->mib_node_cnt; i++) {
		if (snmp_oid_equal(&inst->mib_nodes[i].oid, oid)) {
			vb->oid = *oid;
			int ret = 0;
			if (inst->mib_nodes[i].get_cb) {
				ret = inst->mib_nodes[i].get_cb(inst, &inst->mib_nodes[i], vb);
			} else {
				vb->type = inst->mib_nodes[i].type;
			}
			snmp_mib_unlock(inst);
			return ret;
		}
	}

	snmp_mib_unlock(inst);
	vb->oid = *oid;
	vb->type = SNMP_TAG_EXCEPT_NO_SUCH_INST;
	return 0;
}

int snmp_mib_get_next(struct snmp_agent *inst, const struct snmp_oid *oid, struct snmp_varbind *vb)
{
	if (!inst || !oid || !vb)
		return -EINVAL;

	snmp_mib_lock(inst);

	/* Find best table candidate */
	bool has_table_cand = false;
	struct snmp_oid best_table_oid;
	struct snmp_mib_table *best_tbl = NULL;
	uint8_t best_col_idx = 0;
	struct snmp_table_row *best_row = NULL;

	for (size_t t = 0; t < inst->mib_table_cnt; t++) {
		uint8_t c_idx = 0;
		struct snmp_table_row *r_ptr = NULL;
		struct snmp_oid cand_oid;

		if (snmp_table_find_next_entry(inst->mib_tables[t], oid, &c_idx, &r_ptr, &cand_oid)) {
			if (!has_table_cand || snmp_oid_compare(&cand_oid, &best_table_oid) < 0) {
				has_table_cand = true;
				best_table_oid = cand_oid;
				best_tbl = inst->mib_tables[t];
				best_col_idx = c_idx;
				best_row = r_ptr;
			}
		}
	}

	/* Find best scalar candidate */
	bool has_scalar_cand = false;
	size_t best_scalar_idx = 0;

	for (size_t i = 0; i < inst->mib_node_cnt; i++) {
		if (snmp_oid_compare(&inst->mib_nodes[i].oid, oid) > 0) {
			has_scalar_cand = true;
			best_scalar_idx = i;
			break;
		}
	}

	/* Decide between table candidate and scalar candidate */
	bool pick_table = false;
	if (has_table_cand && has_scalar_cand) {
		if (snmp_oid_compare(&best_table_oid, &inst->mib_nodes[best_scalar_idx].oid) < 0) {
			pick_table = true;
		} else {
			pick_table = false;
		}
	} else if (has_table_cand) {
		pick_table = true;
	} else if (has_scalar_cand) {
		pick_table = false;
	} else {
		snmp_mib_unlock(inst);
		vb->oid = *oid;
		vb->type = SNMP_TAG_EXCEPT_END_MIB_VIEW;
		return 0;
	}

	if (pick_table) {
		vb->oid = best_table_oid;
		if (best_row && best_tbl->get_cbs && best_tbl->get_cbs[best_col_idx]) {
			int ret = best_tbl->get_cbs[best_col_idx](inst, best_row, best_col_idx, vb);
			snmp_mib_unlock(inst);
			return ret;
		}
		vb->type = best_tbl->column_types[best_col_idx];
		snmp_mib_unlock(inst);
		return 0;
	} else {
		vb->oid = inst->mib_nodes[best_scalar_idx].oid;
		int ret = 0;
		if (inst->mib_nodes[best_scalar_idx].get_cb) {
			ret = inst->mib_nodes[best_scalar_idx].get_cb(
			    inst, &inst->mib_nodes[best_scalar_idx], vb);
		} else {
			vb->type = inst->mib_nodes[best_scalar_idx].type;
		}
		snmp_mib_unlock(inst);
		return ret;
	}
}

#define MIB_COUNTER_INC(inst, field)                                                               \
	do {                                                                                       \
		struct snmp_agent *_i = (inst) ? (inst) : snmp_agent_get_default();                \
		snmp_counter_inc(&_i->counters.field);                                             \
		if (_i == snmp_agent_get_default()) {                                              \
			snmp_counter_inc(&g_snmp_counters.field);                                  \
		}                                                                                  \
	} while (0)

static int snmp_map_error_to_version(int err, int version)
{
	int status;

	if (err == 0) {
		return SNMP_ERR_NO_ERROR;
	} else if (err > 0) {
		status = err;
	} else {
		switch (err) {
		case -EINVAL:
			status = (version == 0) ? SNMP_ERR_BAD_VALUE : SNMP_ERR_WRONG_VALUE;
			break;
		case -EACCES:
		case -EPERM:
			status = (version == 0) ? SNMP_ERR_READ_ONLY : SNMP_ERR_NOT_WRITABLE;
			break;
		case -ENOENT:
			status = (version == 0) ? SNMP_ERR_NO_SUCH_NAME : SNMP_ERR_NOT_WRITABLE;
			break;
		case -ENOMEM:
		case -ENOSPC:
			status = (version == 0) ? SNMP_ERR_GEN_ERR : SNMP_ERR_RESOURCE_UNAVAILABLE;
			break;
		case -ERANGE:
			status = (version == 0) ? SNMP_ERR_BAD_VALUE : SNMP_ERR_WRONG_VALUE;
			break;
		default:
			status = SNMP_ERR_GEN_ERR;
			break;
		}
	}

	if (version == 0) {
		switch (status) {
		case SNMP_ERR_NO_ERROR:
		case SNMP_ERR_TOO_BIG:
		case SNMP_ERR_NO_SUCH_NAME:
		case SNMP_ERR_BAD_VALUE:
		case SNMP_ERR_READ_ONLY:
		case SNMP_ERR_GEN_ERR:
			return status;
		case SNMP_ERR_NO_ACCESS:
		case SNMP_ERR_NOT_WRITABLE:
			return SNMP_ERR_READ_ONLY;
		case SNMP_ERR_WRONG_TYPE:
		case SNMP_ERR_WRONG_LENGTH:
		case SNMP_ERR_WRONG_ENCODING:
		case SNMP_ERR_WRONG_VALUE:
		case SNMP_ERR_INCONSISTENT_VALUE:
			return SNMP_ERR_BAD_VALUE;
		case SNMP_ERR_NO_CREATION:
		case SNMP_ERR_INCONSISTENT_NAME:
			return SNMP_ERR_NO_SUCH_NAME;
		case SNMP_ERR_RESOURCE_UNAVAILABLE:
		case SNMP_ERR_COMMIT_FAILED:
		case SNMP_ERR_UNDO_FAILED:
		case SNMP_ERR_AUTHORIZATION_ERR:
		default:
			return SNMP_ERR_GEN_ERR;
		}
	}

	return status;
}

struct snmp_set_tx_item {
	struct snmp_mib_node *node;
	struct snmp_mib_table *tbl;
	struct snmp_table_row *tbl_row;
	uint8_t tbl_col;
	bool is_table;
	bool reserved;
	bool has_old_vb;
	struct snmp_varbind old_vb;
	void *tx_ctx;
};

int snmp_mib_set(struct snmp_agent *inst, const struct snmp_oid *oid, const struct snmp_varbind *vb)
{
	if (!inst || !oid || !vb)
		return -EINVAL;

	snmp_mib_lock(inst);

	/* Check tables first */
	for (size_t t = 0; t < inst->mib_table_cnt; t++) {
		struct snmp_mib_table *tbl = inst->mib_tables[t];

		if (oid->len != tbl->table_oid.len + 2)
			continue;

		bool match = true;
		for (uint8_t i = 0; i < tbl->table_oid.len; i++) {
			if (oid->ids[i] != tbl->table_oid.ids[i]) {
				match = false;
				break;
			}
		}
		if (!match)
			continue;

		uint8_t col_subid = (uint8_t)oid->ids[tbl->table_oid.len];
		uint32_t row_idx = (uint32_t)oid->ids[tbl->table_oid.len + 1];

		for (uint8_t c = 0; c < tbl->column_cnt; c++) {
			if (tbl->column_subids[c] != col_subid)
				continue;

			if (!tbl->set_cbs || !tbl->set_cbs[c]) {
				snmp_mib_unlock(inst);
				MIB_COUNTER_INC(inst, snmpInReadOnlys);
				return -EACCES;
			}

			for (struct snmp_table_row *r = tbl->rows; r; r = r->next) {
				if (r->index == row_idx) {
					int ret = tbl->set_cbs[c](inst, r, c, vb);
					snmp_mib_unlock(inst);
					return ret;
				}
			}

			snmp_mib_unlock(inst);
			MIB_COUNTER_INC(inst, snmpInNoSuchNames);
			return -ENOENT;
		}
	}

	/* Check scalar nodes */
	for (size_t i = 0; i < inst->mib_node_cnt; i++) {
		if (snmp_oid_equal(&inst->mib_nodes[i].oid, oid)) {
			if (inst->mib_nodes[i].set_tx_cb) {
				void *tx_ctx = NULL;
				int ret = inst->mib_nodes[i].set_tx_cb(
				    inst, &inst->mib_nodes[i], vb, SNMP_SET_RESERVE, &tx_ctx);
				if (ret == 0) {
					ret = inst->mib_nodes[i].set_tx_cb(
					    inst, &inst->mib_nodes[i], vb, SNMP_SET_COMMIT,
					    &tx_ctx);
				}
				inst->mib_nodes[i].set_tx_cb(inst, &inst->mib_nodes[i], vb,
							     SNMP_SET_CLEANUP, &tx_ctx);
				snmp_mib_unlock(inst);
				return ret;
			}
			if (!inst->mib_nodes[i].set_cb) {
				snmp_mib_unlock(inst);
				MIB_COUNTER_INC(inst, snmpInReadOnlys);
				return -EACCES;
			}
			int ret = inst->mib_nodes[i].set_cb(inst, &inst->mib_nodes[i], vb);
			snmp_mib_unlock(inst);
			return ret;
		}
	}

	snmp_mib_unlock(inst);
	MIB_COUNTER_INC(inst, snmpInNoSuchNames);
	return -ENOENT;
}

int snmp_mib_dispatch(struct snmp_agent *inst, struct snmp_pdu *pdu)
{
	if (!pdu)
		return -EINVAL;

	if (!inst) {
		inst = snmp_agent_get_default();
	}

	pdu->error_status = 0;
	pdu->error_index = 0;

	if (pdu->type == SNMP_PDU_GET_REQ) {
		MIB_COUNTER_INC(inst, snmpInGetRequests);
		for (uint8_t i = 0; i < pdu->varbind_cnt; i++) {
			MIB_COUNTER_INC(inst, snmpInTotalReqVars);
			int ret = snmp_mib_get(inst, &pdu->varbinds[i].oid, &pdu->varbinds[i]);
			if (ret < 0 && pdu->varbinds[i].type != SNMP_TAG_EXCEPT_NO_SUCH_INST) {
				pdu->error_status = 5; /* genErr */
				pdu->error_index = i + 1;
				MIB_COUNTER_INC(inst, snmpOutGenErrs);
				break;
			}
			if (pdu->version == 0 && (pdu->varbinds[i].type == SNMP_TAG_EXCEPT_NO_SUCH_INST ||
						  pdu->varbinds[i].type == SNMP_TAG_EXCEPT_NO_SUCH_OBJ)) {
				pdu->error_status = 2; /* noSuchName per RFC 1157 */
				pdu->error_index = i + 1;
				pdu->varbinds[i].type = ASN1_TAG_NULL;
				MIB_COUNTER_INC(inst, snmpOutNoSuchNames);
				break;
			}
		}
		pdu->type = SNMP_PDU_GET_RESP;
		MIB_COUNTER_INC(inst, snmpOutGetResponses);
	} else if (pdu->type == SNMP_PDU_GET_NEXT_REQ) {
		MIB_COUNTER_INC(inst, snmpInGetNexts);
		for (uint8_t i = 0; i < pdu->varbind_cnt; i++) {
			MIB_COUNTER_INC(inst, snmpInTotalReqVars);
			snmp_mib_get_next(inst, &pdu->varbinds[i].oid, &pdu->varbinds[i]);
			if (pdu->version == 0 && pdu->varbinds[i].type == SNMP_TAG_EXCEPT_END_MIB_VIEW) {
				pdu->error_status = 2; /* noSuchName per RFC 1157 */
				pdu->error_index = i + 1;
				pdu->varbinds[i].type = ASN1_TAG_NULL;
				MIB_COUNTER_INC(inst, snmpOutNoSuchNames);
				break;
			}
		}
		pdu->type = SNMP_PDU_GET_RESP;
		MIB_COUNTER_INC(inst, snmpOutGetResponses);
	} else if (pdu->type == SNMP_PDU_GET_BULK_REQ) {
		MIB_COUNTER_INC(inst, snmpInGetNexts);
		uint8_t orig_cnt = pdu->varbind_cnt;
		int32_t non_rep = pdu->non_repeaters < 0 ? 0 : pdu->non_repeaters;
		int32_t max_rep = pdu->max_repetitions < 0 ? 0 : pdu->max_repetitions;

		if (non_rep > orig_cnt)
			non_rep = orig_cnt;
		uint8_t new_cnt = 0;

		snmp_mib_lock(inst);
		struct snmp_varbind res_vb[CONFIG_SNMP_MAX_VARBINDS];
		struct snmp_oid current_oids[CONFIG_SNMP_MAX_VARBINDS];

		for (int i = 0; i < non_rep && new_cnt < CONFIG_SNMP_MAX_VARBINDS; i++) {
			res_vb[new_cnt] = pdu->varbinds[i];
			snmp_mib_get_next(inst, &pdu->varbinds[i].oid, &res_vb[new_cnt]);
			new_cnt++;
		}

		uint8_t num_repeaters = orig_cnt - non_rep;
		if (num_repeaters > 0 && max_rep > 0) {
			for (uint8_t r = 0; r < num_repeaters; r++) {
				current_oids[r] = pdu->varbinds[non_rep + r].oid;
			}

			for (int rep = 0; rep < max_rep; rep++) {
				bool all_end = true;
				for (uint8_t r = 0; r < num_repeaters && new_cnt < CONFIG_SNMP_MAX_VARBINDS; r++) {
					struct snmp_varbind vb;
					snmp_mib_get_next(inst, &current_oids[r], &vb);
					res_vb[new_cnt++] = vb;
					if (vb.type != SNMP_TAG_EXCEPT_END_MIB_VIEW) {
						all_end = false;
						current_oids[r] = vb.oid;
					}
				}
				if (all_end)
					break;
			}
		}

		pdu->varbind_cnt = new_cnt;
		memcpy(pdu->varbinds, res_vb, new_cnt * sizeof(struct snmp_varbind));
		snmp_mib_unlock(inst);

		/* RFC 1907: count total variables processed by GetBulk */
		inst->counters.snmpInTotalReqVars += new_cnt;
		if (inst == snmp_agent_get_default()) {
			g_snmp_counters.snmpInTotalReqVars += new_cnt;
		}

		pdu->type = SNMP_PDU_GET_RESP;
		MIB_COUNTER_INC(inst, snmpOutGetResponses);
	} else if (pdu->type == SNMP_PDU_SET_REQ) {
		MIB_COUNTER_INC(inst, snmpInSetRequests);

		struct snmp_set_tx_item tx_items[CONFIG_SNMP_MAX_VARBINDS];
		memset(tx_items, 0, sizeof(tx_items));

		int error_status = SNMP_ERR_NO_ERROR;
		int error_index = 0;

		snmp_mib_lock(inst);

		/* Phase 1: Reserve & Validation */
		for (uint8_t i = 0; i < pdu->varbind_cnt; i++) {
			MIB_COUNTER_INC(inst, snmpInTotalSetVars);
			struct snmp_varbind *vb = &pdu->varbinds[i];
			struct snmp_set_tx_item *item = &tx_items[i];
			bool found = false;

			/* 1. Check table */
			for (size_t t = 0; t < inst->mib_table_cnt; t++) {
				struct snmp_mib_table *tbl = inst->mib_tables[t];
				if (vb->oid.len != tbl->table_oid.len + 2) {
					continue;
				}
				bool match = true;
				for (uint8_t k = 0; k < tbl->table_oid.len; k++) {
					if (vb->oid.ids[k] != tbl->table_oid.ids[k]) {
						match = false;
						break;
					}
				}
				if (!match) continue;

				uint8_t col_subid = (uint8_t)vb->oid.ids[tbl->table_oid.len];
				uint32_t row_idx = (uint32_t)vb->oid.ids[tbl->table_oid.len + 1];

				for (uint8_t c = 0; c < tbl->column_cnt; c++) {
					if (tbl->column_subids[c] != col_subid) {
						continue;
					}
					found = true;
					item->is_table = true;
					item->tbl = tbl;
					item->tbl_col = c;

					if (!tbl->set_cbs || !tbl->set_cbs[c]) {
						error_status = (pdu->version == 0) ? SNMP_ERR_READ_ONLY : SNMP_ERR_NOT_WRITABLE;
						error_index = i + 1;
						break;
					}

					if (tbl->column_types[c] != vb->type) {
						error_status = (pdu->version == 0) ? SNMP_ERR_BAD_VALUE : SNMP_ERR_WRONG_TYPE;
						error_index = i + 1;
						break;
					}

					for (struct snmp_table_row *r = tbl->rows; r; r = r->next) {
						if (r->index == row_idx) {
							item->tbl_row = r;
							break;
						}
					}
					if (!item->tbl_row) {
						error_status = (pdu->version == 0) ? SNMP_ERR_NO_SUCH_NAME : SNMP_ERR_NOT_WRITABLE;
						error_index = i + 1;
						break;
					}

					if (tbl->get_cbs && tbl->get_cbs[c]) {
						item->old_vb.oid = vb->oid;
						if (tbl->get_cbs[c](inst, item->tbl_row, c,
								    &item->old_vb) == 0) {
							item->has_old_vb = true;
						}
					}
					item->reserved = true;
					break;
				}
				if (found) break;
			}

			if (error_status != SNMP_ERR_NO_ERROR) {
				break;
			}

			/* 2. Check scalar nodes if not a table column */
			if (!found) {
				for (size_t k = 0; k < inst->mib_node_cnt; k++) {
					if (snmp_oid_equal(&inst->mib_nodes[k].oid, &vb->oid)) {
						found = true;
						item->node = &inst->mib_nodes[k];
						break;
					}
				}

				if (!found) {
					error_status = (pdu->version == 0) ? SNMP_ERR_NO_SUCH_NAME : SNMP_ERR_NOT_WRITABLE;
					error_index = i + 1;
					break;
				}

				if (!item->node->set_tx_cb && !item->node->set_cb) {
					error_status = (pdu->version == 0) ? SNMP_ERR_READ_ONLY : SNMP_ERR_NOT_WRITABLE;
					error_index = i + 1;
					break;
				}

				if (item->node->type != vb->type) {
					error_status = (pdu->version == 0) ? SNMP_ERR_BAD_VALUE : SNMP_ERR_WRONG_TYPE;
					error_index = i + 1;
					break;
				}

				if (item->node->set_tx_cb) {
					int rc = item->node->set_tx_cb(
					    inst, item->node, vb, SNMP_SET_RESERVE, &item->tx_ctx);
					if (rc != 0) {
						error_status = snmp_map_error_to_version(rc, pdu->version);
						error_index = i + 1;
						break;
					}
					item->reserved = true;
				} else {
					if (item->node->get_cb) {
						item->old_vb.oid = item->node->oid;
						if (item->node->get_cb(inst, item->node,
								       &item->old_vb) == 0) {
							item->has_old_vb = true;
						}
					}
					item->reserved = true;
				}
			}
		}

		/* If Phase 1 failed, cleanup reserved resources and abort */
		if (error_status != SNMP_ERR_NO_ERROR) {
			for (uint8_t j = 0; j < pdu->varbind_cnt; j++) {
				if (tx_items[j].reserved && tx_items[j].node && tx_items[j].node->set_tx_cb) {
					tx_items[j].node->set_tx_cb(
					    inst, tx_items[j].node, &pdu->varbinds[j],
					    SNMP_SET_CLEANUP, &tx_items[j].tx_ctx);
				}
			}
			snmp_mib_unlock(inst);

			pdu->error_status = error_status;
			pdu->error_index = error_index;
			pdu->type = SNMP_PDU_GET_RESP;

			if (error_status == SNMP_ERR_BAD_VALUE || error_status == SNMP_ERR_WRONG_VALUE) {
				MIB_COUNTER_INC(inst, snmpOutBadValues);
			} else if (error_status == SNMP_ERR_READ_ONLY || error_status == SNMP_ERR_NOT_WRITABLE) {
				MIB_COUNTER_INC(inst, snmpInReadOnlys);
			} else if (error_status == SNMP_ERR_NO_SUCH_NAME) {
				MIB_COUNTER_INC(inst, snmpOutNoSuchNames);
			} else {
				MIB_COUNTER_INC(inst, snmpOutGenErrs);
			}
			MIB_COUNTER_INC(inst, snmpOutGetResponses);
			return 0;
		}

		/* Phase 2: Commit */
		uint8_t commit_fail_idx = 0;
		bool commit_failed = false;

		for (uint8_t k = 0; k < pdu->varbind_cnt; k++) {
			struct snmp_set_tx_item *item = &tx_items[k];
			struct snmp_varbind *vb = &pdu->varbinds[k];
			int rc = 0;

			if (item->node && item->node->set_tx_cb) {
				rc = item->node->set_tx_cb(inst, item->node, vb, SNMP_SET_COMMIT,
							   &item->tx_ctx);
			} else if (item->node && item->node->set_cb) {
				rc = item->node->set_cb(inst, item->node, vb);
			} else if (item->is_table && item->tbl && item->tbl->set_cbs[item->tbl_col]) {
				rc = item->tbl->set_cbs[item->tbl_col](inst, item->tbl_row,
								       item->tbl_col, vb);
			}

			if (rc != 0) {
				commit_failed = true;
				commit_fail_idx = k;
				break;
			}
		}

		if (commit_failed) {
			/* Phase 3: Rollback / Undo */
			for (int u = (int)commit_fail_idx - 1; u >= 0; u--) {
				struct snmp_set_tx_item *item = &tx_items[u];
				if (item->node && item->node->set_tx_cb) {
					item->node->set_tx_cb(inst, item->node, &pdu->varbinds[u],
							      SNMP_SET_UNDO, &item->tx_ctx);
				} else if (item->has_old_vb) {
					if (item->node && item->node->set_cb) {
						item->node->set_cb(inst, item->node, &item->old_vb);
					} else if (item->is_table && item->tbl && item->tbl->set_cbs[item->tbl_col]) {
						item->tbl->set_cbs[item->tbl_col](
						    inst, item->tbl_row, item->tbl_col,
						    &item->old_vb);
					}
				}
			}

			/* Cleanup all */
			for (uint8_t j = 0; j < pdu->varbind_cnt; j++) {
				if (tx_items[j].reserved && tx_items[j].node && tx_items[j].node->set_tx_cb) {
					tx_items[j].node->set_tx_cb(
					    inst, tx_items[j].node, &pdu->varbinds[j],
					    SNMP_SET_CLEANUP, &tx_items[j].tx_ctx);
				}
			}
			snmp_mib_unlock(inst);

			pdu->error_status = (pdu->version == 0) ? SNMP_ERR_GEN_ERR : SNMP_ERR_COMMIT_FAILED;
			pdu->error_index = commit_fail_idx + 1;
			pdu->type = SNMP_PDU_GET_RESP;

			MIB_COUNTER_INC(inst, snmpOutGenErrs);
			MIB_COUNTER_INC(inst, snmpOutGetResponses);
			return 0;
		}

		/* Phase 4: Commit Succeeded -> Cleanup & Read Back */
		for (uint8_t j = 0; j < pdu->varbind_cnt; j++) {
			if (tx_items[j].reserved && tx_items[j].node && tx_items[j].node->set_tx_cb) {
				tx_items[j].node->set_tx_cb(inst, tx_items[j].node,
							    &pdu->varbinds[j], SNMP_SET_CLEANUP,
							    &tx_items[j].tx_ctx);
			}
		}

		/* Read back confirmed values per RFC 3416 §4.2.5 */
		for (uint8_t i = 0; i < pdu->varbind_cnt; i++) {
			snmp_mib_get(inst, &pdu->varbinds[i].oid, &pdu->varbinds[i]);
		}

		snmp_mib_unlock(inst);

		pdu->error_status = SNMP_ERR_NO_ERROR;
		pdu->error_index = 0;
		pdu->type = SNMP_PDU_GET_RESP;
		MIB_COUNTER_INC(inst, snmpOutGetResponses);
		return 0;
	}

	return 0;
}

/* --- MIB Table Support --- */

int snmp_mib_register_table_inst(struct snmp_agent *inst, struct snmp_mib_table *table)
{
	if (!inst || !table || table->column_cnt == 0 || !table->column_subids ||
	    !table->column_types || !table->get_cbs)
		return -EINVAL;

	snmp_mib_lock(inst);

	for (size_t t = 0; t < inst->mib_table_cnt; t++) {
		if (snmp_oid_equal(&inst->mib_tables[t]->table_oid, &table->table_oid)) {
			inst->mib_tables[t] = table;
			snmp_mib_unlock(inst);
			return 0;
		}
	}

	if (inst->mib_table_cnt >= CONFIG_SNMP_MAX_TABLES) {
		snmp_mib_unlock(inst);
		return -ENOMEM;
	}

	inst->mib_tables[inst->mib_table_cnt++] = table;

	snmp_mib_unlock(inst);
	return 0;
}

int snmp_mib_register_table(struct snmp_mib_table *table)
{
	return snmp_mib_register_table_inst(snmp_agent_get_default(), table);
}

int snmp_mib_table_add_row(struct snmp_mib_table *table, struct snmp_table_row *row)
{
	if (!table || !row)
		return -EINVAL;

	/* TODO(8c): the row list is application-owned and this helper takes no agent,
	 * so it serialises on the default instance's lock, exactly as before.
	 */
	snmp_mib_lock(snmp_agent_get_default());

	row->next = table->rows;
	table->rows = row;

	snmp_mib_unlock(snmp_agent_get_default());
	return 0;
}

int snmp_mib_table_remove_row(struct snmp_mib_table *table, uint32_t index)
{
	if (!table)
		return -EINVAL;

	snmp_mib_lock(snmp_agent_get_default());

	struct snmp_table_row *prev = NULL;
	struct snmp_table_row *cur = table->rows;

	while (cur) {
		if (cur->index == index) {
			if (prev)
				prev->next = cur->next;
			else
				table->rows = cur->next;
			snmp_mib_unlock(snmp_agent_get_default());
			return 0;
		}
		prev = cur;
		cur = cur->next;
	}

	snmp_mib_unlock(snmp_agent_get_default());
	return -ENOENT;
}

#endif /* CONFIG_SNMP_AGENT */
