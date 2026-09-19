/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 */

#include <snmp/snmp_mib.h>
#include <zephyr/sys/atomic.h>
#include <string.h>
#include <errno.h>

#ifdef CONFIG_SNMP_AGENT

static struct snmp_mib_node g_mib_nodes[CONFIG_SNMP_MAX_MIB_NODES];

static size_t g_mib_node_cnt = 0;
static K_MUTEX_DEFINE(g_snmp_mib_mutex);
static K_MUTEX_DEFINE(g_getbulk_mutex);

static struct snmp_mib_table *g_mib_tables[CONFIG_SNMP_MAX_TABLES];
static size_t g_mib_table_cnt = 0;

struct snmp_mib2_counters g_snmp_counters = {
	.snmpEnableAuthenTraps = 1 /* 1 = enabled per RFC 1907 */
};

void snmp_mib_lock(void)
{
	k_mutex_lock(&g_snmp_mib_mutex, K_FOREVER);
}

void snmp_mib_unlock(void)
{
	k_mutex_unlock(&g_snmp_mib_mutex);
}

/* Callbacks for snmp MIB-II group counters */
static int mib2_counter_get(const struct snmp_mib_node *node, struct snmp_varbind *vb)
{
	if (!node || !vb)
		return -EINVAL;
	uint32_t *counter_ptr = (uint32_t *)node->user_data;
	vb->type = SNMP_TAG_COUNTER32;
	vb->val.uint_val = *counter_ptr;
	return 0;
}

static int mib2_enable_authen_traps_get(const struct snmp_mib_node *node, struct snmp_varbind *vb)
{
	if (!node || !vb)
		return -EINVAL;
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = g_snmp_counters.snmpEnableAuthenTraps;
	return 0;
}

static int mib2_enable_authen_traps_set(struct snmp_mib_node *node, const struct snmp_varbind *vb)
{
	if (!node || !vb)
		return -EINVAL;
	if (vb->type != ASN1_TAG_INTEGER)
		return -EINVAL;
	if (vb->val.int_val != 1 && vb->val.int_val != 2)
		return -EINVAL;
	g_snmp_counters.snmpEnableAuthenTraps = vb->val.int_val;
	return 0;
}

static char g_sys_descr[128] = "Zephyr SNMP Agent";
static char g_sys_contact[64] = "admin@example.com";
static char g_sys_name[64] = "zephyr-node";
static char g_sys_location[64] = "Server Room";
static struct snmp_oid g_sys_object_id = {
	.len = 7,
	.ids = {1, 3, 6, 1, 4, 1, 0} /* Generic Enterprise OID default */
};

int snmp_set_device_enterprise_oid(const struct snmp_oid *oid)
{
	if (!oid || oid->len == 0 || oid->len > CONFIG_SNMP_MAX_OID_LEN)
		return -EINVAL;
	snmp_mib_lock();
	g_sys_object_id = *oid;
	snmp_mib_unlock();
	return 0;
}

int snmp_mib2_set_sysdescr(const char *descr)
{
	if (!descr || strlen(descr) >= sizeof(g_sys_descr))
		return -EINVAL;
	snmp_mib_lock();
	strncpy(g_sys_descr, descr, sizeof(g_sys_descr) - 1);
	g_sys_descr[sizeof(g_sys_descr) - 1] = '\0';
	snmp_mib_unlock();
	return 0;
}

int snmp_mib2_set_syscontact(const char *contact)
{
	if (!contact || strlen(contact) >= sizeof(g_sys_contact))
		return -EINVAL;
	snmp_mib_lock();
	strncpy(g_sys_contact, contact, sizeof(g_sys_contact) - 1);
	g_sys_contact[sizeof(g_sys_contact) - 1] = '\0';
	snmp_mib_unlock();
	return 0;
}

int snmp_mib2_set_sysname(const char *name)
{
	if (!name || strlen(name) >= sizeof(g_sys_name))
		return -EINVAL;
	snmp_mib_lock();
	strncpy(g_sys_name, name, sizeof(g_sys_name) - 1);
	g_sys_name[sizeof(g_sys_name) - 1] = '\0';
	snmp_mib_unlock();
	return 0;
}

int snmp_mib2_set_syslocation(const char *location)
{
	if (!location || strlen(location) >= sizeof(g_sys_location))
		return -EINVAL;
	snmp_mib_lock();
	strncpy(g_sys_location, location, sizeof(g_sys_location) - 1);
	g_sys_location[sizeof(g_sys_location) - 1] = '\0';
	snmp_mib_unlock();
	return 0;
}

/* System Group Callbacks */
static int sys_descr_get(const struct snmp_mib_node *node, struct snmp_varbind *vb)
{
	(void)node;
	vb->type = ASN1_TAG_OCTET_STRING;
	vb->val.octet_str.len = strlen(g_sys_descr);
	memcpy(vb->val.octet_str.data, g_sys_descr, vb->val.octet_str.len);
	return 0;
}

static int sys_object_id_get(const struct snmp_mib_node *node, struct snmp_varbind *vb)
{
	(void)node;
	vb->type = ASN1_TAG_OID;
	vb->val.oid = g_sys_object_id;
	return 0;
}

static int sys_uptime_get(const struct snmp_mib_node *node, struct snmp_varbind *vb)
{
	(void)node;
	vb->type = SNMP_TAG_TIMETICKS;
	vb->val.uint_val = (uint32_t)(k_uptime_get() / 10);
	return 0;
}

static int sys_string_get(const struct snmp_mib_node *node, struct snmp_varbind *vb)
{
	const char *str = (const char *)node->user_data;
	vb->type = ASN1_TAG_OCTET_STRING;
	vb->val.octet_str.len = strlen(str);
	memcpy(vb->val.octet_str.data, str, vb->val.octet_str.len);
	return 0;
}

static int sys_string_set(struct snmp_mib_node *node, const struct snmp_varbind *vb)
{
	if (vb->type != ASN1_TAG_OCTET_STRING)
		return -EINVAL;
	char *dst = (char *)node->user_data;
	size_t max_len = (dst == g_sys_contact || dst == g_sys_name || dst == g_sys_location) ? 64 : 128;

	if (vb->val.octet_str.len >= max_len)
		return -EINVAL;
	memcpy(dst, vb->val.octet_str.data, vb->val.octet_str.len);
	dst[vb->val.octet_str.len] = '\0';
	return 0;
}

static int sys_services_get(const struct snmp_mib_node *node, struct snmp_varbind *vb)
{
	(void)node;
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = 72; /* Application + Link layer service */
	return 0;
}

static void register_mib2_counter(const uint32_t *subids, uint8_t len, uint32_t *counter_ptr)
{
	struct snmp_mib_node node;
	memset(&node, 0, sizeof(node));
	node.oid.len = len;
	memcpy(node.oid.ids, subids, len * sizeof(uint32_t));
	node.type = SNMP_TAG_COUNTER32;
	node.get_cb = mib2_counter_get;
	node.set_cb = NULL;
	node.user_data = (void *)counter_ptr;
	snmp_mib_register(&node);
}

int snmp_mib_init(void)
{
	snmp_mib_lock();
	g_mib_node_cnt = 0;
	g_mib_table_cnt = 0;
	snmp_mib_unlock();
	return 0;
}

int snmp_mib_register_defaults(void)
{
	/* Register standard snmp group (1.3.6.1.2.1.11.x.0) */
	static const uint32_t base_oid[9] = {1, 3, 6, 1, 2, 1, 11, 0, 0};

#define REG_COUNTER(subid, field)                                  \
	do                                                             \
	{                                                              \
		uint32_t oid_buf[10];                                      \
		memcpy(oid_buf, base_oid, 8 * sizeof(uint32_t));           \
		oid_buf[7] = subid;                                        \
		oid_buf[8] = 0;                                            \
		register_mib2_counter(oid_buf, 9, &g_snmp_counters.field); \
	} while (0)

	REG_COUNTER(1, snmpInPkts);
	REG_COUNTER(2, snmpOutPkts);
	REG_COUNTER(3, snmpInBadVersions);
	REG_COUNTER(4, snmpInBadCommunityNames);
	REG_COUNTER(5, snmpInBadCommunityUses);
	REG_COUNTER(6, snmpInASNParseErrs);
	REG_COUNTER(8, snmpInTooBigs);
	REG_COUNTER(9, snmpInNoSuchNames);
	REG_COUNTER(10, snmpInBadValues);
	REG_COUNTER(11, snmpInReadOnlys);
	REG_COUNTER(12, snmpInGenErrs);
	REG_COUNTER(13, snmpInTotalReqVars);
	REG_COUNTER(14, snmpInTotalSetVars);
	REG_COUNTER(15, snmpInGetRequests);
	REG_COUNTER(16, snmpInGetNexts);
	REG_COUNTER(17, snmpInSetRequests);
	REG_COUNTER(18, snmpInGetResponses);
	REG_COUNTER(19, snmpInTraps);
	REG_COUNTER(20, snmpOutTooBigs);
	REG_COUNTER(21, snmpOutNoSuchNames);
	REG_COUNTER(22, snmpOutBadValues);
	REG_COUNTER(24, snmpOutGenErrs);
	REG_COUNTER(25, snmpOutGetRequests);
	REG_COUNTER(26, snmpOutGetNexts);
	REG_COUNTER(27, snmpOutSetRequests);
	REG_COUNTER(28, snmpOutGetResponses);
	REG_COUNTER(29, snmpOutTraps);
	REG_COUNTER(31, snmpSilentDrops);
	REG_COUNTER(32, snmpProxyDrops);

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
	authen_node.user_data = NULL;
	snmp_mib_register(&authen_node);

	/* Register MIB-II System group (1.3.6.1.2.1.1.x.0) */
	static const uint32_t sys_base[7] = {1, 3, 6, 1, 2, 1, 1};

#define REG_SYS_NODE(subid, tag_val, g_cb, s_cb, u_data)   \
	do                                                     \
	{                                                      \
		struct snmp_mib_node n;                            \
		memset(&n, 0, sizeof(n));                          \
		n.oid.len = 9;                                     \
		memcpy(n.oid.ids, sys_base, 7 * sizeof(uint32_t)); \
		n.oid.ids[7] = subid;                              \
		n.oid.ids[8] = 0;                                  \
		n.type = tag_val;                                  \
		n.get_cb = g_cb;                                   \
		n.set_cb = s_cb;                                   \
		n.user_data = (void *)u_data;                      \
		snmp_mib_register(&n);                             \
	} while (0)

	REG_SYS_NODE(1, ASN1_TAG_OCTET_STRING, sys_descr_get, NULL, NULL);						/* sysDescr */
	REG_SYS_NODE(2, ASN1_TAG_OID, sys_object_id_get, NULL, NULL);							/* sysObjectID */
	REG_SYS_NODE(3, SNMP_TAG_TIMETICKS, sys_uptime_get, NULL, NULL);						/* sysUpTime */
	REG_SYS_NODE(4, ASN1_TAG_OCTET_STRING, sys_string_get, sys_string_set, g_sys_contact);	/* sysContact */
	REG_SYS_NODE(5, ASN1_TAG_OCTET_STRING, sys_string_get, sys_string_set, g_sys_name);		/* sysName */
	REG_SYS_NODE(6, ASN1_TAG_OCTET_STRING, sys_string_get, sys_string_set, g_sys_location); /* sysLocation */
	REG_SYS_NODE(7, ASN1_TAG_INTEGER, sys_services_get, NULL, NULL);						/* sysServices */

	return 0;
}

int snmp_mib_register(const struct snmp_mib_node *node)
{
	if (!node)
		return -EINVAL;

	snmp_mib_lock();

	for (size_t k = 0; k < g_mib_node_cnt; k++) {
		if (snmp_oid_equal(&g_mib_nodes[k].oid, &node->oid)) {
			g_mib_nodes[k] = *node;
			snmp_mib_unlock();
			return 0;
		}
	}

	if (g_mib_node_cnt >= CONFIG_SNMP_MAX_MIB_NODES)
	{
		snmp_mib_unlock();
		return -ENOMEM;
	}

	/* Insertion sort keeping g_mib_nodes ordered lexicographically */
	size_t i = g_mib_node_cnt;
	while (i > 0 && snmp_oid_compare(&g_mib_nodes[i - 1].oid, &node->oid) > 0)
	{
		g_mib_nodes[i] = g_mib_nodes[i - 1];
		i--;
	}

	g_mib_nodes[i] = *node;
	g_mib_node_cnt++;

	snmp_mib_unlock();
	return 0;
}

int snmp_mib_register_nodes(const struct snmp_mib_node *nodes, size_t count)
{
	if (!nodes || count == 0)
		return -EINVAL;

	snmp_mib_lock();

	if (g_mib_node_cnt + count > CONFIG_SNMP_MAX_MIB_NODES)

	{
		snmp_mib_unlock();
		return -ENOMEM;
	}

	/* Bulk register then re-sort once */
	for (size_t j = 0; j < count; j++)
	{
		g_mib_nodes[g_mib_node_cnt + j] = nodes[j];
	}
	g_mib_node_cnt += count;

	/* Insertion sort to re-establish lexicographic order */
	for (size_t i = 0; i < g_mib_node_cnt; i++)
	{
		for (size_t j = i + 1; j < g_mib_node_cnt; j++)
		{
			if (snmp_oid_compare(&g_mib_nodes[i].oid, &g_mib_nodes[j].oid) > 0)
			{
				struct snmp_mib_node tmp = g_mib_nodes[i];
				g_mib_nodes[i] = g_mib_nodes[j];
				g_mib_nodes[j] = tmp;
			}
		}
	}

	snmp_mib_unlock();
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

int snmp_mib_get(const struct snmp_oid *oid, struct snmp_varbind *vb)
{
	if (!oid || !vb)
		return -EINVAL;

	snmp_mib_lock();

	for (size_t t = 0; t < g_mib_table_cnt; t++) {
		struct snmp_mib_table *tbl = g_mib_tables[t];

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
					int ret = tbl->get_cbs[c](r, c, vb);
					snmp_mib_unlock();
					return ret;
				}
			}

			vb->oid = *oid;
			vb->type = SNMP_TAG_EXCEPT_NO_SUCH_INST;
			snmp_mib_unlock();
			return 0;
		}
	}

	for (size_t i = 0; i < g_mib_node_cnt; i++)
	{
		if (snmp_oid_equal(&g_mib_nodes[i].oid, oid))
		{
			vb->oid = *oid;
			int ret = 0;
			if (g_mib_nodes[i].get_cb)
			{
				ret = g_mib_nodes[i].get_cb(&g_mib_nodes[i], vb);
			}
			else
			{
				vb->type = g_mib_nodes[i].type;
			}
			snmp_mib_unlock();
			return ret;
		}
	}

	snmp_mib_unlock();
	vb->oid = *oid;
	vb->type = SNMP_TAG_EXCEPT_NO_SUCH_INST;
	return 0;
}

int snmp_mib_get_next(const struct snmp_oid *oid, struct snmp_varbind *vb)
{
	if (!oid || !vb)
		return -EINVAL;

	snmp_mib_lock();

	/* Find best table candidate */
	bool has_table_cand = false;
	struct snmp_oid best_table_oid;
	struct snmp_mib_table *best_tbl = NULL;
	uint8_t best_col_idx = 0;
	struct snmp_table_row *best_row = NULL;

	for (size_t t = 0; t < g_mib_table_cnt; t++) {
		uint8_t c_idx = 0;
		struct snmp_table_row *r_ptr = NULL;
		struct snmp_oid cand_oid;

		if (snmp_table_find_next_entry(g_mib_tables[t], oid, &c_idx, &r_ptr, &cand_oid)) {
			if (!has_table_cand || snmp_oid_compare(&cand_oid, &best_table_oid) < 0) {
				has_table_cand = true;
				best_table_oid = cand_oid;
				best_tbl = g_mib_tables[t];
				best_col_idx = c_idx;
				best_row = r_ptr;
			}
		}
	}

	/* Find best scalar candidate */
	bool has_scalar_cand = false;
	size_t best_scalar_idx = 0;

	for (size_t i = 0; i < g_mib_node_cnt; i++) {
		if (snmp_oid_compare(&g_mib_nodes[i].oid, oid) > 0) {
			has_scalar_cand = true;
			best_scalar_idx = i;
			break;
		}
	}

	/* Decide between table candidate and scalar candidate */
	bool pick_table = false;
	if (has_table_cand && has_scalar_cand) {
		if (snmp_oid_compare(&best_table_oid, &g_mib_nodes[best_scalar_idx].oid) < 0) {
			pick_table = true;
		} else {
			pick_table = false;
		}
	} else if (has_table_cand) {
		pick_table = true;
	} else if (has_scalar_cand) {
		pick_table = false;
	} else {
		snmp_mib_unlock();
		vb->oid = *oid;
		vb->type = SNMP_TAG_EXCEPT_END_MIB_VIEW;
		return 0;
	}

	if (pick_table) {
		vb->oid = best_table_oid;
		if (best_row && best_tbl->get_cbs && best_tbl->get_cbs[best_col_idx]) {
			int ret = best_tbl->get_cbs[best_col_idx](best_row, best_col_idx, vb);
			snmp_mib_unlock();
			return ret;
		}
		vb->type = best_tbl->column_types[best_col_idx];
		snmp_mib_unlock();
		return 0;
	} else {
		vb->oid = g_mib_nodes[best_scalar_idx].oid;
		int ret = 0;
		if (g_mib_nodes[best_scalar_idx].get_cb) {
			ret = g_mib_nodes[best_scalar_idx].get_cb(&g_mib_nodes[best_scalar_idx], vb);
		} else {
			vb->type = g_mib_nodes[best_scalar_idx].type;
		}
		snmp_mib_unlock();
		return ret;
	}
}

int snmp_mib_set(const struct snmp_oid *oid, const struct snmp_varbind *vb)
{
	if (!oid || !vb)
		return -EINVAL;

	snmp_mib_lock();

	/* Check tables first */
	for (size_t t = 0; t < g_mib_table_cnt; t++) {
		struct snmp_mib_table *tbl = g_mib_tables[t];

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
				snmp_mib_unlock();
				snmp_counter_inc(&g_snmp_counters.snmpInReadOnlys);
				return -EACCES;
			}

			for (struct snmp_table_row *r = tbl->rows; r; r = r->next) {
				if (r->index == row_idx) {
					int ret = tbl->set_cbs[c](r, c, vb);
					snmp_mib_unlock();
					return ret;
				}
			}

			snmp_mib_unlock();
			snmp_counter_inc(&g_snmp_counters.snmpInNoSuchNames);
			return -ENOENT;
		}
	}

	/* Check scalar nodes */
	for (size_t i = 0; i < g_mib_node_cnt; i++)
	{
		if (snmp_oid_equal(&g_mib_nodes[i].oid, oid))
		{
			if (!g_mib_nodes[i].set_cb)
			{
				snmp_mib_unlock();
				snmp_counter_inc(&g_snmp_counters.snmpInReadOnlys);
				return -EACCES;
			}
			int ret = g_mib_nodes[i].set_cb(&g_mib_nodes[i], vb);
			snmp_mib_unlock();
			return ret;
		}
	}

	snmp_mib_unlock();
	snmp_counter_inc(&g_snmp_counters.snmpInNoSuchNames);
	return -ENOENT;
}

int snmp_mib_dispatch(struct snmp_pdu *pdu)
{
	if (!pdu)
		return -EINVAL;

	pdu->error_status = 0;
	pdu->error_index = 0;

	if (pdu->type == SNMP_PDU_GET_REQ)
	{
		snmp_counter_inc(&g_snmp_counters.snmpInGetRequests);
		for (uint8_t i = 0; i < pdu->varbind_cnt; i++)
		{
			snmp_counter_inc(&g_snmp_counters.snmpInTotalReqVars);
			int ret = snmp_mib_get(&pdu->varbinds[i].oid, &pdu->varbinds[i]);
			if (ret < 0 && pdu->varbinds[i].type != SNMP_TAG_EXCEPT_NO_SUCH_INST)
			{
				pdu->error_status = 5; /* genErr */
				pdu->error_index = i + 1;
				snmp_counter_inc(&g_snmp_counters.snmpOutGenErrs);
				break;
			}
			if (pdu->version == 0 && (pdu->varbinds[i].type == SNMP_TAG_EXCEPT_NO_SUCH_INST ||
						  pdu->varbinds[i].type == SNMP_TAG_EXCEPT_NO_SUCH_OBJ))
			{
				pdu->error_status = 2; /* noSuchName per RFC 1157 */
				pdu->error_index = i + 1;
				pdu->varbinds[i].type = ASN1_TAG_NULL;
				snmp_counter_inc(&g_snmp_counters.snmpOutNoSuchNames);
				break;
			}
		}
		pdu->type = SNMP_PDU_GET_RESP;
		snmp_counter_inc(&g_snmp_counters.snmpOutGetResponses);
	}
	else if (pdu->type == SNMP_PDU_GET_NEXT_REQ)
	{
		snmp_counter_inc(&g_snmp_counters.snmpInGetNexts);
		for (uint8_t i = 0; i < pdu->varbind_cnt; i++)
		{
			snmp_counter_inc(&g_snmp_counters.snmpInTotalReqVars);
			snmp_mib_get_next(&pdu->varbinds[i].oid, &pdu->varbinds[i]);
			if (pdu->version == 0 && pdu->varbinds[i].type == SNMP_TAG_EXCEPT_END_MIB_VIEW)
			{
				pdu->error_status = 2; /* noSuchName per RFC 1157 */
				pdu->error_index = i + 1;
				pdu->varbinds[i].type = ASN1_TAG_NULL;
				snmp_counter_inc(&g_snmp_counters.snmpOutNoSuchNames);
				break;
			}
		}
		pdu->type = SNMP_PDU_GET_RESP;
		snmp_counter_inc(&g_snmp_counters.snmpOutGetResponses);
	}
	else if (pdu->type == SNMP_PDU_GET_BULK_REQ)
	{
		snmp_counter_inc(&g_snmp_counters.snmpInGetNexts);
		uint8_t orig_cnt = pdu->varbind_cnt;
		int32_t non_rep = pdu->non_repeaters < 0 ? 0 : pdu->non_repeaters;
		int32_t max_rep = pdu->max_repetitions < 0 ? 0 : pdu->max_repetitions;

		if (non_rep > orig_cnt)
			non_rep = orig_cnt;
		uint8_t new_cnt = 0;
		k_mutex_lock(&g_getbulk_mutex, K_FOREVER);
		struct snmp_varbind res_vb[CONFIG_SNMP_MAX_VARBINDS];
		struct snmp_oid current_oids[CONFIG_SNMP_MAX_VARBINDS];

		for (int i = 0; i < non_rep && new_cnt < CONFIG_SNMP_MAX_VARBINDS; i++)
		{
			res_vb[new_cnt] = pdu->varbinds[i];
			snmp_mib_get_next(&pdu->varbinds[i].oid, &res_vb[new_cnt]);
			new_cnt++;
		}

		uint8_t num_repeaters = orig_cnt - non_rep;
		if (num_repeaters > 0 && max_rep > 0)
		{
			for (uint8_t r = 0; r < num_repeaters; r++)
			{
				current_oids[r] = pdu->varbinds[non_rep + r].oid;
			}

			for (int rep = 0; rep < max_rep; rep++)
			{
				bool all_end = true;
				for (uint8_t r = 0; r < num_repeaters && new_cnt < CONFIG_SNMP_MAX_VARBINDS; r++)
				{
					struct snmp_varbind vb;
					snmp_mib_get_next(&current_oids[r], &vb);
					res_vb[new_cnt++] = vb;
					if (vb.type != SNMP_TAG_EXCEPT_END_MIB_VIEW)
					{
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
		k_mutex_unlock(&g_getbulk_mutex);

		/* RFC 1907: count total variables processed by GetBulk */
		g_snmp_counters.snmpInTotalReqVars += new_cnt;

		pdu->type = SNMP_PDU_GET_RESP;
		snmp_counter_inc(&g_snmp_counters.snmpOutGetResponses);
	}
	else if (pdu->type == SNMP_PDU_SET_REQ)
	{
		snmp_counter_inc(&g_snmp_counters.snmpInSetRequests);
		for (uint8_t i = 0; i < pdu->varbind_cnt; i++)
		{
			snmp_counter_inc(&g_snmp_counters.snmpInTotalSetVars);
			int ret = snmp_mib_set(&pdu->varbinds[i].oid, &pdu->varbinds[i]);
			if (ret < 0)
			{
				if (ret == -EACCES)
					pdu->error_status = 3; /* readOnly */
				else if (ret == -ENOENT)
					pdu->error_status = 2; /* noSuchName */
				else
					pdu->error_status = 5; /* genErr */
				pdu->error_index = i + 1;
				snmp_counter_inc(&g_snmp_counters.snmpOutGenErrs);
				break;
			}
			/* RFC 3416: Update response varbind with confirmed value */
			snmp_mib_get(&pdu->varbinds[i].oid, &pdu->varbinds[i]);
		}
		pdu->type = SNMP_PDU_GET_RESP;
		snmp_counter_inc(&g_snmp_counters.snmpOutGetResponses);
	}

	return 0;
}

/* --- MIB Table Support --- */

int snmp_mib_register_table(struct snmp_mib_table *table)
{
	if (!table || table->column_cnt == 0 || !table->column_subids ||
	    !table->column_types || !table->get_cbs)
		return -EINVAL;

	snmp_mib_lock();

	for (size_t t = 0; t < g_mib_table_cnt; t++) {
		if (snmp_oid_equal(&g_mib_tables[t]->table_oid, &table->table_oid)) {
			g_mib_tables[t] = table;
			snmp_mib_unlock();
			return 0;
		}
	}

	if (g_mib_table_cnt >= CONFIG_SNMP_MAX_TABLES) {
		snmp_mib_unlock();
		return -ENOMEM;
	}

	g_mib_tables[g_mib_table_cnt++] = table;

	snmp_mib_unlock();
	return 0;
}

int snmp_mib_table_add_row(struct snmp_mib_table *table, struct snmp_table_row *row)
{
	if (!table || !row)
		return -EINVAL;

	snmp_mib_lock();

	row->next = table->rows;
	table->rows = row;

	snmp_mib_unlock();
	return 0;
}

int snmp_mib_table_remove_row(struct snmp_mib_table *table, uint32_t index)
{
	if (!table)
		return -EINVAL;

	snmp_mib_lock();

	struct snmp_table_row *prev = NULL;
	struct snmp_table_row *cur = table->rows;

	while (cur) {
		if (cur->index == index) {
			if (prev)
				prev->next = cur->next;
			else
				table->rows = cur->next;
			snmp_mib_unlock();
			return 0;
		}
		prev = cur;
		cur = cur->next;
	}

	snmp_mib_unlock();
	return -ENOENT;
}

#endif /* CONFIG_SNMP_AGENT */
