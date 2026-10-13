/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 *
 * MIB Engine Unit Tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "snmp/snmp_ber.h"
#include "snmp/snmp_mib.h"
#include "snmp/snmp_core.h"

#define ASSERT(cond)                                                                               \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			printf("FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond);                    \
			exit(1);                                                                   \
		}                                                                                  \
	} while (0)
#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_GT(a, b) ASSERT((a) > (b))
#define ASSERT_LT(a, b) ASSERT((a) < (b))

/*
 * All MIB engine tests run against one explicit instance (no default-agent reliance):
 * the dispatcher and every lookup now takes the owning agent.
 */
static struct snmp_agent s_mib_agent;

static int test_counter = 42;
static int test_get_called = 0;

static int my_get_cb(struct snmp_agent *agent, const struct snmp_mib_node *node,
		     struct snmp_varbind *vb)
{
	(void)agent;
	(void)node;
	test_get_called++;
	vb->type = SNMP_TAG_COUNTER32;
	vb->val.uint_val = test_counter;
	return 0;
}

__attribute__((unused)) static int my_set_cb(struct snmp_agent *agent, struct snmp_mib_node *node,
					     const struct snmp_varbind *vb)
{
	(void)agent;
	(void)node;
	if (vb->type == SNMP_TAG_COUNTER32) {
		test_counter = vb->val.uint_val;
		return 0;
	}
	return -22;
}

void test_mib_register_get(void)
{
	int ret = snmp_mib_init(&s_mib_agent);
	ASSERT_EQ(ret, 0);

	struct snmp_mib_node node = {0};
	node.oid.len = 9;
	node.oid.ids[0] = 1;
	node.oid.ids[1] = 3;
	node.oid.ids[2] = 6;
	node.oid.ids[3] = 1;
	node.oid.ids[4] = 4;
	node.oid.ids[5] = 1;
	node.oid.ids[6] = 99;
	node.oid.ids[7] = 1;
	node.oid.ids[8] = 0;
	node.type = SNMP_TAG_COUNTER32;
	node.get_cb = my_get_cb;
	node.set_cb = NULL;

	ret = snmp_mib_register(&s_mib_agent, &node);
	ASSERT_EQ(ret, 0);

	struct snmp_varbind vb = {0};
	ret = snmp_mib_get(&s_mib_agent, &node.oid, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(test_get_called, 1);
	ASSERT_EQ(vb.type, SNMP_TAG_COUNTER32);
	ASSERT_EQ(vb.val.uint_val, 42);
}

void test_mib_get_next(void)
{
	snmp_mib_init(&s_mib_agent);

	struct snmp_mib_node node_a = {0};
	node_a.oid.len = 9;
	node_a.oid.ids[0] = 1;
	node_a.oid.ids[1] = 3;
	node_a.oid.ids[2] = 6;
	node_a.oid.ids[3] = 1;
	node_a.oid.ids[4] = 4;
	node_a.oid.ids[5] = 1;
	node_a.oid.ids[6] = 99;
	node_a.oid.ids[7] = 1;
	node_a.oid.ids[8] = 0;
	node_a.type = SNMP_TAG_COUNTER32;
	node_a.get_cb = my_get_cb;
	snmp_mib_register(&s_mib_agent, &node_a);

	struct snmp_mib_node node_b = {0};
	node_b.oid.len = 9;
	node_b.oid.ids[0] = 1;
	node_b.oid.ids[1] = 3;
	node_b.oid.ids[2] = 6;
	node_b.oid.ids[3] = 1;
	node_b.oid.ids[4] = 4;
	node_b.oid.ids[5] = 1;
	node_b.oid.ids[6] = 99;
	node_b.oid.ids[7] = 2;
	node_b.oid.ids[8] = 0;
	node_b.type = SNMP_TAG_GAUGE32;
	node_b.get_cb = my_get_cb;
	snmp_mib_register(&s_mib_agent, &node_b);

	struct snmp_oid query = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 99, 0, 99}};
	struct snmp_varbind vb = {0};
	int ret = snmp_mib_get_next(&s_mib_agent, &query, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.oid.ids[7], 1);

	ret = snmp_mib_get_next(&s_mib_agent, &node_a.oid, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.oid.ids[7], 2);

	struct snmp_oid past_end = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 99, 99, 0}};
	ret = snmp_mib_get_next(&s_mib_agent, &past_end, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.type, SNMP_TAG_EXCEPT_END_MIB_VIEW);
}

void test_mib_duplicate_oid(void)
{
	snmp_mib_init(&s_mib_agent);

	struct snmp_mib_node node = {0};
	node.oid.len = 9;
	node.oid.ids[0] = 1;
	node.oid.ids[1] = 3;
	node.oid.ids[2] = 6;
	node.oid.ids[3] = 1;
	node.oid.ids[4] = 4;
	node.oid.ids[5] = 1;
	node.oid.ids[6] = 99;
	node.oid.ids[7] = 1;
	node.oid.ids[8] = 0;
	node.type = SNMP_TAG_COUNTER32;
	node.get_cb = my_get_cb;

	int ret = snmp_mib_register(&s_mib_agent, &node);
	ASSERT_EQ(ret, 0);
	ret = snmp_mib_register(&s_mib_agent, &node);
	ASSERT_EQ(ret, 0);
}

static int32_t g_test_table_data[3][3] = {
    {0, 0, 0},
    {0, 101, 102}, /* row 1: col 1, col 2 */
    {0, 201, 202}  /* row 2: col 1, col 2 */
};

static int test_col1_get(struct snmp_agent *agent, const struct snmp_table_row *row, uint8_t column,
			 struct snmp_varbind *vb)
{
	(void)agent;
	(void)column;
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = g_test_table_data[row->index][1];
	return 0;
}

static int test_col2_get(struct snmp_agent *agent, const struct snmp_table_row *row, uint8_t column,
			 struct snmp_varbind *vb)
{
	(void)agent;
	(void)column;
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = g_test_table_data[row->index][2];
	return 0;
}

static int test_col2_set(struct snmp_agent *agent, struct snmp_table_row *row, uint8_t column,
			 const struct snmp_varbind *vb)
{
	(void)agent;
	(void)column;
	if (vb->type != ASN1_TAG_INTEGER) {
		return -EINVAL;
	}
	g_test_table_data[row->index][2] = vb->val.int_val;
	return 0;
}

static const uint8_t g_test_cols[] = {1, 2};
static const uint8_t g_test_types[] = {ASN1_TAG_INTEGER, ASN1_TAG_INTEGER};
static snmp_table_get_cb_t g_test_get_cbs[] = {test_col1_get, test_col2_get};
static snmp_table_set_cb_t g_test_set_cbs[] = {NULL, test_col2_set};

static struct snmp_table_row g_test_rows[2] = {{.index = 1, .next = NULL, .user_data = NULL},
					       {.index = 2, .next = NULL, .user_data = NULL}};

static struct snmp_mib_table g_test_tbl = {
    .table_oid = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 99, 10, 1}},
    .column_cnt = 2,
    .column_subids = g_test_cols,
    .column_types = g_test_types,
    .get_cbs = g_test_get_cbs,
    .set_cbs = g_test_set_cbs,
    .rows = NULL,
    .user_data = NULL};

void test_table_register_get(void)
{
	snmp_mib_init(&s_mib_agent);

	g_test_tbl.rows = NULL;
	g_test_rows[0].next = NULL;
	g_test_rows[1].next = NULL;

	int ret = snmp_mib_register_table(&s_mib_agent, &g_test_tbl);
	ASSERT_EQ(ret, 0);

	ret = snmp_mib_table_add_row(&s_mib_agent, &g_test_tbl, &g_test_rows[0]);
	ASSERT_EQ(ret, 0);
	ret = snmp_mib_table_add_row(&s_mib_agent, &g_test_tbl, &g_test_rows[1]);
	ASSERT_EQ(ret, 0);

	/* Get col 1, row 1 */
	struct snmp_oid oid_c1_r1 = {.len = 11, .ids = {1, 3, 6, 1, 4, 1, 99, 10, 1, 1, 1}};
	struct snmp_varbind vb = {0};
	ret = snmp_mib_get(&s_mib_agent, &oid_c1_r1, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.val.int_val, 101);

	/* Get col 2, row 2 */
	struct snmp_oid oid_c2_r2 = {.len = 11, .ids = {1, 3, 6, 1, 4, 1, 99, 10, 1, 2, 2}};
	memset(&vb, 0, sizeof(vb));
	ret = snmp_mib_get(&s_mib_agent, &oid_c2_r2, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.val.int_val, 202);

	/* Non-existent row 3 */
	struct snmp_oid oid_c1_r3 = {.len = 11, .ids = {1, 3, 6, 1, 4, 1, 99, 10, 1, 1, 3}};
	memset(&vb, 0, sizeof(vb));
	ret = snmp_mib_get(&s_mib_agent, &oid_c1_r3, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.type, SNMP_TAG_EXCEPT_NO_SUCH_INST);
}

void test_table_get_next_order(void)
{
	snmp_mib_init(&s_mib_agent);

	g_test_tbl.rows = NULL;
	g_test_rows[0].next = NULL;
	g_test_rows[1].next = NULL;

	snmp_mib_register_table(&s_mib_agent, &g_test_tbl);
	snmp_mib_table_add_row(&s_mib_agent, &g_test_tbl, &g_test_rows[0]);
	snmp_mib_table_add_row(&s_mib_agent, &g_test_tbl, &g_test_rows[1]);

	struct snmp_varbind vb = {0};

	/* Query before table: 1.3.6.1.4.1.99.10.0 */
	struct snmp_oid query = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 99, 10, 0}};
	int ret = snmp_mib_get_next(&s_mib_agent, &query, &vb);
	ASSERT_EQ(ret, 0);
	/* Should hit col 1, row 1 */
	ASSERT_EQ(vb.oid.len, 11);
	ASSERT_EQ(vb.oid.ids[9], 1);  /* col 1 */
	ASSERT_EQ(vb.oid.ids[10], 1); /* row 1 */
	ASSERT_EQ(vb.val.int_val, 101);

	/* Next from col 1, row 1 -> col 1, row 2 */
	query = vb.oid;
	ret = snmp_mib_get_next(&s_mib_agent, &query, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.oid.ids[9], 1);  /* col 1 */
	ASSERT_EQ(vb.oid.ids[10], 2); /* row 2 */
	ASSERT_EQ(vb.val.int_val, 201);

	/* Next from col 1, row 2 -> col 2, row 1 (column-first ordering!) */
	query = vb.oid;
	ret = snmp_mib_get_next(&s_mib_agent, &query, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.oid.ids[9], 2);  /* col 2 */
	ASSERT_EQ(vb.oid.ids[10], 1); /* row 1 */
	ASSERT_EQ(vb.val.int_val, 102);

	/* Next from col 2, row 1 -> col 2, row 2 */
	query = vb.oid;
	ret = snmp_mib_get_next(&s_mib_agent, &query, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.oid.ids[9], 2);  /* col 2 */
	ASSERT_EQ(vb.oid.ids[10], 2); /* row 2 */
	ASSERT_EQ(vb.val.int_val, 202);

	/* Next from col 2, row 2 -> end of MIB view */
	query = vb.oid;
	ret = snmp_mib_get_next(&s_mib_agent, &query, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.type, SNMP_TAG_EXCEPT_END_MIB_VIEW);
}

void test_table_set(void)
{
	snmp_mib_init(&s_mib_agent);

	g_test_tbl.rows = NULL;
	g_test_rows[0].next = NULL;
	g_test_rows[1].next = NULL;

	snmp_mib_register_table(&s_mib_agent, &g_test_tbl);
	snmp_mib_table_add_row(&s_mib_agent, &g_test_tbl, &g_test_rows[0]);
	snmp_mib_table_add_row(&s_mib_agent, &g_test_tbl, &g_test_rows[1]);

	/* Set col 2, row 1 to 999 */
	struct snmp_varbind vb_set = {
	    .oid = {.len = 11, .ids = {1, 3, 6, 1, 4, 1, 99, 10, 1, 2, 1}},
	    .type = ASN1_TAG_INTEGER,
	    .val = {.int_val = 999}};
	int ret = snmp_mib_set(&s_mib_agent, &vb_set.oid, &vb_set);
	ASSERT_EQ(ret, 0);

	/* Verify via get */
	struct snmp_varbind vb_get = {0};
	ret = snmp_mib_get(&s_mib_agent, &vb_set.oid, &vb_get);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb_get.val.int_val, 999);

	/* --- Execute 2PC SET & Multi-Instance Tests --- */
	void run_2pc_and_multi_instance_tests(void);
	run_2pc_and_multi_instance_tests();
}

/* -------------------------------------------------------------------------- */
/* Two-Phase Commit (2PC) SET & Multi-Instance Unit Tests                     */
/* -------------------------------------------------------------------------- */

static int32_t s_legacy_val1 = 10;
static int32_t s_legacy_val2 = 20;

static int get_legacy_val1(struct snmp_agent *agent, const struct snmp_mib_node *node,
			   struct snmp_varbind *vb)
{
	(void)agent;
	(void)node;
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = s_legacy_val1;
	return 0;
}

static int set_legacy_val1(struct snmp_agent *agent, struct snmp_mib_node *node,
			   const struct snmp_varbind *vb)
{
	(void)agent;
	(void)node;
	if (vb->type != ASN1_TAG_INTEGER) {
		return -EINVAL;
	}
	s_legacy_val1 = vb->val.int_val;
	return 0;
}

static int get_legacy_val2(struct snmp_agent *agent, const struct snmp_mib_node *node,
			   struct snmp_varbind *vb)
{
	(void)agent;
	(void)node;
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = s_legacy_val2;
	return 0;
}

static int set_legacy_val2(struct snmp_agent *agent, struct snmp_mib_node *node,
			   const struct snmp_varbind *vb)
{
	(void)agent;
	(void)node;
	if (vb->type != ASN1_TAG_INTEGER) {
		return -EINVAL;
	}
	s_legacy_val2 = vb->val.int_val;
	return 0;
}

static int32_t s_tx_val_a = 50;
static int32_t s_tx_val_b = 60;
static bool s_tx_b_fail_reserve = false;
static bool s_tx_b_fail_commit = false;
static bool s_tx_a_undo_called = false;
static bool s_tx_a_cleanup_called = false;

static int get_tx_val_a(struct snmp_agent *agent, const struct snmp_mib_node *node,
			struct snmp_varbind *vb)
{
	(void)agent;
	(void)node;
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = s_tx_val_a;
	return 0;
}

static int set_tx_val_a(struct snmp_agent *agent, struct snmp_mib_node *node,
			const struct snmp_varbind *vb, enum snmp_set_action action, void **tx_ctx)
{
	(void)agent;
	(void)node;
	switch (action) {
	case SNMP_SET_RESERVE:
		if (vb->type != ASN1_TAG_INTEGER) {
			return SNMP_ERR_WRONG_TYPE;
		}
		*tx_ctx = (void *)(intptr_t)s_tx_val_a;
		return 0;
	case SNMP_SET_COMMIT:
		s_tx_val_a = vb->val.int_val;
		return 0;
	case SNMP_SET_UNDO:
		s_tx_val_a = (int32_t)(intptr_t)(*tx_ctx);
		s_tx_a_undo_called = true;
		return 0;
	case SNMP_SET_CLEANUP:
		s_tx_a_cleanup_called = true;
		return 0;
	default:
		return -EINVAL;
	}
}

static int get_tx_val_b(struct snmp_agent *agent, const struct snmp_mib_node *node,
			struct snmp_varbind *vb)
{
	(void)agent;
	(void)node;
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = s_tx_val_b;
	return 0;
}

static int set_tx_val_b(struct snmp_agent *agent, struct snmp_mib_node *node,
			const struct snmp_varbind *vb, enum snmp_set_action action, void **tx_ctx)
{
	(void)agent;
	(void)node;
	switch (action) {
	case SNMP_SET_RESERVE:
		if (s_tx_b_fail_reserve) {
			return SNMP_ERR_WRONG_VALUE;
		}
		if (vb->type != ASN1_TAG_INTEGER) {
			return SNMP_ERR_WRONG_TYPE;
		}
		*tx_ctx = (void *)(intptr_t)s_tx_val_b;
		return 0;
	case SNMP_SET_COMMIT:
		if (s_tx_b_fail_commit) {
			return SNMP_ERR_COMMIT_FAILED;
		}
		s_tx_val_b = vb->val.int_val;
		return 0;
	case SNMP_SET_UNDO:
		s_tx_val_b = (int32_t)(intptr_t)(*tx_ctx);
		return 0;
	case SNMP_SET_CLEANUP:
		return 0;
	default:
		return -EINVAL;
	}
}

static void setup_2pc_test_nodes(void)
{
	snmp_mib_init(&s_mib_agent);

	s_legacy_val1 = 10;
	s_legacy_val2 = 20;
	s_tx_val_a = 50;
	s_tx_val_b = 60;
	s_tx_b_fail_reserve = false;
	s_tx_b_fail_commit = false;
	s_tx_a_undo_called = false;
	s_tx_a_cleanup_called = false;

	/* Node 1: 1.3.6.1.4.1.9999.1.0 (legacy) */
	struct snmp_mib_node node1 = {
	    .oid = {.len = 8, .ids = {1, 3, 6, 1, 4, 1, 9999, 1}},
	    .type = ASN1_TAG_INTEGER,
	    .get_cb = get_legacy_val1,
	    .set_cb = set_legacy_val1,
	    .set_tx_cb = NULL,
	};
	snmp_mib_register(&s_mib_agent, &node1);

	/* Node 2: 1.3.6.1.4.1.9999.2.0 (legacy) */
	struct snmp_mib_node node2 = {
	    .oid = {.len = 8, .ids = {1, 3, 6, 1, 4, 1, 9999, 2}},
	    .type = ASN1_TAG_INTEGER,
	    .get_cb = get_legacy_val2,
	    .set_cb = set_legacy_val2,
	    .set_tx_cb = NULL,
	};
	snmp_mib_register(&s_mib_agent, &node2);

	/* Node A: 1.3.6.1.4.1.9999.3.0 (2PC) */
	struct snmp_mib_node node_a = {
	    .oid = {.len = 8, .ids = {1, 3, 6, 1, 4, 1, 9999, 3}},
	    .type = ASN1_TAG_INTEGER,
	    .get_cb = get_tx_val_a,
	    .set_cb = NULL,
	    .set_tx_cb = set_tx_val_a,
	};
	snmp_mib_register(&s_mib_agent, &node_a);

	/* Node B: 1.3.6.1.4.1.9999.4.0 (2PC) */
	struct snmp_mib_node node_b = {
	    .oid = {.len = 8, .ids = {1, 3, 6, 1, 4, 1, 9999, 4}},
	    .type = ASN1_TAG_INTEGER,
	    .get_cb = get_tx_val_b,
	    .set_cb = NULL,
	    .set_tx_cb = set_tx_val_b,
	};
	snmp_mib_register(&s_mib_agent, &node_b);

	/* Read-only Node: 1.3.6.1.4.1.9999.5.0 */
	struct snmp_mib_node node_ro = {
	    .oid = {.len = 8, .ids = {1, 3, 6, 1, 4, 1, 9999, 5}},
	    .type = ASN1_TAG_INTEGER,
	    .get_cb = get_legacy_val1,
	    .set_cb = NULL,
	    .set_tx_cb = NULL,
	};
	snmp_mib_register(&s_mib_agent, &node_ro);
}

static void test_set_2pc_atomic_failure_legacy(void)
{
	setup_2pc_test_nodes();

	struct snmp_pdu pdu;
	memset(&pdu, 0, sizeof(pdu));
	pdu.version = 1; /* SNMPv2c */
	pdu.type = SNMP_PDU_SET_REQ;
	pdu.varbind_cnt = 2;

	/* Varbind 0: valid Node 1 */
	pdu.varbinds[0].oid.len = 8;
	memcpy(pdu.varbinds[0].oid.ids, (uint32_t[]){1, 3, 6, 1, 4, 1, 9999, 1},
	       8 * sizeof(uint32_t));
	pdu.varbinds[0].type = ASN1_TAG_INTEGER;
	pdu.varbinds[0].val.int_val = 100;

	/* Varbind 1: Node 2 with WRONG TYPE */
	pdu.varbinds[1].oid.len = 8;
	memcpy(pdu.varbinds[1].oid.ids, (uint32_t[]){1, 3, 6, 1, 4, 1, 9999, 2},
	       8 * sizeof(uint32_t));
	pdu.varbinds[1].type = ASN1_TAG_OCTET_STRING;
	pdu.varbinds[1].val.octet_str.len = 4;
	memcpy(pdu.varbinds[1].val.octet_str.data, "test", 4);

	int ret = snmp_mib_dispatch(&s_mib_agent, &pdu);
	ASSERT_EQ(ret, 0);

	ASSERT_EQ(pdu.error_status, SNMP_ERR_WRONG_TYPE);
	ASSERT_EQ(pdu.error_index, 2);

	/* Atomicity guarantee: Node 1 must remain 10 */
	ASSERT_EQ(s_legacy_val1, 10);
	ASSERT_EQ(s_legacy_val2, 20);
}

static void test_set_2pc_atomic_failure_tx(void)
{
	setup_2pc_test_nodes();
	s_tx_b_fail_reserve = true;

	struct snmp_pdu pdu;
	memset(&pdu, 0, sizeof(pdu));
	pdu.version = 1; /* SNMPv2c */
	pdu.type = SNMP_PDU_SET_REQ;
	pdu.varbind_cnt = 2;

	/* Varbind 0: Node A */
	pdu.varbinds[0].oid.len = 8;
	memcpy(pdu.varbinds[0].oid.ids, (uint32_t[]){1, 3, 6, 1, 4, 1, 9999, 3},
	       8 * sizeof(uint32_t));
	pdu.varbinds[0].type = ASN1_TAG_INTEGER;
	pdu.varbinds[0].val.int_val = 500;

	/* Varbind 1: Node B (Reserve fails) */
	pdu.varbinds[1].oid.len = 8;
	memcpy(pdu.varbinds[1].oid.ids, (uint32_t[]){1, 3, 6, 1, 4, 1, 9999, 4},
	       8 * sizeof(uint32_t));
	pdu.varbinds[1].type = ASN1_TAG_INTEGER;
	pdu.varbinds[1].val.int_val = 600;

	int ret = snmp_mib_dispatch(&s_mib_agent, &pdu);
	ASSERT_EQ(ret, 0);

	ASSERT_EQ(pdu.error_status, SNMP_ERR_WRONG_VALUE);
	ASSERT_EQ(pdu.error_index, 2);

	/* Atomicity: Node A was cleaned up without committing */
	ASSERT_EQ(s_tx_val_a, 50);
	ASSERT_EQ(s_tx_a_cleanup_called, true);
	ASSERT_EQ(s_tx_val_b, 60);
}

static void test_set_2pc_rollback_on_commit_failure(void)
{
	setup_2pc_test_nodes();
	s_tx_b_fail_commit = true;

	struct snmp_pdu pdu;
	memset(&pdu, 0, sizeof(pdu));
	pdu.version = 1; /* SNMPv2c */
	pdu.type = SNMP_PDU_SET_REQ;
	pdu.varbind_cnt = 2;

	/* Varbind 0: Node A */
	pdu.varbinds[0].oid.len = 8;
	memcpy(pdu.varbinds[0].oid.ids, (uint32_t[]){1, 3, 6, 1, 4, 1, 9999, 3},
	       8 * sizeof(uint32_t));
	pdu.varbinds[0].type = ASN1_TAG_INTEGER;
	pdu.varbinds[0].val.int_val = 500;

	/* Varbind 1: Node B (Commit fails) */
	pdu.varbinds[1].oid.len = 8;
	memcpy(pdu.varbinds[1].oid.ids, (uint32_t[]){1, 3, 6, 1, 4, 1, 9999, 4},
	       8 * sizeof(uint32_t));
	pdu.varbinds[1].type = ASN1_TAG_INTEGER;
	pdu.varbinds[1].val.int_val = 600;

	int ret = snmp_mib_dispatch(&s_mib_agent, &pdu);
	ASSERT_EQ(ret, 0);

	ASSERT_EQ(pdu.error_status, SNMP_ERR_COMMIT_FAILED);
	ASSERT_EQ(pdu.error_index, 2);

	/* Atomicity: Node A was rolled back via UNDO */
	ASSERT_EQ(s_tx_a_undo_called, true);
	ASSERT_EQ(s_tx_val_a, 50);
	ASSERT_EQ(s_tx_val_b, 60);
}

static void test_set_2pc_atomic_success(void)
{
	setup_2pc_test_nodes();

	struct snmp_pdu pdu;
	memset(&pdu, 0, sizeof(pdu));
	pdu.version = 1; /* SNMPv2c */
	pdu.type = SNMP_PDU_SET_REQ;
	pdu.varbind_cnt = 2;

	pdu.varbinds[0].oid.len = 8;
	memcpy(pdu.varbinds[0].oid.ids, (uint32_t[]){1, 3, 6, 1, 4, 1, 9999, 1},
	       8 * sizeof(uint32_t));
	pdu.varbinds[0].type = ASN1_TAG_INTEGER;
	pdu.varbinds[0].val.int_val = 111;

	pdu.varbinds[1].oid.len = 8;
	memcpy(pdu.varbinds[1].oid.ids, (uint32_t[]){1, 3, 6, 1, 4, 1, 9999, 3},
	       8 * sizeof(uint32_t));
	pdu.varbinds[1].type = ASN1_TAG_INTEGER;
	pdu.varbinds[1].val.int_val = 222;

	int ret = snmp_mib_dispatch(&s_mib_agent, &pdu);
	ASSERT_EQ(ret, 0);

	ASSERT_EQ(pdu.error_status, SNMP_ERR_NO_ERROR);
	ASSERT_EQ(pdu.error_index, 0);

	ASSERT_EQ(s_legacy_val1, 111);
	ASSERT_EQ(s_tx_val_a, 222);

	/* Confirmed values in response */
	ASSERT_EQ(pdu.varbinds[0].val.int_val, 111);
	ASSERT_EQ(pdu.varbinds[1].val.int_val, 222);
}

static void test_smiv2_error_code_mapping_v2c_and_v1(void)
{
	setup_2pc_test_nodes();

	/* 1. Read-only node on v2c -> notWritable (17) */
	struct snmp_pdu pdu_v2_ro;
	memset(&pdu_v2_ro, 0, sizeof(pdu_v2_ro));
	pdu_v2_ro.version = 1;
	pdu_v2_ro.type = SNMP_PDU_SET_REQ;
	pdu_v2_ro.varbind_cnt = 1;
	pdu_v2_ro.varbinds[0].oid.len = 8;
	memcpy(pdu_v2_ro.varbinds[0].oid.ids, (uint32_t[]){1, 3, 6, 1, 4, 1, 9999, 5},
	       8 * sizeof(uint32_t));
	pdu_v2_ro.varbinds[0].type = ASN1_TAG_INTEGER;
	pdu_v2_ro.varbinds[0].val.int_val = 999;

	snmp_mib_dispatch(&s_mib_agent, &pdu_v2_ro);
	ASSERT_EQ(pdu_v2_ro.error_status, SNMP_ERR_NOT_WRITABLE);
	ASSERT_EQ(pdu_v2_ro.error_index, 1);

	/* 2. Read-only node on v1 -> readOnly (4) */
	struct snmp_pdu pdu_v1_ro;
	memset(&pdu_v1_ro, 0, sizeof(pdu_v1_ro));
	pdu_v1_ro.version = 0;
	pdu_v1_ro.type = SNMP_PDU_SET_REQ;
	pdu_v1_ro.varbind_cnt = 1;
	pdu_v1_ro.varbinds[0].oid.len = 8;
	memcpy(pdu_v1_ro.varbinds[0].oid.ids, (uint32_t[]){1, 3, 6, 1, 4, 1, 9999, 5},
	       8 * sizeof(uint32_t));
	pdu_v1_ro.varbinds[0].type = ASN1_TAG_INTEGER;
	pdu_v1_ro.varbinds[0].val.int_val = 999;

	snmp_mib_dispatch(&s_mib_agent, &pdu_v1_ro);
	ASSERT_EQ(pdu_v1_ro.error_status, SNMP_ERR_READ_ONLY);
	ASSERT_EQ(pdu_v1_ro.error_index, 1);

	/* 3. Type mismatch on v2c -> wrongType (7) */
	struct snmp_pdu pdu_v2_type;
	memset(&pdu_v2_type, 0, sizeof(pdu_v2_type));
	pdu_v2_type.version = 1;
	pdu_v2_type.type = SNMP_PDU_SET_REQ;
	pdu_v2_type.varbind_cnt = 1;
	pdu_v2_type.varbinds[0].oid.len = 8;
	memcpy(pdu_v2_type.varbinds[0].oid.ids, (uint32_t[]){1, 3, 6, 1, 4, 1, 9999, 1},
	       8 * sizeof(uint32_t));
	pdu_v2_type.varbinds[0].type = ASN1_TAG_OCTET_STRING;

	snmp_mib_dispatch(&s_mib_agent, &pdu_v2_type);
	ASSERT_EQ(pdu_v2_type.error_status, SNMP_ERR_WRONG_TYPE);
	ASSERT_EQ(pdu_v2_type.error_index, 1);

	/* 4. Type mismatch on v1 -> badValue (3) */
	struct snmp_pdu pdu_v1_type;
	memset(&pdu_v1_type, 0, sizeof(pdu_v1_type));
	pdu_v1_type.version = 0;
	pdu_v1_type.type = SNMP_PDU_SET_REQ;
	pdu_v1_type.varbind_cnt = 1;
	pdu_v1_type.varbinds[0].oid.len = 8;
	memcpy(pdu_v1_type.varbinds[0].oid.ids, (uint32_t[]){1, 3, 6, 1, 4, 1, 9999, 1},
	       8 * sizeof(uint32_t));
	pdu_v1_type.varbinds[0].type = ASN1_TAG_OCTET_STRING;

	snmp_mib_dispatch(&s_mib_agent, &pdu_v1_type);
	ASSERT_EQ(pdu_v1_type.error_status, SNMP_ERR_BAD_VALUE);
	ASSERT_EQ(pdu_v1_type.error_index, 1);
}

static void test_multi_instance_independence(void)
{
	setup_2pc_test_nodes();

	struct snmp_agent inst1;
	struct snmp_agent inst2;

	int ret1 = snmp_agent_init(&inst1, NULL);
	int ret2 = snmp_agent_init(&inst2, NULL);
	ASSERT_EQ(ret1, 0);
	ASSERT_EQ(ret2, 0);

	snmp_agent_set_read_community(&inst1, "dept_alpha");
	snmp_agent_set_write_community(&inst1, "secret_alpha");

	snmp_agent_set_read_community(&inst2, "dept_beta");
	snmp_agent_set_write_community(&inst2, "secret_beta");

	/* Build encoded SNMPv2c GET request for Node 1 with community 'dept_alpha' */
	struct snmp_pdu req_pdu;
	memset(&req_pdu, 0, sizeof(req_pdu));
	req_pdu.version = 1; /* v2c */
	strncpy((char *)req_pdu.community, "dept_alpha", sizeof(req_pdu.community) - 1);
	req_pdu.community_len = strlen((char *)req_pdu.community);
	req_pdu.type = SNMP_PDU_GET_REQ;
	req_pdu.request_id = 12345;
	req_pdu.varbind_cnt = 1;
	req_pdu.varbinds[0].oid.len = 8;
	memcpy(req_pdu.varbinds[0].oid.ids, (uint32_t[]){1, 3, 6, 1, 4, 1, 9999, 1},
	       8 * sizeof(uint32_t));
	req_pdu.varbinds[0].type = ASN1_TAG_NULL;

	uint8_t req_buf[256];
	size_t req_len = 0;
	int enc_ret = snmp_ber_encode_pdu(req_buf, sizeof(req_buf), &req_len, &req_pdu);
	ASSERT_EQ(enc_ret, 0);

	uint8_t resp_buf[256];
	size_t resp_len = 0;

	/* 1. Pass request with 'dept_alpha' to inst1 -> should succeed */
	int proc_ret1 =
	    snmp_agent_process_pdu(&inst1, req_buf, req_len, resp_buf, sizeof(resp_buf), &resp_len);
	ASSERT_EQ(proc_ret1, 0);
	ASSERT(resp_len > 0);
	ASSERT_EQ(inst1.counters.snmpInPkts, 1);
	ASSERT_EQ(inst1.counters.snmpInBadCommunityNames, 0);

	/* 2. Pass SAME request with 'dept_alpha' to inst2 -> rejected with -EACCES */
	resp_len = 0;
	int proc_ret2 =
	    snmp_agent_process_pdu(&inst2, req_buf, req_len, resp_buf, sizeof(resp_buf), &resp_len);
	ASSERT_EQ(proc_ret2, -EACCES);
	ASSERT_EQ(resp_len, 0);
	ASSERT_EQ(inst2.counters.snmpInPkts, 1);
	ASSERT_EQ(inst2.counters.snmpInBadCommunityNames, 1);

	/* inst1 counters must be completely unaffected */
	ASSERT_EQ(inst1.counters.snmpInPkts, 1);
	ASSERT_EQ(inst1.counters.snmpInBadCommunityNames, 0);
}

void run_2pc_and_multi_instance_tests(void)
{
	test_set_2pc_atomic_failure_legacy();
	test_set_2pc_atomic_failure_tx();
	test_set_2pc_rollback_on_commit_failure();
	test_set_2pc_atomic_success();
	test_smiv2_error_code_mapping_v2c_and_v1();
	test_multi_instance_independence();
}

void test_interleaved_scalar_and_table_walk(void)
{
	snmp_mib_init(&s_mib_agent);

	/* Scalar before table: 1.3.6.1.4.1.99.5.0 */
	struct snmp_mib_node node_before = {0};
	node_before.oid.len = 9;
	node_before.oid.ids[0] = 1;
	node_before.oid.ids[1] = 3;
	node_before.oid.ids[2] = 6;
	node_before.oid.ids[3] = 1;
	node_before.oid.ids[4] = 4;
	node_before.oid.ids[5] = 1;
	node_before.oid.ids[6] = 99;
	node_before.oid.ids[7] = 5;
	node_before.oid.ids[8] = 0;
	node_before.type = SNMP_TAG_COUNTER32;
	node_before.get_cb = my_get_cb;
	snmp_mib_register(&s_mib_agent, &node_before);

	/* Table: 1.3.6.1.4.1.99.10.1 */
	g_test_tbl.rows = NULL;
	g_test_rows[0].next = NULL;
	g_test_rows[1].next = NULL;

	snmp_mib_register_table(&s_mib_agent, &g_test_tbl);
	snmp_mib_table_add_row(&s_mib_agent, &g_test_tbl, &g_test_rows[0]);
	snmp_mib_table_add_row(&s_mib_agent, &g_test_tbl, &g_test_rows[1]);

	/* Scalar after table: 1.3.6.1.4.1.99.20.0 */
	struct snmp_mib_node node_after = {0};
	node_after.oid.len = 9;
	node_after.oid.ids[0] = 1;
	node_after.oid.ids[1] = 3;
	node_after.oid.ids[2] = 6;
	node_after.oid.ids[3] = 1;
	node_after.oid.ids[4] = 4;
	node_after.oid.ids[5] = 1;
	node_after.oid.ids[6] = 99;
	node_after.oid.ids[7] = 20;
	node_after.oid.ids[8] = 0;
	node_after.type = SNMP_TAG_GAUGE32;
	node_after.get_cb = my_get_cb;
	snmp_mib_register(&s_mib_agent, &node_after);

	struct snmp_varbind vb = {0};

	/* Query 1.3.6.1.4.1.99.0 */
	struct snmp_oid query = {.len = 8, .ids = {1, 3, 6, 1, 4, 1, 99, 0}};
	int ret = snmp_mib_get_next(&s_mib_agent, &query, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.oid.ids[7], 5); /* scalar before */

	/* Next -> table col 1, row 1 */
	query = vb.oid;
	ret = snmp_mib_get_next(&s_mib_agent, &query, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.oid.ids[7], 10);
	ASSERT_EQ(vb.oid.ids[9], 1);
	ASSERT_EQ(vb.oid.ids[10], 1);

	/* Advance through table */
	query = vb.oid;
	snmp_mib_get_next(&s_mib_agent, &query, &vb); /* col 1, row 2 */
	ASSERT_EQ(vb.oid.ids[9], 1);
	ASSERT_EQ(vb.oid.ids[10], 2);

	query = vb.oid;
	snmp_mib_get_next(&s_mib_agent, &query, &vb); /* col 2, row 1 */
	ASSERT_EQ(vb.oid.ids[9], 2);
	ASSERT_EQ(vb.oid.ids[10], 1);

	query = vb.oid;
	snmp_mib_get_next(&s_mib_agent, &query, &vb); /* col 2, row 2 */
	ASSERT_EQ(vb.oid.ids[9], 2);
	ASSERT_EQ(vb.oid.ids[10], 2);

	/* Next -> scalar after table (1.3.6.1.4.1.99.20.0) */
	query = vb.oid;
	ret = snmp_mib_get_next(&s_mib_agent, &query, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.oid.ids[7], 20); /* scalar after */

	/* Next -> endOfMibView */
	query = vb.oid;
	ret = snmp_mib_get_next(&s_mib_agent, &query, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.type, SNMP_TAG_EXCEPT_END_MIB_VIEW);
}

static int bsearch_test_cb(struct snmp_agent *agent, const struct snmp_mib_node *node,
			   struct snmp_varbind *vb)
{
	(void)agent;
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = (int32_t)node->oid.ids[7];
	return 0;
}

void test_mib_bsearch_lookup(void)
{
	static struct snmp_agent agent;
	int ret = snmp_mib_init(&agent);
	ASSERT_EQ(ret, 0);

	/* Register 5 nodes out of order to verify lexicographic sorting */
	static const uint32_t subids[] = {30, 10, 50, 20, 40};
	for (size_t i = 0; i < 5; i++) {
		struct snmp_mib_node node = {0};
		node.oid.len = 9;
		node.oid.ids[0] = 1;
		node.oid.ids[1] = 3;
		node.oid.ids[2] = 6;
		node.oid.ids[3] = 1;
		node.oid.ids[4] = 4;
		node.oid.ids[5] = 1;
		node.oid.ids[6] = 88;
		node.oid.ids[7] = subids[i];
		node.oid.ids[8] = 0;
		node.type = ASN1_TAG_INTEGER;
		node.get_cb = bsearch_test_cb;
		ret = snmp_mib_register(&agent, &node);
		ASSERT_EQ(ret, 0);
	}

	struct snmp_varbind vb;

	/* 1. First node (subid 10) */
	struct snmp_oid oid_first = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 88, 10, 0}};
	memset(&vb, 0, sizeof(vb));
	ret = snmp_mib_get(&agent, &oid_first, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.type, ASN1_TAG_INTEGER);
	ASSERT_EQ(vb.val.int_val, 10);

	/* 2. Middle node (subid 30) */
	struct snmp_oid oid_mid = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 88, 30, 0}};
	memset(&vb, 0, sizeof(vb));
	ret = snmp_mib_get(&agent, &oid_mid, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.type, ASN1_TAG_INTEGER);
	ASSERT_EQ(vb.val.int_val, 30);

	/* 3. Last node (subid 50) */
	struct snmp_oid oid_last = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 88, 50, 0}};
	memset(&vb, 0, sizeof(vb));
	ret = snmp_mib_get(&agent, &oid_last, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.type, ASN1_TAG_INTEGER);
	ASSERT_EQ(vb.val.int_val, 50);

	/* 4. Non-existent nodes */
	struct snmp_oid oid_none1 = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 88, 5, 0}};
	memset(&vb, 0, sizeof(vb));
	ret = snmp_mib_get(&agent, &oid_none1, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.type, SNMP_TAG_EXCEPT_NO_SUCH_OBJ);

	struct snmp_oid oid_none2 = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 88, 25, 0}};
	memset(&vb, 0, sizeof(vb));
	ret = snmp_mib_get(&agent, &oid_none2, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.type, SNMP_TAG_EXCEPT_NO_SUCH_OBJ);

	struct snmp_oid oid_none3 = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 88, 99, 0}};
	memset(&vb, 0, sizeof(vb));
	ret = snmp_mib_get(&agent, &oid_none3, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.type, SNMP_TAG_EXCEPT_NO_SUCH_OBJ);
}

static int scalar_cb_42(struct snmp_agent *agent, const struct snmp_mib_node *node,
			struct snmp_varbind *vb)
{
	(void)agent;
	(void)node;
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = 42;
	return 0;
}

void test_mib_no_such_object_vs_instance(void)
{
	static struct snmp_agent agent;
	int ret = snmp_mib_init(&agent);
	ASSERT_EQ(ret, 0);

	/* Register scalar: 1.3.6.1.4.1.500.1.0 */
	struct snmp_mib_node scalar_node = {0};
	scalar_node.oid.len = 9;
	scalar_node.oid.ids[0] = 1;
	scalar_node.oid.ids[1] = 3;
	scalar_node.oid.ids[2] = 6;
	scalar_node.oid.ids[3] = 1;
	scalar_node.oid.ids[4] = 4;
	scalar_node.oid.ids[5] = 1;
	scalar_node.oid.ids[6] = 500;
	scalar_node.oid.ids[7] = 1;
	scalar_node.oid.ids[8] = 0;
	scalar_node.type = ASN1_TAG_INTEGER;
	scalar_node.get_cb = scalar_cb_42;
	ret = snmp_mib_register(&agent, &scalar_node);
	ASSERT_EQ(ret, 0);

	/* Register table: 1.3.6.1.4.1.500.2.1 with columns {1, 2} and row 1 */
	static const uint8_t t_cols[] = {1, 2};
	static const uint8_t t_types[] = {ASN1_TAG_INTEGER, ASN1_TAG_INTEGER};
	static snmp_table_get_cb_t t_get_cbs[] = {test_col1_get, test_col2_get};
	static struct snmp_table_row t_row = {.index = 1, .next = NULL, .user_data = NULL};
	struct snmp_mib_table t_table = {
	    .table_oid = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 500, 2, 1}},
	    .column_cnt = 2,
	    .column_subids = t_cols,
	    .column_types = t_types,
	    .get_cbs = t_get_cbs,
	    .set_cbs = NULL,
	    .rows = NULL,
	    .user_data = NULL};
	ret = snmp_mib_register_table(&agent, &t_table);
	ASSERT_EQ(ret, 0);
	ret = snmp_mib_table_add_row(&agent, &t_table, &t_row);
	ASSERT_EQ(ret, 0);

	struct snmp_varbind vb;

	/* 1. Query valid scalar .0: returns value */
	struct snmp_oid oid_scalar_0 = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 500, 1, 0}};
	memset(&vb, 0, sizeof(vb));
	ret = snmp_mib_get(&agent, &oid_scalar_0, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.type, ASN1_TAG_INTEGER);
	ASSERT_EQ(vb.val.int_val, 42);

	/* 2. Query scalar .1: returns noSuchInstance */
	struct snmp_oid oid_scalar_1 = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 500, 1, 1}};
	memset(&vb, 0, sizeof(vb));
	ret = snmp_mib_get(&agent, &oid_scalar_1, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.type, SNMP_TAG_EXCEPT_NO_SUCH_INST);

	/* 3. Query completely foreign OID 1.3.6.1.2.1.99.1.0: returns noSuchObject */
	struct snmp_oid oid_foreign = {.len = 9, .ids = {1, 3, 6, 1, 2, 1, 99, 1, 0}};
	memset(&vb, 0, sizeof(vb));
	ret = snmp_mib_get(&agent, &oid_foreign, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.type, SNMP_TAG_EXCEPT_NO_SUCH_OBJ);

	/* 4. Query table with existing column (1) and non-existing row (99): returns noSuchInstance
	 */
	struct snmp_oid oid_tbl_no_row = {.len = 11, .ids = {1, 3, 6, 1, 4, 1, 500, 2, 1, 1, 99}};
	memset(&vb, 0, sizeof(vb));
	ret = snmp_mib_get(&agent, &oid_tbl_no_row, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.type, SNMP_TAG_EXCEPT_NO_SUCH_INST);

	/* 5. Query table with non-existing column (5) and row 1: returns noSuchObject */
	struct snmp_oid oid_tbl_no_col = {.len = 11, .ids = {1, 3, 6, 1, 4, 1, 500, 2, 1, 5, 1}};
	memset(&vb, 0, sizeof(vb));
	ret = snmp_mib_get(&agent, &oid_tbl_no_col, &vb);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(vb.type, SNMP_TAG_EXCEPT_NO_SUCH_OBJ);

	/* 6. Verify SNMPv1 converts both noSuchInstance and noSuchObject to noSuchName */
	struct snmp_pdu v1_pdu;
	memset(&v1_pdu, 0, sizeof(v1_pdu));
	v1_pdu.version = 0; /* SNMPv1 */
	v1_pdu.type = SNMP_PDU_GET_REQ;
	v1_pdu.varbind_cnt = 1;
	v1_pdu.varbinds[0].oid = oid_scalar_1; /* noSuchInstance */
	ret = snmp_mib_dispatch(&agent, &v1_pdu);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(v1_pdu.error_status, SNMP_ERR_NO_SUCH_NAME);
	ASSERT_EQ(v1_pdu.error_index, 1);

	memset(&v1_pdu, 0, sizeof(v1_pdu));
	v1_pdu.version = 0; /* SNMPv1 */
	v1_pdu.type = SNMP_PDU_GET_REQ;
	v1_pdu.varbind_cnt = 1;
	v1_pdu.varbinds[0].oid = oid_foreign; /* noSuchObject */
	ret = snmp_mib_dispatch(&agent, &v1_pdu);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(v1_pdu.error_status, SNMP_ERR_NO_SUCH_NAME);
	ASSERT_EQ(v1_pdu.error_index, 1);
}

void test_getbulk_response_pruning_on_buffer_limit(void)
{
	static struct snmp_agent agent;
	int ret = snmp_agent_init(&agent, NULL);
	ASSERT_EQ(ret, 0);
	ret = snmp_agent_set_read_community(&agent, "public");
	ASSERT_EQ(ret, 0);

	/* Register 10 scalar nodes: 1.3.6.1.4.1.600.1.0 to 1.3.6.1.4.1.600.10.0 */
	for (uint32_t i = 1; i <= 10; i++) {
		struct snmp_mib_node node = {0};
		node.oid.len = 9;
		node.oid.ids[0] = 1;
		node.oid.ids[1] = 3;
		node.oid.ids[2] = 6;
		node.oid.ids[3] = 1;
		node.oid.ids[4] = 4;
		node.oid.ids[5] = 1;
		node.oid.ids[6] = 600;
		node.oid.ids[7] = i;
		node.oid.ids[8] = 0;
		node.type = ASN1_TAG_INTEGER;
		node.get_cb = scalar_cb_42;
		ret = snmp_mib_register(&agent, &node);
		ASSERT_EQ(ret, 0);
	}

	/* Build GETBULK request: non_repeaters = 0, max_repetitions = 10 */
	struct snmp_pdu req_pdu;
	memset(&req_pdu, 0, sizeof(req_pdu));
	req_pdu.version = 1; /* SNMPv2c */
	req_pdu.type = SNMP_PDU_GET_BULK_REQ;
	req_pdu.request_id = 999;
	req_pdu.non_repeaters = 0;
	req_pdu.max_repetitions = 10;
	strncpy((char *)req_pdu.community, "public", sizeof(req_pdu.community) - 1);
	req_pdu.community_len = strlen((char *)req_pdu.community);
	req_pdu.varbind_cnt = 1;
	req_pdu.varbinds[0].oid.len = 8;
	req_pdu.varbinds[0].oid.ids[0] = 1;
	req_pdu.varbinds[0].oid.ids[1] = 3;
	req_pdu.varbinds[0].oid.ids[2] = 6;
	req_pdu.varbinds[0].oid.ids[3] = 1;
	req_pdu.varbinds[0].oid.ids[4] = 4;
	req_pdu.varbinds[0].oid.ids[5] = 1;
	req_pdu.varbinds[0].oid.ids[6] = 600;
	req_pdu.varbinds[0].oid.ids[7] = 0; /* will getNext to .1.0 */
	req_pdu.varbinds[0].type = ASN1_TAG_NULL;

	uint8_t req_buf[256];
	size_t req_len = 0;
	ret = snmp_ber_encode_pdu(req_buf, sizeof(req_buf), &req_len, &req_pdu);
	ASSERT_EQ(ret, 0);

	/* 1. Large buffer test: full 10 repetitions fit */
	uint8_t resp_buf[1024];
	size_t resp_len = 0;
	ret =
	    snmp_agent_process_pdu(&agent, req_buf, req_len, resp_buf, sizeof(resp_buf), &resp_len);
	ASSERT_EQ(ret, 0);

	struct snmp_pdu resp_pdu;
	memset(&resp_pdu, 0, sizeof(resp_pdu));
	ret = snmp_ber_decode_pdu(resp_buf, resp_len, &resp_pdu);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(resp_pdu.error_status, SNMP_ERR_NO_ERROR);
	ASSERT_EQ(resp_pdu.varbind_cnt, 10);
	size_t full_resp_len = resp_len;

	/* 2. Constrained buffer test: small buffer size that can hold some but not all varbinds */
	size_t small_buf_sz = full_resp_len / 2;
	memset(resp_buf, 0, sizeof(resp_buf));
	resp_len = 0;
	ret = snmp_agent_process_pdu(&agent, req_buf, req_len, resp_buf, small_buf_sz, &resp_len);
	ASSERT_EQ(ret, 0);
	ASSERT_GT(resp_len, 0);
	ASSERT(resp_len <= small_buf_sz);

	memset(&resp_pdu, 0, sizeof(resp_pdu));
	ret = snmp_ber_decode_pdu(resp_buf, resp_len, &resp_pdu);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(resp_pdu.error_status, SNMP_ERR_NO_ERROR);
	ASSERT_GT(resp_pdu.varbind_cnt, 0);
	ASSERT_LT(resp_pdu.varbind_cnt, 10);

	/* 3. Extremely small buffer test: non_repeaters cannot fit in buffer */
	/* With non_repeaters = 1, repetition pruning stops at 1 varbind (~42 bytes). */
	/* When buffer is 35 bytes, non-repeater cannot fit -> returns tooBig with varbind_cnt = 0
	 */
	struct snmp_pdu req_pdu2;
	memset(&req_pdu2, 0, sizeof(req_pdu2));
	req_pdu2.version = 1; /* SNMPv2c */
	req_pdu2.type = SNMP_PDU_GET_BULK_REQ;
	req_pdu2.request_id = 1000;
	req_pdu2.non_repeaters = 1;
	req_pdu2.max_repetitions = 5;
	strncpy((char *)req_pdu2.community, "public", sizeof(req_pdu2.community) - 1);
	req_pdu2.community_len = strlen((char *)req_pdu2.community);
	req_pdu2.varbind_cnt = 1;
	req_pdu2.varbinds[0].oid.len = 8;
	req_pdu2.varbinds[0].oid.ids[0] = 1;
	req_pdu2.varbinds[0].oid.ids[1] = 3;
	req_pdu2.varbinds[0].oid.ids[2] = 6;
	req_pdu2.varbinds[0].oid.ids[3] = 1;
	req_pdu2.varbinds[0].oid.ids[4] = 4;
	req_pdu2.varbinds[0].oid.ids[5] = 1;
	req_pdu2.varbinds[0].oid.ids[6] = 600;
	req_pdu2.varbinds[0].oid.ids[7] = 0;
	req_pdu2.varbinds[0].type = ASN1_TAG_NULL;

	ret = snmp_ber_encode_pdu(req_buf, sizeof(req_buf), &req_len, &req_pdu2);
	ASSERT_EQ(ret, 0);

	uint32_t too_bigs_before = agent.counters.snmpOutTooBigs;
	size_t tiny_buf_sz = 35;
	memset(resp_buf, 0, sizeof(resp_buf));
	resp_len = 0;
	ret = snmp_agent_process_pdu(&agent, req_buf, req_len, resp_buf, tiny_buf_sz, &resp_len);
	ASSERT_EQ(ret, 0);
	ASSERT_GT(resp_len, 0);
	ASSERT(resp_len <= tiny_buf_sz);

	memset(&resp_pdu, 0, sizeof(resp_pdu));
	ret = snmp_ber_decode_pdu(resp_buf, resp_len, &resp_pdu);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(resp_pdu.error_status, SNMP_ERR_TOO_BIG);
	ASSERT_EQ(resp_pdu.error_index, 0);
	ASSERT_EQ(resp_pdu.varbind_cnt, 0);
	ASSERT_GT(agent.counters.snmpOutTooBigs, too_bigs_before);
}
