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
#include "snmp/snmp_mib.h"

#define ASSERT(cond) do { if (!(cond)) { printf("FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); exit(1); } } while(0)
#define ASSERT_EQ(a, b) ASSERT((a) == (b))

static int test_counter = 42;
static int test_get_called = 0;

static int my_get_cb(const struct snmp_mib_node *node, struct snmp_varbind *vb)
{
    (void)node;
    test_get_called++;
    vb->type = SNMP_TAG_COUNTER32;
    vb->val.uint_val = test_counter;
    return 0;
}

__attribute__((unused)) static int my_set_cb(struct snmp_mib_node *node, const struct snmp_varbind *vb)
{
    (void)node;
    if (vb->type == SNMP_TAG_COUNTER32) {
        test_counter = vb->val.uint_val;
        return 0;
    }
    return -22;
}

void test_mib_register_get(void)
{
    int ret = snmp_mib_init();
    ASSERT_EQ(ret, 0);

    struct snmp_mib_node node = {0};
    node.oid.len = 9;
    node.oid.ids[0] = 1; node.oid.ids[1] = 3; node.oid.ids[2] = 6;
    node.oid.ids[3] = 1; node.oid.ids[4] = 4; node.oid.ids[5] = 1;
    node.oid.ids[6] = 99; node.oid.ids[7] = 1; node.oid.ids[8] = 0;
    node.type = SNMP_TAG_COUNTER32;
    node.get_cb = my_get_cb;
    node.set_cb = NULL;

    ret = snmp_mib_register(&node);
    ASSERT_EQ(ret, 0);

    struct snmp_varbind vb = {0};
    ret = snmp_mib_get(&node.oid, &vb);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(test_get_called, 1);
    ASSERT_EQ(vb.type, SNMP_TAG_COUNTER32);
    ASSERT_EQ(vb.val.uint_val, 42);
}

void test_mib_get_next(void)
{
    snmp_mib_init();

    struct snmp_mib_node node_a = {0};
    node_a.oid.len = 9;
    node_a.oid.ids[0] = 1; node_a.oid.ids[1] = 3; node_a.oid.ids[2] = 6;
    node_a.oid.ids[3] = 1; node_a.oid.ids[4] = 4; node_a.oid.ids[5] = 1;
    node_a.oid.ids[6] = 99; node_a.oid.ids[7] = 1; node_a.oid.ids[8] = 0;
    node_a.type = SNMP_TAG_COUNTER32;
    node_a.get_cb = my_get_cb;
    snmp_mib_register(&node_a);

    struct snmp_mib_node node_b = {0};
    node_b.oid.len = 9;
    node_b.oid.ids[0] = 1; node_b.oid.ids[1] = 3; node_b.oid.ids[2] = 6;
    node_b.oid.ids[3] = 1; node_b.oid.ids[4] = 4; node_b.oid.ids[5] = 1;
    node_b.oid.ids[6] = 99; node_b.oid.ids[7] = 2; node_b.oid.ids[8] = 0;
    node_b.type = SNMP_TAG_GAUGE32;
    node_b.get_cb = my_get_cb;
    snmp_mib_register(&node_b);

    struct snmp_oid query = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 99, 0, 99}};
    struct snmp_varbind vb = {0};
    int ret = snmp_mib_get_next(&query, &vb);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(vb.oid.ids[7], 1);

    ret = snmp_mib_get_next(&node_a.oid, &vb);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(vb.oid.ids[7], 2);

    struct snmp_oid past_end = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 99, 99, 0}};
    ret = snmp_mib_get_next(&past_end, &vb);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(vb.type, SNMP_TAG_EXCEPT_END_MIB_VIEW);
}

void test_mib_duplicate_oid(void)
{
    snmp_mib_init();

    struct snmp_mib_node node = {0};
    node.oid.len = 9;
    node.oid.ids[0] = 1; node.oid.ids[1] = 3; node.oid.ids[2] = 6;
    node.oid.ids[3] = 1; node.oid.ids[4] = 4; node.oid.ids[5] = 1;
    node.oid.ids[6] = 99; node.oid.ids[7] = 1; node.oid.ids[8] = 0;
    node.type = SNMP_TAG_COUNTER32;
    node.get_cb = my_get_cb;

    int ret = snmp_mib_register(&node);
    ASSERT_EQ(ret, 0);
    ret = snmp_mib_register(&node);
    ASSERT_EQ(ret, 0);
}

static int32_t g_test_table_data[3][3] = {
    {0, 0, 0},
    {0, 101, 102},  /* row 1: col 1, col 2 */
    {0, 201, 202}   /* row 2: col 1, col 2 */
};

static int test_col1_get(const struct snmp_table_row *row, uint8_t column, struct snmp_varbind *vb)
{
    (void)column;
    vb->type = ASN1_TAG_INTEGER;
    vb->val.int_val = g_test_table_data[row->index][1];
    return 0;
}

static int test_col2_get(const struct snmp_table_row *row, uint8_t column, struct snmp_varbind *vb)
{
    (void)column;
    vb->type = ASN1_TAG_INTEGER;
    vb->val.int_val = g_test_table_data[row->index][2];
    return 0;
}

static int test_col2_set(struct snmp_table_row *row, uint8_t column, const struct snmp_varbind *vb)
{
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

static struct snmp_table_row g_test_rows[2] = {
    {.index = 1, .next = NULL, .user_data = NULL},
    {.index = 2, .next = NULL, .user_data = NULL}
};

static struct snmp_mib_table g_test_tbl = {
    .table_oid = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 99, 10, 1}},
    .column_cnt = 2,
    .column_subids = g_test_cols,
    .column_types = g_test_types,
    .get_cbs = g_test_get_cbs,
    .set_cbs = g_test_set_cbs,
    .rows = NULL,
    .user_data = NULL
};

void test_table_register_get(void)
{
    snmp_mib_init();

    g_test_tbl.rows = NULL;
    g_test_rows[0].next = NULL;
    g_test_rows[1].next = NULL;

    int ret = snmp_mib_register_table(&g_test_tbl);
    ASSERT_EQ(ret, 0);

    ret = snmp_mib_table_add_row(&g_test_tbl, &g_test_rows[0]);
    ASSERT_EQ(ret, 0);
    ret = snmp_mib_table_add_row(&g_test_tbl, &g_test_rows[1]);
    ASSERT_EQ(ret, 0);

    /* Get col 1, row 1 */
    struct snmp_oid oid_c1_r1 = {.len = 11, .ids = {1, 3, 6, 1, 4, 1, 99, 10, 1, 1, 1}};
    struct snmp_varbind vb = {0};
    ret = snmp_mib_get(&oid_c1_r1, &vb);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(vb.val.int_val, 101);

    /* Get col 2, row 2 */
    struct snmp_oid oid_c2_r2 = {.len = 11, .ids = {1, 3, 6, 1, 4, 1, 99, 10, 1, 2, 2}};
    memset(&vb, 0, sizeof(vb));
    ret = snmp_mib_get(&oid_c2_r2, &vb);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(vb.val.int_val, 202);

    /* Non-existent row 3 */
    struct snmp_oid oid_c1_r3 = {.len = 11, .ids = {1, 3, 6, 1, 4, 1, 99, 10, 1, 1, 3}};
    memset(&vb, 0, sizeof(vb));
    ret = snmp_mib_get(&oid_c1_r3, &vb);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(vb.type, SNMP_TAG_EXCEPT_NO_SUCH_INST);
}

void test_table_get_next_order(void)
{
    snmp_mib_init();

    g_test_tbl.rows = NULL;
    g_test_rows[0].next = NULL;
    g_test_rows[1].next = NULL;

    snmp_mib_register_table(&g_test_tbl);
    snmp_mib_table_add_row(&g_test_tbl, &g_test_rows[0]);
    snmp_mib_table_add_row(&g_test_tbl, &g_test_rows[1]);

    struct snmp_varbind vb = {0};

    /* Query before table: 1.3.6.1.4.1.99.10.0 */
    struct snmp_oid query = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 99, 10, 0}};
    int ret = snmp_mib_get_next(&query, &vb);
    ASSERT_EQ(ret, 0);
    /* Should hit col 1, row 1 */
    ASSERT_EQ(vb.oid.len, 11);
    ASSERT_EQ(vb.oid.ids[9], 1);  /* col 1 */
    ASSERT_EQ(vb.oid.ids[10], 1); /* row 1 */
    ASSERT_EQ(vb.val.int_val, 101);

    /* Next from col 1, row 1 -> col 1, row 2 */
    query = vb.oid;
    ret = snmp_mib_get_next(&query, &vb);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(vb.oid.ids[9], 1);  /* col 1 */
    ASSERT_EQ(vb.oid.ids[10], 2); /* row 2 */
    ASSERT_EQ(vb.val.int_val, 201);

    /* Next from col 1, row 2 -> col 2, row 1 (column-first ordering!) */
    query = vb.oid;
    ret = snmp_mib_get_next(&query, &vb);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(vb.oid.ids[9], 2);  /* col 2 */
    ASSERT_EQ(vb.oid.ids[10], 1); /* row 1 */
    ASSERT_EQ(vb.val.int_val, 102);

    /* Next from col 2, row 1 -> col 2, row 2 */
    query = vb.oid;
    ret = snmp_mib_get_next(&query, &vb);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(vb.oid.ids[9], 2);  /* col 2 */
    ASSERT_EQ(vb.oid.ids[10], 2); /* row 2 */
    ASSERT_EQ(vb.val.int_val, 202);

    /* Next from col 2, row 2 -> end of MIB view */
    query = vb.oid;
    ret = snmp_mib_get_next(&query, &vb);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(vb.type, SNMP_TAG_EXCEPT_END_MIB_VIEW);
}

void test_table_set(void)
{
    snmp_mib_init();

    g_test_tbl.rows = NULL;
    g_test_rows[0].next = NULL;
    g_test_rows[1].next = NULL;

    snmp_mib_register_table(&g_test_tbl);
    snmp_mib_table_add_row(&g_test_tbl, &g_test_rows[0]);
    snmp_mib_table_add_row(&g_test_tbl, &g_test_rows[1]);

    /* Set col 2, row 1 to 999 */
    struct snmp_varbind vb_set = {
        .oid = {.len = 11, .ids = {1, 3, 6, 1, 4, 1, 99, 10, 1, 2, 1}},
        .type = ASN1_TAG_INTEGER,
        .val = {.int_val = 999}
    };
    int ret = snmp_mib_set(&vb_set.oid, &vb_set);
    ASSERT_EQ(ret, 0);

    /* Verify via get */
    struct snmp_varbind vb_get = {0};
    ret = snmp_mib_get(&vb_set.oid, &vb_get);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(vb_get.val.int_val, 999);
}

void test_interleaved_scalar_and_table_walk(void)
{
    snmp_mib_init();

    /* Scalar before table: 1.3.6.1.4.1.99.5.0 */
    struct snmp_mib_node node_before = {0};
    node_before.oid.len = 9;
    node_before.oid.ids[0] = 1; node_before.oid.ids[1] = 3; node_before.oid.ids[2] = 6;
    node_before.oid.ids[3] = 1; node_before.oid.ids[4] = 4; node_before.oid.ids[5] = 1;
    node_before.oid.ids[6] = 99; node_before.oid.ids[7] = 5; node_before.oid.ids[8] = 0;
    node_before.type = SNMP_TAG_COUNTER32;
    node_before.get_cb = my_get_cb;
    snmp_mib_register(&node_before);

    /* Table: 1.3.6.1.4.1.99.10.1 */
    g_test_tbl.rows = NULL;
    g_test_rows[0].next = NULL;
    g_test_rows[1].next = NULL;

    snmp_mib_register_table(&g_test_tbl);
    snmp_mib_table_add_row(&g_test_tbl, &g_test_rows[0]);
    snmp_mib_table_add_row(&g_test_tbl, &g_test_rows[1]);

    /* Scalar after table: 1.3.6.1.4.1.99.20.0 */
    struct snmp_mib_node node_after = {0};
    node_after.oid.len = 9;
    node_after.oid.ids[0] = 1; node_after.oid.ids[1] = 3; node_after.oid.ids[2] = 6;
    node_after.oid.ids[3] = 1; node_after.oid.ids[4] = 4; node_after.oid.ids[5] = 1;
    node_after.oid.ids[6] = 99; node_after.oid.ids[7] = 20; node_after.oid.ids[8] = 0;
    node_after.type = SNMP_TAG_GAUGE32;
    node_after.get_cb = my_get_cb;
    snmp_mib_register(&node_after);

    struct snmp_varbind vb = {0};

    /* Query 1.3.6.1.4.1.99.0 */
    struct snmp_oid query = {.len = 8, .ids = {1, 3, 6, 1, 4, 1, 99, 0}};
    int ret = snmp_mib_get_next(&query, &vb);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(vb.oid.ids[7], 5); /* scalar before */

    /* Next -> table col 1, row 1 */
    query = vb.oid;
    ret = snmp_mib_get_next(&query, &vb);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(vb.oid.ids[7], 10);
    ASSERT_EQ(vb.oid.ids[9], 1);
    ASSERT_EQ(vb.oid.ids[10], 1);

    /* Advance through table */
    query = vb.oid;
    snmp_mib_get_next(&query, &vb); /* col 1, row 2 */
    ASSERT_EQ(vb.oid.ids[9], 1);
    ASSERT_EQ(vb.oid.ids[10], 2);

    query = vb.oid;
    snmp_mib_get_next(&query, &vb); /* col 2, row 1 */
    ASSERT_EQ(vb.oid.ids[9], 2);
    ASSERT_EQ(vb.oid.ids[10], 1);

    query = vb.oid;
    snmp_mib_get_next(&query, &vb); /* col 2, row 2 */
    ASSERT_EQ(vb.oid.ids[9], 2);
    ASSERT_EQ(vb.oid.ids[10], 2);

    /* Next -> scalar after table (1.3.6.1.4.1.99.20.0) */
    query = vb.oid;
    ret = snmp_mib_get_next(&query, &vb);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(vb.oid.ids[7], 20); /* scalar after */

    /* Next -> endOfMibView */
    query = vb.oid;
    ret = snmp_mib_get_next(&query, &vb);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(vb.type, SNMP_TAG_EXCEPT_END_MIB_VIEW);
}

