/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 *
 * Unit tests for SNMPv3 View-based Access Control Model (RFC 3415).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <snmp/snmp_ber.h>
#include <snmp/snmp_vacm.h>
#include <snmp/snmp_core.h>

/*
 * Two independent instances: the VACM tables under test live in s_vacm_test_agent and
 * are driven exclusively through the agent-parameter API. The module has no default
 * agent any more (sub-phase 8c), so there is nothing else to stub.
 */
static struct snmp_agent s_vacm_test_agent;

/* Assert macros defined in main.c */
#define ASSERT(cond)                                                                               \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			printf("FAIL (%s:%d: %s)\n", __FILE__, __LINE__, #cond);                   \
			exit(1);                                                                   \
		}                                                                                  \
	} while (0)

#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))

void test_vacm_group_mapping_resolution(void)
{
	int ret = snmp_vacm_init(&s_vacm_test_agent);
	ASSERT_EQ(ret, 0);

	struct snmp_oid sys_oid = {.len = 8, .ids = {1, 3, 6, 1, 2, 1, 1, 1, 0}};

	/* Default admin user ("admin") maps to group admin and has full access */
	ret =
	    snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "admin",
				      SNMP_SEC_LEVEL_AUTH_NOPRIV, SNMP_VACM_ACCESS_READ, &sys_oid);
	ASSERT_EQ(ret, 0);

	/* Default monitor user ("monitor") maps to group readonly */
	ret = snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "monitor",
					SNMP_SEC_LEVEL_NOAUTH_NOPRIV, SNMP_VACM_ACCESS_READ,
					&sys_oid);
	ASSERT_EQ(ret, 0);

	/* Unknown user has no mapping -> rejected */
	ret =
	    snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "unknown_user",
				      SNMP_SEC_LEVEL_AUTH_NOPRIV, SNMP_VACM_ACCESS_READ, &sys_oid);
	ASSERT_EQ(ret, -EACCES);

	/* Add new mapping for operator user -> group admin */
	ret = snmp_vacm_add_group_mapping(&s_vacm_test_agent, SNMP_SEC_MODEL_USM, "operator",
					  "admin");
	ASSERT_EQ(ret, 0);

	ret =
	    snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "operator",
				      SNMP_SEC_LEVEL_AUTH_NOPRIV, SNMP_VACM_ACCESS_READ, &sys_oid);
	ASSERT_EQ(ret, 0);
}

void test_vacm_security_level_enforcement(void)
{
	int ret = snmp_vacm_init(&s_vacm_test_agent);
	ASSERT_EQ(ret, 0);

	struct snmp_oid sys_oid = {.len = 8, .ids = {1, 3, 6, 1, 2, 1, 1, 1, 0}};

	/* Admin group rule requires min_sec_level = authNoPriv (2).
	 * Request with noAuthNoPriv (1) must be REJECTED.
	 */
	ret = snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "admin",
					SNMP_SEC_LEVEL_NOAUTH_NOPRIV, SNMP_VACM_ACCESS_READ,
					&sys_oid);
	ASSERT_EQ(ret, -EACCES);

	ret = snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "admin",
					SNMP_SEC_LEVEL_NOAUTH_NOPRIV, SNMP_VACM_ACCESS_WRITE,
					&sys_oid);
	ASSERT_EQ(ret, -EACCES);

	/* Request with authNoPriv (2) meets min_sec_level -> ALLOWED */
	ret =
	    snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "admin",
				      SNMP_SEC_LEVEL_AUTH_NOPRIV, SNMP_VACM_ACCESS_WRITE, &sys_oid);
	ASSERT_EQ(ret, 0);

	/* Request with authPriv (3) exceeds min_sec_level -> ALLOWED */
	ret = snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "admin",
					SNMP_SEC_LEVEL_AUTH_PRIV, SNMP_VACM_ACCESS_WRITE, &sys_oid);
	ASSERT_EQ(ret, 0);

	/* Monitor user has rule with min_sec_level = noAuthNoPriv (1) for read, but NO write view
	 */
	ret = snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "monitor",
					SNMP_SEC_LEVEL_NOAUTH_NOPRIV, SNMP_VACM_ACCESS_READ,
					&sys_oid);
	ASSERT_EQ(ret, 0);

	ret = snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "monitor",
					SNMP_SEC_LEVEL_NOAUTH_NOPRIV, SNMP_VACM_ACCESS_WRITE,
					&sys_oid);
	ASSERT_EQ(ret, -EACCES);
}

void test_vacm_oid_subtree_matching(void)
{
	int ret = snmp_vacm_init(&s_vacm_test_agent);
	ASSERT_EQ(ret, 0);

	/* restrictedView includes 1.3.6.1.2.1.1 (system group) */
	struct snmp_oid sys_descr = {.len = 8, .ids = {1, 3, 6, 1, 2, 1, 1, 1, 0}};
	struct snmp_oid sys_uptime = {.len = 8, .ids = {1, 3, 6, 1, 2, 1, 1, 3, 0}};
	struct snmp_oid if_number = {
	    .len = 8, .ids = {1, 3, 6, 1, 2, 1, 2, 1, 0} /* 1.3.6.1.2.1.2 is interfaces */
	};
	struct snmp_oid ent_sensor = {
	    .len = 9, .ids = {1, 3, 6, 1, 4, 1, 54321, 1, 0} /* Enterprise OID */
	};

	/* monitor user in restrictedView: system group is allowed */
	ret = snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "monitor",
					SNMP_SEC_LEVEL_NOAUTH_NOPRIV, SNMP_VACM_ACCESS_READ,
					&sys_descr);
	ASSERT_EQ(ret, 0);

	ret = snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "monitor",
					SNMP_SEC_LEVEL_NOAUTH_NOPRIV, SNMP_VACM_ACCESS_READ,
					&sys_uptime);
	ASSERT_EQ(ret, 0);

	/* Interfaces group (1.3.6.1.2.1.2) is outside restrictedView -> REJECTED */
	ret = snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "monitor",
					SNMP_SEC_LEVEL_NOAUTH_NOPRIV, SNMP_VACM_ACCESS_READ,
					&if_number);
	ASSERT_EQ(ret, -EACCES);

	/* Enterprise OID is outside restrictedView -> REJECTED */
	ret = snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "monitor",
					SNMP_SEC_LEVEL_NOAUTH_NOPRIV, SNMP_VACM_ACCESS_READ,
					&ent_sensor);
	ASSERT_EQ(ret, -EACCES);

	/* admin user in fullView (1.3.6.1): both system and enterprise allowed */
	ret = snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "admin",
					SNMP_SEC_LEVEL_AUTH_NOPRIV, SNMP_VACM_ACCESS_READ,
					&if_number);
	ASSERT_EQ(ret, 0);

	ret = snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "admin",
					SNMP_SEC_LEVEL_AUTH_NOPRIV, SNMP_VACM_ACCESS_READ,
					&ent_sensor);
	ASSERT_EQ(ret, 0);
}

void test_vacm_oid_subtree_excluded(void)
{
	int ret = snmp_vacm_init(&s_vacm_test_agent);
	ASSERT_EQ(ret, 0);

	/* In fullView (1.3.6.1 included), add an EXCLUDED subtree: 1.3.6.1.4.1.99999 */
	struct snmp_oid secret_subtree = {.len = 7, .ids = {1, 3, 6, 1, 4, 1, 99999}};
	ret = snmp_vacm_add_view_tree(&s_vacm_test_agent, "fullView", &secret_subtree, NULL, 0,
				      SNMP_VACM_VIEW_EXCLUDED);
	ASSERT_EQ(ret, 0);

	struct snmp_oid regular_oid = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 54321, 1, 0}};
	struct snmp_oid excluded_oid = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 99999, 1, 0}};

	/* Regular enterprise OID is still allowed in fullView */
	ret = snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "admin",
					SNMP_SEC_LEVEL_AUTH_NOPRIV, SNMP_VACM_ACCESS_READ,
					&regular_oid);
	ASSERT_EQ(ret, 0);

	/* Excluded subtree is REJECTED even though 1.3.6.1 is included */
	ret = snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "admin",
					SNMP_SEC_LEVEL_AUTH_NOPRIV, SNMP_VACM_ACCESS_READ,
					&excluded_oid);
	ASSERT_EQ(ret, -EACCES);
}

void test_vacm_wildcard_mask(void)
{
	int ret = snmp_vacm_init(&s_vacm_test_agent);
	ASSERT_EQ(ret, 0);

	/* Create a custom view "wildView" with subtree 1.3.6.1.4.1.54321.0.1
	 * Mask wildcards sub-identifier at index 6 (the 7th sub-id, value 0).
	 * Mask: 0xBF (10111111b: bit 6 is 0) followed by 0x80 (10000000b: bit 7 is 1).
	 * Indices:
	 * index 0..5: 1 (exact)
	 * index 6:    0 (wildcard)
	 * index 7:    1 (exact)
	 */
	struct snmp_oid pattern_subtree = {.len = 8, .ids = {1, 3, 6, 1, 4, 1, 0, 1}};
	uint8_t mask[2] = {0xFD,
			   0x80}; /* 1111 1101 1000 0000:
				   * bit 0: 0x80 (id 0 = 1) -> 1
				   * bit 1: 0x40 (id 1 = 3) -> 1
				   * bit 2: 0x20 (id 2 = 6) -> 1
				   * bit 3: 0x10 (id 3 = 1) -> 1
				   * bit 4: 0x08 (id 4 = 4) -> 1
				   * bit 5: 0x04 (id 5 = 1) -> 1
				   * bit 6: 0x02 (id 6 = 54321) -> 1
				   * bit 7: 0x01 (id 7 = 0) -> 0 (wildcard!)
				   * byte 1 bit 0: 0x80 (id 8 = 1) -> 1 (exact)
				   * Wait: pattern_subtree.len is 8:
				   * ids[0]=1, ids[1]=3, ids[2]=6, ids[3]=1,
				   * ids[4]=4, ids[5]=1, ids[6]=0 (wildcard!), ids[7]=1
				   * So index 6 is the 7th sub-id!
				   * In byte 0:
				   * bit 0 (0x80) -> idx 0
				   * bit 1 (0x40) -> idx 1
				   * bit 2 (0x20) -> idx 2
				   * bit 3 (0x10) -> idx 3
				   * bit 4 (0x08) -> idx 4
				   * bit 5 (0x04) -> idx 5
				   * bit 6 (0x02) -> idx 6 (WILDCARD: 0)
				   * bit 7 (0x01) -> idx 7 (EXACT: 1)
				   * Therefore byte 0 = 0x80|0x40|0x20|0x10|0x08|0x04|0x01 = 0xFD!
				   */

	ret = snmp_vacm_add_view_tree(&s_vacm_test_agent, "wildView", &pattern_subtree, mask, 1,
				      SNMP_VACM_VIEW_INCLUDED);
	ASSERT_EQ(ret, 0);

	ret = snmp_vacm_add_access_rule(&s_vacm_test_agent, "admin", "", SNMP_SEC_MODEL_USM,
					SNMP_SEC_LEVEL_AUTH_NOPRIV, "wildView", "wildView",
					"wildView");
	ASSERT_EQ(ret, 0);

	/* Target A: 1.3.6.1.4.1.10.1.0 (id[6] = 10, id[7] = 1) -> MATCH */
	struct snmp_oid target_a = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 10, 1, 0}};
	ret =
	    snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "admin",
				      SNMP_SEC_LEVEL_AUTH_NOPRIV, SNMP_VACM_ACCESS_READ, &target_a);
	ASSERT_EQ(ret, 0);

	/* Target B: 1.3.6.1.4.1.99.1.0 (id[6] = 99, id[7] = 1) -> MATCH */
	struct snmp_oid target_b = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 99, 1, 0}};
	ret =
	    snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "admin",
				      SNMP_SEC_LEVEL_AUTH_NOPRIV, SNMP_VACM_ACCESS_READ, &target_b);
	ASSERT_EQ(ret, 0);

	/* Target C: 1.3.6.1.4.1.10.2.0 (id[6] = 10, id[7] = 2 != 1) -> MISMATCH */
	struct snmp_oid target_c = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 10, 2, 0}};
	ret =
	    snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "admin",
				      SNMP_SEC_LEVEL_AUTH_NOPRIV, SNMP_VACM_ACCESS_READ, &target_c);
	ASSERT_EQ(ret, -EACCES);
}

void test_vacm_unknown_context_rejected(void)
{
	int ret = snmp_vacm_init(&s_vacm_test_agent);
	ASSERT_EQ(ret, 0);

	struct snmp_oid sys_oid = {.len = 8, .ids = {1, 3, 6, 1, 2, 1, 1, 1, 0}};

	/* Default context "" is valid */
	ret =
	    snmp_vacm_check_access_ex(&s_vacm_test_agent, "", SNMP_SEC_MODEL_USM, "admin",
				      SNMP_SEC_LEVEL_AUTH_NOPRIV, SNMP_VACM_ACCESS_READ, &sys_oid);
	ASSERT_EQ(ret, 0);

	/* Non-existent context "vrf1" is rejected */
	ret =
	    snmp_vacm_check_access_ex(&s_vacm_test_agent, "vrf1", SNMP_SEC_MODEL_USM, "admin",
				      SNMP_SEC_LEVEL_AUTH_NOPRIV, SNMP_VACM_ACCESS_READ, &sys_oid);
	ASSERT_EQ(ret, -EACCES);

	/* Add context "vrf1" */
	ret = snmp_vacm_add_context(&s_vacm_test_agent, "vrf1");
	ASSERT_EQ(ret, 0);

	/* Add access rule for context_prefix "vrf1" */
	ret = snmp_vacm_add_access_rule(&s_vacm_test_agent, "admin", "vrf1", SNMP_SEC_MODEL_USM,
					SNMP_SEC_LEVEL_AUTH_NOPRIV, "fullView", "fullView",
					"fullView");
	ASSERT_EQ(ret, 0);

	/* Now context "vrf1" is accepted */
	ret =
	    snmp_vacm_check_access_ex(&s_vacm_test_agent, "vrf1", SNMP_SEC_MODEL_USM, "admin",
				      SNMP_SEC_LEVEL_AUTH_NOPRIV, SNMP_VACM_ACCESS_READ, &sys_oid);
	ASSERT_EQ(ret, 0);
}

void test_vacm_check_access_backward_compat(void)
{
	int ret = snmp_vacm_init(&s_vacm_test_agent);
	ASSERT_EQ(ret, 0);

	struct snmp_v3_msg msg;
	memset(&msg, 0, sizeof(msg));

	strncpy((char *)msg.usm.user_name, "admin", sizeof(msg.usm.user_name) - 1);
	msg.usm.user_name_len = strlen("admin");
	msg.global.msg_security_model = SNMP_SEC_MODEL_USM;
	msg.global.msg_flags = 0x01; /* authNoPriv */
	msg.scoped.context_name[0] = '\0';
	msg.scoped.context_name_len = 0;

	/* Add varbind with system OID */
	msg.scoped.pdu.varbind_cnt = 1;
	msg.scoped.pdu.varbinds[0].oid.len = 8;
	msg.scoped.pdu.varbinds[0].oid.ids[0] = 1;
	msg.scoped.pdu.varbinds[0].oid.ids[1] = 3;
	msg.scoped.pdu.varbinds[0].oid.ids[2] = 6;
	msg.scoped.pdu.varbinds[0].oid.ids[3] = 1;
	msg.scoped.pdu.varbinds[0].oid.ids[4] = 2;
	msg.scoped.pdu.varbinds[0].oid.ids[5] = 1;
	msg.scoped.pdu.varbinds[0].oid.ids[6] = 1;
	msg.scoped.pdu.varbinds[0].oid.ids[7] = 0;

	/* Read access for admin with authNoPriv */
	ret = snmp_vacm_check_access(&s_vacm_test_agent, &msg, false);
	ASSERT_EQ(ret, 0);

	/* Write access for admin with authNoPriv */
	ret = snmp_vacm_check_access(&s_vacm_test_agent, &msg, true);
	ASSERT_EQ(ret, 0);

	/* Now switch user to monitor (readonly, noAuth) */
	strncpy((char *)msg.usm.user_name, "monitor", sizeof(msg.usm.user_name) - 1);
	msg.usm.user_name_len = strlen("monitor");
	msg.global.msg_flags = 0x00; /* noAuthNoPriv */

	/* Read access for monitor -> OK */
	ret = snmp_vacm_check_access(&s_vacm_test_agent, &msg, false);
	ASSERT_EQ(ret, 0);

	/* Write access for monitor -> DENIED */
	ret = snmp_vacm_check_access(&s_vacm_test_agent, &msg, true);
	ASSERT_EQ(ret, -EACCES);
}

#define RUN_TEST(name)                                                                             \
	do {                                                                                       \
		printf("  %-50s ", #name);                                                         \
		fflush(stdout);                                                                    \
		name();                                                                            \
		tests_passed++;                                                                    \
		printf("PASS\n");                                                                  \
	} while (0)

int main(void)
{
	int tests_passed = 0;
	printf("SNMP VACM Unit Tests (RFC 3415)\n");
	printf("===============================\n\n");

	RUN_TEST(test_vacm_group_mapping_resolution);
	RUN_TEST(test_vacm_security_level_enforcement);
	RUN_TEST(test_vacm_oid_subtree_matching);
	RUN_TEST(test_vacm_oid_subtree_excluded);
	RUN_TEST(test_vacm_wildcard_mask);
	RUN_TEST(test_vacm_unknown_context_rejected);
	RUN_TEST(test_vacm_check_access_backward_compat);

	printf("\n===============================\n");
	printf("Results: %d passed, 0 failed, 7 total\n", tests_passed);
	return 0;
}
