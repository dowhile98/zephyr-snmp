/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 *
 * Multi-Instance Coexistence & Zero-Singleton Unit Tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <snmp/snmp_ber.h>
#include <snmp/snmp_mib.h>
#include <snmp/snmp_core.h>

#define ASSERT(cond) do { \
	if (!(cond)) { \
		printf("FAIL (%s:%d: %s)\n", __FILE__, __LINE__, #cond); \
		exit(1); \
	} \
} while(0)

#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))

static int get_val_1111(const struct snmp_mib_node *node, struct snmp_varbind *vb)
{
	(void)node;
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = 1234;
	return 0;
}

static int get_val_2222(const struct snmp_mib_node *node, struct snmp_varbind *vb)
{
	(void)node;
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = 5678;
	return 0;
}

static size_t build_get_req_packet(uint8_t *buf, size_t buf_sz,
				   const char *community,
				   const struct snmp_oid *oid,
				   int32_t req_id)
{
	struct snmp_pdu pdu;
	memset(&pdu, 0, sizeof(pdu));
	pdu.version = 1; /* SNMPv2c */
	pdu.type = SNMP_PDU_GET_REQ;
	pdu.request_id = req_id;
	strncpy((char *)pdu.community, community, sizeof(pdu.community) - 1);
	pdu.community_len = strlen((char *)pdu.community);

	pdu.varbind_cnt = 1;
	pdu.varbinds[0].oid = *oid;
	pdu.varbinds[0].type = ASN1_TAG_NULL;

	size_t enc_len = 0;
	int ret = snmp_ber_encode_pdu(buf, buf_sz, &enc_len, &pdu);
	ASSERT_EQ(ret, 0);
	return enc_len;
}

void test_multi_instance_coexistence(void)
{
	static struct snmp_agent_inst lan_agent;
	static struct snmp_agent_inst wan_agent;

	/* 1. Initialize both independent instances */
	int ret = snmp_agent_inst_init(&lan_agent);
	ASSERT_EQ(ret, 0);
	ret = snmp_agent_inst_init(&wan_agent);
	ASSERT_EQ(ret, 0);

	/* 2. Configure distinct community strings */
	ret = snmp_agent_inst_set_read_community(&lan_agent, "lan_pub");
	ASSERT_EQ(ret, 0);
	ret = snmp_agent_inst_set_read_community(&wan_agent, "wan_pub");
	ASSERT_EQ(ret, 0);

	/* 3. Configure distinct sysName strings */
	ret = snmp_mib2_set_sysname_inst(&lan_agent, "router-lan");
	ASSERT_EQ(ret, 0);
	ret = snmp_mib2_set_sysname_inst(&wan_agent, "gateway-wan");
	ASSERT_EQ(ret, 0);

	/* 4. Register scalar .1.3.6.1.4.1.1111.1.0 on lan_agent only */
	struct snmp_mib_node node1 = {0};
	node1.oid.len = 9;
	node1.oid.ids[0] = 1;
	node1.oid.ids[1] = 3;
	node1.oid.ids[2] = 6;
	node1.oid.ids[3] = 1;
	node1.oid.ids[4] = 4;
	node1.oid.ids[5] = 1;
	node1.oid.ids[6] = 1111;
	node1.oid.ids[7] = 1;
	node1.oid.ids[8] = 0;
	node1.type = ASN1_TAG_INTEGER;
	node1.get_cb = get_val_1111;
	ret = snmp_mib_register_inst(&lan_agent, &node1);
	ASSERT_EQ(ret, 0);

	/* 5. Register scalar .1.3.6.1.4.1.2222.1.0 on wan_agent only */
	struct snmp_mib_node node2 = {0};
	node2.oid.len = 9;
	node2.oid.ids[0] = 1;
	node2.oid.ids[1] = 3;
	node2.oid.ids[2] = 6;
	node2.oid.ids[3] = 1;
	node2.oid.ids[4] = 4;
	node2.oid.ids[5] = 1;
	node2.oid.ids[6] = 2222;
	node2.oid.ids[7] = 1;
	node2.oid.ids[8] = 0;
	node2.type = ASN1_TAG_INTEGER;
	node2.get_cb = get_val_2222;
	ret = snmp_mib_register_inst(&wan_agent, &node2);
	ASSERT_EQ(ret, 0);

	uint8_t req_buf[512];
	uint8_t resp_buf[512];
	size_t req_len;
	size_t resp_len;
	struct snmp_pdu resp_pdu;

	/* 6. Query lan_agent for .1.3.6.1.4.1.1111.1.0 with community "lan_pub" */
	req_len = build_get_req_packet(req_buf, sizeof(req_buf), "lan_pub", &node1.oid, 101);
	ret = snmp_agent_inst_process_pdu(&lan_agent, req_buf, req_len, resp_buf, sizeof(resp_buf), &resp_len);
	ASSERT_EQ(ret, 0);
	ASSERT(resp_len > 0);

	memset(&resp_pdu, 0, sizeof(resp_pdu));
	ret = snmp_ber_decode_pdu(resp_buf, resp_len, &resp_pdu);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(resp_pdu.error_status, 0);
	ASSERT_EQ(resp_pdu.varbind_cnt, 1);
	ASSERT_EQ(resp_pdu.varbinds[0].type, ASN1_TAG_INTEGER);
	ASSERT_EQ(resp_pdu.varbinds[0].val.int_val, 1234);

	/* Assert LAN agent statistics incremented, WAN agent untouched */
	ASSERT_EQ(lan_agent.counters.snmpInPkts, 1);
	ASSERT_EQ(lan_agent.counters.snmpOutPkts, 1);
	ASSERT_EQ(wan_agent.counters.snmpInPkts, 0);
	ASSERT_EQ(wan_agent.counters.snmpOutPkts, 0);

	/* 7. Send "lan_pub" request to wan_agent -> must be rejected (-EACCES) */
	ret = snmp_agent_inst_process_pdu(&wan_agent, req_buf, req_len, resp_buf, sizeof(resp_buf), &resp_len);
	ASSERT_EQ(ret, -EACCES);
	ASSERT_EQ(wan_agent.counters.snmpInPkts, 1);
	ASSERT_EQ(wan_agent.counters.snmpInBadCommunityNames, 1);
	ASSERT_EQ(wan_agent.counters.snmpOutPkts, 0);
	ASSERT_EQ(lan_agent.counters.snmpInBadCommunityNames, 0);

	/* 8. Query wan_agent for .1.3.6.1.4.1.2222.1.0 with community "wan_pub" */
	req_len = build_get_req_packet(req_buf, sizeof(req_buf), "wan_pub", &node2.oid, 202);
	ret = snmp_agent_inst_process_pdu(&wan_agent, req_buf, req_len, resp_buf, sizeof(resp_buf), &resp_len);
	ASSERT_EQ(ret, 0);
	ASSERT(resp_len > 0);

	memset(&resp_pdu, 0, sizeof(resp_pdu));
	ret = snmp_ber_decode_pdu(resp_buf, resp_len, &resp_pdu);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(resp_pdu.error_status, 0);
	ASSERT_EQ(resp_pdu.varbind_cnt, 1);
	ASSERT_EQ(resp_pdu.varbinds[0].type, ASN1_TAG_INTEGER);
	ASSERT_EQ(resp_pdu.varbinds[0].val.int_val, 5678);
	ASSERT_EQ(wan_agent.counters.snmpInPkts, 2);
	ASSERT_EQ(wan_agent.counters.snmpOutPkts, 1);

	/* 9. Cross-instance isolation: Query lan_agent for .1.3.6.1.4.1.2222.1.0 (WAN OID) */
	req_len = build_get_req_packet(req_buf, sizeof(req_buf), "lan_pub", &node2.oid, 103);
	ret = snmp_agent_inst_process_pdu(&lan_agent, req_buf, req_len, resp_buf, sizeof(resp_buf), &resp_len);
	ASSERT_EQ(ret, 0);
	memset(&resp_pdu, 0, sizeof(resp_pdu));
	ret = snmp_ber_decode_pdu(resp_buf, resp_len, &resp_pdu);
	ASSERT_EQ(ret, 0);
	/* In SNMPv2c, an unmapped OID produces SNMP_TAG_EXCEPT_NO_SUCH_OBJ or noSuchName error */
	ASSERT(resp_pdu.varbinds[0].type == SNMP_TAG_EXCEPT_NO_SUCH_OBJ ||
	       resp_pdu.varbinds[0].type == SNMP_TAG_EXCEPT_NO_SUCH_INST ||
	       resp_pdu.error_status == SNMP_ERR_NO_SUCH_NAME);

	/* 10. Cross-instance isolation: Query wan_agent for .1.3.6.1.4.1.1111.1.0 (LAN OID) */
	req_len = build_get_req_packet(req_buf, sizeof(req_buf), "wan_pub", &node1.oid, 204);
	ret = snmp_agent_inst_process_pdu(&wan_agent, req_buf, req_len, resp_buf, sizeof(resp_buf), &resp_len);
	ASSERT_EQ(ret, 0);
	memset(&resp_pdu, 0, sizeof(resp_pdu));
	ret = snmp_ber_decode_pdu(resp_buf, resp_len, &resp_pdu);
	ASSERT_EQ(ret, 0);
	ASSERT(resp_pdu.varbinds[0].type == SNMP_TAG_EXCEPT_NO_SUCH_OBJ ||
	       resp_pdu.varbinds[0].type == SNMP_TAG_EXCEPT_NO_SUCH_INST ||
	       resp_pdu.error_status == SNMP_ERR_NO_SUCH_NAME);

	/* 11. Query MIB-II sysName on lan_agent -> should return "router-lan" */
	struct snmp_oid sysname_oid = {
		.len = 9,
		.ids = {1, 3, 6, 1, 2, 1, 1, 5, 0}
	};
	req_len = build_get_req_packet(req_buf, sizeof(req_buf), "lan_pub", &sysname_oid, 105);
	ret = snmp_agent_inst_process_pdu(&lan_agent, req_buf, req_len, resp_buf, sizeof(resp_buf), &resp_len);
	ASSERT_EQ(ret, 0);
	memset(&resp_pdu, 0, sizeof(resp_pdu));
	ret = snmp_ber_decode_pdu(resp_buf, resp_len, &resp_pdu);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(resp_pdu.error_status, 0);
	ASSERT_EQ(resp_pdu.varbinds[0].type, ASN1_TAG_OCTET_STRING);
	ASSERT_EQ(strcmp((char *)resp_pdu.varbinds[0].val.octet_str.data, "router-lan"), 0);

	/* 12. Query MIB-II sysName on wan_agent -> should return "gateway-wan" */
	req_len = build_get_req_packet(req_buf, sizeof(req_buf), "wan_pub", &sysname_oid, 206);
	ret = snmp_agent_inst_process_pdu(&wan_agent, req_buf, req_len, resp_buf, sizeof(resp_buf), &resp_len);
	ASSERT_EQ(ret, 0);
	memset(&resp_pdu, 0, sizeof(resp_pdu));
	ret = snmp_ber_decode_pdu(resp_buf, resp_len, &resp_pdu);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(resp_pdu.error_status, 0);
	ASSERT_EQ(resp_pdu.varbinds[0].type, ASN1_TAG_OCTET_STRING);
	ASSERT_EQ(strcmp((char *)resp_pdu.varbinds[0].val.octet_str.data, "gateway-wan"), 0);
}
