/*
 * Copyright (c) 2026 StructCore Embedded
 * SPDX-License-Identifier: Apache-2.0
 *
 * Regression tests for the receive-path hardening done during the production audit:
 * BER/OID edge cases, per-varbind bounds, PDU reflection and community comparison.
 *
 * These only use APIs that exist without CONFIG_SNMP_VERSION_3, so they run in the
 * host suite (no Zephyr kernel, no PSA Crypto).
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <snmp/snmp_core.h>
#include <snmp/snmp_ber.h>
#include <snmp/snmp_mib.h>

/* Pure internal helper (v1 trap parameter mapping); no Zephyr dependency. */
#include "../../src/snmp_internal.h"

/* Zephyr's util.h is not part of the host stubs. */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

/* Same ASSERT helpers as main.c: a failure aborts the whole binary. */
#define ASSERT(cond)                                                                               \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			printf("FAIL (%s:%d: %s)\n", __FILE__, __LINE__, #cond);                   \
			exit(1);                                                                   \
		}                                                                                  \
	} while (0)

#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))
#define ASSERT_GT(a, b) ASSERT((a) > (b))

/* ---- OID: first sub-identifier must be base-128, not one raw octet ---- */

void test_ber_oid_arc2_multibyte_first_subid(void)
{
	struct snmp_oid in = {.len = 3, .ids = {2, 100, 3}};
	struct snmp_oid out;
	uint8_t buf[64];
	size_t off = 0;

	ASSERT_EQ(snmp_ber_encode_oid(buf, sizeof(buf), &off, &in), 0);

	/* 2.100.3 -> first sub-id 2*40+100 = 180 -> 0x81 0x34 */
	ASSERT_EQ(off, 5);
	ASSERT_EQ(buf[0], ASN1_TAG_OID);
	ASSERT_EQ(buf[1], 3);
	ASSERT_EQ(buf[2], 0x81);
	ASSERT_EQ(buf[3], 0x34);
	ASSERT_EQ(buf[4], 3);

	size_t doff = 0;

	ASSERT_EQ(snmp_ber_decode_oid(buf, off, &doff, &out), 0);
	ASSERT_EQ(doff, off);
	ASSERT_EQ(out.len, 3);
	ASSERT_EQ(out.ids[0], 2);
	ASSERT_EQ(out.ids[1], 100);
	ASSERT_EQ(out.ids[2], 3);
}

void test_ber_oid_large_subid_roundtrip(void)
{
	/* 54321 needs three base-128 octets; the enterprise arc must survive intact. */
	struct snmp_oid in = {.len = 7, .ids = {1, 3, 6, 1, 4, 1, 54321}};
	struct snmp_oid out;
	uint8_t buf[64];
	size_t off = 0;

	ASSERT_EQ(snmp_ber_encode_oid(buf, sizeof(buf), &off, &in), 0);
	ASSERT_GT(off, 7);

	size_t doff = 0;

	ASSERT_EQ(snmp_ber_decode_oid(buf, off, &doff, &out), 0);
	ASSERT_EQ(out.len, in.len);
	ASSERT_EQ(memcmp(out.ids, in.ids, in.len * sizeof(uint32_t)), 0);
}

void test_ber_oid_arc2_overflow_rejected(void)
{
	/* 2.x encodes as 80 + x; x close to UINT32_MAX would wrap the sum. */
	struct snmp_oid bad = {.len = 2, .ids = {2, UINT32_MAX}};
	uint8_t buf[32];
	size_t off = 0;

	ASSERT_EQ(snmp_ber_encode_oid(buf, sizeof(buf), &off, &bad), -EINVAL);

	/* Arc 0/1 with a second sub-id above 39 is not a legal OID either. */
	struct snmp_oid bad2 = {.len = 2, .ids = {1, 40}};
	off = 0;
	ASSERT_EQ(snmp_ber_encode_oid(buf, sizeof(buf), &off, &bad2), -EINVAL);
}

/* ---- BER length handling ---- */

void test_ber_oversized_length_rejected(void)
{
	/* 0x84 FF FF FF FF: a hostile length that would wrap a 32-bit size_t. */
	const uint8_t buf[] = {0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF};
	size_t off = 0;
	uint8_t tag;
	size_t len;

	ASSERT_EQ(snmp_ber_decode_header(buf, sizeof(buf), &off, &tag, &len), -EBADMSG);

	/* Indefinite length (0x80) is prohibited by RFC 1157 §3.2.1. */
	const uint8_t indef[] = {0x30, 0x80, 0x00, 0x00};
	off = 0;
	ASSERT_EQ(snmp_ber_decode_header(indef, sizeof(indef), &off, &tag, &len), -EBADMSG);
}

void test_ber_uint64_padding_rules(void)
{
	uint64_t val = 0;
	size_t off = 0;

	/* Nine octets are only legal with a leading zero pad. */
	const uint8_t bad[] = {
	    SNMP_TAG_COUNTER64, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	ASSERT_EQ(snmp_ber_decode_uint64(bad, sizeof(bad), &off, &val), -EBADMSG);

	const uint8_t good[] = {
	    SNMP_TAG_COUNTER64, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};

	off = 0;
	ASSERT_EQ(snmp_ber_decode_uint64(good, sizeof(good), &off, &val), 0);
	ASSERT_EQ(val, 0x0100000000000002ULL);

	/* Zero-length integer is not a valid encoding. */
	const uint8_t empty[] = {SNMP_TAG_COUNTER64, 0x00};

	off = 0;
	ASSERT_EQ(snmp_ber_decode_uint64(empty, sizeof(empty), &off, &val), -EBADMSG);
}

/* ---- Frame construction helpers (hostile / oversized inputs) ---- */

static size_t len_octets(size_t len)
{
	return len < 0x80 ? 1 : (len < 0x100 ? 2 : 3);
}

static void put_header(uint8_t *buf, size_t *pos, uint8_t tag, size_t len)
{
	buf[(*pos)++] = tag;
	if (len < 0x80) {
		buf[(*pos)++] = (uint8_t)len;
	} else if (len < 0x100) {
		buf[(*pos)++] = 0x81;
		buf[(*pos)++] = (uint8_t)len;
	} else {
		buf[(*pos)++] = 0x82;
		buf[(*pos)++] = (uint8_t)(len >> 8);
		buf[(*pos)++] = (uint8_t)len;
	}
}

/* Minimal v2c GET: version 1, community "public", N varbinds of OID 1.3 + NULL. */
static size_t build_get_frame(uint8_t *buf, size_t varbind_cnt)
{
	const size_t vb_len = 7 * varbind_cnt; /* 30 05 06 01 2b 05 00 each */
	const size_t vbl_tlv = vb_len + len_octets(vb_len) + 1;
	const size_t pdu_body = 9 + vbl_tlv; /* 3 x (02 01 xx) */
	const size_t pdu_tlv = pdu_body + len_octets(pdu_body) + 1;
	const size_t msg_body = 3 + 8 + pdu_tlv; /* version + community TLV */
	size_t pos = 0;

	put_header(buf, &pos, ASN1_TAG_SEQUENCE, msg_body);
	put_header(buf, &pos, ASN1_TAG_INTEGER, 1);
	buf[pos++] = 1; /* SNMPv2c */
	put_header(buf, &pos, ASN1_TAG_OCTET_STRING, 6);
	memcpy(&buf[pos], "public", 6);
	pos += 6;
	put_header(buf, &pos, 0xA0 /* GetRequest */, pdu_body);
	put_header(buf, &pos, ASN1_TAG_INTEGER, 1);
	buf[pos++] = 1; /* request-id */
	put_header(buf, &pos, ASN1_TAG_INTEGER, 1);
	buf[pos++] = 0; /* error-status */
	put_header(buf, &pos, ASN1_TAG_INTEGER, 1);
	buf[pos++] = 0; /* error-index */
	put_header(buf, &pos, ASN1_TAG_SEQUENCE, vb_len);

	for (size_t i = 0; i < varbind_cnt; i++) {
		buf[pos++] = ASN1_TAG_SEQUENCE;
		buf[pos++] = 5;
		buf[pos++] = ASN1_TAG_OID;
		buf[pos++] = 1;
		buf[pos++] = 0x2B; /* 1.3 */
		buf[pos++] = ASN1_TAG_NULL;
		buf[pos++] = 0;
	}

	return pos;
}

void test_ber_per_varbind_bounds_enforced(void)
{
	/*
	 * A varbind SEQUENCE whose declared length runs past its enclosing varbind list.
	 * Before the fix the inner length was honoured against the whole datagram, so a
	 * varbind could read into the neighbouring one.
	 */
	const uint8_t frame[] = {0x30, 0x1D,				    /* message */
				 0x02, 0x01, 0x01,			    /* version 1 */
				 0x04, 0x06, 'p',  'u', 'b', 'l', 'i', 'c', /* community */
				 0xA0, 0x10,				    /* GetRequest */
				 0x02, 0x01, 0x01,			    /* request-id */
				 0x02, 0x01, 0x00,			    /* error-status */
				 0x02, 0x01, 0x00,			    /* error-index */
				 0x30, 0x05,	   /* varbind list: 5 bytes */
				 0x30, 0x04,	   /* varbind claims 4 bytes */
				 0x06, 0x01, 0x2B, /* only 3 remain before the end */
				 0x05, 0x00};

	struct snmp_agent agent;

	ASSERT_EQ(snmp_agent_init(&agent, NULL), 0);

	uint8_t resp[CONFIG_SNMP_MAX_PDU_SIZE];
	size_t resp_len = 0;

	ASSERT_EQ(
	    snmp_agent_process_pdu(&agent, frame, sizeof(frame), resp, sizeof(resp), &resp_len),
	    -EBADMSG);
	ASSERT_EQ(resp_len, 0);
	ASSERT_EQ(agent.counters.snmpInASNParseErrs, 1);
}

void test_ber_varbind_count_overflow_rejected(void)
{
	struct snmp_agent agent;
	uint8_t frame[512];
	uint8_t resp[CONFIG_SNMP_MAX_PDU_SIZE];
	size_t resp_len = 0;

	ASSERT_EQ(snmp_agent_init(&agent, NULL), 0);

	/* The maximum is accepted... */
	size_t len = build_get_frame(frame, CONFIG_SNMP_MAX_VARBINDS);

	ASSERT_EQ(snmp_agent_process_pdu(&agent, frame, len, resp, sizeof(resp), &resp_len), 0);
	ASSERT_GT(resp_len, 0);

	/* ...one more is rejected instead of being silently truncated (a truncated
	 * SET would acknowledge writes that were never performed).
	 */
	len = build_get_frame(frame, CONFIG_SNMP_MAX_VARBINDS + 1);

	ASSERT_EQ(snmp_agent_process_pdu(&agent, frame, len, resp, sizeof(resp), &resp_len),
		  -E2BIG);
	ASSERT_EQ(resp_len, 0);
	ASSERT_EQ(agent.counters.snmpInASNParseErrs, 1);
}

/* ---- PDU reflection ---- */

void test_pdu_reflection_rejected(void)
{
	struct snmp_agent agent;
	struct snmp_pdu pdu;
	uint8_t frame[CONFIG_SNMP_MAX_PDU_SIZE];
	uint8_t resp[CONFIG_SNMP_MAX_PDU_SIZE];
	size_t frame_len = 0;
	size_t resp_len = 0;

	ASSERT_EQ(snmp_agent_init(&agent, NULL), 0);

	/* A GetResponse arriving on the agent port must not be echoed back. */
	memset(&pdu, 0, sizeof(pdu));
	pdu.version = 1;
	pdu.type = SNMP_PDU_GET_RESP;
	pdu.request_id = 42;
	pdu.varbind_cnt = 0;
	memcpy(pdu.community, "public", 6);
	pdu.community_len = 6;

	ASSERT_EQ(snmp_ber_encode_pdu(frame, sizeof(frame), &frame_len, &pdu), 0);
	ASSERT_EQ(snmp_agent_process_pdu(&agent, frame, frame_len, resp, sizeof(resp), &resp_len),
		  -EACCES);
	ASSERT_EQ(resp_len, 0);
	ASSERT_EQ(agent.counters.snmpSilentDrops, 1);

	/* The same rule at the engine level, whatever called it. */
	ASSERT_EQ(snmp_mib_dispatch(&agent, &pdu), -EINVAL);
}

/* ---- Community comparison is length-exact, not NUL-terminated ---- */

void test_community_binary_and_prefix_rejected(void)
{
	struct snmp_agent agent;
	struct snmp_pdu pdu;
	uint8_t frame[CONFIG_SNMP_MAX_PDU_SIZE];
	uint8_t resp[CONFIG_SNMP_MAX_PDU_SIZE];
	size_t frame_len = 0;
	size_t resp_len = 0;

	ASSERT_EQ(snmp_agent_init(&agent, NULL), 0);

	/*
	 * "public\0x": strlen("public") stops at the NUL, but the datagram claims eight
	 * octets. A strcmp()-based check would accept this prefix, so the comparison must
	 * use the length the wire actually carried.
	 */
	memset(&pdu, 0, sizeof(pdu));
	pdu.version = 1;
	pdu.type = SNMP_PDU_GET_REQ;
	pdu.request_id = 1;
	pdu.varbind_cnt = 0;
	memcpy(pdu.community, "public\0x", 8);
	pdu.community_len = 8;

	ASSERT_EQ(snmp_ber_encode_pdu(frame, sizeof(frame), &frame_len, &pdu), 0);
	ASSERT_EQ(snmp_agent_process_pdu(&agent, frame, frame_len, resp, sizeof(resp), &resp_len),
		  -EACCES);
	ASSERT_EQ(resp_len, 0);
	ASSERT_EQ(agent.counters.snmpInBadCommunityNames, 1);

	/* Prefix "pub" must not match either. */
	frame_len = 0;
	memcpy(pdu.community, "pub", 3);
	pdu.community_len = 3;
	ASSERT_EQ(snmp_ber_encode_pdu(frame, sizeof(frame), &frame_len, &pdu), 0);
	ASSERT_EQ(snmp_agent_process_pdu(&agent, frame, frame_len, resp, sizeof(resp), &resp_len),
		  -EACCES);
	ASSERT_EQ(agent.counters.snmpInBadCommunityNames, 2);

	/* Control: the exact community is still accepted. */
	frame_len = 0;
	memcpy(pdu.community, "public", 6);
	pdu.community_len = 6;
	ASSERT_EQ(snmp_ber_encode_pdu(frame, sizeof(frame), &frame_len, &pdu), 0);
	ASSERT_EQ(snmp_agent_process_pdu(&agent, frame, frame_len, resp, sizeof(resp), &resp_len),
		  0);
	ASSERT_GT(resp_len, 0);
}

/* ---- INFORM is acknowledged, not dispatched to the MIB ---- */

void test_inform_is_acknowledged_without_mib_dispatch(void)
{
	struct snmp_agent agent;
	struct snmp_pdu pdu;
	struct snmp_pdu resp_pdu;
	uint8_t frame[CONFIG_SNMP_MAX_PDU_SIZE];
	uint8_t resp[CONFIG_SNMP_MAX_PDU_SIZE];
	size_t frame_len = 0;
	size_t resp_len = 0;

	ASSERT_EQ(snmp_agent_init(&agent, NULL), 0);

	/*
	 * A v2c Inform carries the notification varbinds (sysUpTime.0 and
	 * snmpTrapOID.0). The receiver must echo them in a Response and must not try to
	 * resolve them against its own MIB: snmpTrapOID.0 is not a registered object, so
	 * a MIB dispatch would answer noSuchObject instead of acknowledging.
	 */
	memset(&pdu, 0, sizeof(pdu));
	pdu.version = 1; /* SNMPv2c */
	pdu.type = SNMP_PDU_INFORM_REQ;
	pdu.request_id = 4321;
	pdu.error_status = 0;
	pdu.error_index = 0;

	pdu.varbind_cnt = 2;
	pdu.varbinds[0].oid.len = 8;
	pdu.varbinds[0].oid.ids[0] = 1;
	pdu.varbinds[0].oid.ids[1] = 3;
	pdu.varbinds[0].oid.ids[2] = 6;
	pdu.varbinds[0].oid.ids[3] = 1;
	pdu.varbinds[0].oid.ids[4] = 2;
	pdu.varbinds[0].oid.ids[5] = 1;
	pdu.varbinds[0].oid.ids[6] = 1;
	pdu.varbinds[0].oid.ids[7] = 3;
	pdu.varbinds[0].type = SNMP_TAG_TIMETICKS;
	pdu.varbinds[0].val.uint_val = 123456;

	pdu.varbinds[1].oid.len = 10;
	pdu.varbinds[1].oid.ids[0] = 1;
	pdu.varbinds[1].oid.ids[1] = 3;
	pdu.varbinds[1].oid.ids[2] = 6;
	pdu.varbinds[1].oid.ids[3] = 1;
	pdu.varbinds[1].oid.ids[4] = 6;
	pdu.varbinds[1].oid.ids[5] = 3;
	pdu.varbinds[1].oid.ids[6] = 1;
	pdu.varbinds[1].oid.ids[7] = 1;
	pdu.varbinds[1].oid.ids[8] = 4;
	pdu.varbinds[1].oid.ids[9] = 1;
	pdu.varbinds[1].type = ASN1_TAG_OID;
	pdu.varbinds[1].val.oid.len = 10;
	memcpy(pdu.varbinds[1].val.oid.ids, pdu.varbinds[1].oid.ids, 10 * sizeof(uint32_t));

	memcpy(pdu.community, "public", 6);
	pdu.community_len = 6;

	ASSERT_EQ(snmp_ber_encode_pdu(frame, sizeof(frame), &frame_len, &pdu), 0);
	ASSERT_EQ(snmp_agent_process_pdu(&agent, frame, frame_len, resp, sizeof(resp), &resp_len),
		  0);
	ASSERT_GT(resp_len, 0);

	ASSERT_EQ(snmp_ber_decode_pdu(resp, resp_len, &resp_pdu), 0);
	ASSERT_EQ(resp_pdu.type, SNMP_PDU_GET_RESP);
	ASSERT_EQ(resp_pdu.request_id, 4321);
	ASSERT_EQ(resp_pdu.error_status, SNMP_ERR_NO_ERROR);
	ASSERT_EQ(resp_pdu.varbind_cnt, 2);
	ASSERT_EQ(resp_pdu.varbinds[0].type, SNMP_TAG_TIMETICKS);
	ASSERT_EQ(resp_pdu.varbinds[0].val.uint_val, 123456);
	ASSERT_EQ(resp_pdu.varbinds[1].type, ASN1_TAG_OID);
	ASSERT_EQ(agent.counters.snmpInTraps, 1);
}

/* ---- SNMPv1 notification parameters (RFC 2576 section 3.2) ---- */

static void make_oid(struct snmp_oid *oid, const uint32_t *ids, uint8_t len)
{
	oid->len = len;
	memcpy(oid->ids, ids, len * sizeof(uint32_t));
}

void test_v1_trap_parameters_from_trap_oid(void)
{
	struct snmp_pdu pdu;
	struct snmp_oid oid;
	static const uint32_t snmp_traps[] = {1, 3, 6, 1, 6, 3, 1, 1, 5};

	/* coldStart: generic-trap 0, enterprise = snmpTraps, specific-trap 0. */
	static const uint32_t cold_start[] = {1, 3, 6, 1, 6, 3, 1, 1, 5, 1};
	static const uint32_t auth_failure[] = {1, 3, 6, 1, 6, 3, 1, 1, 5, 5};

	memset(&pdu, 0, sizeof(pdu));
	make_oid(&oid, cold_start, ARRAY_SIZE(cold_start));
	snmp_v1_trap_parameters(&pdu, &oid);
	ASSERT_EQ(pdu.generic_trap, 0);
	ASSERT_EQ(pdu.specific_trap, 0);
	ASSERT_EQ(pdu.enterprise.len, ARRAY_SIZE(snmp_traps));
	ASSERT_EQ(memcmp(pdu.enterprise.ids, snmp_traps, sizeof(snmp_traps)), 0);

	memset(&pdu, 0, sizeof(pdu));
	make_oid(&oid, auth_failure, ARRAY_SIZE(auth_failure));
	snmp_v1_trap_parameters(&pdu, &oid);
	ASSERT_EQ(pdu.generic_trap, 4); /* authenticationFailure */

	/*
	 * SMIv1 TRAP-TYPE converted to SMIv2 has the shape <enterprise>.0.<specific>.
	 * RFC 2576 section 3.2(1) then requires dropping BOTH trailing arcs, and
	 * specific-trap keeps the last one, so appending it reconstructs the OID.
	 */
	static const uint32_t converted[] = {1, 3, 6, 1, 4, 1, 54321, 0, 7};

	memset(&pdu, 0, sizeof(pdu));
	make_oid(&oid, converted, ARRAY_SIZE(converted));
	snmp_v1_trap_parameters(&pdu, &oid);
	ASSERT_EQ(pdu.generic_trap, SNMP_TRAP_ENTERPRISESPEC);
	ASSERT_EQ(pdu.specific_trap, 7);
	ASSERT_EQ(pdu.enterprise.len, 7); /* 1.3.6.1.4.1.54321 */
	ASSERT_EQ(memcmp(pdu.enterprise.ids, converted, 7 * sizeof(uint32_t)), 0);

	/* A plain SMIv2 enterprise notification drops only the last arc. */
	static const uint32_t enterprise[] = {1, 3, 6, 1, 4, 1, 54321, 1, 1, 5, 0};

	memset(&pdu, 0, sizeof(pdu));
	make_oid(&oid, enterprise, ARRAY_SIZE(enterprise));
	snmp_v1_trap_parameters(&pdu, &oid);
	ASSERT_EQ(pdu.generic_trap, SNMP_TRAP_ENTERPRISESPEC);
	ASSERT_EQ(pdu.specific_trap, 0);
	ASSERT_EQ(pdu.enterprise.len, 10);

	/* Degenerate OID: no crash, no illegal one-arc enterprise. */
	static const uint32_t single[] = {5};

	memset(&pdu, 0, sizeof(pdu));
	make_oid(&oid, single, ARRAY_SIZE(single));
	snmp_v1_trap_parameters(&pdu, &oid);
	ASSERT_EQ(pdu.generic_trap, SNMP_TRAP_ENTERPRISESPEC);
	ASSERT_EQ(pdu.specific_trap, 0);
	ASSERT_EQ(pdu.enterprise.len, 1);
}
