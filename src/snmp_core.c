/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 *
 * SNMP core dispatcher — routes v1/v2c and v3 messages, handles version
 * validation, community/USM security, MIB dispatch, and response encoding.
 */

#include <snmp/snmp_core.h>
#include <snmp/snmp_trap.h>
#include <snmp/snmp_mib.h>
#include <zephyr/sys/atomic.h>
#include <string.h>
#include <errno.h>

#ifdef CONFIG_SNMP_AGENT

#if defined(CONFIG_SNMP_VERSION_3)
#include <snmp/snmp_usm.h>
#include <snmp/snmp_vacm.h>
#endif

static char g_read_community[64]  = "public";
static char g_write_community[64] = "private";

int snmp_set_read_community(const char *community)
{
	if (!community || strlen(community) >= sizeof(g_read_community))
		return -EINVAL;
	strncpy(g_read_community, community, sizeof(g_read_community) - 1);
	g_read_community[sizeof(g_read_community) - 1] = '\0';
	return 0;
}

int snmp_set_write_community(const char *community)
{
	if (!community || strlen(community) >= sizeof(g_write_community))
		return -EINVAL;
	strncpy(g_write_community, community, sizeof(g_write_community) - 1);
	g_write_community[sizeof(g_write_community) - 1] = '\0';
	return 0;
}

/* ---- Detect SNMP version from raw buffer ---- */

static int snmp_detect_version(const uint8_t *buf, size_t buf_len)
{
	size_t off = 0;
	uint8_t tag;
	size_t seq_len;

	int ret = snmp_ber_decode_header(buf, buf_len, &off, &tag, &seq_len);
	if (ret < 0 || tag != ASN1_TAG_SEQUENCE)
		return -1;

	int32_t version = 0;
	ret = snmp_ber_decode_int(buf, buf_len, &off, &version);
	if (ret < 0)
		return -1;

	return version;
}

/* ---- v1 / v2c processing ---- */

static struct snmp_pdu g_core_pdu;

static int process_v1v2c(const uint8_t *req_buf, size_t req_len,
			 uint8_t *resp_buf, size_t max_resp_len,
			 size_t *out_resp_len)
{
	*out_resp_len = 0;

	memset(&g_core_pdu, 0, sizeof(g_core_pdu));
	int ret = snmp_ber_decode_pdu(req_buf, req_len, &g_core_pdu);
	if (ret < 0) {
		snmp_counter_inc(&g_snmp_counters.snmpInASNParseErrs);
		return ret;
	}

	/* Version validation */
	if (g_core_pdu.version == 0) {
#ifndef CONFIG_SNMP_VERSION_1
		snmp_counter_inc(&g_snmp_counters.snmpInBadVersions);
		return -ENOTSUP;
#endif
		if (g_core_pdu.type == SNMP_PDU_GET_BULK_REQ) {
			snmp_counter_inc(&g_snmp_counters.snmpInBadVersions);
			return -ENOTSUP;
		}
	} else if (g_core_pdu.version == 1) {
#ifndef CONFIG_SNMP_VERSION_2C
		snmp_counter_inc(&g_snmp_counters.snmpInBadVersions);
		return -ENOTSUP;
#endif
	} else {
		snmp_counter_inc(&g_snmp_counters.snmpInBadVersions);
		return -ENOTSUP;
	}

	/* Community / Security validation */
	bool is_write = (g_core_pdu.type == SNMP_PDU_SET_REQ);

	if (is_write) {
		if (strcmp((const char *)g_core_pdu.community, g_write_community) != 0) {
			if (strcmp((const char *)g_core_pdu.community, g_read_community) == 0) {
				snmp_counter_inc(&g_snmp_counters.snmpInBadCommunityUses);
			} else {
				snmp_counter_inc(&g_snmp_counters.snmpInBadCommunityNames);
			}
#if defined(CONFIG_SNMP_TRAP_ENABLED)
			snmp_trap_send_auth_failure();
#endif
			return -EACCES;
		}
	} else {
		/* GET / GETNEXT / GETBULK acepta la community de lectura (public) o escritura (private) */
		if (strcmp((const char *)g_core_pdu.community, g_read_community) != 0 &&
		    strcmp((const char *)g_core_pdu.community, g_write_community) != 0) {
			snmp_counter_inc(&g_snmp_counters.snmpInBadCommunityNames);
#if defined(CONFIG_SNMP_TRAP_ENABLED)
			snmp_trap_send_auth_failure();
#endif
			return -EACCES;
		}
	}


	/* Dispatch to MIB engine */
	ret = snmp_mib_dispatch(&g_core_pdu);
	if (ret < 0) return ret;

	/* Encode response PDU */
	size_t encoded_len = 0;
	ret = snmp_ber_encode_pdu(resp_buf, max_resp_len, &encoded_len, &g_core_pdu);
	if (ret < 0) {
		if (ret == -ENOBUFS) {
			snmp_counter_inc(&g_snmp_counters.snmpOutTooBigs);
		}
		return ret;
	}

	*out_resp_len = encoded_len;
	snmp_counter_inc(&g_snmp_counters.snmpOutPkts);
	return 0;
}

/* ---- v3 processing ---- */

#if defined(CONFIG_SNMP_VERSION_3)

static int process_v3(const uint8_t *req_buf, size_t req_len,
		      uint8_t *resp_buf, size_t max_resp_len,
		      size_t *out_resp_len)
{
	*out_resp_len = 0;

	struct snmp_v3_msg msg;
	int ret = snmp_ber_decode_v3_msg(req_buf, req_len, &msg);
	if (ret < 0) {
		snmp_counter_inc(&g_snmp_counters.snmpInASNParseErrs);
		return ret;
	}

	/* USM verify */
	ret = snmp_usm_verify_incoming(&msg, req_buf, req_len);
	if (ret < 0) {
		if (ret == -EACCES)
			snmp_counter_inc(&g_snmp_counters.snmpSilentDrops);
		return ret;
	}

	/* Engine discovery: if USM returned a Report-PDU, encode and send */
	if (msg.scoped.pdu.type == SNMP_PDU_REPORT) {
		/* Echo incoming msg_id as the Report-PDU request_id */
		msg.scoped.pdu.request_id = msg.global.msg_id;

		/* RFC 3414 §7: Report-PDUs must include a counter varbind */
		static const uint32_t unknown_engine_oid[] = {1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0}; /* snmpUnknownEngineIDs.0 */
		msg.scoped.pdu.varbinds[0].oid.len = 11;
		memcpy(msg.scoped.pdu.varbinds[0].oid.ids, unknown_engine_oid, sizeof(unknown_engine_oid));
		msg.scoped.pdu.varbinds[0].type = SNMP_TAG_COUNTER32;
		msg.scoped.pdu.varbinds[0].val.uint_val = 0;
		msg.scoped.pdu.varbind_cnt = 1;

		msg.global.msg_max_size = CONFIG_SNMP_MAX_PDU_SIZE;
		msg.global.msg_security_model = 3;
		uint8_t eng_len = sizeof(msg.scoped.context_engine_id);
		if (snmp_usm_get_engine_id(msg.scoped.context_engine_id, &eng_len) == 0) {
			msg.scoped.context_engine_id_len = eng_len;
		}
		msg.scoped.context_name_len = 0;

		ret = snmp_usm_build_outgoing(&msg);
		if (ret < 0)
			return ret;

		size_t encoded_len = 0;
		ret = snmp_ber_encode_v3_msg(resp_buf, max_resp_len, &encoded_len, &msg);
		if (ret < 0)
			return ret;

		*out_resp_len = encoded_len;
		snmp_counter_inc(&g_snmp_counters.snmpOutPkts);
		return 0;
	}

	/* VACM access check */
	bool is_write = (msg.scoped.pdu.type == SNMP_PDU_SET_REQ);
	ret = snmp_vacm_check_access(&msg, is_write);
	if (ret < 0) {
		snmp_counter_inc(&g_snmp_counters.snmpSilentDrops);
		return ret;
	}

	/* Dispatch to MIB */
	ret = snmp_mib_dispatch(&msg.scoped.pdu);
	if (ret < 0)
		return ret;

	/* Set response metadata */
	msg.global.msg_max_size       = 1500;
	msg.global.msg_security_model = 3;
	msg.scoped.context_engine_id_len = 0;
	msg.scoped.context_name_len      = 0;

	/* Build outgoing USM */
	ret = snmp_usm_build_outgoing(&msg);
	if (ret < 0)
		return ret;

	/* Encode */
	size_t encoded_len = 0;
	ret = snmp_ber_encode_v3_msg(resp_buf, max_resp_len, &encoded_len, &msg);
	if (ret < 0) {
		if (ret == -ENOBUFS)
			snmp_counter_inc(&g_snmp_counters.snmpOutTooBigs);
		return ret;
	}

	*out_resp_len = encoded_len;
	snmp_counter_inc(&g_snmp_counters.snmpOutPkts);
	return 0;
}

#endif /* CONFIG_SNMP_VERSION_3 */

/* ---- Main entry point ---- */

int snmp_core_process_pdu(const uint8_t *req_buf, size_t req_len,
			  uint8_t *resp_buf, size_t max_resp_len,
			  size_t *out_resp_len)
{
	if (!req_buf || !resp_buf || !out_resp_len)
		return -EINVAL;

	*out_resp_len = 0;
	snmp_counter_inc(&g_snmp_counters.snmpInPkts);

	int version = snmp_detect_version(req_buf, req_len);

	switch (version) {
	case 0:
	case 1:
		return process_v1v2c(req_buf, req_len, resp_buf, max_resp_len, out_resp_len);
	case 3:
#if defined(CONFIG_SNMP_VERSION_3)
		return process_v3(req_buf, req_len, resp_buf, max_resp_len, out_resp_len);
#else
		snmp_counter_inc(&g_snmp_counters.snmpInBadVersions);
		return -ENOTSUP;
#endif
	default:
		snmp_counter_inc(&g_snmp_counters.snmpInBadVersions);
		return -ENOTSUP;
	}
}

#endif /* CONFIG_SNMP_AGENT */
