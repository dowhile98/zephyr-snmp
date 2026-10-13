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

#ifndef CONFIG_SNMP_COMMUNITY_READ
#define CONFIG_SNMP_COMMUNITY_READ "public"
#endif

#ifndef CONFIG_SNMP_COMMUNITY_WRITE
#define CONFIG_SNMP_COMMUNITY_WRITE "private"
#endif

static struct snmp_agent_inst g_default_agent = {
	.read_community = CONFIG_SNMP_COMMUNITY_READ,
	.write_community = CONFIG_SNMP_COMMUNITY_WRITE,
	.port = 161,
	.sock_v4 = -1,
	.sock_v6 = -1,
	.counters = {
		.snmpEnableAuthenTraps = 1,
	},
	.sys_descr = "Zephyr SNMP Agent",
	.sys_contact = "admin@example.com",
	.sys_name = "zephyr-node",
	.sys_location = "Server Room",
	.sys_object_id = {
		.len = 7,
		.ids = {1, 3, 6, 1, 4, 1, 0},
	},
};

static bool g_default_agent_inited = false;

struct snmp_agent_inst *snmp_agent_get_default(void)
{
	if (!g_default_agent_inited) {
		g_default_agent_inited = true;
		k_mutex_init(&g_default_agent.mib_lock);
		snmp_mib_init_inst(&g_default_agent);
		snmp_mib_register_defaults_inst(&g_default_agent);
#if defined(CONFIG_SNMP_VERSION_3)
		snmp_usm_init_inst(&g_default_agent);
		snmp_vacm_init_inst(&g_default_agent);
#endif
	}
	return &g_default_agent;
}

#define INST_COUNTER_INC(inst, field) do { \
	snmp_counter_inc(&(inst)->counters.field); \
	if ((inst) == &g_default_agent) { \
		snmp_counter_inc(&g_snmp_counters.field); \
	} \
} while (0)

int snmp_agent_inst_init(struct snmp_agent_inst *inst)
{
	if (!inst) {
		return -EINVAL;
	}

	memset(inst, 0, sizeof(*inst));
	k_mutex_init(&inst->mib_lock);

	strncpy(inst->read_community, CONFIG_SNMP_COMMUNITY_READ, sizeof(inst->read_community) - 1);
	inst->read_community[sizeof(inst->read_community) - 1] = '\0';
	strncpy(inst->write_community, CONFIG_SNMP_COMMUNITY_WRITE, sizeof(inst->write_community) - 1);
	inst->write_community[sizeof(inst->write_community) - 1] = '\0';

	inst->port = 161;
	inst->sock_v4 = -1;
	inst->sock_v6 = -1;
	inst->counters.snmpEnableAuthenTraps = 1;

	strncpy(inst->sys_descr, "Zephyr SNMP Agent", sizeof(inst->sys_descr) - 1);
	strncpy(inst->sys_contact, "admin@example.com", sizeof(inst->sys_contact) - 1);
	strncpy(inst->sys_name, "zephyr-node", sizeof(inst->sys_name) - 1);
	strncpy(inst->sys_location, "Server Room", sizeof(inst->sys_location) - 1);
	inst->sys_object_id.len = 7;
	inst->sys_object_id.ids[0] = 1;
	inst->sys_object_id.ids[1] = 3;
	inst->sys_object_id.ids[2] = 6;
	inst->sys_object_id.ids[3] = 1;
	inst->sys_object_id.ids[4] = 4;
	inst->sys_object_id.ids[5] = 1;
	inst->sys_object_id.ids[6] = 0;

	snmp_mib_init_inst(inst);
	snmp_mib_register_defaults_inst(inst);

#if defined(CONFIG_SNMP_VERSION_3)
	snmp_usm_init_inst(inst);
	snmp_vacm_init_inst(inst);
#endif

	return 0;
}

int snmp_agent_inst_set_read_community(struct snmp_agent_inst *inst, const char *community)
{
	if (!inst || !community || strlen(community) >= sizeof(inst->read_community)) {
		return -EINVAL;
	}
	strncpy(inst->read_community, community, sizeof(inst->read_community) - 1);
	inst->read_community[sizeof(inst->read_community) - 1] = '\0';
	return 0;
}

int snmp_agent_inst_set_write_community(struct snmp_agent_inst *inst, const char *community)
{
	if (!inst || !community || strlen(community) >= sizeof(inst->write_community)) {
		return -EINVAL;
	}
	strncpy(inst->write_community, community, sizeof(inst->write_community) - 1);
	inst->write_community[sizeof(inst->write_community) - 1] = '\0';
	return 0;
}

int snmp_set_read_community(const char *community)
{
	return snmp_agent_inst_set_read_community(&g_default_agent, community);
}

int snmp_set_write_community(const char *community)
{
	return snmp_agent_inst_set_write_community(&g_default_agent, community);
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

static int process_v1v2c(struct snmp_agent_inst *inst,
			 const uint8_t *req_buf, size_t req_len,
			 uint8_t *resp_buf, size_t max_resp_len,
			 size_t *out_resp_len)
{
	*out_resp_len = 0;

	memset(&inst->current_pdu, 0, sizeof(inst->current_pdu));
	int ret = snmp_ber_decode_pdu(req_buf, req_len, &inst->current_pdu);
	if (ret < 0) {
		INST_COUNTER_INC(inst, snmpInASNParseErrs);
		return ret;
	}

	/* Version validation */
	if (inst->current_pdu.version == 0) {
#ifndef CONFIG_SNMP_VERSION_1
		INST_COUNTER_INC(inst, snmpInBadVersions);
		return -ENOTSUP;
#endif
		if (inst->current_pdu.type == SNMP_PDU_GET_BULK_REQ) {
			INST_COUNTER_INC(inst, snmpInBadVersions);
			return -ENOTSUP;
		}
	} else if (inst->current_pdu.version == 1) {
#ifndef CONFIG_SNMP_VERSION_2C
		INST_COUNTER_INC(inst, snmpInBadVersions);
		return -ENOTSUP;
#endif
	} else {
		INST_COUNTER_INC(inst, snmpInBadVersions);
		return -ENOTSUP;
	}

	/* Community / Security validation */
	bool is_write = (inst->current_pdu.type == SNMP_PDU_SET_REQ);

	if (is_write) {
		if (strcmp((const char *)inst->current_pdu.community, inst->write_community) != 0) {
			if (strcmp((const char *)inst->current_pdu.community, inst->read_community) == 0) {
				INST_COUNTER_INC(inst, snmpInBadCommunityUses);
			} else {
				INST_COUNTER_INC(inst, snmpInBadCommunityNames);
			}
#if defined(CONFIG_SNMP_TRAP_ENABLED)
			snmp_trap_send_auth_failure_inst(inst);
#endif
			return -EACCES;
		}
	} else {
		/* GET / GETNEXT / GETBULK accepts read community or write community */
		if (strcmp((const char *)inst->current_pdu.community, inst->read_community) != 0 &&
		    strcmp((const char *)inst->current_pdu.community, inst->write_community) != 0) {
			INST_COUNTER_INC(inst, snmpInBadCommunityNames);
#if defined(CONFIG_SNMP_TRAP_ENABLED)
			snmp_trap_send_auth_failure_inst(inst);
#endif
			return -EACCES;
		}
	}

	/* Dispatch to MIB engine with instance context */
	ret = snmp_mib_dispatch_inst(inst, &inst->current_pdu);
	if (ret < 0) {
		return ret;
	}

	/* Encode response PDU */
	size_t encoded_len = 0;
	ret = snmp_ber_encode_pdu(resp_buf, max_resp_len, &encoded_len, &inst->current_pdu);
	if (ret < 0) {
		if (ret == -ENOBUFS) {
			INST_COUNTER_INC(inst, snmpOutTooBigs);
		}
		return ret;
	}

	*out_resp_len = encoded_len;
	INST_COUNTER_INC(inst, snmpOutPkts);
	return 0;
}

/* ---- v3 processing ---- */

#if defined(CONFIG_SNMP_VERSION_3)

static int process_v3(struct snmp_agent_inst *inst,
		      const uint8_t *req_buf, size_t req_len,
		      uint8_t *resp_buf, size_t max_resp_len,
		      size_t *out_resp_len)
{
	*out_resp_len = 0;

	struct snmp_v3_msg msg;
	int ret = snmp_ber_decode_v3_msg(req_buf, req_len, &msg);
	if (ret < 0) {
		INST_COUNTER_INC(inst, snmpInASNParseErrs);
		return ret;
	}

	/* USM verify */
	ret = snmp_usm_verify_incoming_inst(inst, &msg, req_buf, req_len);
	if (ret < 0) {
		if (ret == -EACCES) {
			INST_COUNTER_INC(inst, snmpSilentDrops);
		}
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
		if (snmp_usm_get_engine_id_inst(inst, msg.scoped.context_engine_id, &eng_len) == 0) {
			msg.scoped.context_engine_id_len = eng_len;
		}
		msg.scoped.context_name_len = 0;

		ret = snmp_usm_build_outgoing_inst(inst, &msg);
		if (ret < 0) {
			return ret;
		}

		size_t encoded_len = 0;
		ret = snmp_ber_encode_v3_msg(resp_buf, max_resp_len, &encoded_len, &msg);
		if (ret < 0) {
			return ret;
		}

		*out_resp_len = encoded_len;
		INST_COUNTER_INC(inst, snmpOutPkts);
		return 0;
	}

	/* VACM access check per RFC 3415 */
	int sec_level = SNMP_SEC_LEVEL_NOAUTH_NOPRIV;
	if (msg.global.msg_flags & 0x02) {
		sec_level = SNMP_SEC_LEVEL_AUTH_PRIV;
	} else if (msg.global.msg_flags & 0x01) {
		sec_level = SNMP_SEC_LEVEL_AUTH_NOPRIV;
	}
	int access_type = (msg.scoped.pdu.type == SNMP_PDU_SET_REQ) ?
			  SNMP_VACM_ACCESS_WRITE : SNMP_VACM_ACCESS_READ;

	char user_name[sizeof(msg.usm.user_name) + 1];
	size_t name_len = msg.usm.user_name_len < sizeof(msg.usm.user_name)
			  ? msg.usm.user_name_len : sizeof(msg.usm.user_name);
	memcpy(user_name, msg.usm.user_name, name_len);
	user_name[name_len] = '\0';

	if (msg.scoped.pdu.varbind_cnt == 0) {
		ret = snmp_vacm_check_access_ex_inst(inst, (const char *)msg.scoped.context_name,
						     msg.global.msg_security_model,
						     user_name, sec_level, access_type, NULL);
		if (ret < 0) {
			INST_COUNTER_INC(inst, snmpSilentDrops);
			return ret;
		}
	} else {
		for (size_t i = 0; i < msg.scoped.pdu.varbind_cnt; i++) {
			ret = snmp_vacm_check_access_ex_inst(inst, (const char *)msg.scoped.context_name,
							     msg.global.msg_security_model,
							     user_name, sec_level, access_type,
							     &msg.scoped.pdu.varbinds[i].oid);
			if (ret < 0) {
				INST_COUNTER_INC(inst, snmpSilentDrops);
				return ret;
			}
		}
	}

	/* Dispatch to MIB */
	ret = snmp_mib_dispatch_inst(inst, &msg.scoped.pdu);
	if (ret < 0) {
		return ret;
	}

	/* Set response metadata (RFC 3412 §7.1: echo request's contextEngineID and contextName) */
	msg.global.msg_max_size       = 1500;
	msg.global.msg_security_model = 3;

	/* Build outgoing USM */
	ret = snmp_usm_build_outgoing_inst(inst, &msg);
	if (ret < 0) {
		return ret;
	}

	/* Encode */
	size_t encoded_len = 0;
	ret = snmp_ber_encode_v3_msg(resp_buf, max_resp_len, &encoded_len, &msg);
	if (ret < 0) {
		if (ret == -ENOBUFS) {
			INST_COUNTER_INC(inst, snmpOutTooBigs);
		}
		return ret;
	}

	*out_resp_len = encoded_len;
	INST_COUNTER_INC(inst, snmpOutPkts);
	return 0;
}

#endif /* CONFIG_SNMP_VERSION_3 */

/* ---- Main entry points ---- */

int snmp_agent_inst_process_pdu(struct snmp_agent_inst *inst,
				const uint8_t *req_buf, size_t req_len,
				uint8_t *resp_buf, size_t max_resp_len,
				size_t *out_resp_len)
{
	if (!inst || !req_buf || !resp_buf || !out_resp_len) {
		return -EINVAL;
	}

	*out_resp_len = 0;
	INST_COUNTER_INC(inst, snmpInPkts);

	int version = snmp_detect_version(req_buf, req_len);

	switch (version) {
	case 0:
	case 1:
		return process_v1v2c(inst, req_buf, req_len, resp_buf, max_resp_len, out_resp_len);
	case 3:
#if defined(CONFIG_SNMP_VERSION_3)
		return process_v3(inst, req_buf, req_len, resp_buf, max_resp_len, out_resp_len);
#else
		INST_COUNTER_INC(inst, snmpInBadVersions);
		return -ENOTSUP;
#endif
	default:
		INST_COUNTER_INC(inst, snmpInBadVersions);
		return -ENOTSUP;
	}
}

int snmp_core_process_pdu(const uint8_t *req_buf, size_t req_len,
			  uint8_t *resp_buf, size_t max_resp_len,
			  size_t *out_resp_len)
{
	return snmp_agent_inst_process_pdu(&g_default_agent, req_buf, req_len,
					   resp_buf, max_resp_len, out_resp_len);
}

#endif /* CONFIG_SNMP_AGENT */
