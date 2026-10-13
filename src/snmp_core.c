/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 *
 * SNMP core dispatcher — routes v1/v2c and v3 messages, handles version
 * validation, community/USM security, MIB dispatch, and response encoding.
 *
 * This file also owns the instance lifecycle (snmp_agent_inst_init(),
 * snmp_agent_deinit()) documented in include/snmp/snmp_core.h.
 */

#include <snmp/snmp_core.h>
#include <snmp/snmp_trap.h>
#include <snmp/snmp_mib.h>
#include "snmp_internal.h"
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

#ifndef CONFIG_SNMP_AGENT_PORT
#define CONFIG_SNMP_AGENT_PORT 161
#endif

#ifndef CONFIG_SNMP_V3_ENGINE_BOOTS
#define CONFIG_SNMP_V3_ENGINE_BOOTS 1
#endif

#ifdef CONFIG_SNMP_RATE_LIMIT
#ifndef CONFIG_SNMP_RATE_LIMIT_BURST
#define CONFIG_SNMP_RATE_LIMIT_BURST 5
#endif
#endif

/*
 * Legacy facade storage. Removed in sub-phase 8c together with
 * snmp_agent_get_default() and every no-parameter entry point.
 */
static struct snmp_agent g_default_agent;
static bool g_default_agent_inited;

struct snmp_agent *snmp_agent_get_default(void)
{
	if (!g_default_agent_inited) {
		g_default_agent_inited = true;
		snmp_agent_inst_init(&g_default_agent, NULL);
	}
	return &g_default_agent;
}

#define INST_COUNTER_INC(inst, field) snmp_counter_inc(&(inst)->counters.field)

/* Copy a bounded string, always NUL-terminating. */
static void copy_str(char *dst, size_t dst_sz, const char *src)
{
	strncpy(dst, src, dst_sz - 1);
	dst[dst_sz - 1] = '\0';
}

static void set_defaults(struct snmp_agent *agent)
{
	copy_str(agent->read_community, sizeof(agent->read_community), CONFIG_SNMP_COMMUNITY_READ);
	copy_str(agent->write_community, sizeof(agent->write_community),
		 CONFIG_SNMP_COMMUNITY_WRITE);

	agent->port = CONFIG_SNMP_AGENT_PORT;
	agent->sock_v4 = -1;
	agent->sock_v6 = -1;
	agent->bound_iface = NULL;
	agent->svc_slot = SNMP_SLOT_NONE;

	agent->counters.snmpEnableAuthenTraps = 1;

	copy_str(agent->sys_descr, sizeof(agent->sys_descr), "Zephyr SNMP Agent");
	copy_str(agent->sys_contact, sizeof(agent->sys_contact), "admin@example.com");
	copy_str(agent->sys_name, sizeof(agent->sys_name), "zephyr-node");
	copy_str(agent->sys_location, sizeof(agent->sys_location), "Server Room");

	agent->sys_object_id.len = 7;
	agent->sys_object_id.ids[0] = 1;
	agent->sys_object_id.ids[1] = 3;
	agent->sys_object_id.ids[2] = 6;
	agent->sys_object_id.ids[3] = 1;
	agent->sys_object_id.ids[4] = 4;
	agent->sys_object_id.ids[5] = 1;
	agent->sys_object_id.ids[6] = 0;
}

int snmp_agent_inst_init(struct snmp_agent *agent, const struct snmp_agent_cfg *cfg)
{
	if (!agent) {
		return -EINVAL;
	}

	memset(agent, 0, sizeof(*agent));
	k_mutex_init(&agent->lock);

	set_defaults(agent);

#ifdef CONFIG_SNMP_RATE_LIMIT
	agent->rate_tokens = CONFIG_SNMP_RATE_LIMIT_BURST;
	agent->rate_last_refill = k_uptime_get();
#endif

	if (cfg) {
		if (cfg->port != 0) {
			agent->port = cfg->port;
		}
		agent->bound_iface = cfg->iface;
		if (cfg->read_community != NULL) {
			copy_str(agent->read_community, sizeof(agent->read_community),
				 cfg->read_community);
		}
		if (cfg->write_community != NULL) {
			copy_str(agent->write_community, sizeof(agent->write_community),
				 cfg->write_community);
		}
		if (cfg->sys_descr != NULL) {
			copy_str(agent->sys_descr, sizeof(agent->sys_descr), cfg->sys_descr);
		}
		if (cfg->sys_contact != NULL) {
			copy_str(agent->sys_contact, sizeof(agent->sys_contact), cfg->sys_contact);
		}
		if (cfg->sys_name != NULL) {
			copy_str(agent->sys_name, sizeof(agent->sys_name), cfg->sys_name);
		}
		if (cfg->sys_location != NULL) {
			copy_str(agent->sys_location, sizeof(agent->sys_location),
				 cfg->sys_location);
		}
		if (cfg->sys_object_id != NULL && cfg->sys_object_id->len > 0 &&
		    cfg->sys_object_id->len <= CONFIG_SNMP_MAX_OID_LEN) {
			agent->sys_object_id = *cfg->sys_object_id;
		}
		agent->user_data = (void *)cfg->user_data;
	}

	/* MIB tree: always fresh on init (defaults are instance-scoped). */
	snmp_mib_init(agent);
	snmp_mib_register_defaults(agent);

#if defined(CONFIG_SNMP_VERSION_3)
	if (cfg) {
		if (cfg->engine_id != NULL && cfg->engine_id_len > 0 &&
		    cfg->engine_id_len <= sizeof(agent->engine_id)) {
			memcpy(agent->engine_id, cfg->engine_id, cfg->engine_id_len);
			agent->engine_id_len = cfg->engine_id_len;
		}
		if (cfg->engine_boots != 0) {
			agent->engine_boots = cfg->engine_boots;
		}
		agent->settings_prefix = cfg->settings_prefix;
	}
	snmp_usm_init(agent);
	snmp_vacm_init(agent);

	/* Contract 3.7 call order: defaults -> cfg.engine_boots -> persisted override. */
	if (agent->settings_prefix != NULL) {
		(void)snmp_agent_load_engine_boots(agent);
	}
#endif

	agent->state = SNMP_AGENT_INITIALIZED;
	return 0;
}

int snmp_agent_deinit(struct snmp_agent *agent)
{
	if (!agent) {
		return -EINVAL;
	}
	if (agent->state == SNMP_AGENT_UNINIT) {
		return -EPERM;
	}

	/*
	 * TODO(8b): snmp_agent_stop() the transport first. Until the per-instance
	 * adapter lands, deinit() only resets the domain state.
	 */

	k_mutex_lock(&agent->lock, K_FOREVER);

	agent->state = SNMP_AGENT_STOPPED;

	set_defaults(agent);
	memset(&agent->counters, 0, sizeof(agent->counters));
	agent->counters.snmpEnableAuthenTraps = 1;

	snmp_mib_init(agent);
	snmp_mib_register_defaults(agent);

#if defined(CONFIG_SNMP_VERSION_3)
	/* Drop credentials/access tables, keep this engine's identity. */
	memset(agent->users, 0, sizeof(agent->users));
	agent->user_cnt = 0;
	memset(agent->contexts, 0, sizeof(agent->contexts));
	agent->context_cnt = 0;
	memset(agent->groups, 0, sizeof(agent->groups));
	agent->group_cnt = 0;
	memset(agent->access_rules, 0, sizeof(agent->access_rules));
	agent->access_rule_cnt = 0;
	memset(agent->views, 0, sizeof(agent->views));
	agent->view_cnt = 0;
	snmp_usm_init(agent);
	snmp_vacm_init(agent);
#endif

	agent->state = SNMP_AGENT_INITIALIZED;

	k_mutex_unlock(&agent->lock);
	return 0;
}

int snmp_agent_set_read_community(struct snmp_agent *agent, const char *community)
{
	if (!agent || !community || strlen(community) >= sizeof(agent->read_community)) {
		return -EINVAL;
	}
	if (agent->state == SNMP_AGENT_UNINIT) {
		return -EPERM;
	}
	k_mutex_lock(&agent->lock, K_FOREVER);
	copy_str(agent->read_community, sizeof(agent->read_community), community);
	k_mutex_unlock(&agent->lock);
	return 0;
}

int snmp_agent_set_write_community(struct snmp_agent *agent, const char *community)
{
	if (!agent || !community || strlen(community) >= sizeof(agent->write_community)) {
		return -EINVAL;
	}
	if (agent->state == SNMP_AGENT_UNINIT) {
		return -EPERM;
	}
	k_mutex_lock(&agent->lock, K_FOREVER);
	copy_str(agent->write_community, sizeof(agent->write_community), community);
	k_mutex_unlock(&agent->lock);
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

static int process_v1v2c(struct snmp_agent *agent, const uint8_t *req_buf, size_t req_len,
			 uint8_t *resp_buf, size_t max_resp_len, size_t *out_resp_len)
{
	*out_resp_len = 0;

	memset(&agent->current_pdu, 0, sizeof(agent->current_pdu));
	int ret = snmp_ber_decode_pdu(req_buf, req_len, &agent->current_pdu);
	if (ret < 0) {
		INST_COUNTER_INC(agent, snmpInASNParseErrs);
		return ret;
	}

	/* Version validation */
	if (agent->current_pdu.version == 0) {
#ifndef CONFIG_SNMP_VERSION_1
		INST_COUNTER_INC(agent, snmpInBadVersions);
		return -ENOTSUP;
#endif
		if (agent->current_pdu.type == SNMP_PDU_GET_BULK_REQ) {
			INST_COUNTER_INC(agent, snmpInBadVersions);
			return -ENOTSUP;
		}
	} else if (agent->current_pdu.version == 1) {
#ifndef CONFIG_SNMP_VERSION_2C
		INST_COUNTER_INC(agent, snmpInBadVersions);
		return -ENOTSUP;
#endif
	} else {
		INST_COUNTER_INC(agent, snmpInBadVersions);
		return -ENOTSUP;
	}

	/* Community / Security validation */
	bool is_write = (agent->current_pdu.type == SNMP_PDU_SET_REQ);

	if (is_write) {
		if (strcmp((const char *)agent->current_pdu.community, agent->write_community) !=
		    0) {
			if (strcmp((const char *)agent->current_pdu.community,
				   agent->read_community) == 0) {
				INST_COUNTER_INC(agent, snmpInBadCommunityUses);
			} else {
				INST_COUNTER_INC(agent, snmpInBadCommunityNames);
			}
#if defined(CONFIG_SNMP_TRAP_ENABLED)
			snmp_trap_send_auth_failure(agent);
#endif
			return -EACCES;
		}
	} else {
		/* GET / GETNEXT / GETBULK accepts read community or write community */
		if (strcmp((const char *)agent->current_pdu.community, agent->read_community) !=
			0 &&
		    strcmp((const char *)agent->current_pdu.community, agent->write_community) !=
			0) {
			INST_COUNTER_INC(agent, snmpInBadCommunityNames);
#if defined(CONFIG_SNMP_TRAP_ENABLED)
			snmp_trap_send_auth_failure(agent);
#endif
			return -EACCES;
		}
	}

	/* Dispatch to MIB engine with instance context */
	ret = snmp_mib_dispatch(agent, &agent->current_pdu);
	if (ret < 0) {
		return ret;
	}

	/* Encode response PDU */
	size_t encoded_len = 0;
	ret = snmp_ber_encode_pdu(resp_buf, max_resp_len, &encoded_len, &agent->current_pdu);
	if (ret < 0) {
		if (ret == -ENOBUFS) {
			INST_COUNTER_INC(agent, snmpOutTooBigs);
		}
		return ret;
	}

	*out_resp_len = encoded_len;
	INST_COUNTER_INC(agent, snmpOutPkts);
	return 0;
}

/* ---- v3 processing ---- */

#if defined(CONFIG_SNMP_VERSION_3)

static int process_v3(struct snmp_agent *agent, const uint8_t *req_buf, size_t req_len,
		      uint8_t *resp_buf, size_t max_resp_len, size_t *out_resp_len)
{
	*out_resp_len = 0;

	struct snmp_v3_msg msg;
	int ret = snmp_ber_decode_v3_msg(req_buf, req_len, &msg);
	if (ret < 0) {
		INST_COUNTER_INC(agent, snmpInASNParseErrs);
		return ret;
	}

	/* USM verify */
	ret = snmp_usm_verify_incoming(agent, &msg, req_buf, req_len);
	if (ret < 0) {
		if (ret == -EACCES) {
			INST_COUNTER_INC(agent, snmpSilentDrops);
		}
		return ret;
	}

	/* Engine discovery: if USM returned a Report-PDU, encode and send */
	if (msg.scoped.pdu.type == SNMP_PDU_REPORT) {
		/* Echo incoming msg_id as the Report-PDU request_id */
		msg.scoped.pdu.request_id = msg.global.msg_id;

		/* RFC 3414 §7: Report-PDUs must include a counter varbind */
		static const uint32_t unknown_engine_oid[] = {
		    1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0}; /* snmpUnknownEngineIDs.0 */
		msg.scoped.pdu.varbinds[0].oid.len = 11;
		memcpy(msg.scoped.pdu.varbinds[0].oid.ids, unknown_engine_oid,
		       sizeof(unknown_engine_oid));
		msg.scoped.pdu.varbinds[0].type = SNMP_TAG_COUNTER32;
		msg.scoped.pdu.varbinds[0].val.uint_val = 0;
		msg.scoped.pdu.varbind_cnt = 1;

		msg.global.msg_max_size = CONFIG_SNMP_MAX_PDU_SIZE;
		msg.global.msg_security_model = 3;
		uint8_t eng_len = sizeof(msg.scoped.context_engine_id);
		if (snmp_usm_get_engine_id(agent, msg.scoped.context_engine_id, &eng_len) == 0) {
			msg.scoped.context_engine_id_len = eng_len;
		}
		msg.scoped.context_name_len = 0;

		ret = snmp_usm_build_outgoing(agent, &msg);
		if (ret < 0) {
			return ret;
		}

		size_t encoded_len = 0;
		ret = snmp_ber_encode_v3_msg(resp_buf, max_resp_len, &encoded_len, &msg);
		if (ret < 0) {
			return ret;
		}

		*out_resp_len = encoded_len;
		INST_COUNTER_INC(agent, snmpOutPkts);
		return 0;
	}

	/* VACM access check per RFC 3415 */
	int sec_level = SNMP_SEC_LEVEL_NOAUTH_NOPRIV;
	if (msg.global.msg_flags & 0x02) {
		sec_level = SNMP_SEC_LEVEL_AUTH_PRIV;
	} else if (msg.global.msg_flags & 0x01) {
		sec_level = SNMP_SEC_LEVEL_AUTH_NOPRIV;
	}
	int access_type = (msg.scoped.pdu.type == SNMP_PDU_SET_REQ) ? SNMP_VACM_ACCESS_WRITE
								    : SNMP_VACM_ACCESS_READ;

	char user_name[sizeof(msg.usm.user_name) + 1];
	size_t name_len = msg.usm.user_name_len < sizeof(msg.usm.user_name)
			      ? msg.usm.user_name_len
			      : sizeof(msg.usm.user_name);
	memcpy(user_name, msg.usm.user_name, name_len);
	user_name[name_len] = '\0';

	if (msg.scoped.pdu.varbind_cnt == 0) {
		ret = snmp_vacm_check_access_ex(agent, (const char *)msg.scoped.context_name,
						msg.global.msg_security_model, user_name, sec_level,
						access_type, NULL);
		if (ret < 0) {
			INST_COUNTER_INC(agent, snmpSilentDrops);
			return ret;
		}
	} else {
		for (size_t i = 0; i < msg.scoped.pdu.varbind_cnt; i++) {
			ret = snmp_vacm_check_access_ex(
			    agent, (const char *)msg.scoped.context_name,
			    msg.global.msg_security_model, user_name, sec_level, access_type,
			    &msg.scoped.pdu.varbinds[i].oid);
			if (ret < 0) {
				INST_COUNTER_INC(agent, snmpSilentDrops);
				return ret;
			}
		}
	}

	/* Dispatch to MIB */
	ret = snmp_mib_dispatch(agent, &msg.scoped.pdu);
	if (ret < 0) {
		return ret;
	}

	/* Set response metadata (RFC 3412 §7.1: echo request's contextEngineID and contextName) */
	msg.global.msg_max_size = CONFIG_SNMP_MAX_PDU_SIZE;
	msg.global.msg_security_model = 3;

	/* Build outgoing USM */
	ret = snmp_usm_build_outgoing(agent, &msg);
	if (ret < 0) {
		return ret;
	}

	/* Encode */
	size_t encoded_len = 0;
	ret = snmp_ber_encode_v3_msg(resp_buf, max_resp_len, &encoded_len, &msg);
	if (ret < 0) {
		if (ret == -ENOBUFS) {
			INST_COUNTER_INC(agent, snmpOutTooBigs);
		}
		return ret;
	}

	*out_resp_len = encoded_len;
	INST_COUNTER_INC(agent, snmpOutPkts);
	return 0;
}

#endif /* CONFIG_SNMP_VERSION_3 */

/* ---- Main entry points ---- */

int snmp_agent_process_pdu(struct snmp_agent *agent, const uint8_t *req_buf, size_t req_len,
			   uint8_t *resp_buf, size_t max_resp_len, size_t *out_resp_len)
{
	if (!agent || !req_buf || !resp_buf || !out_resp_len) {
		return -EINVAL;
	}
	if (agent->state == SNMP_AGENT_UNINIT) {
		return -EPERM;
	}

	*out_resp_len = 0;
	INST_COUNTER_INC(agent, snmpInPkts);

	int version = snmp_detect_version(req_buf, req_len);

	switch (version) {
	case 0:
	case 1:
		return process_v1v2c(agent, req_buf, req_len, resp_buf, max_resp_len, out_resp_len);
	case 3:
#if defined(CONFIG_SNMP_VERSION_3)
		return process_v3(agent, req_buf, req_len, resp_buf, max_resp_len, out_resp_len);
#else
		INST_COUNTER_INC(agent, snmpInBadVersions);
		return -ENOTSUP;
#endif
	default:
		INST_COUNTER_INC(agent, snmpInBadVersions);
		return -ENOTSUP;
	}
}

/* ---- Legacy facade (delegates to default agent) ---- */

int snmp_set_read_community(const char *community)
{
	return snmp_agent_set_read_community(snmp_agent_get_default(), community);
}

int snmp_set_write_community(const char *community)
{
	return snmp_agent_set_write_community(snmp_agent_get_default(), community);
}

#endif /* CONFIG_SNMP_AGENT */
