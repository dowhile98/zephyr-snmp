/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 */

#include <snmp/snmp_trap.h>
#include <snmp/snmp_mib.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/socket.h>
#include <string.h>
#include <errno.h>

#if defined(CONFIG_SNMP_AGENT) && defined(CONFIG_SNMP_TRAP_ENABLED)

#ifdef CONFIG_SNMP_VERSION_3
#include <snmp/snmp_usm.h>
#endif

static struct sockaddr_in g_trap_dests[CONFIG_SNMP_TRAP_DEST_COUNT];
static uint8_t g_trap_dest_cnt = 0;

int snmp_trap_add_destination(const char *addr)
{
	if (!addr)
		return -EINVAL;
	if (g_trap_dest_cnt >= CONFIG_SNMP_TRAP_DEST_COUNT)
		return -ENOMEM;

	struct sockaddr_in *dest = &g_trap_dests[g_trap_dest_cnt];
	memset(dest, 0, sizeof(*dest));
	dest->sin_family = AF_INET;
	dest->sin_port = htons(162);

	int ret = zsock_inet_pton(AF_INET, addr, &dest->sin_addr);
	if (ret <= 0)
		return -EINVAL;

	g_trap_dest_cnt++;
	return 0;
}

static K_MUTEX_DEFINE(g_trap_mutex);
static struct snmp_pdu g_trap_pdu;
static uint8_t g_trap_tx_buf[CONFIG_SNMP_MAX_PDU_SIZE];

#if defined(CONFIG_SNMP_VERSION_3)
int snmp_trap_send_v3(const struct snmp_oid *trap_oid,
		     const struct snmp_varbind *varbinds,
		     uint8_t varbind_cnt,
		     bool is_inform)
{
	struct snmp_v3_msg msg;
	uint8_t tx_buf[CONFIG_SNMP_MAX_PDU_SIZE];
	size_t tx_len = 0;

	if (!trap_oid) {
		return -EINVAL;
	}

#if defined(CONFIG_NET_IPV4)
	struct net_if *iface = net_if_get_default();
	if (!iface || !net_if_is_up(iface) || !iface->config.ip.ipv4 ||
	    iface->config.ip.ipv4->unicast[0].ipv4.address.in_addr.s_addr == 0) {
		return -ENETDOWN;
	}
#endif

	memset(&msg, 0, sizeof(msg));

	msg.global.msg_id = (int32_t)k_uptime_get_32();
	msg.global.msg_max_size = CONFIG_SNMP_MAX_PDU_SIZE;
	msg.global.msg_flags = is_inform ? 0x04 : 0x00;
	msg.global.msg_security_model = 3;

	memcpy(msg.usm.user_name, CONFIG_SNMP_V3_USER_NAME, strlen(CONFIG_SNMP_V3_USER_NAME));
	msg.usm.user_name_len = strlen(CONFIG_SNMP_V3_USER_NAME);

	msg.scoped.pdu.version = 3;
	msg.scoped.pdu.type = is_inform ? SNMP_PDU_INFORM_REQ : SNMP_PDU_TRAP_V2;
	msg.scoped.pdu.request_id = (int32_t)k_uptime_get_32();
	msg.scoped.pdu.error_status = 0;
	msg.scoped.pdu.error_index = 0;

	static const uint32_t uptime_oid[9] = {1, 3, 6, 1, 2, 1, 1, 3, 0};
	static const uint32_t trap_oid_spec[11] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};

	msg.scoped.pdu.varbinds[0].oid.len = 9;
	memcpy(msg.scoped.pdu.varbinds[0].oid.ids, uptime_oid, sizeof(uptime_oid));
	msg.scoped.pdu.varbinds[0].type = SNMP_TAG_TIMETICKS;
	msg.scoped.pdu.varbinds[0].val.uint_val = (uint32_t)(k_uptime_get() / 10);

	msg.scoped.pdu.varbinds[1].oid.len = 11;
	memcpy(msg.scoped.pdu.varbinds[1].oid.ids, trap_oid_spec, sizeof(trap_oid_spec));
	msg.scoped.pdu.varbinds[1].type = ASN1_TAG_OID;
	msg.scoped.pdu.varbinds[1].val.oid = *trap_oid;

	msg.scoped.pdu.varbind_cnt = 2;

	if (varbinds && varbind_cnt > 0) {
		for (uint8_t i = 0; i < varbind_cnt &&
			    msg.scoped.pdu.varbind_cnt < CONFIG_SNMP_MAX_VARBINDS; i++) {
			msg.scoped.pdu.varbinds[msg.scoped.pdu.varbind_cnt++] = varbinds[i];
		}
	}

	uint8_t eng_len = sizeof(msg.scoped.context_engine_id);
	if (snmp_usm_get_engine_id(msg.scoped.context_engine_id, &eng_len) == 0) {
		msg.scoped.context_engine_id_len = eng_len;
	}
	msg.scoped.context_name_len = 0;

	int ret = snmp_usm_build_outgoing(&msg);
	if (ret < 0)
		return ret;

	ret = snmp_ber_encode_v3_msg(tx_buf, sizeof(tx_buf), &tx_len, &msg);
	if (ret < 0)
		return ret;

	struct sockaddr_in dest;
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(162);
	dest.sin_addr.s_addr = INADDR_BROADCAST;

	int sock = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
		return -errno;

	int broadcast_enable = 1;
	zsock_setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable));

	if (g_trap_dest_cnt > 0) {
		for (uint8_t d = 0; d < g_trap_dest_cnt; d++) {
			zsock_sendto(sock, tx_buf, tx_len, 0,
				     (struct sockaddr *)&g_trap_dests[d],
				     sizeof(g_trap_dests[d]));
		}
	} else {
		zsock_sendto(sock, tx_buf, tx_len, 0,
			     (struct sockaddr *)&dest, sizeof(dest));
	}

	snmp_counter_inc(&g_snmp_counters.snmpOutTraps);
	zsock_close(sock);
	return 0;
}
#endif

int snmp_trap_send(const struct snmp_oid *trap_oid,
		   const struct snmp_varbind *varbinds,
		   uint8_t varbind_cnt,
		   bool is_inform)
{
	if (!trap_oid)
		return -EINVAL;

#if defined(CONFIG_SNMP_VERSION_2C)
	/* Proceed with SNMPv2c trap */
#elif defined(CONFIG_SNMP_VERSION_3)
	return snmp_trap_send_v3(trap_oid, varbinds, varbind_cnt, is_inform);
#elif defined(CONFIG_SNMP_VERSION_1)
	/* Proceed with SNMPv1 trap */
#else
	return -ENOTSUP;
#endif

#if defined(CONFIG_NET_IPV4)
	struct net_if *iface = net_if_get_default();
	if (!iface || !net_if_is_up(iface) || !iface->config.ip.ipv4 ||
		iface->config.ip.ipv4->unicast[0].ipv4.address.in_addr.s_addr == 0)
	{
		return -ENETDOWN;
	}
#endif

	k_mutex_lock(&g_trap_mutex, K_FOREVER);

	int sock = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
	{
		k_mutex_unlock(&g_trap_mutex);
		return -errno;
	}

	int broadcast_enable = 1;
	zsock_setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable));

	memset(&g_trap_pdu, 0, sizeof(g_trap_pdu));

#if defined(CONFIG_SNMP_VERSION_2C)
	g_trap_pdu.version = 1;
	g_trap_pdu.type = is_inform ? SNMP_PDU_INFORM_REQ : SNMP_PDU_TRAP_V2;
	g_trap_pdu.request_id = (int32_t)k_uptime_get_32();
	g_trap_pdu.error_status = 0;
	g_trap_pdu.error_index = 0;
	memcpy(g_trap_pdu.community, "public", 6);
	g_trap_pdu.community_len = 6;

	/* sysUpTime.0 (1.3.6.1.2.1.1.3.0) and snmpTrapOID.0 (1.3.6.1.6.3.1.1.4.1.0) */
	static const uint32_t uptime_oid[9]  = {1, 3, 6, 1, 2, 1, 1, 3, 0};
	static const uint32_t trap_oid_spec[11] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};

	g_trap_pdu.varbinds[0].oid.len = 9;
	memcpy(g_trap_pdu.varbinds[0].oid.ids, uptime_oid, sizeof(uptime_oid));
	g_trap_pdu.varbinds[0].type = SNMP_TAG_TIMETICKS;
	g_trap_pdu.varbinds[0].val.uint_val = (uint32_t)(k_uptime_get() / 10);

	g_trap_pdu.varbinds[1].oid.len = 11;
	memcpy(g_trap_pdu.varbinds[1].oid.ids, trap_oid_spec, sizeof(trap_oid_spec));
	g_trap_pdu.varbinds[1].type = ASN1_TAG_OID;
	g_trap_pdu.varbinds[1].val.oid = *trap_oid;

	g_trap_pdu.varbind_cnt = 2;
#elif defined(CONFIG_SNMP_VERSION_1)
	g_trap_pdu.version = 0;
	g_trap_pdu.type = SNMP_PDU_TRAP_V1;
	g_trap_pdu.enterprise = *trap_oid;
	g_trap_pdu.generic_trap = SNMP_TRAP_ENTERPRISESPEC;
	g_trap_pdu.specific_trap = 1;
	g_trap_pdu.timestamp = (uint32_t)(k_uptime_get() / 10);

#if defined(CONFIG_NET_IPV4)
	struct net_if *iface_v1 = net_if_get_default();
	if (iface_v1 && iface_v1->config.ip.ipv4) {
		memcpy(g_trap_pdu.agent_addr, &iface_v1->config.ip.ipv4->unicast[0].ipv4.address.in_addr, 4);
	}
#endif
	memcpy(g_trap_pdu.community, "public", 6);
	g_trap_pdu.community_len = 6;
#endif

	if (varbinds && varbind_cnt > 0)
	{
		for (uint8_t i = 0; i < varbind_cnt && g_trap_pdu.varbind_cnt < CONFIG_SNMP_MAX_VARBINDS; i++)
		{
			g_trap_pdu.varbinds[g_trap_pdu.varbind_cnt++] = varbinds[i];
		}
	}

	size_t tx_len = 0;
	int ret = snmp_ber_encode_pdu(g_trap_tx_buf, sizeof(g_trap_tx_buf), &tx_len, &g_trap_pdu);
	if (ret < 0)
	{
		zsock_close(sock);
		k_mutex_unlock(&g_trap_mutex);
		return ret;
	}

	/* Broadcast or send to configured destinations */
	struct sockaddr_in dest;
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(162);
	dest.sin_addr.s_addr = INADDR_BROADCAST;

	if (g_trap_dest_cnt > 0)
	{
		for (uint8_t d = 0; d < g_trap_dest_cnt; d++)
		{
			zsock_sendto(sock, g_trap_tx_buf, tx_len, 0, (struct sockaddr *)&g_trap_dests[d], sizeof(g_trap_dests[d]));
		}
	}
	else
	{
		zsock_sendto(sock, g_trap_tx_buf, tx_len, 0, (struct sockaddr *)&dest, sizeof(dest));
	}

	snmp_counter_inc(&g_snmp_counters.snmpOutTraps);
	zsock_close(sock);
	k_mutex_unlock(&g_trap_mutex);
	return 0;
}

int snmp_trap_send_coldstart(void)
{
	static const struct snmp_oid cold_start_oid = {
		.len = 10,
		.ids = {1, 3, 6, 1, 6, 3, 1, 1, 5, 1}};
	return snmp_trap_send(&cold_start_oid, NULL, 0, false);
}

int snmp_trap_send_auth_failure(void)
{
	if (g_snmp_counters.snmpEnableAuthenTraps != 1)
	{
		return 0; /* Traps disabled */
	}
	static const struct snmp_oid auth_fail_oid = {
		.len = 10,
		.ids = {1, 3, 6, 1, 6, 3, 1, 1, 5, 5}};
	return snmp_trap_send(&auth_fail_oid, NULL, 0, false);
}

#endif /* CONFIG_SNMP_AGENT && CONFIG_SNMP_TRAP_ENABLED */
