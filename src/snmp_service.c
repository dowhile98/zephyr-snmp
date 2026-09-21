/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 */

#include <snmp/snmp.h>
#include <snmp/snmp_core.h>
#include <snmp/snmp_service.h>
#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/socket_service.h>
#include <string.h>
#include <errno.h>

#ifdef CONFIG_SNMP_AGENT

#if defined(CONFIG_SNMP_VERSION_3)
#include <snmp/snmp_usm.h>
#include <snmp/snmp_vacm.h>
#endif

static int g_snmp_sock = -1;
#ifdef CONFIG_NET_IPV6
static int g_snmp_sock6 = -1;
#endif
static uint8_t g_rx_buf[CONFIG_SNMP_MAX_PDU_SIZE];
static uint8_t g_tx_buf[CONFIG_SNMP_MAX_PDU_SIZE];

#ifdef CONFIG_SNMP_RATE_LIMIT
static uint32_t g_rate_tokens;
static int64_t g_rate_last_refill;
static bool snmp_rate_check(void);
#endif

static void snmp_service_callback(struct net_socket_service_event *pev)
{
	if (!pev || pev->event.fd < 0)
		return;

	if (pev->event.revents & ZSOCK_POLLIN)
	{
#ifdef CONFIG_SNMP_RATE_LIMIT
		if (!snmp_rate_check()) {
			g_snmp_counters.snmpSilentDrops++;
			return; /* Silently drop — don't respond */
		}
#endif

		struct sockaddr_storage client_addr;
		socklen_t addr_len = sizeof(client_addr);

		ssize_t len = zsock_recvfrom(pev->event.fd, g_rx_buf, sizeof(g_rx_buf), 0,
									 (struct sockaddr *)&client_addr, &addr_len);
		if (len > 0)
		{
			size_t resp_len = 0;
			int ret = snmp_core_process_pdu(g_rx_buf, (size_t)len,
											g_tx_buf, sizeof(g_tx_buf),
											&resp_len);
			if (ret == 0 && resp_len > 0)
			{
				zsock_sendto(pev->event.fd, g_tx_buf, resp_len, 0,
							 (const struct sockaddr *)&client_addr, addr_len);
			}
		}
	}
}

#ifdef CONFIG_SNMP_RATE_LIMIT
static bool snmp_rate_check(void)
{
	int64_t now = k_uptime_get();
	int64_t elapsed_ms = now - g_rate_last_refill;

	/* Refill tokens based on elapsed time */
	uint32_t refill = (uint32_t)(elapsed_ms * CONFIG_SNMP_RATE_LIMIT_RPS / 1000);
	if (refill > 0) {
		g_rate_tokens += refill;
		if (g_rate_tokens > CONFIG_SNMP_RATE_LIMIT_BURST + CONFIG_SNMP_RATE_LIMIT_RPS) {
			g_rate_tokens = CONFIG_SNMP_RATE_LIMIT_BURST + CONFIG_SNMP_RATE_LIMIT_RPS;
		}
		g_rate_last_refill = now;
	}

	if (g_rate_tokens > 0) {
		g_rate_tokens--;
		return true;
	}

	return false;
}
#endif

#ifdef CONFIG_NET_IPV6
#define SNMP_SVC_SOCKET_COUNT 2
#else
#define SNMP_SVC_SOCKET_COUNT 1
#endif

NET_SOCKET_SERVICE_SYNC_DEFINE_STATIC(snmp_svc, snmp_service_callback, SNMP_SVC_SOCKET_COUNT);

int snmp_service_init(void)
{
#ifdef CONFIG_SNMP_RATE_LIMIT
	g_rate_tokens = CONFIG_SNMP_RATE_LIMIT_BURST;
	g_rate_last_refill = k_uptime_get();
#endif

	struct zsock_pollfd pfds[SNMP_SVC_SOCKET_COUNT];
	int pfd_count = 0;

#ifndef CONFIG_SNMP_AGENT_PORT
#define CONFIG_SNMP_AGENT_PORT 161
#endif

	g_snmp_sock = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (g_snmp_sock >= 0) {
		struct sockaddr_in bind_addr;
		memset(&bind_addr, 0, sizeof(bind_addr));
		bind_addr.sin_family = AF_INET;
		bind_addr.sin_port = htons(CONFIG_SNMP_AGENT_PORT);
		bind_addr.sin_addr.s_addr = INADDR_ANY;

		int ret = zsock_bind(g_snmp_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
		if (ret < 0) {
			zsock_close(g_snmp_sock);
			g_snmp_sock = -1;
			return -errno;
		}

		pfds[pfd_count].fd = g_snmp_sock;
		pfds[pfd_count].events = ZSOCK_POLLIN;
		pfd_count++;
	} else {
		return -errno;
	}

#ifdef CONFIG_NET_IPV6
	struct sockaddr_in6 bind_addr6;
	memset(&bind_addr6, 0, sizeof(bind_addr6));
	bind_addr6.sin6_family = AF_INET6;
	bind_addr6.sin6_port = htons(CONFIG_SNMP_AGENT_PORT);

	g_snmp_sock6 = zsock_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (g_snmp_sock6 >= 0) {
		int ret6 = zsock_bind(g_snmp_sock6, (struct sockaddr *)&bind_addr6, sizeof(bind_addr6));
		if (ret6 < 0) {
			zsock_close(g_snmp_sock6);
			g_snmp_sock6 = -1;
		} else {
			pfds[pfd_count].fd = g_snmp_sock6;
			pfds[pfd_count].events = ZSOCK_POLLIN;
			pfd_count++;
		}
	}
#endif

	if (pfd_count > 0) {
		int ret = net_socket_service_register(&snmp_svc, pfds, pfd_count, NULL);
		if (ret < 0) {
			if (g_snmp_sock >= 0) {
				zsock_close(g_snmp_sock);
				g_snmp_sock = -1;
			}
#ifdef CONFIG_NET_IPV6
			if (g_snmp_sock6 >= 0) {
				zsock_close(g_snmp_sock6);
				g_snmp_sock6 = -1;
			}
#endif
			return ret;
		}
	}

	return 0;
}

int snmp_agent_init(void)
{
	int ret = snmp_mib_init();
	if (ret < 0)
		return ret;

	ret = snmp_mib_register_defaults();
	if (ret < 0)
		return ret;

#if defined(CONFIG_SNMP_VERSION_3)
	ret = snmp_usm_init();
	if (ret < 0)
		return ret;

	ret = snmp_vacm_init();
	if (ret < 0)
		return ret;
#endif

	ret = snmp_service_init();
	if (ret < 0)
		return ret;

	/* Cold-start trap is deferred to the application's DHCP callback
	 * (NET_EVENT_IPV4_ADDR_ADD) to ensure the network interface has an
	 * assigned IP before transmission. */

	return 0;
}

int snmp_agent_deinit(void)
{
	(void)net_socket_service_unregister(&snmp_svc);
	if (g_snmp_sock >= 0) {
		zsock_close(g_snmp_sock);
		g_snmp_sock = -1;
	}
#ifdef CONFIG_NET_IPV6
	if (g_snmp_sock6 >= 0) {
		zsock_close(g_snmp_sock6);
		g_snmp_sock6 = -1;
	}
#endif
	return 0;
}

#endif /* CONFIG_SNMP_AGENT */
