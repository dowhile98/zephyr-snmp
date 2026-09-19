/*
 * Copyright (c) 2026 Zephyr SNMP Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/net_ip.h>
#include <snmp/snmp.h>
#include <snmp/snmp_mib.h>
#include <snmp/snmp_trap.h>

LOG_MODULE_REGISTER(snmp_sample, LOG_LEVEL_INF);

/* Simulated sensor data */
static int32_t g_temperature = 24;

/* Scalar GET callback for simulated temperature (1.3.6.1.4.1.54321.1.1.0) */
static int get_temperature(const struct snmp_mib_node *node, struct snmp_varbind *vb)
{
	(void)node;
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = g_temperature;
	return 0;
}

/* Scalar SET callback */
static int set_temperature(struct snmp_mib_node *node, const struct snmp_varbind *vb)
{
	(void)node;
	if (vb->type != ASN1_TAG_INTEGER) {
		return -EINVAL;
	}
	g_temperature = vb->val.int_val;
	LOG_INF("Temperature updated via SNMP SET: %d C", g_temperature);
	return 0;
}

/* Table callbacks for sensorTable (1.3.6.1.4.1.54321.2.1)
 * Columns:
 * 1: sensorIndex (INTEGER)
 * 2: sensorName (OCTET STRING)
 * 3: sensorValue (INTEGER)
 */
static const char *g_sensor_names[] = {"CPU Temp", "Amb Humidity", "Voltage"};
static int32_t g_sensor_values[] = {42, 55, 3300};

static int sensor_col1_get(const struct snmp_table_row *row, uint8_t column,
			   struct snmp_varbind *vb)
{
	(void)column;
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = (int32_t)row->index;
	return 0;
}

static int sensor_col2_get(const struct snmp_table_row *row, uint8_t column,
			   struct snmp_varbind *vb)
{
	(void)column;
	if (row->index < 1 || row->index > 3) {
		return -ENOENT;
	}
	vb->type = ASN1_TAG_OCTET_STRING;
	const char *name = g_sensor_names[row->index - 1];
	size_t len = strlen(name);
	if (len > sizeof(vb->val.octet_str.data)) {
		len = sizeof(vb->val.octet_str.data);
	}
	memcpy(vb->val.octet_str.data, name, len);
	vb->val.octet_str.len = (uint16_t)len;
	return 0;
}

static int sensor_col3_get(const struct snmp_table_row *row, uint8_t column,
			   struct snmp_varbind *vb)
{
	(void)column;
	if (row->index < 1 || row->index > 3) {
		return -ENOENT;
	}
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = (row->index == 1) ? g_temperature : g_sensor_values[row->index - 1];
	return 0;
}

static const uint8_t g_sensor_cols[] = {1, 2, 3};
static const uint8_t g_sensor_types[] = {ASN1_TAG_INTEGER, ASN1_TAG_OCTET_STRING, ASN1_TAG_INTEGER};
static snmp_table_get_cb_t g_sensor_get_cbs[] = {sensor_col1_get, sensor_col2_get, sensor_col3_get};

static struct snmp_table_row g_sensor_rows[3] = {{.index = 1}, {.index = 2}, {.index = 3}};

static struct snmp_mib_table g_sensor_table = {
    .table_oid = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 54321, 2, 1}},
    .column_cnt = 3,
    .column_subids = g_sensor_cols,
    .column_types = g_sensor_types,
    .get_cbs = g_sensor_get_cbs,
    .set_cbs = NULL,
};

static struct net_mgmt_event_callback mgmt_cb;

static void print_network_status(struct net_if *iface)
{
	if (!iface) {
		LOG_WRN("No default network interface found.");
		return;
	}

	const struct device *dev = net_if_get_device(iface);
	LOG_INF("Network Interface : %s (index %d)",
		dev ? dev->name : "eth", net_if_get_by_iface(iface));

	struct net_linkaddr *link = net_if_get_link_addr(iface);
	if (link && link->addr && link->len == 6) {
		LOG_INF("Ethernet MAC      : %02X:%02X:%02X:%02X:%02X:%02X",
			link->addr[0], link->addr[1], link->addr[2],
			link->addr[3], link->addr[4], link->addr[5]);
	}

	LOG_INF("Ethernet Carrier  : %s",
		net_if_is_carrier_ok(iface) ? "LINK UP" : "LINK DOWN (check Ethernet cable)");

	if (iface->config.ip.ipv4) {
		char buf[NET_IPV4_ADDR_LEN];
		for (int i = 0; i < NET_IF_MAX_IPV4_ADDR; i++) {
			struct net_if_addr_ipv4 *uni = &iface->config.ip.ipv4->unicast[i];
			if (!uni->ipv4.is_used) {
				continue;
			}
			net_addr_ntop(AF_INET, &uni->ipv4.address.in_addr, buf, sizeof(buf));
			LOG_INF("IPv4 Address [%d]  : %s (%s)", i + 1, buf,
				uni->ipv4.addr_type == NET_ADDR_DHCP ? "DHCP" :
				(uni->ipv4.addr_type == NET_ADDR_OVERRIDABLE ? "Static (overridable)" : "Static"));
			net_addr_ntop(AF_INET, &uni->netmask, buf, sizeof(buf));
			LOG_INF("Netmask      [%d]  : %s", i + 1, buf);
		}
		if (iface->config.ip.ipv4->gw.s_addr != 0) {
			net_addr_ntop(AF_INET, &iface->config.ip.ipv4->gw, buf, sizeof(buf));
			LOG_INF("Default Gateway   : %s", buf);
		}
	}
}

static void net_event_handler(struct net_mgmt_event_callback *cb,
			      uint64_t mgmt_event, struct net_if *iface)
{
	if (mgmt_event == NET_EVENT_IPV4_ADDR_ADD) {
		char buf[NET_IPV4_ADDR_LEN];
		for (int i = 0; i < NET_IF_MAX_IPV4_ADDR; i++) {
			struct net_if_addr_ipv4 *uni = &iface->config.ip.ipv4->unicast[i];
			if (!uni->ipv4.is_used) {
				continue;
			}
			net_addr_ntop(AF_INET, &uni->ipv4.address.in_addr, buf, sizeof(buf));
			LOG_INF(">>> IPv4 READY: %s (%s) <<<", buf,
				uni->ipv4.addr_type == NET_ADDR_DHCP ? "DHCP assigned" : "Static");
			LOG_INF(">>> SNMP Agent listening on UDP %s:161 <<<", buf);
			LOG_INF("Query SysDescr : snmpget -v2c -c public %s 1.3.6.1.2.1.1.1.0", buf);
			LOG_INF("Query Sensor   : snmpget -v2c -c public %s 1.3.6.1.4.1.54321.1.1.0", buf);
			LOG_INF("Walk Sensors   : snmpwalk -v2c -c public %s 1.3.6.1.4.1.54321.2.1", buf);
		}
	} else if (mgmt_event == NET_EVENT_IPV4_ADDR_DEL) {
		LOG_WRN("IPv4 address removed from network interface");
	}
}

int main(void)
{
	LOG_INF("========================================");
	LOG_INF("Starting SNMP Agent Sample on Zephyr");
	LOG_INF("========================================");

	/* 1. Register network event listener and report current interface status */
	net_mgmt_init_event_callback(&mgmt_cb, net_event_handler,
				     NET_EVENT_IPV4_ADDR_ADD | NET_EVENT_IPV4_ADDR_DEL);
	net_mgmt_add_event_callback(&mgmt_cb);

	struct net_if *iface = net_if_get_default();
	print_network_status(iface);

	/* 2. Initialize SNMP Subsystem (starts UDP port 161 listener) */
	int ret = snmp_agent_init();
	if (ret < 0) {
		LOG_ERR("Failed to initialize SNMP agent: %d", ret);
		return ret;
	}

	/* 2. Configure MIB-II System Group */
	snmp_mib2_set_sysname("Zephyr-SNMP-Device");
	snmp_mib2_set_syslocation("Lab Bench 1");
	snmp_mib2_set_syscontact("admin@example.com");
	snmp_set_read_community("public");
	snmp_set_write_community("private");

	/* 3. Register custom Enterprise Scalar OID: 1.3.6.1.4.1.54321.1.1.0 */
	static const struct snmp_mib_node temp_node = {
	    .oid =
		{
		    .len = 10,
		    .ids = {1, 3, 6, 1, 4, 1, 54321, 1, 1, 0},
		},
	    .type = ASN1_TAG_INTEGER,
	    .get_cb = get_temperature,
	    .set_cb = set_temperature,
	};
	snmp_mib_register(&temp_node);

	/* 4. Register custom Enterprise Table: 1.3.6.1.4.1.54321.2.1 */
	ret = snmp_mib_register_table(&g_sensor_table);
	if (ret == 0) {
		snmp_mib_table_add_row(&g_sensor_table, &g_sensor_rows[0]);
		snmp_mib_table_add_row(&g_sensor_table, &g_sensor_rows[1]);
		snmp_mib_table_add_row(&g_sensor_table, &g_sensor_rows[2]);
	}

	/* 5. Configure Trap destination and send coldStart trap */
	snmp_trap_add_destination("192.0.2.2");
	snmp_trap_send_coldstart();

	LOG_INF("SNMP Agent running. Ready for incoming requests on UDP :161.");

	/* Main loop: simulate sensor readings variation */
	while (1) {
		k_sleep(K_SECONDS(5));
		g_temperature = 20 + (k_uptime_get_32() % 15);
	}

	return 0;
}
