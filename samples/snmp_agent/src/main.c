/*
 * Copyright (c) 2026 Zephyr SNMP Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
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

static int sensor_col1_get(const struct snmp_table_row *row, uint8_t column, struct snmp_varbind *vb)
{
	(void)column;
	vb->type = ASN1_TAG_INTEGER;
	vb->val.int_val = (int32_t)row->index;
	return 0;
}

static int sensor_col2_get(const struct snmp_table_row *row, uint8_t column, struct snmp_varbind *vb)
{
	(void)column;
	if (row->index < 1 || row->index > 3) {
		return -ENOENT;
	}
	vb->type = ASN1_TAG_OCTET_STRING;
	strncpy(vb->val.str_val, g_sensor_names[row->index - 1], sizeof(vb->val.str_val) - 1);
	vb->val.str_val[sizeof(vb->val.str_val) - 1] = '\0';
	return 0;
}

static int sensor_col3_get(const struct snmp_table_row *row, uint8_t column, struct snmp_varbind *vb)
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

static struct snmp_table_row g_sensor_rows[3] = {
	{.index = 1},
	{.index = 2},
	{.index = 3}
};

static struct snmp_mib_table g_sensor_table = {
	.table_oid = {.len = 9, .ids = {1, 3, 6, 1, 4, 1, 54321, 2, 1}},
	.column_cnt = 3,
	.column_subids = g_sensor_cols,
	.column_types = g_sensor_types,
	.get_cbs = g_sensor_get_cbs,
	.set_cbs = NULL,
};

int main(void)
{
	LOG_INF("Starting SNMP Agent Sample...");

	/* 1. Initialize SNMP Subsystem (starts UDP port 161 listener) */
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
		.oid = {
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
		k_sleep(K_SECONDS(5));
		g_temperature = 20 + (k_uptime_get_32() % 15);
	}

	return 0;
}
