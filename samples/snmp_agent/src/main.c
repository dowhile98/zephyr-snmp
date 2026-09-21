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
#include "app_led.h"
#include "app_sensor.h"
#include "app_button.h"
#include "app_mib.h"

LOG_MODULE_REGISTER(main, LOG_LEVEL_INF);

#ifndef CONFIG_SNMP_SAMPLE_ENTERPRISE_ID
#define CONFIG_SNMP_SAMPLE_ENTERPRISE_ID 54321
#endif

#ifndef CONFIG_SNMP_SAMPLE_TRAP_DEST
#define CONFIG_SNMP_SAMPLE_TRAP_DEST "192.168.16.100"
#endif

#ifndef CONFIG_SNMP_AGENT_PORT
#define CONFIG_SNMP_AGENT_PORT 161
#endif

#ifndef CONFIG_SNMP_COMMUNITY_READ
#define CONFIG_SNMP_COMMUNITY_READ "public"
#endif

#ifndef CONFIG_SNMP_COMMUNITY_WRITE
#define CONFIG_SNMP_COMMUNITY_WRITE "private"
#endif

static struct net_mgmt_event_callback s_mgmt_cb;
static K_SEM_DEFINE(s_ip_ready_sem, 0, 1);

static void print_banner(const char *ip_str)
{
	LOG_INF("================================================================");
	LOG_INF("       SNMP VALIDATION SAMPLE ON ZEPHYR RTOS (NUCLEO-H743ZI)    ");
	LOG_INF("================================================================");
	LOG_INF("Protocol Support:");
	LOG_INF("  - SNMPv1  : %s", IS_ENABLED(CONFIG_SNMP_VERSION_1) ? "ENABLED" : "DISABLED");
	LOG_INF("  - SNMPv2c : %s", IS_ENABLED(CONFIG_SNMP_VERSION_2C) ? "ENABLED" : "DISABLED");
	LOG_INF("  - SNMPv3  : %s", IS_ENABLED(CONFIG_SNMP_VERSION_3) ? "ENABLED" : "DISABLED");
	LOG_INF("Security & Network:");
	LOG_INF("  - Agent IP / Port : %s : %d", ip_str, CONFIG_SNMP_AGENT_PORT);
	LOG_INF("  - Read Community  : \"%s\"", CONFIG_SNMP_COMMUNITY_READ);
	LOG_INF("  - Write Community : \"%s\"", CONFIG_SNMP_COMMUNITY_WRITE);
#if defined(CONFIG_SNMP_TRAP_ENABLED)
	LOG_INF("  - Trap Destination: %s : %d", CONFIG_SNMP_SAMPLE_TRAP_DEST, CONFIG_SNMP_TRAP_PORT);
#endif
	LOG_INF("Private MIB Structure (1.3.6.1.4.1.%d.1):", CONFIG_SNMP_SAMPLE_ENTERPRISE_ID);
	LOG_INF("  .1.1.0 sensorValue       (INTEGER, temp in C)   [R/W]");
	LOG_INF("  .1.2.0 ledState          (INTEGER, 0=OFF, 1=ON) [R/W]");
	LOG_INF("  .1.3.0 buttonCounter     (Counter32, press cnt) [RO]");
	LOG_INF("  .1.4.0 sensorHumidity    (Gauge32, %% relative)  [RO]");
	LOG_INF("  .1.5.0 sensorDescription (OCTET STRING)          [RO]");
	LOG_INF("  .1.6.0 sensorStatusOid   (OBJECT IDENTIFIER)    [RO]");
	LOG_INF("  .1.3.1 sensorTable       (Columns: idx, name, val)");
	LOG_INF("  .1.2.1 buttonPressed     (Notification/Trap)");
	LOG_INF("Validation Command Examples:");
	LOG_INF("  snmpget  -v2c -c %s %s 1.3.6.1.4.1.%d.1.1.0",
		CONFIG_SNMP_COMMUNITY_READ, ip_str, CONFIG_SNMP_SAMPLE_ENTERPRISE_ID);
	LOG_INF("  snmpset  -v2c -c %s %s 1.3.6.1.4.1.%d.1.2.0 i 1",
		CONFIG_SNMP_COMMUNITY_WRITE, ip_str, CONFIG_SNMP_SAMPLE_ENTERPRISE_ID);
	LOG_INF("  snmpwalk -v2c -c %s %s 1.3.6.1.4.1.%d.1",
		CONFIG_SNMP_COMMUNITY_READ, ip_str, CONFIG_SNMP_SAMPLE_ENTERPRISE_ID);
	LOG_INF("  snmpbulkwalk -v2c -c %s %s 1.3.6.1.4.1.%d.1.3",
		CONFIG_SNMP_COMMUNITY_READ, ip_str, CONFIG_SNMP_SAMPLE_ENTERPRISE_ID);
	LOG_INF("================================================================");
}

static void net_event_handler(struct net_mgmt_event_callback *cb,
			      uint64_t mgmt_event, struct net_if *iface)
{
	ARG_UNUSED(cb);
	ARG_UNUSED(iface);

	if (mgmt_event == NET_EVENT_IPV4_ADDR_ADD) {
		k_sem_give(&s_ip_ready_sem);
	}
}

#if defined(CONFIG_SHELL)
#include <zephyr/shell/shell.h>
#include <stdlib.h>

static int cmd_app_button(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	shell_print(sh, "Simulating User Button press...");
	app_button_simulate_press();
	shell_print(sh, "Button count now: %u", app_button_get_counter());
	return 0;
}

static int cmd_app_led(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		shell_print(sh, "User LED state: %s (%d)",
			    app_led_get_state() ? "ON" : "OFF", app_led_get_state());
		return 0;
	}
	int val = atoi(argv[1]);
	if (val != 0 && val != 1) {
		shell_error(sh, "Invalid value %d. Must be 0 (OFF) or 1 (ON).", val);
		return -EINVAL;
	}
	app_led_set_state(val);
	shell_print(sh, "User LED set to: %s (%d)", val ? "ON" : "OFF", val);
	return 0;
}

static int cmd_app_sensor(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	shell_print(sh, "Sensor Readings:");
	shell_print(sh, "  Temperature : %d C", app_sensor_get_temp());
	shell_print(sh, "  Humidity    : %u %%", app_sensor_get_humidity());
	shell_print(sh, "  Description : %s", app_sensor_get_description());
	shell_print(sh, "  Button Count: %u", app_button_get_counter());
	shell_print(sh, "  LED State   : %d", app_led_get_state());
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_app,
	SHELL_CMD(button, NULL, "Simulate User Button press and send SNMP Trap", cmd_app_button),
	SHELL_CMD_ARG(led, NULL, "Get or set User LED [0|1]", cmd_app_led, 1, 1),
	SHELL_CMD(sensor, NULL, "Display current sensor and device values", cmd_app_sensor),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(app, &sub_app, "SNMP validation sample commands", NULL);
#endif

int main(void)
{
	LOG_INF("Booting SNMP Validation Sample...");

	/* 1. Initialize hardware drivers */
	app_led_init();
	app_sensor_init();
	app_button_init();

	/* 2. Register network management event listener */
	net_mgmt_init_event_callback(&s_mgmt_cb, net_event_handler,
				     NET_EVENT_IPV4_ADDR_ADD | NET_EVENT_IPV4_ADDR_DEL);
	net_mgmt_add_event_callback(&s_mgmt_cb);

	/* 3. Initialize SNMP Subsystem (starts UDP port 161 listener) */
	int ret = snmp_agent_init();
	if (ret < 0) {
		LOG_ERR("Failed to initialize SNMP agent: %d", ret);
		return ret;
	}

	/* 4. Configure MIB-II System Group identity */
	snmp_mib2_set_sysname("NUCLEO-H743ZI-SNMP");
	snmp_mib2_set_syslocation("Lab Bench 1");
	snmp_mib2_set_syscontact("admin@example.com");
	snmp_mib2_set_sysdescr("Zephyr RTOS SNMP Validation Node (STM32H743ZI)");

	snmp_set_read_community(CONFIG_SNMP_COMMUNITY_READ);
	snmp_set_write_community(CONFIG_SNMP_COMMUNITY_WRITE);

	/* 5. Register Private MIB */
	ret = app_mib_init();
	if (ret < 0) {
		LOG_ERR("Failed to initialize Private MIB: %d", ret);
		return ret;
	}

#if defined(CONFIG_SNMP_TRAP_ENABLED)
	/* 6. Configure trap destination */
	snmp_trap_add_destination(CONFIG_SNMP_SAMPLE_TRAP_DEST);
	LOG_INF("Configured SNMP Trap destination: %s", CONFIG_SNMP_SAMPLE_TRAP_DEST);
#endif

	/* Check if interface already has IP assigned; if not, wait for DHCP */
	struct net_if *iface = net_if_get_default();
	bool has_ip = false;
	char ip_buf[NET_IPV4_ADDR_LEN] = "192.0.2.1";

	if (iface && iface->config.ip.ipv4) {
		for (int i = 0; i < NET_IF_MAX_IPV4_ADDR; i++) {
			if (iface->config.ip.ipv4->unicast[i].ipv4.is_used &&
			    iface->config.ip.ipv4->unicast[i].ipv4.address.in_addr.s_addr != 0) {
				net_addr_ntop(AF_INET,
					      &iface->config.ip.ipv4->unicast[i].ipv4.address.in_addr,
					      ip_buf, sizeof(ip_buf));
				has_ip = true;
				break;
			}
		}
	}

	if (!has_ip) {
		LOG_INF("Waiting for DHCP lease...");
		k_sem_take(&s_ip_ready_sem, K_FOREVER);
		if (iface && iface->config.ip.ipv4) {
			for (int i = 0; i < NET_IF_MAX_IPV4_ADDR; i++) {
				if (iface->config.ip.ipv4->unicast[i].ipv4.is_used) {
					net_addr_ntop(AF_INET,
						      &iface->config.ip.ipv4->unicast[i].ipv4.address.in_addr,
						      ip_buf, sizeof(ip_buf));
					break;
				}
			}
		}
	}

	print_banner(ip_buf);

#if defined(CONFIG_SNMP_TRAP_ENABLED)
	snmp_trap_send_coldstart();
	LOG_INF("ColdStart Trap dispatched to %s", CONFIG_SNMP_SAMPLE_TRAP_DEST);
#endif

	/* 7. Main loop: periodically update sensor values */
	while (1) {
		k_sleep(K_SECONDS(2));
		app_sensor_update_periodic();
	}

	return 0;
}
