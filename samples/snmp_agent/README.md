# SNMP Agent Sample Application

This sample demonstrates how to integrate and use the Zephyr SNMP Agent module (`zephyr-snmp`).

## Features Demonstrated

- Initialization of the SNMP agent subsystem (`snmp_agent_init`)
- MIB-II system information configuration (sysName, sysLocation, sysContact)
- Registration and serving of custom enterprise scalar MIB variables (`snmp_mib_register`)
- Registration and traversal of enterprise tabular MIB objects (`snmp_mib_register_table`)
- Notification generation: sending standard coldStart traps (`snmp_trap_send_coldstart`)

## Building and Running

### Native Simulator (`native_sim`)

```bash
west build -b native_sim samples/snmp_agent
./build/zephyr/zephyr.exe
```

### Testing with Net-SNMP Tools

From the host:

```bash
# Query sysDescr
snmpget -v2c -c public 192.0.2.1 1.3.6.1.2.1.1.1.0

# Walk the full MIB tree
snmpwalk -v2c -c public 192.0.2.1 1.3.6.1

# Query enterprise scalar temperature
snmpget -v2c -c public 192.0.2.1 1.3.6.1.4.1.54321.1.1.0

# Update temperature via SNMP SET
snmpset -v2c -c private 192.0.2.1 1.3.6.1.4.1.54321.1.1.0 i 28

# Walk the sensor table
snmptable -v2c -c public 192.0.2.1 1.3.6.1.4.1.54321.2.1
```
