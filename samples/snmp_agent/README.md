# SNMP Validation Sample Application (NUCLEO-H743ZI)

This sample provides a comprehensive, modular, and hardware-verified reference implementation of an SNMP agent for **Zephyr RTOS**.

Targeted at the **ST NUCLEO-H743ZI** development board with 100 Mbps RMII Ethernet, this project systematically validates **SNMPv1 and SNMPv2c** protocol capabilities, physical peripheral actuation (User LED and User Push Button), multi-type telemetry simulation, dynamic multidimensional tables, and autonomous asynchronous notification dispatch (**Traps / Informs**).

---

## 📋 Features Demonstrated

- **SNMP Protocols**:
  - **SNMPv1** (RFC 1157): GET, GETNEXT, SET, and TRAP-v1.
  - **SNMPv2c** (RFC 3416): GET, GETNEXT, GETBULK (`snmpbulkget`, `snmpbulkwalk`), SET, and SNMPv2-Trap.
- **Standard MIB-II** (RFC 1213 / RFC 3418):
  - `system` group queries (`sysDescr`, `sysObjectID`, `sysUpTime`, `sysContact`, `sysName`, `sysLocation`) and `snmp` traffic statistics counters.
- **Private Enterprise MIB** (`1.3.6.1.4.1.54321.1`):
  - Formally mapped against the SMIv2 definition file [NUCLEO-H743-MIB.txt](NUCLEO-H743-MIB.txt).
  - Scalar variables covering various ASN.1 syntax types: `INTEGER`, `Gauge32`, `Counter32`, `OCTET STRING`, and `OBJECT IDENTIFIER`.
  - Multidimensional sensor table (`sensorTable`) with 3 columns and dynamic row indexing.
- **Physical Peripheral Integration**:
  - **Actuator (User LED `led0`)**: Bidirectional control via SNMP SET/GET with physical visual confirmation.
  - **Event Sensor (User Button `sw0`)**: Hardware GPIO interrupt with software debounce filter delegating to a `k_work` thread for non-blocking trap dispatch.
- **Interactive Shell Console**:
  - Integrated UART terminal commands for runtime inspection and simulation (`app led`, `app button`, `app sensor`).

---

## 🗂️ Modular Sample Architecture

```text
samples/snmp_agent/
├── CMakeLists.txt              # Build configuration and Zephyr module registration
├── Kconfig                     # Declarative configuration options for the sample
├── prj.conf                    # Network, stack sizing, logging, and SNMP parameters
├── NUCLEO-H743-MIB.txt          # Formal enterprise MIB in SMIv2 format
├── README.md                   # This comprehensive manual
└── src/
    ├── app_led.h / .c          # User LED driver (Devicetree led0)
    ├── app_button.h / .c       # User button driver (sw0) + debounce + trap dispatcher
    ├── app_sensor.h / .c       # Telemetry simulation engine (scalars and table)
    ├── app_mib.h / .c          # MIB node registration and read/write callbacks
    └── main.c                  # DHCP synchronization, boot banner, and shell commands
```

---

## ⚙️ Kconfig Configuration Reference

All features can be configured at compile time in `prj.conf` or interactively via `west build -t menuconfig`:

### Network and Protocol Parameters (`prj.conf`)

| Kconfig Symbol | Value in this Sample | Description |
| :--- | :---: | :--- |
| `CONFIG_SNMP_AGENT` | `y` | Enables the SNMP agent subsystem. |
| `CONFIG_SNMP_AGENT_PORT` | `161` | UDP listening port for incoming requests. |
| `CONFIG_SNMP_COMMUNITY_READ` | `"public"` | Community string for read-only requests (GET/WALK). |
| `CONFIG_SNMP_COMMUNITY_WRITE` | `"private"` | Community string required for modifications (SET). |
| `CONFIG_SNMP_VERSION_1` | `y` | Enables SNMPv1 protocol support. |
| `CONFIG_SNMP_VERSION_2C` | `y` | Enables SNMPv2c protocol and bulk transfer support. |
| `CONFIG_SNMP_TRAP_ENABLED` | `y` | Enables autonomous trap notification generator. |
| `CONFIG_SNMP_TRAP_PORT` | `162` | Destination UDP port for traps (162 standard or 1162 for unprivileged host reception). |
| `CONFIG_SNMP_TRAP_FORMAT_V2C` | `y` | Formats traps according to RFC 3416 standard. |
| `CONFIG_NET_SOCKETS_SERVICE_STACK_SIZE` | `4096` | Stack size for socket service thread (ensures overflow-free PDU processing). |

### Sample-Specific Options

| Kconfig Symbol | Value in this Sample | Description |
| :--- | :---: | :--- |
| `CONFIG_SNMP_SAMPLE_ENTERPRISE_ID` | `54321` | Private Enterprise Number under `1.3.6.1.4.1.<ID>`. |
| `CONFIG_SNMP_SAMPLE_SENSOR_OBJECT` | `y` | Registers telemetry scalar variables and `sensorTable`. |
| `CONFIG_SNMP_SAMPLE_LED_OBJECT` | `y` | Registers physical user LED control node. |
| `CONFIG_SNMP_SAMPLE_BUTTON_TRAP` | `y` | Enables button interrupt and asynchronous trap emission. |
| `CONFIG_SNMP_SAMPLE_TRAP_DEST` | `"192.168.16.101"` | Target IP address of remote NMS manager receiving traps. |
| `CONFIG_SNMP_SAMPLE_SECOND_INSTANCE` | `n` (optional) | Spawns a secondary independent agent (`g_agent_wan`) demonstrating multi-instance support. |
| `CONFIG_SNMP_SAMPLE_WAN_PORT` | `1610` | UDP listening port for the secondary agent in dual-instance mode. |

### 🧬 Dual-Instance Demo (Multi-Instance)

`CONFIG_SNMP_SAMPLE_SECOND_INSTANCE=y` runs two completely isolated SNMP agents from a single `main.c`: each maintaining its own static storage, `sysName`, community strings, MIB tree, `.11` statistics counters, and dedicated socket service slots.

Both agents share the same network interface but **cannot bind to the same UDP port** (a second `bind()` on :161 fails with `-EADDRINUSE`). Thus, the WAN agent listens on UDP port 1610.

**Polling Budget Requirement**: Zephyr Virtual File System (ZVFS) poll budget must satisfy:
$$\text{CONFIG\_ZVFS\_POLL\_MAX} \ge \text{CONFIG\_SNMP\_MAX\_INSTANCES} \times \text{SNMP\_SVC\_FDS} + 1$$
*(where $\text{SNMP\_SVC\_FDS} = 2$ with IPv6 enabled, $1$ for IPv4 only).*

Build command with 2 instances on QEMU x86:
```bash
west build -b qemu_x86 samples/snmp_agent -- \
  -DCONFIG_SNMP_MAX_INSTANCES=2 -DCONFIG_ZVFS_POLL_MAX=5 \
  -DCONFIG_SNMP_SAMPLE_SECOND_INSTANCE=y
```

Host verification of agent isolation:
```bash
snmpget -v2c -c public udp:<IP>:1610 1.3.6.1.2.1.1.5.0   # -> NUCLEO-H743ZI-WAN
snmpget -v2c -c public udp:<IP>:161  1.3.6.1.2.1.1.5.0   # -> NUCLEO-H743ZI-SNMP
```

---

## 🛠️ Build and Flash Guide

### Prerequisites
1. Zephyr SDK and Python virtual environment configured:
   ```bash
   source ~/zephyrproject/.venv/bin/activate
   export ZEPHYR_BASE=~/zephyrproject/zephyr
   ```
2. **NUCLEO-H743ZI** board connected via USB (ST-LINK debug port) and Ethernet cable connected to your local network.

### Build and Flash Commands

```bash
# Navigate to repository root
cd /media/jeffry/jqb/GitHub/zephyr-snmp

# Build application for NUCLEO-H743ZI target
west build -p always -b nucleo_h743zi samples/snmp_agent

# Flash firmware onto target microcontroller
west flash
```

---

## 🖥️ Serial Console and Interactive Shell

Connect a serial terminal emulator (`picocom`, `minicom`, or `screen`) to `/dev/ttyACM0` at **115200 baud (8N1)**. Upon acquiring an IP address via DHCP, the agent outputs its diagnostic banner:

```text
*** Booting Zephyr OS build v4.4.0-15809-g55303e23f59d ***
[00:00:00.059,000] <inf> main: Booting SNMP Validation Sample...
[00:00:00.068,000] <inf> app_led: User LED initialized on gpio@58020400 pin 0
[00:00:00.078,000] <inf> app_sensor: Sensor module initialized (Initial Temp: 25 C, Hum: 55%)
[00:00:00.089,000] <inf> app_button: User Button initialized on gpio@58020800 pin 13 (Interrupt active edge)
[00:00:00.101,000] <inf> app_mib: Private MIB registered under 1.3.6.1.4.1.54321.1 (nucleoH743)
[00:00:00.113,000] <inf> main: Configured SNMP Trap destination: 192.168.16.101 : 1162
[00:00:00.122,000] <inf> main: ================================================================
[00:00:00.134,000] <inf> main:        SNMP VALIDATION SAMPLE ON ZEPHYR RTOS (NUCLEO-H743ZI)    
[00:00:00.145,000] <inf> main: ================================================================
[00:00:00.156,000] <inf> main: Protocol Support:
[00:00:00.163,000] <inf> main:   - SNMPv1  : ENABLED
[00:00:00.171,000] <inf> main:   - SNMPv2c : ENABLED
[00:00:00.179,000] <inf> main:   - SNMPv3  : DISABLED
[00:00:00.186,000] <inf> main: Security & Network:
[00:00:00.194,000] <inf> main:   - Agent IP / Port : 192.168.16.100 : 161
[00:00:00.203,000] <inf> main:   - Read Community  : "public"
[00:00:00.211,000] <inf> main:   - Write Community : "private"
[00:00:00.219,000] <inf> main:   - Trap Destination: 192.168.16.101 : 1162
[00:00:00.384,000] <inf> main: ColdStart Trap dispatched to 192.168.16.101
[00:00:01.752,000] <inf> phy_mii: PHY (0) Link speed 100 Mb, full duplex
uart:~$
```

### Available Shell Commands

Interact with the running firmware via the Zephyr Shell:
- `app sensor`: Displays internal telemetry readings.
  ```text
  uart:~$ app sensor
  Sensor Readings:
    Temperature : 28 C
    Humidity    : 52 %
    Description : NUCLEO-H743ZI Sensor Node
    Button Count: 3
    LED State   : 1
  ```
- `app led [0|1]`: Reads or drives the physical green user LED.
  ```text
  uart:~$ app led 1
  User LED set to: ON (1)
  ```
- `app button`: Simulates a button press event, increments the press counter, and dispatches the SNMP trap.
  ```text
  uart:~$ app button
  Simulating User Button press...
  [00:00:43.085,000] <inf> app_button: SNMP Notification dispatched successfully (buttonCounter=4, ledState=1)
  Button count now: 4
  ```
- `net iface`: Inspects network interface parameters, MAC address, and active IPv4/IPv6 leases.

---

## 🧪 Net-SNMP Host Verification Suite

*(Replace `192.168.16.100` with the actual IP address assigned to your target board)*

### 1. Scalar Object Querying with Symbolic and Numeric OIDs

Private enterprise branch `1.3.6.1.4.1.54321.1` (`nucleoH743`):
- `.1.1.1.0` -> `sensorValue.0` (`INTEGER`, simulated temperature in °C)
- `.1.1.2.0` -> `ledState.0` (`INTEGER (0..1)`, green user LED state)
- `.1.1.3.0` -> `buttonCounter.0` (`Counter32`, cumulative button presses)
- `.1.1.4.0` -> `sensorHumidity.0` (`Gauge32 (0..100)`, relative humidity in %)
- `.1.1.5.0` -> `sensorDescription.0` (`OCTET STRING`, node description)
- `.1.1.6.0` -> `sensorStatusOid.0` (`OBJECT IDENTIFIER`, OID pointer to `sensorValue.0`)

**Symbolic query (loading MIB):**
```bash
snmpget -v2c -c public -m ./NUCLEO-H743-MIB.txt 192.168.16.100 \
  sensorValue.0 ledState.0 buttonCounter.0 sensorHumidity.0 sensorDescription.0 sensorStatusOid.0
```
**Expected Output:**
```text
NUCLEO-H743-MIB::sensorValue.0 = INTEGER: 28
NUCLEO-H743-MIB::ledState.0 = INTEGER: 0
NUCLEO-H743-MIB::buttonCounter.0 = Counter32: 3
NUCLEO-H743-MIB::sensorHumidity.0 = Gauge32: 52
NUCLEO-H743-MIB::sensorDescription.0 = STRING: NUCLEO-H743ZI Sensor Node
NUCLEO-H743-MIB::sensorStatusOid.0 = OID: NUCLEO-H743-MIB::sensorValue.0
```

**Numeric query:**
```bash
snmpget -v2c -c public 192.168.16.100 \
  1.3.6.1.4.1.54321.1.1.1.0 \
  1.3.6.1.4.1.54321.1.1.2.0 \
  1.3.6.1.4.1.54321.1.1.3.0 \
  1.3.6.1.4.1.54321.1.1.4.0 \
  1.3.6.1.4.1.54321.1.1.5.0 \
  1.3.6.1.4.1.54321.1.1.6.0
```

### 2. Physical LED Actuation via SNMP SET
```bash
# Turn User LED ON (requires write community 'private')
snmpset -v2c -c private -m ./NUCLEO-H743-MIB.txt 192.168.16.100 ledState.0 i 1

# Turn User LED OFF
snmpset -v2c -c private -m ./NUCLEO-H743-MIB.txt 192.168.16.100 ledState.0 i 0
```

### 3. Security and Bounds Validation Tests
- **SET attempt using unauthorized read community (`public`):**
  ```bash
  snmpset -v2c -c public -m ./NUCLEO-H743-MIB.txt 192.168.16.100 ledState.0 i 1
  # Output: Timeout: No Response (RFC-compliant silent drop)
  ```
- **SET attempt with out-of-range value (`99` for boolean `0..1`):**
  ```bash
  snmpset -v2c -c private -m ./NUCLEO-H743-MIB.txt 192.168.16.100 ledState.0 i 99
  # Output: Error in packet. Reason: (badValue)
  ```

### 4. Multidimensional Table Query (`sensorTable` .1.3.1)

The sensor table (`1.3.6.1.4.1.54321.1.3.1`) exposes 3 rows indexed by `sensorIndex`:
- Column 1 (`.1.3.1.1.<idx>`): `sensorIndex` (`INTEGER`)
- Column 2 (`.1.3.1.2.<idx>`): `sensorName` (`OCTET STRING` / `DisplayString`)
- Column 3 (`.1.3.1.3.<idx>`): `sensorVal` (`INTEGER`)

```bash
snmptable -v2c -c public -m ./NUCLEO-H743-MIB.txt 192.168.16.100 sensorTable
```
**Expected Output:**
```text
SNMP table: NUCLEO-H743-MIB::sensorTable

 sensorIndex   sensorName sensorVal
           1     CPU Temp        28
           2 Amb Humidity        52
           3 Core Voltage      3300
```

**Sequential tree walk with `snmpwalk`:**
```bash
snmpwalk -v2c -c public 192.168.16.100 1.3.6.1.4.1.54321.1.3.1
```

### 5. High-Efficiency Bulk Transfer (`snmpbulkget` / `snmpbulkwalk`)
```bash
# Request 9 variables in a single UDP packet exchange
snmpbulkget -v2c -c public -m ./NUCLEO-H743-MIB.txt -Cn0 -Cr9 192.168.16.100 sensorTable

# Direct numeric OID request:
snmpbulkget -v2c -c public -Cn0 -Cr9 192.168.16.100 1.3.6.1.4.1.54321.1.3.1
```

---

## 📡 Host Trap Reception and Verification

The sample dispatches autonomous SNMPv2-Trap notifications to `CONFIG_SNMP_SAMPLE_TRAP_DEST` on port `CONFIG_SNMP_TRAP_PORT` (`162` default in `prj.conf`, or configurable to `1162`).

- **Notification OID (`buttonPressed`)**: `1.3.6.1.4.1.54321.1.2.1` (`notifications 1`).
- **Bound Varbinds**:
  1. `buttonCounter.0` (`.1.1.3.0`): monotonic button press counter.
  2. `ledState.0` (`.1.1.2.0`): current physical LED state at the time of the event.

### Option A: Standard Daemon (`snmptrapd` on UDP :162)
Recommended for formal SMIv2 decoding:
1. **Firewall Rule (UFW)**: Allow inbound UDP traffic on trap port:
   ```bash
   sudo ufw allow 162/udp
   ```
2. **Access Configuration (`/etc/snmp/snmptrapd.conf`)**:
   ```text
   authCommunity log,execute,net public
   ```
3. **Run `snmptrapd` receiver in terminal**:
   ```bash
   sudo snmptrapd -f -Lo -C -c /etc/snmp/snmptrapd.conf -m ./NUCLEO-H743-MIB.txt
   ```
   Pressing the blue button `sw0` or executing `app button` produces decoded output with `buttonPressed`, `buttonCounter.0`, and `ledState.0`.

### Option B: Lightweight Unprivileged Receiver (Python or `tcpdump`)
Ideal for lab testing without host root privileges:
1. If using port `1162` (`CONFIG_SNMP_TRAP_PORT=1162`), run this Python script on the host:
   ```python
   import socket

   s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   s.bind(('0.0.0.0', 1162))
   print("Trap receiver listening on UDP :1162...")
   while True:
       data, addr = s.recvfrom(2048)
       print(f"Trap received ({len(data)} bytes) from {addr}")
       print(f"Hex: {data.hex()}\n")
   ```
2. For packet capture on standard port 162:
   ```bash
   sudo tcpdump -i any -nn -vv -X udp port 162
   ```

---

## 🚀 Production Deployment Checklist

To adapt this validation sample for production firmware:
1. **Adapt `src/app_sensor.c`**: Connect physical device drivers (ADC, I2C, SPI, or CAN) replacing simulated telemetry with real sensor reads.
2. **Customize `NUCLEO-H743-MIB.txt`**: Replace enterprise ID `54321` with your organization's IANA-assigned enterprise number.
3. **Preserve `app_button.c` and `app_mib.c` patterns**: The deferred workqueue (`k_work`) trap dispatch and non-blocking MIB callback architecture implemented here ensure deterministic RTOS performance.

