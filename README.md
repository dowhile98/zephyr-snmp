# Zephyr SNMP Agent

[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](CHANGELOG.md)
[![Zephyr](https://img.shields.io/badge/Zephyr-RTOS-3C8CB4.svg?logo=zephyr)](https://zephyrproject.org/)

Embedded SNMP agent (v1, v2c, v3) for Zephyr RTOS. Self-contained, zero dynamic allocation, designed for constrained devices.

## Table of Contents

- [Documentation & Wiki](#documentation--wiki)
- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [MIB-II Coverage](#mib-ii-coverage)
- [Architecture](#architecture)
- [Security](#security-considerations)
- [Memory Footprint](#memory-footprint)
- [Testing](#testing)
- [RFC Compatibility](#rfc-compatibility)
- [Known Limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)
- [Changelog](#changelog)

## Documentation & Wiki

Para obtener documentación detallada, consulte el **[Wiki del Proyecto](docs/wiki/Home.md)**:

- 🏛️ **[Arquitectura e Internales](docs/wiki/Architecture-and-Internals.md)**: Modelo de cero asignación dinámica, códec ASN.1 BER, `net_socket_service` y motor de MIB.
- 📊 **[Diseño e Implementación de MIBs](docs/wiki/MIB-Design-and-Implementation.md)**: Guía paso a paso para variables escalares (RO/RW), tablas dinámicas y especificación SMIv2.
- ⚡ **[Integración de Hardware y Red](docs/wiki/Hardware-and-Network-Integration.md)**: DeviceTree (`led0`, `sw0`), interrupciones con debounce, delegación a workqueue y sincronización DHCPv4.
- 📋 **[Matriz de Protocolos y Auditoría Técnica](docs/wiki/SNMP-Version-Matrix-and-Interoperability.md)**: Análisis comparativo exhaustivo v1/v2c/v3 y auditoría de USM/VACM.
- 🔧 **[Guía de Depuración y Troubleshooting](docs/wiki/Troubleshooting-and-Debugging.md)**: Resolución de timeouts, caídas de stack, colisiones de sockets y captura de traps.
- 🚀 **[Sample de Validación en NUCLEO-H743ZI](samples/snmp_agent/README.md)**: Manual exhaustivo con comandos de prueba Net-SNMP listos para usar y consola interactiva.

## Features

| Feature | v1 | v2c | v3 |
|---------|----|-----|----|
| GET | Yes | Yes | Yes |
| GETNEXT | Yes | Yes | Yes |
| GETBULK | No | Yes | Yes |
| SET | Yes | Yes | Yes |
| TRAP | Yes | Yes | Yes |
| INFORM | No | Yes | Yes |
| Auth | Community | Community | HMAC-SHA1 / HMAC-MD5 |
| Privacy | None | None | AES-128-CFB / DES-CBC |
| VACM | No | No | Yes |

## Quick Start

### 1. Enable in `prj.conf`

```ini
CONFIG_SNMP_AGENT=y
CONFIG_SNMP_VERSION_1=y
CONFIG_SNMP_VERSION_2C=y
CONFIG_SNMP_TRAP_ENABLED=y
# Optional: v3 with authentication and encryption
# CONFIG_SNMP_VERSION_3=y
# CONFIG_SNMP_RATE_LIMIT=y
```

### 2. Initialize in `main.c`

The agent has no global instance: you own one `struct snmp_agent` per SNMP endpoint
(static storage, zero dynamic allocation) and every API takes it explicitly.

```c
#include <snmp/snmp.h>
#include <snmp/snmp_trap.h>

static struct snmp_agent g_agent;           /* caller-owned storage */

int main(void) {
    struct snmp_agent_cfg cfg = {
        .read_community  = "public",
        .write_community = "private",
        .sys_name        = "Zephyr-Node",
        .sys_contact     = "admin@example.com",
    };
    snmp_agent_init(&g_agent, &cfg);        /* domain state + default MIB-II groups */

    snmp_mib2_set_sysname(&g_agent, "Zephyr-Node");   /* setters work after init too */
    snmp_agent_set_read_community(&g_agent, "public");

    snmp_trap_add_destination(&g_agent, "192.168.1.100");
    snmp_agent_start(&g_agent);             /* open UDP :161 listener */

    snmp_trap_send_coldstart(&g_agent);     /* only once the interface has an IP */
}
```

A second agent is just more storage: `static struct snmp_agent g_agent2;` with its own
`cfg.port` (instances sharing an interface need distinct ports) and its own `sysName` —
see `samples/snmp_agent` with `CONFIG_SNMP_SAMPLE_SECOND_INSTANCE=y` for a working demo.
Lifecycle: `init → start → stop → deinit`; APIs called in the wrong state return `-EPERM`.

### 3. Test from Linux

```bash
snmpget   -v2c -c public  <IP> sysDescr.0
snmpwalk  -v2c -c public  <IP> 1.3.6.1.2.1
snmpbulkwalk -v2c -c public <IP> 1.3.6.1

# v3 authPriv
snmpwalk -v3 -u admin -l authPriv \
  -a SHA -A authpass123 -x AES -X privpass123 <IP> 1.3.6.1

# Listen for traps
snmptrapd -f -Lo
```

## Configuration

### Core Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `CONFIG_SNMP_AGENT` | bool | n | Master switch for the SNMP agent subsystem |
| `CONFIG_SNMP_VERSION_1` | bool | y | Enable SNMPv1 support (RFC 1157) |
| `CONFIG_SNMP_VERSION_2C` | bool | y | Enable SNMPv2c support (RFC 3416) |
| `CONFIG_SNMP_VERSION_3` | bool | n | Enable SNMPv3 support (RFC 3412/3414/3415) |
| `CONFIG_SNMP_MAX_PDU_SIZE` | int | 1024 | Maximum PDU size in bytes |
| `CONFIG_SNMP_MAX_OID_LEN` | int | 16 | Maximum OID sub-identifier depth |
| `CONFIG_SNMP_MAX_VARBINDS` | int | 32 | Maximum varbinds per PDU |
| `CONFIG_SNMP_MAX_MIB_NODES` | int | 128 | Maximum registered MIB nodes |
| `CONFIG_SNMP_MAX_TABLES` | int | 8 | Maximum registered MIB tables |
| `CONFIG_SNMP_MAX_INSTANCES` | int | 1 | Concurrently RUNNING `struct snmp_agent` slots (~31 KiB RAM/instance at defaults, ~21 KiB with v3 off) |

### v3 Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `CONFIG_SNMP_V3_ENGINE_BOOTS` | int | 1 | Initial engine boots counter (monotonic) |
| `CONFIG_SNMP_V3_USER_NAME` | string | "admin" | Default SNMPv3 username |
| `CONFIG_SNMP_V3_AUTH_PASS` | string | "authpass123" | Authentication password |
| `CONFIG_SNMP_V3_PRIV_PASS` | string | "privpass123" | Privacy (encryption) password |
| `CONFIG_SNMP_USM_AUTH_SHA` | bool | y | Enable HMAC-SHA1 authentication |
| `CONFIG_SNMP_USM_AUTH_MD5` | bool | n | Enable HMAC-MD5 authentication |
| `CONFIG_SNMP_USM_PRIV_AES` | bool | y | Enable AES-128-CFB privacy |
| `CONFIG_SNMP_USM_PRIV_DES` | bool | n | Enable DES privacy |

### Trap Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `CONFIG_SNMP_TRAP_ENABLED` | bool | y | Enable trap and inform engine |
| `CONFIG_SNMP_TRAP_DEST_COUNT` | int | 3 | Maximum trap destinations |

### Rate Limiting

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `CONFIG_SNMP_RATE_LIMIT` | bool | n | Enable token-bucket rate limiter |
| `CONFIG_SNMP_RATE_LIMIT_RPS` | int | 20 | Maximum requests per second (1-1000) |
| `CONFIG_SNMP_RATE_LIMIT_BURST` | int | 5 | Burst allowance beyond steady-state (0-50) |

## API Reference

### Agent Lifecycle

```c
int  snmp_agent_init(struct snmp_agent *agent, const struct snmp_agent_cfg *cfg);
int  snmp_agent_start(struct snmp_agent *agent);
int  snmp_agent_stop(struct snmp_agent *agent);
int  snmp_agent_deinit(struct snmp_agent *agent);
```
The application owns the `struct snmp_agent` storage (static, zero dynamic allocation;
NULL `cfg` selects the Kconfig defaults). `snmp_agent_init()` zero-fills the storage,
registers the MIB-II default groups and initializes USM/VACM for v3.
`snmp_agent_start()` opens and binds the UDP listener and attaches one socket-service
slot; `snmp_agent_stop()` detaches with the documented quiesce ordering;
`snmp_agent_deinit()` tears down the transport and resets tree, counters and security
state on caller-owned storage. APIs called in the wrong state return `-EPERM`.

### Community Strings (v1/v2c)

```c
int snmp_agent_set_read_community(struct snmp_agent *agent, const char *community);
int snmp_agent_set_write_community(struct snmp_agent *agent, const char *community);
```

### MIB-II System Group Setters

```c
int snmp_mib2_set_sysname(struct snmp_agent *agent, const char *name);
int snmp_mib2_set_syscontact(struct snmp_agent *agent, const char *contact);
int snmp_mib2_set_syslocation(struct snmp_agent *agent, const char *location);
int snmp_mib2_set_sysdescr(struct snmp_agent *agent, const char *descr);
int snmp_set_device_enterprise_oid(struct snmp_agent *agent, const struct snmp_oid *oid);
```

### Custom MIB Registration

```c
/* Register a single scalar node (copied into this agent's tree) */
int snmp_mib_register(struct snmp_agent *agent, const struct snmp_mib_node *node);

/* Register an array of scalar nodes */
int snmp_mib_register_nodes(struct snmp_agent *agent,
                            const struct snmp_mib_node *nodes, size_t count);

/* Register a table (descriptor pointer stored per agent; rows stay app-owned) */
int snmp_mib_register_table(struct snmp_agent *agent, struct snmp_mib_table *table);

/* Link / unlink one application-owned row, serialised against this agent's walks */
int snmp_mib_table_add_row(struct snmp_agent *agent,
                           struct snmp_mib_table *table, struct snmp_table_row *row);
int snmp_mib_table_remove_row(struct snmp_agent *agent,
                              struct snmp_mib_table *table, uint32_t index);
```

### Trap Engine

```c
int snmp_trap_add_destination(struct snmp_agent *agent, const char *ipv4);
int snmp_trap_send_coldstart(struct snmp_agent *agent);
int snmp_trap_send_auth_failure(struct snmp_agent *agent);
int snmp_trap_send(struct snmp_agent *agent,
                   const struct snmp_oid *trap_oid,
                   const struct snmp_varbind *varbinds,
                   uint8_t varbind_cnt,
                   bool is_inform);
```
The notification wire format (v1 / v2c / v3) is selected by Kconfig inside
`snmp_trap_send()`; traps always leave through the agent that owns the notification.

#### SNMPv2-Trap over UDP & Host Setup
When `CONFIG_SNMP_TRAP_FORMAT_V2C=y`, notifications are emitted as RFC 3416 SNMPv2-Trap UDP datagrams to destinations configured with `snmp_trap_add_destination()` (default UDP port 162 or custom port e.g. 1162).

To capture traps on the host:
- **Host Firewall (UFW)**: Allow incoming UDP trap packets:
  ```bash
  sudo ufw allow 162/udp     # or sudo ufw allow 1162/udp
  ```
- **Daemon Authorization (`snmptrapd`)**: Authorize reception in `/etc/snmp/snmptrapd.conf`:
  ```text
  authCommunity log,execute,net public
  # Or disable authorization checks for local lab testing:
  # disableAuthorization yes
  ```
- **Non-Root Capture Alternative**: Run a Python UDP receiver or `tcpdump`:
  ```bash
  sudo tcpdump -i any -nn -vv udp port 162
  ```

## MIB-II Coverage

### System Group (1.3.6.1.2.1.1)

| OID suffix | Name | Access | Notes |
|------------|------|--------|-------|
| 1.0 | sysDescr | RO | Device description |
| 2.0 | sysObjectID | RO | Configurable enterprise OID |
| 3.0 | sysUpTime | RO | Live from `k_uptime_get()` |
| 4.0 | sysContact | RW | Configurable at runtime |
| 5.0 | sysName | RW | Configurable at runtime |
| 6.0 | sysLocation | RW | Configurable at runtime |
| 7.0 | sysServices | RO | Fixed value (72) |

### SNMP Group (1.3.6.1.2.1.11)

| Counter | Access | Notes |
|---------|--------|-------|
| snmpInPkts | RO | Incremented per received PDU |
| snmpOutPkts | RO | Incremented per transmitted response |
| snmpInBadVersions | RO | Version mismatch counter |
| snmpInBadCommunityNames | RO | Community string mismatch |
| snmpInBadCommunityUses | RO | Community use mismatch |
| snmpInASNParseErrs | RO | BER decode errors |
| snmpSilentDrops | RO | Rate-limited or unauthorized drops |
| snmpEnableAuthenTraps | RW | Trap authentication toggle |

All 30 standard SNMP group counters plus `snmpEnableAuthenTraps` are implemented.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                     Application                      │
│  main.c  ───────── snmp.h (public API) ─────────     │
└────────────────────────┬────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────┐
│                   snmp_service.c                     │
│              UDP :161 listener + rate limit          │
└────────────────────────┬────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────┐
│                    snmp_core.c                       │
│            PDU dispatch, version routing             │
│         ┌──────────┬──────────┬──────────┐           │
│         │  v1/2c   │    v3    │  traps   │           │
│         │ dispatch │ USM/VACM │  :162    │           │
│         └────┬─────┴────┬─────┴────┬─────┘           │
└──────────────┼──────────┼──────────┼─────────────────┘
               │          │          │
┌──────────────▼──────┐┌──▼─────────▼──┐┌────────────┐
│    snmp_mib.c       ││ snmp_usm.c    ││snmp_trap.c │
│    MIB tree engine  ││ snmp_vacm.c   ││ :162 send  │
│    + MIB-II system  ││ PSA/mbedtls   ││ engine     │
└──────────┬──────────┘└───────────────┘└────────────┘
           │
┌──────────▼──────────────────────────────────────────┐
│                   snmp_ber.c                         │
│              ASN.1 BER encode/decode                 │
└─────────────────────────────────────────────────────┘
```

### Ultra-Low Stack Frame Architecture
In standard embedded SNMP implementations, multi-variable SET transactions (Two-Phase Commit tracking) and GETBULK sweep buffers require sizable local arrays on the execution stack. In `zephyr-snmp`, all temporary transaction buffers and GETBULK repetition states are consolidated into the instance-level `inst->scratch` mutual-exclusion union inside `struct snmp_agent`:

- **Stack Frame Reduction**: Reduces the stack frame of `snmp_mib_dispatch()` from **~9.8 KiB down to only 52 bytes**.
- **Thread Stack Safety**: Completely protects constrained RTOS service thread stacks (such as Zephyr's `net_sockets_service` thread, typically sized at 2–4 KiB with `CONFIG_NET_SOCKETS_SERVICE_STACK_SIZE=4096`).
- **Zero Dynamic Allocation**: Allocates no heap memory while avoiding stack overflows during deep multi-varbind packet processing.

## Security Considerations

- **Community strings**: v1/v2c transmit community strings in plaintext. Use v3 for production deployments requiring confidentiality.
- **Rate limiting**: Enable `CONFIG_SNMP_RATE_LIMIT` to protect against CPU exhaustion from SNMP floods. Silently dropped requests increment `snmpSilentDrops`.
- **Engine boots**: Persist `CONFIG_SNMP_V3_ENGINE_BOOTS` across reboots to prevent SNMPv3 replay attacks (RFC 3414 §5.1.3).
- **VACM**: v3 access control restricts MIB access per user/group. Configure appropriately for your security model.
- **Auth algorithms**: SHA-1 is preferred over MD5 for v3 authentication. MD5 is provided only for legacy NMS compatibility.
- **Privacy**: AES-128-CFB is preferred over DES. DES is deprecated and should only be used for legacy interoperability.

## Memory Footprint

| Configuration | FLASH | RAM | Notes |
|---------------|-------|-----|-------|
| v1/v2c only | ~270 KB | ~110 KB | No crypto dependencies |
| v1/v2c + v3 | ~280 KB | ~114 KB | PSA Crypto + mbedtls overhead |
| + Rate limit | ~0.5 KB | ~12 B | Token bucket state only |

- **Zero Dynamic Allocation / Zero Heap**: All agent state is statically allocated inside caller-owned `struct snmp_agent` (~23.8 KiB for v1/v2c, ~33.3 KiB with v3). Never calls `malloc` or `k_malloc`.
- **Ultra-Low Stack Frame**: The instance `scratch` union stores Two-Phase Commit transaction items and GETBULK working buffers, reducing dispatch stack usage from 9.8 KiB to 52 B and allowing safe execution within standard Zephyr socket service thread stacks (`CONFIG_NET_SOCKETS_SERVICE_STACK_SIZE=4096`).

## Testing

### Prerequisites

- Linux with `net-snmp` utilities installed
- Zephyr board with network connectivity (QEMU or hardware)

### Basic Tests

```bash
# System group
snmpget -v2c -c public <IP> 1.3.6.1.2.1.1.1.0      # sysDescr
snmpget -v2c -c public <IP> 1.3.6.1.2.1.1.3.0      # sysUpTime
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.1          # Full system group

# SNMP counters
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.11         # SNMP group

# GetBulk
snmpbulkwalk -v2c -c public <IP> 1.3.6.1.2.1

# SET operations
snmpset -v2c -c private <IP> sysContact.0 s "new@corp.com"
```

### v3 Tests

```bash
# noAuthNoPriv
snmpwalk -v3 -u admin -l noAuthNoPriv <IP> 1.3.6.1.2.1

# authNoPriv
snmpwalk -v3 -u admin -l authNoPriv -a SHA -A authpass123 <IP> 1.3.6.1.2.1

# authPriv
snmpwalk -v3 -u admin -l authPriv \
  -a SHA -A authpass123 -x AES -X privpass123 <IP> 1.3.6.1.2.1
```

### Rate Limit Test

```bash
# With CONFIG_SNMP_RATE_LIMIT=y, CONFIG_SNMP_RATE_LIMIT_RPS=20
# Rapid requests should see silent drops
for i in $(seq 1 50); do
  snmpget -v2c -c public <IP> sysDescr.0 &
done
wait
# Check snmpSilentDrops counter
snmpget -v2c -c public <IP> 1.3.6.1.2.1.11.25.0
```

### Hardware-in-the-Loop (HIL) Physical Validation

The agent has undergone comprehensive physical Hardware-in-the-Loop (HIL) automated validation on target microcontrollers:
- **Target Hardware**: STMicroelectronics **NUCLEO-H743ZI** / **NUCLEO-H753ZI** (ARM Cortex-M7 @ 480 MHz, LAN8742A 10/100 Mbps RMII Ethernet PHY).
- **Validation Score**: **100% PASS (23/23 test cases)**.
- **Automated Test Matrix**:
  1. **Scalar GET/GETNEXT**: Verified across standard MIB-II (`sysDescr`, `sysUpTime`, `sysContact`) and private SMIv2 nodes (`sensorValue`, `sensorHumidity`, `sensorDescription`, `sensorStatusOid`).
  2. **Two-Phase Commit (2PC) SET Transactions**: Atomic multi-varbind SET operations with reserve/commit/rollback semantics validated for hardware LED actuation (`ledState`) and range limit boundary guards (`badValue` handling).
  3. **Lexicographical Tree Walks**: Full subtree inspection via `snmpwalk` over standard MIB-II (`1.3.6.1.2.1`) and private enterprise subtrees (`1.3.6.1.4.1.54321.1`).
  4. **GETBULK Transfer & Repetition Sweeps**: Multi-repetition transfers (`snmpbulkget`, `snmpbulkwalk`) over multidimensional `sensorTable` entries, validating dynamic pruning and zero heap allocations.
  5. **SNMPv2-Trap Generation**: Asynchronous event-driven notifications dispatched to host NMS on hardware GPIO interrupts (`sw0` User Button push) with `sysUpTime`, `snmpTrapOID` (`buttonPressed`), and bound payload varbinds (`buttonCounter`, `ledState`).
  6. **SNMPv1 Backward Compatibility**: Verification of RFC 1157 PDU exchanges, error status mappings (`noSuchName`), and Trap-v1 emission.
  7. **UART Telemetry Correlation**: Real-time cross-validation between network-level SNMP responses and target console shell telemetry (`app led`, `app button`, `app sensor`).


## RFC Compatibility

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| RFC 1157 | SNMPv1 | Full | GET, GETNEXT, SET, TRAP |
| RFC 1907 | MIB-II snmp group | Full | 30 counters + authenTraps |
| RFC 3412 | Message Processing and Dispatching | Full | v3 message routing |
| RFC 3414 | User-based Security Model | Full | Auth + privacy, key localization |
| RFC 3415 | View-based Access Control Model | Full | Admin/readonly groups |
| RFC 3416 | Protocol Operations v2 | Full | GETBULK, INFORM |
| RFC 3418 | MIB for SNMP | Full | Counter64, Unsigned32 types |
| RFC 2576 | Coexistence v1/v2/v3 | Partial | Community-to-securityName mapping |

## Known Limitations

- No SNMPv3 context engine support (single context only)
- No proxy forwarding
- No MIB-II interfaces group (ifTable/ifXTable) — application must register
- No persistent storage for v3 engine boots or user credentials
- Rate limiter uses a simple token bucket without per-source tracking
- Trap destinations configured at runtime only (no persistence)
- Maximum one community string each for read and write access

## Contributing

Contributions are welcome. Please open an issue or pull request at the project repository.

## License

Apache-2.0. See the license header in each source file.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.
