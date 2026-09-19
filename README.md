# Zephyr SNMP Agent

[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](CHANGELOG.md)
[![Zephyr](https://img.shields.io/badge/Zephyr-RTOS-3C8CB4.svg?logo=zephyr)](https://zephyrproject.org/)

Embedded SNMP agent (v1, v2c, v3) for Zephyr RTOS. Self-contained, zero dynamic allocation, designed for constrained devices.

## Table of Contents

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

```c
#include <snmp/snmp.h>
#include <snmp/snmp_trap.h>

int main(void) {
    snmp_agent_init();

    snmp_mib2_set_sysname("Zephyr-Node");
    snmp_mib2_set_syscontact("admin@example.com");
    snmp_set_read_community("public");
    snmp_set_write_community("secret");

    snmp_trap_add_destination("192.168.1.100");
    snmp_trap_send_coldstart();
}
```

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
int snmp_agent_init(void);
int snmp_agent_deinit(void);
```
Initializes the MIB tree, registers default MIB-II nodes, starts the UDP :161 listener, and initializes USM/VACM for v3. `snmp_agent_deinit()` unregisters the socket service and stops the agent.

### Community Strings (v1/v2c)

```c
int snmp_set_read_community(const char *community);
int snmp_set_write_community(const char *community);
```

### MIB-II System Group Setters

```c
int snmp_mib2_set_sysname(const char *name);
int snmp_mib2_set_syscontact(const char *contact);
int snmp_mib2_set_syslocation(const char *location);
int snmp_mib2_set_sysdescr(const char *descr);
int snmp_set_device_enterprise_oid(const struct snmp_oid *oid);
```

### Custom MIB Registration

```c
/* Register a single scalar node */
int snmp_mib_register(const struct snmp_mib_node *node);

/* Register an array of scalar nodes */
int snmp_mib_register_nodes(const struct snmp_mib_node *nodes, size_t count);

/* Register a 2D table */
int snmp_mib_register_table(struct snmp_mib_table *tbl,
                            const struct snmp_oid *base_oid,
                            uint8_t col_count,
                            snmp_table_get_cb_t get_cb,
                            snmp_table_set_cb_t set_cb);

/* Add a row index to a registered table */
int snmp_mib_table_add_row(struct snmp_mib_table *tbl, uint32_t row_idx);
```

### Trap Engine

```c
int snmp_trap_add_destination(const char *ip_addr);
int snmp_trap_send_coldstart(void);
int snmp_trap_send_auth_failure(void);
int snmp_trap_send(const struct snmp_oid *trap_oid,
                   const struct snmp_varbind *varbinds,
                   uint8_t varbind_cnt,
                   bool is_inform);
int snmp_trap_send_v3(const struct snmp_oid *trap_oid,
                     const struct snmp_varbind *varbinds,
                     uint8_t varbind_cnt,
                     bool is_inform);
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

All memory is statically allocated. Zero heap usage. GetBulk scratch buffers use static memory to avoid stack overflow.

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
snmpset -v2c -c secret <IP> sysContact.0 s "new@corp.com"
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
