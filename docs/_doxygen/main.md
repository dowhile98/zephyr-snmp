# zephyr-snmp — Embedded SNMP Agent (v1/v2c/v3) for Zephyr RTOS {#mainpage}

Welcome to the API and architecture reference documentation for the **zephyr-snmp** module.

## 1. Overview

`zephyr-snmp` is an RFC-compliant, fully native Simple Network Management Protocol (SNMP) agent designed specifically for **Zephyr RTOS**. It operates as an out-of-tree Zephyr module (`module.yml` module name `snmp`) and provides complete support for SNMPv1, SNMPv2c, and SNMPv3 (USM / VACM), along with RFC 1213 / RFC 2863 MIB-II network instrumentation.

Key attributes:
- **Zero Dynamic Allocation**: 100% static, deterministic memory allocation bounded at compile time via Kconfig (`CONFIG_SNMP_MAX_*`). No calls to `malloc`, `k_malloc`, or dynamic heaps anywhere in `src/`.
- **Multi-Instance Support**: Full re-entrancy through explicit `struct snmp_agent *` handles. Multiple independent agents can run concurrently across different network interfaces, VRFs, or ports.
- **Transactional Two-Phase Commit (2PC)**: Complete ACID-like rollback semantics for multi-variable SET operations per RFC 3416.
- **Fast O(log N) MIB Engine**: Sorted binary search lookups for registered scalar nodes and efficient compound-indexed table walks.
- **Native Zephyr Networking**: Built upon Zephyr's `net_socket_service` and integrated with `net_if` and `net_stats` subsystems.

---

## 2. Architecture & Design Principles

### 2.1 Zero Dynamic Allocation Invariant
In mission-critical embedded systems and hard real-time environments, memory fragmentation and heap exhaustion can compromise system stability. `zephyr-snmp` enforces a strict compile-time bounded memory model:
- All protocol buffers (`rx_buf`, `tx_buf`), PDU representations, MIB node descriptors, USM user registries, and VACM view tables reside directly within the `struct snmp_agent` state structure.
- Variable bindings and sub-identifier arrays are bounded by configurable limits (`CONFIG_SNMP_MAX_VARBINDS`, `CONFIG_SNMP_MAX_OID_LEN`).
- Verification: Production object files (`src/*.o`) are validated to ensure zero mutable file-scope global symbols outside of platform-mandated socket service structures.

### 2.2 Multi-Instance Aggregate Root
All mutable domain state is encapsulated in `struct snmp_agent`. The public API is instance-explicit:

```c
struct snmp_agent agent;
struct snmp_agent_cfg cfg = {
    .port = 161,
    .community_ro = "public",
    .community_rw = "private",
};

snmp_agent_init(&agent, &cfg);
snmp_mib_register(&agent, ...);
snmp_agent_start(&agent);
```

There are no singleton references or implicit default agents. MIB node callbacks receive `struct snmp_agent *agent` as their first parameter.

---

## 3. Protocol Operations

`zephyr-snmp` supports all major SNMP protocol versions:

### 3.1 SNMPv1 (RFC 1157)
- Protocol operations: `GET`, `GETNEXT`, `SET`, and Trap generation.
- Community-string-based access control.
- Faithful error status mapping: protocol exceptions like `noSuchObject` and `noSuchInstance` are automatically mapped to SNMPv1 `noSuchName`.

### 3.2 SNMPv2c (RFC 1901, RFC 3416)
- Enhanced PDU handling: `GET`, `GETNEXT`, `GETBULK`, `SET`, and `SNMPv2-Trap`.
- **GETBULK Pruning & Fallback (RFC 3416 §4.2.3)**: When a large GETBULK response exceeds the MTU / buffer limits (`-ENOBUFS`), repetitions are dynamically pruned down to `non-repeaters`. If even non-repeaters exceed buffer space, an RFC-compliant `tooBig` response is generated.
- Detailed exception reporting (`noSuchObject`, `noSuchInstance`, `endOfMibView`).

### 3.3 SNMPv3 USM & VACM (RFC 3412, RFC 3414, RFC 3415)
- **User-Based Security Model (USM RFC 3414 / RFC 7860)**:
  - Authentication: HMAC-MD5-96, HMAC-SHA-96, and HMAC-SHA-256 (RFC 7860).
  - Privacy / Encryption: CBC-DES and AES-128 CFB (RFC 3826).
  - Key Localization: Password-to-key streaming localization algorithms (RFC 3414 Appendix A.2).
  - Timeliness & Anti-Replay: SnmpEngineBoots / SnmpEngineTime window validation; returns `usmStatsNotInTimeWindows.0` Report-PDUs on clock skew; continuous uptime wrap guards.
- **View-Based Access Control Model (VACM RFC 3415)**:
  - Security-to-Group, Access, View Tree Family, and Context tables.
  - Subtree wildcard mask matching (`view_mask`) for fine-grained OID access policies.

---

## 4. MIB Tree Engine & Transactional SET (2PC)

### 4.1 O(log N) Binary Search MIB Lookup
The MIB engine maintains registered OID nodes in lexicographical order:
- `snmp_mib_find_node_idx()` performs an $O(\log N)$ binary search using `snmp_oid_compare()`.
- Guarantees worst-case lookup in $\le 7$ comparisons for 128 nodes, preventing CPU starvation during high packet bursts.
- Candidate searches in `snmp_mib_get_next()` leverage binary search to jump directly to the closest candidate.

### 4.2 Two-Phase Commit (2PC) Transaction Engine
Per RFC 3416, a SET PDU must succeed completely or have no effect (all-or-nothing atomicity):
1. **Phase 1 (Reserve / Test)**: The agent validates all varbinds in the request across all target nodes. If any varbind fails validation (type mismatch, range error, notWritable, etc.), the operation is aborted with the corresponding error status and index without applying any state changes.
2. **Phase 2 (Commit or Undo)**: If all validations succeed, the commit phase persists the changes. If an unexpected commit failure occurs on an individual node, preceding commits are rolled back using registered undo handlers.

### 4.3 Generalized Compound Table Indexing
`zephyr-snmp` supports both scalar rows and multi-variable compound table keys via `struct snmp_table_index`:
- Arbitrary composite keys (e.g., IPv4 addresses with 4 sub-identifiers, or TCP connections with 10 sub-identifiers).
- `snmp_table_index_compare()` provides lexicographical multi-subid ordering.
- Full backward compatibility for legacy single-integer scalar indices.

---

## 5. MIB-II Standard Network Subsystem

The agent provides built-in instrumentation for RFC 1213 / RFC 2863 / RFC 4293 MIB-II groups via `snmp_mib2.h`:

- **System Group (`1.3.6.1.2.1.1`)**: `sysDescr`, `sysObjectID`, `sysUpTime`, `sysContact`, `sysName`, `sysLocation`, `sysServices`.
- **SNMP Group (`1.3.6.1.2.1.11`)**: Full SNMP engine counters (`snmpInPkts`, `snmpOutPkts`, `snmpInBadVersions`, `snmpInBadCommunityNames`, `snmpInBadCommunityUses`, `snmpInASNParseErrs`, etc.).
- **Interfaces Group (`1.3.6.1.2.1.2`)**: `ifNumber` and `ifTable` (22 columns including descriptions, types, MTU, speed, physical MAC addresses, admin/oper status, and packet/octet traffic counters) bound to Zephyr's `net_if` and `net_stats`.
- **IP Group (`1.3.6.1.2.1.4`)**: RFC 1213 IP scalars and `ipAddrTable` indexed by IPv4 address compound keys (`1.3.6.1.2.1.4.20.1.*.<ip0>.<ip1>.<ip2>.<ip3>`).
- **ICMP Group (`1.3.6.1.2.1.5`)**: RFC 1213 ICMP in/out messages, error counters, unreachable, echo/reply counters.
- **TCP Group (`1.3.6.1.2.1.6`)**: TCP algorithm settings, connection metrics, segment counters, and `tcpConnTable`.
- **UDP Group (`1.3.6.1.2.1.7`)**: UDP in/out datagram counters, port error counters, and `udpTable`.

---

## 6. Modules and Doxygen Groups

The API is structured into the following Doxygen documentation groups:

| Group | Identifier | Description |
|---|---|---|
| **Public Agent API** | @ref snmp_api | Initialization, configuration, lifecycle, and MIB node registration |
| **Core Protocol Engine** | @ref snmp_core | Packet dispatcher, PDU parsing, request processing, and error mapping |
| **ASN.1 BER Codec** | @ref snmp_ber | Tag, length, and value encoders and decoders |
| **MIB Engine & 2PC** | @ref snmp_mib | MIB registration, $O(\log N)$ lookup, table walking, and 2PC transactions |
| **MIB-II Subsystem** | @ref snmp_mib2 | RFC 1213 / RFC 2863 standard network groups and Zephyr OS bindings |
| **USM Security Model** | @ref snmp_usm | RFC 3414 / RFC 7860 authentication, encryption, and key localization |
| **VACM Access Control** | @ref snmp_vacm | RFC 3415 view-based access control and subtree mask matching |
| **Socket Service** | @ref snmp_service | Zephyr `net_socket_service` adapter and UDP transport |
| **Notification Engine** | @ref snmp_trap | SNMPv1 traps and SNMPv2c/v3 Inform / Trap notifications |

---

## 7. Sample Application

See `samples/snmp_agent` for a complete reference application demonstrating:
- Initialization with Zephyr network stack and DHCP.
- MIB-II network group registration (`snmp_mib2_register_all()`).
- Custom enterprise MIB registration (LED control with 2PC SET, button states, sensor telemetry).
- Asynchronous SNMP trap emission triggered by hardware events.
