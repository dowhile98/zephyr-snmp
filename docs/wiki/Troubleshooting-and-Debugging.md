# Troubleshooting and Debugging Guide

This document catalogs common issues encountered during development, integration, and deployment of the Zephyr SNMP agent, accompanied by root-cause analysis and verified solutions.

---

## 1. Network Communication and Timeout Issues

### Symptom: `Timeout: No Response from <IP>`

```text
$ snmpget -v2c -c public 192.168.16.100 1.3.6.1.2.1.1.1.0
Timeout: No Response from 192.168.16.100
```

#### Causes and Diagnostic Steps:

1. **Incorrect Community String (RFC Compliant Silent Drop)**:
   - Per RFC 1213 and RFC 3416, if an incoming SNMP request carries a community string that does not match `CONFIG_SNMP_COMMUNITY_READ` or `CONFIG_SNMP_COMMUNITY_WRITE`, the agent **must not return an error packet**. Instead, it silently drops the datagram and increments the `snmpInBadCommunityNames` counter.
   - **Fix**: Verify that the community string passed to `-c` matches `prj.conf` exactly.

2. **Ethernet Carrier Link Down**:
   - If the Ethernet cable is disconnected or link autonegotiation has not completed, the MAC/PHY cannot process or transmit Ethernet frames.
   - **Diagnostic in serial console**:
     ```text
     <inf> snmp_sample: Ethernet Carrier  : LINK DOWN (check Ethernet cable)
     ```
   - **Fix**: Connect the RJ45 cable to an active switch/router and confirm the console log:
     ```text
     <inf> phy_mii: PHY (0) Link speed 100 Mb, full duplex
     ```

3. **Unassigned IP or DHCP Lease Timeout**:
   - If the agent is configured for DHCPv4 client operation but the DHCP server does not respond within the timeout, the stack falls back to the static address configured in `CONFIG_NET_CONFIG_MY_IPV4_ADDR` (default `192.0.2.1`).
   - **Diagnostic via Zephyr Shell**:
     ```text
     uart:~$ net iface
     ```
     Inspect the active `IPv4 unicast addresses` section.

4. **Insufficient ZVFS Poll Descriptor Budget (`CONFIG_ZVFS_POLL_MAX`)**:
   - When running multiple SNMP agent instances or dual-stack IPv4/IPv6, each agent requires `SNMP_SVC_FDS` descriptors (`2` for IPv4+IPv6, `1` for IPv4 only).
   - If `CONFIG_ZVFS_POLL_MAX` is too low, socket polling registrations fail. A compile-time `BUILD_ASSERT` validates this:
     $$\text{CONFIG\_ZVFS\_POLL\_MAX} \ge \text{CONFIG\_SNMP\_MAX\_INSTANCES} \times \text{SNMP\_SVC\_FDS} + 1$$
   - **Fix**: For 2 instances with IPv6, set `-DCONFIG_ZVFS_POLL_MAX=5` (default 3 is insufficient).

---

## 2. Zephyr Kernel Panics and Fatal Faults

### Symptom: `ZEPHYR FATAL ERROR 2: Stack overflow`

```text
[00:00:01.810,000] <err> os: ***** STACK OVERFLOW *****
[00:00:01.810,000] <err> os: Current thread: 0x20000840 (net_mgmt)
[00:00:01.810,000] <err> os: Faulting instruction at 0x08012a4c
[00:00:01.810,000] <err> os: Fatal fault in ISR! Jumping to fatal handler
```

#### Root Cause:
The Zephyr network management event thread (`net_mgmt`) defaults to a small stack size (768 to 1024 bytes). Executing complex operations directly inside `net_mgmt_event_handler` (such as extensive `LOG_INF` formatting, string copies, or sending UDP traps) causes instantaneous stack overflow.

#### Solutions:
1. Increase the network management event stack size in `prj.conf`:
   ```ini
   CONFIG_NET_MGMT_EVENT_STACK_SIZE=2048
   ```
2. **Best Architectural Practice**: Do not execute network socket or trap logic inside the `net_mgmt` callback. Signal a synchronization semaphore (`k_sem_give(&s_ip_ready_sem)`) and perform agent startup in thread context (`main()`).

---

### Symptom: Memory Fault / HardFault with Deferred Logging

#### Root Cause:
In deferred logging mode (`CONFIG_LOG_MODE_DEFERRED=y`), format strings referencing stack-allocated buffers may be processed after the calling function has returned, referencing deallocated memory.

#### Solution:
During debugging and integration, enable immediate logging mode in `prj.conf`:
```ini
CONFIG_LOG=y
CONFIG_LOG_MODE_IMMEDIATE=y
```

---

## 3. SNMP Protocol Errors and Diagnostic Mapping

| Protocol Error Code | RFC Symbol | Root Cause | Solution |
| :--- | :--- | :--- | :--- |
| `noSuchName` / `noSuchInstance` | `SNMP_ERR_NO_SUCH_NAME` | Scalar OID requested without `.0` suffix (e.g. `...54321.1.1` instead of `...54321.1.1.0`), or unknown OID. | Append `.0` to scalar OIDs. Verify OID is registered in MIB tree. |
| `badValue` | `SNMP_ERR_BAD_VALUE` | In a SET operation, the submitted value violates allowable semantic bounds. | Check allowable ranges in `set_cb` / `set_tx_cb`. |
| `wrongType` | `SNMP_ERR_WRONG_TYPE` | ASN.1 syntax mismatch (e.g., sending `OCTET STRING` to an `INTEGER` node). | Ensure CLI argument type matches node type (`i`, `u`, `s`). |
| `notWritable` | `SNMP_ERR_NOT_WRITABLE` | SET attempted against a read-only node (`set_cb == NULL`). | Implement `set_cb` or `set_tx_cb` if variable is writable. |
| `authorizationError` | `SNMP_ERR_AUTHORIZATION_ERR` | VACM access control check failed for user/view/security level. | Check VACM view masks and access levels in `snmp_vacm.c`. |
| `genErr` | `SNMP_ERR_GEN_ERR` | Internal callback execution returned negative errno or error. | Inspect device driver return codes in callback implementation. |

---

## 4. Host Trap Reception on Unprivileged Ports

On POSIX/Linux hosts, binding to UDP ports below 1024 (including standard SNMP trap port 162) requires root privileges (`sudo`).

To capture traps without root permissions:
1. Configure an unprivileged destination port in `prj.conf`:
   ```ini
   CONFIG_SNMP_TRAP_PORT=1162
   ```
2. Run a lightweight Python listener on the management host:

```python
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 1162))
print("Listening for SNMP Traps on UDP :1162...")

while True:
    data, addr = sock.recvfrom(2048)
    print(f"Trap received ({len(data)} bytes) from {addr}")
    print(f"Hex payload: {data.hex()}\n")
```

