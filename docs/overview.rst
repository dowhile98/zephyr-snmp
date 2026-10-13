Overview
========

The **zephyr-snmp** module provides an RFC-compliant, fully native Simple Network Management Protocol (SNMP) agent for Zephyr RTOS.

Key Features
------------

- **Zero Dynamic Allocation**: 100% static memory allocation bounded at compile time via Kconfig (``CONFIG_SNMP_MAX_*``). Never uses dynamic heaps or ``malloc`` in ``src/``.
- **Multi-Instance Support**: Re-entrant architecture driven by explicit ``struct snmp_agent *`` handles. Multiple independent agents can run concurrently on different ports or network interfaces.
- **Protocol Versions**:
  - **SNMPv1 (RFC 1157)**: Community string authentication, GET, GETNEXT, SET, and Trap operations with automatic RFC exception mapping.
  - **SNMPv2c (RFC 1901, RFC 3416)**: GET, GETNEXT, GETBULK (with dynamic repetition pruning and tooBig fallback), SET (2PC), and SNMPv2-Trap.
  - **SNMPv3 (RFC 3412, RFC 3414, RFC 3415)**: User-Based Security Model (USM) and View-Based Access Control Model (VACM).
- **USM Cryptographic Security**:
  - Authentication: HMAC-MD5-96, HMAC-SHA-96, and HMAC-SHA-256 (RFC 7860).
  - Privacy: CBC-DES and AES-128 CFB (RFC 3826).
  - Streaming password-to-key localization (RFC 3414 A.2) and anti-replay window checking with ``usmStatsNotInTimeWindows.0`` Report-PDUs.
- **VACM Access Control**: Four-table access model (Security-to-Group, Access, View Tree Family, Context) with subtree wildcard mask matching.
- **MIB Engine**:
  - :math:`O(\log N)` binary search node lookup (``snmp_oid_compare``) over sorted MIB nodes.
  - Two-Phase Commit (2PC) transactional SET engine ensuring atomic configuration changes.
  - Compound table indexing (``struct snmp_table_index``) supporting multi-subid keys (IPv4 addresses, TCP connection tuples).
- **MIB-II Network Subsystem (RFC 1213 / RFC 2863)**:
  - System (``1.3.6.1.2.1.1``), SNMP (``1.3.6.1.2.1.11``), Interfaces (``ifTable`` with 22 columns), IP (``ipAddrTable`` + stats), ICMP, TCP (``tcpConnTable`` + stats), and UDP (``udpTable`` + stats).
  - Native integration with Zephyr's ``net_if`` and ``net_stats`` subsystems.

Architecture Diagram
--------------------

.. code-block:: text

   +-----------------------------------------------------------+
   |               Application / Enterprise MIBs               |
   |       (LED / Button / Sensor nodes, Trap triggers)        |
   +-----------------------------+-----------------------------+
                                 |
                                 v
   +-----------------------------------------------------------+
   |                MIB Engine & Security Layer                |
   |   - MIB Engine (snmp_mib.c): O(log N) lookup, 2PC SET     |
   |   - MIB-II Network Subsystem (snmp_mib2.c): RFC 1213/2863 |
   |   - USM Security (snmp_usm.c): HMAC / AES / Timeliness    |
   |   - VACM Access Control (snmp_vacm.c): View filtering     |
   +-----------------------------+-----------------------------+
                                 |
                                 v
   +-----------------------------------------------------------+
   |                Core Protocol & Codec Layer                |
   |   - Core Dispatcher (snmp_core.c): PDU processing         |
   |   - ASN.1 BER Codec (snmp_ber.c): Zero-copy TLV parsing   |
   |   - Notification Engine (snmp_trap.c): Traps & Informs    |
   +-----------------------------+-----------------------------+
                                 |
                                 v
   +-----------------------------------------------------------+
   |                Transport & Zephyr OS Layer                |
   |   - Socket Service (snmp_service.c): net_socket_service   |
   |   - Zephyr BSD Sockets (UDP :161), Net Stack & Stats      |
   +-----------------------------------------------------------+
