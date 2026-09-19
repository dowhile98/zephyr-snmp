# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-09-18

### Fixed

- **CRITICAL (SEC-01)**: Fixed buffer overflow in SNMPv3 scopedPDU encryption where 992-byte ciphertext was written into 32-byte community buffer. Dedicated `priv_ciphertext` field with bounds checking added to `struct snmp_v3_scoped_pdu`.
- **HIGH (SEC-02)**: Eliminated thread stack exhaustion in SNMPv3 message decoding and scopedPDU serialization. Replaced redundant multi-kilobyte nested scratch buffers with zero-copy/in-place BER body decoding (`snmp_ber_decode_pdu_body`).
- **HIGH (SEC-03)**: Added mutex protection (`g_snmp_ber_enc_mutex`) to `snmp_ber_encode_pdu` preventing race conditions between concurrent UDP socket listener and trap sender threads.
- **HIGH**: Fixed MIB table lexicographical traversal. Implemented column-first, row-second ordering matching RFC 1157 / RFC 3416 requirements (`snmpwalk` / `snmpbulkwalk` now walk tabular OIDs monotonically).
- **HIGH**: Fixed unified candidate evaluation in `snmp_mib_get_next()` across both scalar nodes and registered tabular structures.
- **HIGH**: Added full table column SET support in `snmp_mib_set()` with row/column index parsing and callback routing.
- **MEDIUM**: Added SNMPv1 exception conversion in `snmp_mib_dispatch()`. MIB exceptions (`noSuchObject`, `noSuchInstance`, `endOfMibView`) are translated into RFC 1157 `error_status = 2 (noSuchName)` when servicing v1 requests.
- **MEDIUM**: Fixed IPv6 socket address truncation in `snmp_service.c` by upgrading storage to `struct sockaddr_storage`.
- **MEDIUM**: Added `SO_BROADCAST` socket option when sending subnet broadcast traps.
- **MEDIUM**: Fixed authoritative SNMPv3 engine ID handling in trap generation (`snmp_usm_get_engine_id()`).
- **MEDIUM**: Enforced RFC 3412 `msgFlags` semantics: response, trap, and report PDUs clear the `reportableFlag` bit (0x04).
- **MEDIUM**: Decoupled proprietary hardware names ("BRIGHTC-B1", "DAECGE") and moved proprietary MIB definition to `samples/brightc_sensor/`.

### Added

- Clean standalone sample application in `samples/snmp_agent/` with full Kconfig, CMake, `sample.yaml`, and documentation.
- Runtime user addition in VACM: `snmp_vacm_add_user()`.
- Engine ID accessor: `snmp_usm_get_engine_id()`.
- Dedicated SNMPv3 trap sender: `snmp_trap_send_v3()`.
- Explicit subsystem deinitialization: `snmp_agent_deinit()`.
- Single MIB node registration: `snmp_mib_register()` supporting in-place update for existing OIDs.
- Coding style configuration `.clang-format` matching Zephyr RTOS kernel standards.
- Comprehensive unit test suite covering scalar and table MIB operations (`tests/unit/test_mib.c`).
- GitHub Actions CI workflow supporting `native_sim` and `qemu_x86`.

---

## [0.1.0] — 2026-01-01

### Added

- Initial SNMP v1 support (GET, GETNEXT, SET, TRAP-v1).
- SNMP v2c support (GET, GETNEXT, GETBULK, SET, TRAP-v2c, INFORM).
- SNMP v3 support (USM with HMAC-SHA1/MD5, AES-128-CFB/DES-CBC, VACM).
- MIB-II system group (sysDescr, sysObjectID, sysUpTime, sysContact, sysName, sysLocation, sysServices).
- MIB-II snmp group (30+ standard RFC 1907 counters).
- Enterprise MIB registration API.
- Trap/Inform engine with configurable destinations.
- Kconfig-based build configuration.
- Zero dynamic allocation design.
- Socket Service integration for UDP :161 listener.

[1.0.0]: https://github.com/daecge/zephyr-snmp/releases/tag/v1.0.0
[0.1.0]: https://github.com/daecge/zephyr-snmp/releases/tag/v0.1.0
