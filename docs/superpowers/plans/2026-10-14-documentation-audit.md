# Documentation Audit and Comprehensive Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Conduct an exhaustive technical documentation audit and modernization across the zephyr-snmp module, eliminating all legacy DAECGE references, translating 100% of documentation to English, aligning wiki and README documentation with the multi-instance zero-heap codebase, completing Doxygen API documentation with zero warnings under `WARN_AS_ERROR=YES`, and producing a formal audit report.

**Architecture:** The implementation decomposes into 10 bite-sized, sequential tasks structured around verification against the actual source code. Changes start with global legal/ownership normalization and root documentation, progress through core wiki architecture/MIB/protocol/troubleshooting guides, sample docs, Doxygen header completion, automated gate validation (host tests, Doxygen with `WARN_AS_ERROR=YES`, link checking, clang-format), and culminate in the required audit report at `temp/documentation-audit.md`.

**Tech Stack:** C (C99 / Zephyr RTOS), ASN.1 BER, SNMPv1/v2c/v3 (RFC 1157, 3412, 3414, 3415, 3416, 3418, 3826, 7860), Doxygen 1.9.6+, Markdown, Mermaid.js, Zephyr Ztest, CMake/CTest, clang-format 23.1.1.

**Spec:** `task.md`

## Global Constraints

- Source code is the absolute single source of truth: never document features not backed by existing code (task.md §1, §37).
- Mandatory language is English: 100% of wiki, README, source doc comments, MIB text descriptions, and Doxygen must be English (task.md §2).
- Zero DAECGE references: eliminate all occurrences of DAECGE/daecge across author, copyright, metadata, docs, and sample MIBs; normalize author and organization to "StructCore Embedded" (task.md §3, §4, §31, §32).
- Strict zero-dynamic-memory model: preserve and accurately document static allocation and zero-heap invariants (`sizeof(struct snmp_agent)` sizing, scratch union for 2PC and GETBULK) (AGENTS.md, task.md §16).
- Public API is instance-explicit: all APIs take `struct snmp_agent *agent`, no default instance, no `_inst` suffixes, and all 5 MIB callbacks take `agent` as first argument (AGENTS.md).
- User data invariant: `user_data` in `struct snmp_mib_node` and `struct snmp_table_row` must NEVER point to `struct snmp_agent` (AGENTS.md).
- Doxygen documentation must pass cleanly with `WARN_AS_ERROR=YES` (task.md §23, §33).
- Host unit tests (`snmp_unit_tests`, `vacm_unit_tests`) and code formatting (`clang-format`) must remain passing without regressions (AGENTS.md).

## Review Focus

1. Callback signatures in documentation matching `snmp_mib.h`: ensure every example in `docs/wiki/` passes `struct snmp_agent *agent` as first parameter to prevent compilation errors for users copying examples.
2. Invariant on `user_data`: verify documentation explicitly warns against assigning `agent` to `node->user_data` or `row->user_data`.
3. RFC 3414 SNMPv3 streaming implementation accuracy: verify wiki accurately documents streaming `psa_hash_update` 1 MB cycle and localized key derivation $K_u \parallel \text{snmpEngineID} \parallel K_u$ without repeating old claims of divergence.
4. Multi-instance polling budget and port isolation: ensure documentation states the ZVFS poll formula `CONFIG_ZVFS_POLL_MAX >= CONFIG_SNMP_MAX_INSTANCES * SNMP_SVC_FDS + 1` and distinct port requirement.
5. Internal markdown link integrity: confirm every link in `README.md`, `docs/wiki/Home.md`, and subpages resolves to a valid existing file or anchor without broken relative paths.

---

### Task 1: Legal, Ownership & DAECGE Elimination across all files

**Files:**
- Modify: `include/snmp/snmp.h:1-5`
- Modify: `include/snmp/snmp_ber.h:1-5`
- Modify: `include/snmp/snmp_core.h:1-5`
- Modify: `include/snmp/snmp_mib.h:1-5`
- Modify: `include/snmp/snmp_mib2.h:1-5`
- Modify: `include/snmp/snmp_service.h:1-5`
- Modify: `include/snmp/snmp_trap.h:1-5`
- Modify: `include/snmp/snmp_usm.h:1-5`
- Modify: `include/snmp/snmp_vacm.h:1-5`
- Modify: `src/snmp_ber.c:1-5`
- Modify: `src/snmp_core.c:1-5`
- Modify: `src/snmp_internal.h:1-5`
- Modify: `src/snmp_mib.c:1-5`
- Modify: `src/snmp_mib2.c:1-5`
- Modify: `src/snmp_service.c:1-5`
- Modify: `src/snmp_trap.c:1-5`
- Modify: `src/snmp_usm.c:1-5`
- Modify: `src/snmp_vacm.c:1-5`
- Modify: `tests/src/test_ber.c:1-5`
- Modify: `tests/src/test_mib.c:1-5`
- Modify: `tests/src/test_mib2.c:1-5`
- Modify: `tests/src/test_multi_instance.c:1-5`
- Modify: `tests/src/test_oid.c:1-5`
- Modify: `tests/src/test_set_2pc.c:1-5`
- Modify: `tests/src/test_vacm.c:1-5`
- Modify: `tests/unit/main.c:1-5`
- Modify: `tests/unit/test_ber.c:1-5`
- Modify: `tests/unit/test_mib.c:1-5`
- Modify: `tests/unit/test_mib2.c:1-5`
- Modify: `tests/unit/test_multi_instance.c:1-5`
- Modify: `tests/unit/test_oid.c:1-5`
- Modify: `tests/unit/test_set_2pc.c:1-5`
- Modify: `tests/unit/test_vacm.c:1-5`
- Modify: `tests/unit/zephyr/kernel.h:1-5`
- Modify: `tests/unit/zephyr/sys/atomic.h:1-5`
- Modify: `samples/brightc_sensor/DAECGE-BRIGHTC-MIB.txt:1-20`
- Modify: `samples/brightc_sensor/README.md:1-11`
- Modify: `CHANGELOG.md:20-56`
- Modify: `CONTRIBUTING.md:10-35,145-155`
- Modify: `SECURITY.md:20-30`

**Interfaces:**
- Consumes: Existing files containing legacy copyright "DAECGE", repository URLs `github.com/daecge/zephyr-snmp`, and email `security@daecge.com`.
- Produces: Normalized copyright header `Copyright (c) 2026 StructCore Embedded`, updated repository links `https://github.com/structcore-embedded/zephyr-snmp`, and security email `security@structcore.com`.

- [x] **Step 1: Update copyright headers across all 9 public headers in `include/snmp/`**
  Replace `Copyright (c) 2026 DAECGE` with `Copyright (c) 2026 StructCore Embedded`.

- [x] **Step 2: Update copyright headers across all 9 source files in `src/`**
  Replace `Copyright (c) 2026 DAECGE` with `Copyright (c) 2026 StructCore Embedded` in `snmp_ber.c`, `snmp_core.c`, `snmp_internal.h`, `snmp_mib.c`, `snmp_mib2.c`, `snmp_service.c`, `snmp_trap.c`, `snmp_usm.c`, `snmp_vacm.c`.

- [x] **Step 3: Update copyright headers across all 18 test files in `tests/`**
  Replace `Copyright (c) 2026 DAECGE` with `Copyright (c) 2026 StructCore Embedded` in `tests/src/*.c`, `tests/unit/*.c`, and `tests/unit/zephyr/*.h`.

- [x] **Step 4: Update governance, sample MIB, and metadata files**
  - In `CHANGELOG.md`: update release links from `daecge/zephyr-snmp` to `structcore-embedded/zephyr-snmp`.
  - In `CONTRIBUTING.md`: update issue and discussion links from `daecge/zephyr-snmp` to `structcore-embedded/zephyr-snmp`.
  - In `SECURITY.md`: update security contact email to `security@structcore.com`.
  - In `samples/brightc_sensor/DAECGE-BRIGHTC-MIB.txt`: update `ORGANIZATION` to `"StructCore Embedded"`.
  - In `samples/brightc_sensor/README.md`: update description and file references.

- [x] **Step 5: Run global grep verification for DAECGE**
  Grep search across all files for case-insensitive `daecge`.
  Expected: 0 matches found outside of historical changelog entry notes.

- [x] **Step 6: Commit changes**
  Commit: `git commit -m "docs: normalize legal copyright and eliminate DAECGE references"`

---

### Task 2: Translate and update root documentation (`README.md`, symlink `wiki -> docs/wiki`)

**Files:**
- Modify: `README.md:27-37`
- Create: `wiki` symlink pointing to `docs/wiki`

**Interfaces:**
- Consumes: Current `README.md` with Spanish lines 27-37 and link targets in `docs/wiki/`.
- Produces: 100% English `README.md` and accessible `wiki` alias resolving to `docs/wiki`.

- [x] **Step 1: Translate lines 27-37 of `README.md` to English**
  Translate the "Documentation & Wiki" section from Spanish to English:
  ```markdown
  ## Documentation & Wiki

  For comprehensive technical documentation, refer to the **[Project Wiki](docs/wiki/Home.md)**:

  - 🏛️ **[Architecture and Internals](docs/wiki/Architecture-and-Internals.md)**: Zero dynamic allocation model, ASN.1 BER codec, `net_socket_service` integration, and MIB engine.
  - 📊 **[MIB Design and Implementation](docs/wiki/MIB-Design-and-Implementation.md)**: Guide for scalar variables (RO/RW), dynamic tables, and SMIv2 specification.
  - ⚡ **[Hardware and Network Integration](docs/wiki/Hardware-and-Network-Integration.md)**: Devicetree (`led0`, `sw0`), debounced interrupts, workqueue delegation, and DHCPv4 synchronization.
  - 📋 **[Protocol Matrix and Interoperability Audit](docs/wiki/SNMP-Version-Matrix-and-Interoperability.md)**: Comparative analysis across v1/v2c/v3 and USM/VACM audit.
  - 🔧 **[Troubleshooting and Debugging](docs/wiki/Troubleshooting-and-Debugging.md)**: Resolving timeouts, stack overflows, socket collisions, and trap capture.
  - 🚀 **[Validation Sample on NUCLEO-H743ZI](samples/snmp_agent/README.md)**: Reference manual with Net-SNMP commands and interactive console.
  ```

- [x] **Step 2: Review all sections of `README.md` for consistency**
  Verify that Quick Start, Configuration, MIB-II, Memory Footprint, and Testing sections use the instance-explicit API (`struct snmp_agent`) and contain no Spanish fragments.

- [x] **Step 3: Create symlink `wiki -> docs/wiki`**
  Create symlink `wiki` pointing to `docs/wiki` at repository root so legacy/external wiki paths resolve seamlessly.

- [x] **Step 4: Verify links and formatting**
  Verify markdown syntax and test that `wiki/Home.md` resolves to `docs/wiki/Home.md`.

- [x] **Step 5: Commit changes**
  Commit: `git commit -m "docs: translate README wiki index and add wiki symlink"`

---

### Task 3: Translate, update, and align `docs/wiki/Home.md` and `docs/wiki/Architecture-and-Internals.md`

**Files:**
- Modify: `docs/wiki/Home.md`
- Modify: `docs/wiki/Architecture-and-Internals.md`

**Interfaces:**
- Consumes: Spanish wiki files and architecture implementations in `include/snmp/snmp.h`, `include/snmp/snmp_core.h`, `src/snmp_core.c`, `src/snmp_service.c`.
- Produces: 100% English wiki home and architecture guides reflecting multi-instance re-entrancy, zero dynamic heap, scratch union, and `net_socket_service` integration.

- [x] **Step 1: Translate and modernize `docs/wiki/Home.md`**
  - Translate overview, features, and navigation map into English.
  - Update Mermaid navigation diagram labels to English (`Home`, `Architecture and Internals`, `MIB Design and Implementation`, `Hardware and Network Integration`, `Protocol Matrix & v3 Audit`, `Troubleshooting & Debugging`, `NUCLEO-H743ZI Sample`).
  - Replace obsolete scalar registration example with instance-explicit API:
    ```c
    static int get_temp(struct snmp_agent *agent, const struct snmp_mib_node *node,
                        struct snmp_varbind *vb)
    {
        ARG_UNUSED(agent);
        ARG_UNUSED(node);
        vb->type = ASN1_TAG_INTEGER;
        vb->val.int_val = s_device_temperature;
        return 0;
    }
    ```
  - Show proper registration via `snmp_mib_register_nodes(&agent, nodes, ARRAY_SIZE(nodes))`.

- [x] **Step 2: Translate and modernize `docs/wiki/Architecture-and-Internals.md`**
  - Section 1 (Design Principles): Zero dynamic allocation (`malloc = 0`), multi-instance concurrency (`struct snmp_agent`), thread-safe locking (`k_mutex lock`), synchronous socket polling via Zephyr's `net_socket_service`.
  - Section 2 (Request/Response Pipeline): Update Mermaid sequence diagram to show `struct snmp_agent *agent` handle passing from `snmp_service` -> `snmp_core` -> `snmp_mib` -> callbacks.
  - Section 3 (Core Subsystems):
    - ASN.1 BER codec (`src/snmp_ber.c`): primitive tags, application tags, PDU types, short/long length decoding.
    - MIB Tree Engine (`src/snmp_mib.c`): per-instance `mib_nodes[]` (eliminate all references to non-existent `g_mib_nodes`), lexicographical sorting, binary search lookups, table support.
    - Scratch Memory Architecture: Detail the mutual-exclusion `union` in `struct snmp_agent` (`scratch.tx_items` for 2PC vs `scratch.bulk` for GETBULK) eliminating 9.8 KiB of stack frame down to 52 bytes.
    - Network Service (`src/snmp_service.c`): `CONFIG_SNMP_MAX_INSTANCES`, dual-stack IPv4/IPv6 socket binding, token bucket rate limiter, poll budget requirement (`CONFIG_ZVFS_POLL_MAX >= CONFIG_SNMP_MAX_INSTANCES * SNMP_SVC_FDS + 1`).
    - Traps (`src/snmp_trap.c`): destination array, coldStart and custom traps.
  - Section 4 (Data Structures): Correct definitions of `struct snmp_mib_node`, `struct snmp_agent`, `struct snmp_mib_table`, highlighting `user_data` invariants.

- [x] **Step 3: Verification of data structure definitions**
  Verify all struct definitions match `include/snmp/snmp_core.h` and `include/snmp/snmp_mib.h`.

- [x] **Step 4: Commit changes**
  Commit: `git commit -m "docs(wiki): modernize Home and Architecture guides in English"`

---

### Task 4: Translate, update, and align `docs/wiki/MIB-Design-and-Implementation.md` and `docs/wiki/Hardware-and-Network-Integration.md`

**Files:**
- Modify: `docs/wiki/MIB-Design-and-Implementation.md`
- Modify: `docs/wiki/Hardware-and-Network-Integration.md`

**Interfaces:**
- Consumes: Spanish MIB and hardware guides, and implementations in `src/snmp_mib.c`, `samples/snmp_agent/src/app_mib.c`, `samples/snmp_agent/src/app_button.c`, `samples/snmp_agent/src/app_led.c`.
- Produces: 100% English guides detailing MIB registration with `struct snmp_agent *agent` parameter, 4-phase Two-Phase Commit (`snmp_mib_set_tx_cb_t`), table row management (`struct snmp_table_row`, `struct snmp_table_index`), and DeviceTree + Workqueue real-time rules.

- [x] **Step 1: Translate and modernize `docs/wiki/MIB-Design-and-Implementation.md`**
  - Section 1 (OID Hierarchy): SMIv2 structure under `1.3.6.1.4.1.<ENTERPRISE_ID>`. Explain `.0` scalar instance requirement.
  - Section 2 (Scalar Node Implementation):
    - Update `get_cb` signature: `int (*snmp_mib_get_cb_t)(struct snmp_agent *agent, const struct snmp_mib_node *node, struct snmp_varbind *vb)`.
    - Update `set_cb` signature: `int (*snmp_mib_set_cb_t)(struct snmp_agent *agent, struct snmp_mib_node *node, const struct snmp_varbind *vb)`.
    - Registration via `snmp_mib_register(&agent, &node)` or `snmp_mib_register_nodes(&agent, nodes, count)`.
  - Section 3 (Two-Phase Commit 2PC SET Transactions):
    - Document `snmp_mib_set_tx_cb_t` and `enum snmp_set_action` (`SNMP_SET_RESERVE`, `SNMP_SET_COMMIT`, `SNMP_SET_UNDO`, `SNMP_SET_CLEANUP`) per RFC 3416 §4.2.5.
    - Provide practical example demonstrating reserve validation, commit actuation, and rollback on failure.
  - Section 4 (Dynamic Tables):
    - Document `struct snmp_mib_table`, `struct snmp_table_row`, `struct snmp_table_index`.
    - Multi-column callbacks: `snmp_table_get_cb_t(struct snmp_agent *agent, const struct snmp_table_row *row, uint8_t column, struct snmp_varbind *vb)` and `snmp_table_set_cb_t`.
    - Explain row chaining (`row->next`) and row insertion helper functions (`snmp_table_row_add`).
  - Section 5 (Rules & Invariants):
    - Strict rule on `node->user_data` and `row->user_data`: NEVER point to `struct snmp_agent` or its fields.
    - Thread context: MIB callbacks are invoked with `agent->lock` held; callbacks must never attempt to re-acquire `agent->lock` or call blocking agent lifecycle functions.

- [x] **Step 2: Translate and modernize `docs/wiki/Hardware-and-Network-Integration.md`**
  - Section 1 (DeviceTree Hardware Abstraction): Accessing pins via `GPIO_DT_SPEC_GET`, `DT_ALIAS(led0)`, `DT_ALIAS(sw0)`.
  - Section 2 (Actuator Control): Thread-safe control of LEDs / relays from `set_cb` or `set_tx_cb`.
  - Section 3 (Real-Time Interrupts & Trap Dispatch):
    - Emphasize the critical rule: NEVER call `snmp_trap_send` in ISR.
    - Complete pattern: GPIO ISR -> software debounce (200 ms) -> workqueue dispatch (`k_work_submit`) -> thread context execution of `snmp_trap_send()`.
    - Include updated Mermaid sequence diagram in English.
  - Section 4 (Networking & DHCP Integration):
    - DHCPv4 synchronization using `net_mgmt_event_wait` or semaphore signaling to `main()`.
    - Stack size requirement: `CONFIG_NET_MGMT_EVENT_STACK_SIZE=2048` to avoid stack overflow.

- [x] **Step 3: Verification of callback signatures and code samples**
  Verify all C code snippets against `include/snmp/snmp_mib.h` and `samples/snmp_agent/src/app_mib.c`.

- [x] **Step 4: Commit changes**
  Commit: `git commit -m "docs(wiki): modernize MIB design and hardware integration guides in English"`

---

### Task 5: Translate, update, and align `docs/wiki/SNMP-Version-Matrix-and-Interoperability.md`

**Files:**
- Modify: `docs/wiki/SNMP-Version-Matrix-and-Interoperability.md`

**Interfaces:**
- Consumes: Spanish protocol matrix and real SNMPv3 implementation in `src/snmp_usm.c` and `src/snmp_vacm.c`.
- Produces: 100% English protocol matrix and interoperability guide reflecting full RFC 3414 compliance.

- [x] **Step 1: Translate and update Section 1 (Protocol Capability Matrix)**
  - Mark SNMPv3 as fully supported for USM, VACM, GET, GETNEXT, GETBULK, SET, and Trap/Inform.
  - Clarify differences across v1, v2c, and v3 security models.

- [x] **Step 2: Update Section 2 (SNMPv3 Architecture & RFC Compliance)**
  - Completely remove obsolete claims that `snmp_usm.c` has 1,000,000 hash loops or custom divergence.
  - Accurately document the real implementation in `src/snmp_usm.c`:
    1. Streaming password-to-key algorithm (RFC 3414 Appendix A.2.1): cyclic 1 MB (1,048,576 bytes) stream processed in 64-byte chunks using PSA crypto `psa_hash_setup`, `psa_hash_update`, `psa_hash_finish`. Supported hashes: MD5, SHA-1, SHA-256 (RFC 7860).
    2. Key localization algorithm (RFC 3414 Appendix A.2.2 & RFC 3826 §2.4): localized key $K_{ul} = \text{Hash}(K_u \parallel \text{snmpEngineID} \parallel K_u)$ computed in a single pass.
    3. Encryption & Privacy: AES-128-CFB (RFC 3826) and DES-CBC via PSA crypto primitives.
    4. Engine Discovery & Timeliness: Engine ID discovery report PDUs, boot counter persistence via Zephyr Settings (`CONFIG_SETTINGS`), and replay protection window.
    5. VACM (RFC 3415): View trees, access rules, group mappings in `src/snmp_vacm.c`.

- [x] **Step 3: Update Section 3 (Interoperability Recipes)**
  - Net-SNMP CLI recipes for SNMPv1, SNMPv2c, and SNMPv3 (authNoPriv, authPriv with SHA/AES).
  - iReasoning MIB Browser configuration instructions.
  - Wireshark capture filters and dissection tips (`udp port 161 or udp port 162`).

- [x] **Step 4: Verification against RFC standards**
  Verify RFC citations against RFC 3412, RFC 3414, RFC 3415, RFC 3826, RFC 7860.

- [x] **Step 5: Commit changes**
  Commit: `git commit -m "docs(wiki): update SNMP version matrix with full v3 RFC 3414 compliance"`

---

### Task 6: Translate, update, and align `docs/wiki/Troubleshooting-and-Debugging.md` and `docs/wiki/snmp-hil-validation.md`

**Files:**
- Modify: `docs/wiki/Troubleshooting-and-Debugging.md`
- Modify: `docs/wiki/snmp-hil-validation.md`

**Interfaces:**
- Consumes: Current Spanish troubleshooting guide and HIL validation record.
- Produces: 100% English guides for runtime diagnosis and hardware test logs with `StructCore Embedded` authorship.

- [x] **Step 1: Translate and modernize `docs/wiki/Troubleshooting-and-Debugging.md`**
  - Section 1: Network timeouts and communication failures:
    - Silent community drops: RFC 1213/3416 compliance increments `snmpInBadCommunityNames` without ICMP or UDP response.
    - Ethernet PHY link status diagnosis (`<inf> phy_mii: Link speed 100 Mb`).
    - IP address acquisition and DHCP timeout fallbacks.
    - Multi-instance socket collision: `CONFIG_ZVFS_POLL_MAX` budget formula and distinct port requirement.
  - Section 2: Zephyr fatal errors and panics:
    - `net_mgmt` stack overflow: cause and fix (`CONFIG_NET_MGMT_EVENT_STACK_SIZE=2048`, avoid networking in event callback).
    - Deferred logging string pointer invalidation: recommend `CONFIG_LOG_MODE_IMMEDIATE=y` during debugging.
  - Section 3: SNMP protocol error table:
    - `noSuchName` / `noSuchInstance`, `badValue`, `notWritable`, `genErr`, `authorizationError`.
  - Section 4: Host trap reception without root privileges:
    - Non-privileged UDP port 1162 (`CONFIG_SNMP_TRAP_PORT=1162`) and Python trap listener script.

- [x] **Step 2: Translate and update `docs/wiki/snmp-hil-validation.md`**
  - Normalize header: author "StructCore Embedded QA Automation", verdict PASS.
  - Translate test environment specifications (STM32H743ZI, Cortex-M7 @ 480 MHz, Zephyr v4.4.0, Net-SNMP 5.9.4).
  - Translate the 23 HIL test records (SNMP-001 through SNMP-023) including GET, SET, WALK, BULKWALK, SNMPv1/v2c, and negative test cases.
  - Translate UART telemetry correlation notes and boot banner explanations.

- [x] **Step 3: Verification of markdown tables and logs**
  Verify table alignment, code blocks, and log snippets render cleanly.

- [x] **Step 4: Commit changes**
  Commit: `git commit -m "docs(wiki): translate troubleshooting and HIL validation reports to English"`

---

### Task 7: Translate and update `samples/snmp_agent/README.md` and `samples/brightc_sensor/`

**Files:**
- Modify: `samples/snmp_agent/README.md`
- Modify: `samples/brightc_sensor/README.md`
- Modify: `samples/brightc_sensor/DAECGE-BRIGHTC-MIB.txt`

**Interfaces:**
- Consumes: Current Spanish sample README and BrightC sensor sample files.
- Produces: 100% English sample documentation, verified Kconfig tables, dual-instance instructions, and clean MIB text.

- [x] **Step 1: Translate and modernize `samples/snmp_agent/README.md`**
  - Hardware overview (NUCLEO-H743ZI, RMII Ethernet, `led0`, `sw0`).
  - Architecture: `app_led`, `app_button`, `app_sensor`, `app_mib`, `main.c`.
  - Comprehensive Kconfig table: network parameters, sample options, dual-instance configuration.
  - Multi-instance dual agent demo: explain `CONFIG_SNMP_SAMPLE_SECOND_INSTANCE=y`, port 1610, and poll budget calculation.
  - Build, flash, and shell interaction instructions (`app led [0|1]`, `app button [press]`, `app sensor`).
  - Net-SNMP verification command suite for all registered OIDs.

- [x] **Step 2: Translate and update `samples/brightc_sensor/README.md`**
  - Document the purpose of the sample: pure enterprise MIB definition reference (no code, no build).
  - Instructions for loading enterprise MIBs into Net-SNMP tools.

- [x] **Step 3: Update `samples/brightc_sensor/DAECGE-BRIGHTC-MIB.txt`**
  - Translate all `DESCRIPTION` and comment strings from Spanish to English.
  - Update `ORGANIZATION` to `"StructCore Embedded"` and `CONTACT-INFO` to `"support@structcore.com"`.

- [x] **Step 4: Verification of SMIv2 syntax and paths**
  Verify MIB definitions parse cleanly and file paths are accurate.

- [x] **Step 5: Commit changes**
  Commit: `git commit -m "docs(samples): translate snmp_agent and brightc_sensor documentation to English"`

---

### Task 8: Doxygen API comment completeness check and validation across `include/snmp/*.h`

**Files:**
- Modify: `include/snmp/snmp.h`
- Modify: `include/snmp/snmp_ber.h`
- Modify: `include/snmp/snmp_core.h`
- Modify: `include/snmp/snmp_mib.h`
- Modify: `include/snmp/snmp_mib2.h`
- Modify: `include/snmp/snmp_service.h`
- Modify: `include/snmp/snmp_trap.h`
- Modify: `include/snmp/snmp_usm.h`
- Modify: `include/snmp/snmp_vacm.h`

**Interfaces:**
- Consumes: Public headers in `include/snmp/`.
- Produces: 100% complete, standard Doxygen comments for every public function, struct, enum, and callback, with zero missing parameter tags or return tags.

- [x] **Step 1: Audit `include/snmp/snmp_core.h`**
  - Ensure `@brief`, `@param`, `@return`, `@retval` on `snmp_agent_init`, `snmp_agent_start`, `snmp_agent_stop`, `snmp_agent_deinit`.
  - Document thread safety and locking contract (`agent->lock` required, thread context only, never ISR).
  - Document all fields of `struct snmp_agent_cfg` and public enum values of `enum snmp_agent_state`.

- [x] **Step 2: Audit `include/snmp/snmp_mib.h`**
  - Verify complete Doxygen on callback typedefs: `snmp_mib_get_cb_t`, `snmp_mib_set_cb_t`, `snmp_mib_set_tx_cb_t`, `snmp_table_get_cb_t`, `snmp_table_set_cb_t`.
  - Document `enum snmp_set_action` values.
  - Document MIB node registration APIs: `snmp_mib_register`, `snmp_mib_register_nodes`, `snmp_mib_deregister`, `snmp_mib_register_table`, `snmp_table_row_add`, `snmp_table_row_remove`.
  - Document counter snapshot APIs: `snmp_agent_get_counters`, `snmp_agent_zero_counters`.

- [x] **Step 3: Audit `include/snmp/snmp_ber.h`**
  - Document ASN.1 tag defines, `struct snmp_oid`, `struct snmp_varbind`, `struct snmp_pdu`.
  - Document BER encode/decode functions: `snmp_ber_decode_header`, `snmp_ber_encode_pdu`, `snmp_oid_compare`, `snmp_oid_to_str`.

- [x] **Step 4: Audit `include/snmp/snmp_mib2.h`, `snmp_service.h`, `snmp_trap.h`, `snmp_usm.h`, `snmp_vacm.h`**
  - Verify Doxygen comments on all MIB-II helper setters/getters.
  - Document trap APIs: `snmp_trap_add_destination`, `snmp_trap_send`, `snmp_trap_send_coldstart`.
  - Document USM user management and VACM access rule APIs.

- [x] **Step 5: Verification of parameter completeness**
  Check that every `@param` name matches the exact parameter name in the C prototype.

- [x] **Step 6: Commit changes**
  Commit: `git commit -m "docs(api): complete Doxygen comments across all public headers"`

---

### Task 9: Run tests, run Doxygen (`WARN_AS_ERROR=YES`), verify links, format compliance check

**Files:**
- Modify: `docs/Doxyfile:878` (set `WARN_AS_ERROR = YES`)
- Test: Host unit tests (`tests/unit/build/snmp_unit_tests`, `tests/unit/build/vacm_unit_tests`)
- Test: Doxygen doc generation
- Test: clang-format verification

**Interfaces:**
- Consumes: All repository source, header, test, and documentation files.
- Produces: Clean test outputs, zero Doxygen warnings under `WARN_AS_ERROR=YES`, zero formatting violations, and zero DAECGE matches.

- [x] **Step 1: Build and run host unit tests**
  Command:
  ```bash
  cd tests/unit
  cmake -S . -B build && cmake --build build
  ./build/snmp_unit_tests && ./build/vacm_unit_tests
  ```
  Expected output: Both test binaries exit with 0, all 47 unit test assertions pass.

- [x] **Step 2: Run Doxygen with `WARN_AS_ERROR = YES`**
  Update `docs/Doxyfile` line 878 to `WARN_AS_ERROR = YES`.
  Command:
  ```bash
  doxygen docs/Doxyfile
  ```
  Expected output: Doxygen completes with return code 0 and 0 warnings emitted.

- [x] **Step 3: Run clang-format verification**
  Command:
  ```bash
  clang-format --dry-run --Werror \
    include/snmp/*.h src/*.c src/*.h \
    samples/snmp_agent/src/*.c samples/snmp_agent/src/*.h \
    tests/src/*.c tests/unit/*.c
  ```
  Expected output: No formatting violations or diffs detected.

- [x] **Step 4: Check internal markdown link integrity**
  Verify all links in `README.md`, `docs/wiki/*.md`, `docs/_doxygen/main.md`, and `samples/snmp_agent/README.md` resolve to existing targets.
  Expected output: 0 broken links.

- [x] **Step 5: Final DAECGE grep verification**
  Search the entire repository for `daecge` (case-insensitive).
  Expected output: 0 matches found.

- [x] **Step 6: Commit changes**
  Commit: `git commit -m "ci: enforce Doxygen WARN_AS_ERROR=YES and verify test gates"`

---

### Task 10: Generate comprehensive audit report at `temp/documentation-audit.md`

**Files:**
- Create: `temp/documentation-audit.md`

**Interfaces:**
- Consumes: Audit findings and verification evidence from Tasks 1 through 9.
- Produces: The formal markdown audit report adhering strictly to `task.md` §35.

- [x] **Step 1: Write `temp/documentation-audit.md` with all mandatory sections from `task.md` §35**
  - **Documentation Inventory**: Complete inventory table of all documentation files, status, and line counts.
  - **Wiki Status**: Table detailing each document in `docs/wiki/`, initial state (Spanish, outdated single-instance), changes made, and source verification references.
  - **Doxygen Status**: Summary of headers audited, public symbols documented, warnings encountered, warnings resolved, and verification with `WARN_AS_ERROR=YES`.
  - **Source/Documentation Discrepancies**: Itemized log of documented behavior vs actual implementation vs action taken:
    1. Callback signatures: added `struct snmp_agent *agent` as 1st parameter.
    2. Multi-instance: removed non-existent `g_mib_nodes`; documented per-agent `mib_nodes[]`.
    3. Memory model: documented zero-heap scratch union (`scratch.tx_items` vs `scratch.bulk`).
    4. SNMPv3 USM: corrected outdated claims of broken key derivation; documented real RFC 3414 streaming password-to-key and localized key derivation.
    5. Table row management: documented `struct snmp_table_row` and `user_data` pointer invariant.
    6. Traps in ISR: documented critical prohibition and workqueue offloading.
    7. Multi-instance port collision: documented ZVFS poll budget and distinct port requirement.
  - **DAECGE Cleanup Inventory**: Total occurrences found, occurrences corrected, occurrences intentionally retained (0).
  - **Language Migration**: Count of Spanish documents before (7 wiki files + README section + 2 sample files) vs after (0 remaining).
  - **Limitations and Hardware Verification**: Summary of HIL validation evidence on NUCLEO-H743ZI, host test coverage, and platforms tested.

- [x] **Step 2: Verify audit report completeness against acceptance criteria**
  Check that every item in `task.md` §36 is documented and verified in `temp/documentation-audit.md`.

- [x] **Step 3: Commit changes**
  Commit: `git commit -m "docs: generate formal documentation audit report"`
