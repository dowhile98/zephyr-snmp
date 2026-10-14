# SNMP Version Matrix and Interoperability Audit

This document establishes the technical comparison between the three protocol versions (**SNMPv1**, **SNMPv2c**, and **SNMPv3**) supported by `zephyr-snmp`, documenting verified protocol features, RFC compliance, and interoperability workflows.

---

## 1. Protocol Capability Matrix

| Feature / Standard | SNMPv1 (RFC 1157) | SNMPv2c (RFC 3416) | SNMPv3 (RFC 3412 / 3414) | Implementation Status |
| :--- | :---: | :---: | :---: | :--- |
| **Security Model** | Plaintext community string | Plaintext community string | User-Based Security Model (USM) | Fully supported (v1/v2c communities, v3 USM users) |
| **PDU: GetRequest** | Supported | Supported | Supported | Fully verified across all protocol versions |
| **PDU: GetNextRequest** | Supported | Supported | Supported | Fully verified for sequential tree walks (`snmpwalk`) |
| **PDU: GetBulkRequest** | Not supported by RFC | Supported | Supported | Fully verified (`snmpbulkget`, `snmpbulkwalk`, `snmptable`) |
| **PDU: SetRequest** | Supported | Supported | Supported | Fully verified (bounds validation, 2PC transactions) |
| **PDU: Trap** | TRAPv1 (RFC 1157) | SNMPv2-Trap (RFC 3418) | Trapv3 / Inform | Autonomous event and coldStart notifications |
| **PDU: InformRequest** | Not supported by RFC | Supported | Supported | Acknowledged notifications |
| **PDU: Report** | N/A | N/A | Supported | Engine ID discovery, timeliness sync, error reporting |
| **Table Management** | GETNEXT walk | GETBULK / GETNEXT | GETBULK / GETNEXT | Dynamic multi-column tables with index chaining |
| **Authentication** | Community filter | Community filter | HMAC-MD5, HMAC-SHA1, HMAC-SHA256 | Compliant with RFC 3414 and RFC 7860 via PSA Crypto |
| **Privacy (Encryption)**| None | None | AES-128-CFB, DES-CBC | Compliant with RFC 3826 via PSA Crypto primitives |
| **Access Control** | Binary community match | Binary community match | VACM (RFC 3415) | Views, groups, and access rights in `src/snmp_vacm.c` |
| **Engine Discovery** | N/A | N/A | Supported (RFC 3414 §4) | Responds with `snmpUnknownEngineIDs` and Engine ID |

---

## 2. Technical Audit of SNMPv3 Architecture (RFC Compliance)

The SNMPv3 User-Based Security Model (USM) in `src/snmp_usm.c` is fully compliant with RFC standards:

### A. Streaming Password-to-Key Algorithm (RFC 3414 Appendix A.2.1)
* **Standard Requirement**:
  The user password is treated as a continuous cyclic octet stream and hashed across a total linear length of **1 Megabyte** ($1,048,576$ octets) using 64-byte chunks into a single hash context.
* **Firmware Implementation (`src/snmp_usm.c`)**:
  Implemented in `usm_password_to_key()` using Zephyr's PSA Crypto streaming APIs (`psa_hash_setup`, `psa_hash_update`, and `psa_hash_finish`).
  ```c
  /* RFC 3414 A.2.1: Process 1,048,576 octets of password cycling in 64-byte chunks */
  while (count < 1048576) {
      for (size_t i = 0; i < 64; i++) {
          buf[i] = (uint8_t)password[password_index++ % pw_len];
      }
      status = psa_hash_update(&op, buf, 64);
      ...
  }
  status = psa_hash_finish(&op, ku, ku_sz, ku_len);
  ```
  This streaming execution avoids allocating a 1 MB buffer in RAM, executes in bounded cycles without CPU hogging, and strictly matches standard RFC test vectors.

### B. Localized Key Derivation (RFC 3414 Appendix A.2.2 & RFC 3826 §2.4)
* **Standard Requirement**:
  The localized key ($K_{ul}$) for an agent instance is derived by concatenating the master key ($K_u$), the agent's authoritative `snmpEngineID`, and the master key ($K_u$), then computing a single hash pass:
  $$K_{ul} = \text{Hash}(K_u \parallel \text{snmpEngineID} \parallel K_u)$$
* **Firmware Implementation (`src/snmp_usm.c`)**:
  Implemented in `usm_key_localize()`:
  ```c
  /* Buffer = Ku (hash_size) || engine_id (engine_id_len) || Ku (hash_size) */
  size_t total_len = ku_len + engine_id_len + ku_len;
  memcpy(buffer, ku, ku_len);
  memcpy(buffer + ku_len, engine_id, engine_id_len);
  memcpy(buffer + ku_len + engine_id_len, ku, ku_len);

  status = psa_hash_compute(hash_alg, buffer, total_len, kul, sizeof(kul), &kul_len);
  ```
  The resulting localized digest matches standard tools (Net-SNMP, Wireshark, iReasoning MIB Browser) identically.

### C. Engine Discovery and Timeliness Synchronization
* Compliant with RFC 3414 §4: empty discovery requests receive standard Report PDUs containing the authoritative `contextEngineID` and current `snmpEngineBoots` / `snmpEngineTime`.
* Replay protection ensures datagram timeliness within a configurable window (RFC 3414 §3.2).
* Boot counter persistence is supported via Zephyr Settings (`CONFIG_SETTINGS=y`) with `cfg.settings_prefix`.

### D. View-Based Access Control Model (VACM, RFC 3415)
* Granular access control modeled in `src/snmp_vacm.c` supporting security levels:
  - `noAuthNoPriv`: Plaintext unauthenticated access.
  - `authNoPriv`: HMAC authentication without payload encryption.
  - `authPriv`: Authenticated and encrypted payload (AES-128 / DES).

---

## 3. Host Interoperability Recipes

### A. Net-SNMP CLI (Linux / macOS)

```bash
# --- SNMPv1 ---
snmpget -v1 -c public <TARGET_IP> 1.3.6.1.4.1.54321.1.1.1.0
snmpwalk -v1 -c public <TARGET_IP> 1.3.6.1.4.1.54321.1

# --- SNMPv2c ---
snmpget -v2c -c public -m ./NUCLEO-H743-MIB.txt <TARGET_IP> sensorValue.0 ledState.0
snmpset -v2c -c private -m ./NUCLEO-H743-MIB.txt <TARGET_IP> ledState.0 i 1
snmpbulkget -v2c -c public -m ./NUCLEO-H743-MIB.txt -Cn0 -Cr9 <TARGET_IP> sensorTable
snmptable -v2c -c public -m ./NUCLEO-H743-MIB.txt <TARGET_IP> sensorTable

# --- SNMPv3 (Engine Discovery + authPriv) ---
snmpget -v3 -u admin -l authPriv -a SHA -A "auth_passphrase" -x AES -X "priv_passphrase" \
    <TARGET_IP> 1.3.6.1.4.1.54321.1.1.1.0
```

### B. iReasoning MIB Browser (GUI)
1. Launch iReasoning MIB Browser.
2. Select **File -> Load MIBs** and open your enterprise MIB file (e.g. `NUCLEO-H743-MIB.txt` or `STRUCTCORE-BRIGHTC-MIB.txt`).
3. Set **Address**: IP address of the target board (e.g., `192.168.16.100`).
4. Set **Port**: Target agent port (default `161`).
5. Set **Read Community**: `public`, **Write Community**: `private`.
6. For SNMPv3, open the **Advanced** dialog and configure the USM user credentials, authentication protocol (SHA-1/SHA-256), and privacy protocol (AES-128).
7. In the MIB tree view, navigate to the enterprise node and perform operations (Get, GetNext, Walk, Table View).

### C. Wireshark Packet Inspection
To dissect SNMP network traffic in Wireshark:
1. Capture filter: `udp port 161 or udp port 162 or udp port 1162`.
2. Packets are automatically dissected as SNMP.
3. For SNMPv3 encrypted traffic:
   - Navigate to **Edit -> Preferences -> Protocols -> SNMP**.
   - Add the USM user table entry with user name, auth password, and priv password.
   - Wireshark will decrypt the `scopedPDU` payload in real time.

