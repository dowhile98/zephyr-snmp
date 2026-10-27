# SNMPv3 Agent Validation Sample (NUCLEO-H743ZI)

A reference application for the **SNMPv3** support of the zephyr-snmp module. It
runs one agent instance on a caller-owned `struct snmp_agent`, exposing the
MIB-II `system`/`snmp` groups plus a private enterprise MIB, and it is built to
exercise the v3 machinery that a plain v2c sample cannot:

- USM discovery and the engine-ID `Report` exchange (RFC 3414 §3.2),
- authPriv (HMAC-SHA-256 + AES-128-CFB) and authNoPriv (HMAC-SHA-1) users,
- VACM: the same agent serves a `fullView` account and a read-only account,
- v3 notifications (Trap/Inform) from the same USM user table,
- timeliness checking and silent drops of bad digests.

> **Every credential in this sample is a public test value.** They ship in
> `prj.conf` so the sample can be reproduced without generating keys first, and
> they are logged in the boot banner. Do not ship them in a product.

---

## Files

```text
samples/snmp_agent_v3/
├── CMakeLists.txt          # Zephyr module registration + sources
├── Kconfig                 # Sample options (enterprise ID, destinations, users)
├── prj.conf                # Networking, SNMPv3, USM users, stack sizing
├── sample.yaml             # Twister/sample metadata
├── NUCLEO-H743-MIB.txt     # SMIv2 definition of the private MIB
├── README.md
└── src/
    ├── app_led.c/.h        # User LED (devicetree led0)
    ├── app_button.c/.h     # User button (sw0) + debounce + deferred trap
    ├── app_sensor.c/.h     # Simulated telemetry (scalars + table)
    ├── app_mib.c/.h        # MIB node registration and callbacks
    └── main.c              # USM user setup, DHCP wait, banner, shell
```

`src/app_*.c` is the intended consumption pattern for the module: the
application owns the agent storage, registers its own MIB nodes and adds USM
users; the module owns no global instance.

---

## Configuration

### Protocol and transport

| Symbol | Value | Meaning |
| --- | --- | --- |
| `CONFIG_SNMP_AGENT` | `y` | Enables the agent subsystem. |
| `CONFIG_SNMP_VERSION_3` | `y` | SNMPv3 + USM/VACM (selects PSA Crypto/mbedTLS). |
| `CONFIG_SNMP_VERSION_2C` | `y` | Kept on to compare v2c and v3 against one instance. |
| `CONFIG_SNMP_AGENT_PORT` | `161` | UDP listen port. |
| `CONFIG_SNMP_COMMUNITY_READ` / `_WRITE` | `public` / `private` | v1/v2c communities only. |
| `CONFIG_NET_SOCKETS_SERVICE_STACK_SIZE` | `16384` | v3 receive path runs in the socket-service thread. |

`CONFIG_SNMP_VERSION_3` selects `PSA_CRYPTO`, `MBEDTLS` and the PSA want
symbols for AES-CFB, HMAC and SHA-1/SHA-256/MD5, so no extra crypto config is
required in `prj.conf`.

### Test-only USM users

| Symbol | Value |
| --- | --- |
| `CONFIG_SNMP_V3_USER_NAME` | `v3test` |
| `CONFIG_SNMP_V3_AUTH_PROTOCOL` | `3` (HMAC-SHA-256) |
| `CONFIG_SNMP_V3_AUTH_PASS` | `v3-auth-passphrase-test-only` |
| `CONFIG_SNMP_V3_PRIV_PROTOCOL` | `1` (AES-128-CFB) |
| `CONFIG_SNMP_V3_PRIV_PASS` | `v3-priv-passphrase-test-only` |
| `CONFIG_SNMP_SAMPLE_V3_MONITOR_USER` | `v3monitor` |
| `CONFIG_SNMP_SAMPLE_V3_MONITOR_AUTH_PASS` | `v3-monitor-auth-passphrase-test-only` |

- `v3test` is created by `snmp_usm_init()` from the Kconfig values and is the
  authPriv account used for SET and notifications. `snmp_vacm_init()` maps it to
  group `admin` with view `fullView` (subtree `1.3.6.1`).
- `v3monitor` is added at runtime by `main.c` with SHA-1 authentication and no
  privacy. It is the account that `snmp_vacm_init()` already maps to group
  `readonly` (view `restrictedView`, subtree `1.3.6.1.2.1.1`), which is why a
  walk of the private MIB with this user must be refused rather than returned.

Pass phrases shorter than 8 octets, `priv` without `auth`, and DES privacy are
rejected by `snmp_usm_add_user()` (`-EINVAL` / `-ENOTSUP`), so misconfiguration
surfaces at init instead of as an unexplained authentication failure.

### Notifications

`CONFIG_SNMP_TRAP_FORMAT_V3=y` selects SNMPv3 traps, and
`CONFIG_SNMP_TRAP_V3_USER="v3test"` names the USM account that signs and
encrypts them. The security level is derived from that user's capabilities
(authPriv here). Set `CONFIG_SNMP_SAMPLE_TRAP_DEST` to the collector address.

### engineBoots

`snmpEngineBoots` must strictly increase across reboots to keep the USM
replay window sound (RFC 3414 §5.1.3). The sample sets
`cfg.settings_prefix = "snmp/lan"`, and `snmp_agent_init()` then calls
`snmp_agent_load_engine_boots()`, which reads and advances
`snmp/lan/boots`. That requires a settings backend
(`CONFIG_SETTINGS=y` plus e.g. `CONFIG_SETTINGS_NVS`); without one the call
returns `-ENOTSUP` and the compile-time `CONFIG_SNMP_V3_ENGINE_BOOTS` value is
used. On a device without storage, raise that value in the flashed image or
persist the counter yourself and call `snmp_usm_set_engine_boots()` before
`snmp_agent_start()`.

### snmpEngineID

The NUCLEO-H743ZI enables `CONFIG_HWINFO`, so the module derives the engine ID
as `0x80001F88 05 || <96-bit device ID>` (RFC 3411 §5 format 5). Two boards
flashed with this same sample therefore derive **different** localized keys
from the same pass phrases, which is the point. The resulting ID is printed in
the boot banner; use that value with `snmptrapd createUser`. Boards without a
device-ID driver fall back to the fixed `0x80001F88 05 "ZEPHYR1"` value, in
which case set `cfg.engine_id` yourself if you deploy more than one node.

---

## Build

From the repository root:

```bash
export PATH=/home/jeffry/.zinstaller/.venv/bin:$PATH
source ~/zephyrproject/zephyr/zephyr-env.sh

# Hardware
west build -p always -b nucleo_h743zi samples/snmp_agent_v3

# Emulated targets (no radio/PHY, but the full SNMP path runs)
west build -p always -b qemu_x86 samples/snmp_agent_v3
west build -p always -b native_sim/native/64 samples/snmp_agent_v3
```

Flashing the NUCLEO board goes through the bench tooling (`agentic-hil`), not
`west flash`.

---

## Expected boot banner

```text
<inf> main: ================================================================
<inf> main:        SNMPv3 VALIDATION SAMPLE ON ZEPHYR RTOS (NUCLEO-H743ZI)
<inf> main: ================================================================
<inf> main: Protocol Support:
<inf> main:   - SNMPv1  : DISABLED
<inf> main:   - SNMPv2c : ENABLED
<inf> main:   - SNMPv3  : ENABLED
<inf> main: Security & Network:
<inf> main:   - Agent IP / Port : 192.168.68.102 : 161
<inf> main:   - Read Community  : "public" (v1/v2c)
<inf> main:   - Write Community : "private" (v1/v2c)
<inf> main:   - v3 authPriv user: "v3test" (SHA-256 / AES-128-CFB)
<inf> main:   - v3 authNoPriv   : "v3monitor" (SHA-1, read-only VACM group)
<inf> main:   - engineBoots     : 1 (persisted when CONFIG_SETTINGS is on)
<inf> main:   -- All credentials above are public test values. Never ship them. --
```

The banner also prints copy-pasteable `snmpget` / `snmpwalk` / `snmpset` /
`snmptrap` commands for the address the board actually obtained over DHCP.

---

## Verification with net-snmp

Replace `192.168.68.102` with the board's address.

### 1. Discovery and authPriv Get

```bash
snmpget -v3 -u v3test -l authPriv -a SHA-256 \
        -A 'v3-auth-passphrase-test-only' \
        -x AES -X 'v3-priv-passphrase-test-only' \
        192.168.68.102 1.3.6.1.4.1.54321.1.1.1.0
```

`net-snmp` first sends a discovery probe (empty engine ID, no auth) and expects
a `Report` with `usmStatsUnknownEngineIDs.0` carrying this engine's ID, boots
and time. That is the exchange `snmp_usm_verify_incoming()` implements; a
timeout here means the Report was not produced or not accepted.

### 2. authNoPriv and the VACM boundary

```bash
# Allowed: system group is inside the "restrictedView" subtree.
snmpwalk -v3 -u v3monitor -l authNoPriv -a SHA \
         -A 'v3-monitor-auth-passphrase-test-only' \
         192.168.68.102 1.3.6.1.2.1.1

# Refused: the private MIB is outside this user's view (authorizationError).
snmpget -v3 -u v3monitor -l authNoPriv -a SHA \
        -A 'v3-monitor-auth-passphrase-test-only' \
        192.168.68.102 1.3.6.1.4.1.54321.1.1.1.0
```

### 3. authPriv Set and GetBulk

```bash
snmpset -v3 -u v3test -l authPriv -a SHA-256 \
        -A 'v3-auth-passphrase-test-only' -x AES -X 'v3-priv-passphrase-test-only' \
        192.168.68.102 1.3.6.1.4.1.54321.1.1.2.0 i 1

snmpbulkwalk -v3 -u v3test -l authPriv -a SHA-256 \
        -A 'v3-auth-passphrase-test-only' -x AES -X 'v3-priv-passphrase-test-only' \
        192.168.68.102 1.3.6.1.4.1.54321.1
```

### 4. Negative cases worth checking

| Probe | Expected |
| --- | --- |
| Unknown user name, `-l authNoPriv`, `-u nosuchuser` | `Report` with `usmStatsUnknownUserNames.0` |
| Wrong `-A` pass phrase | silent drop / timeout (`usmStatsWrongDigests` increments) |
| `-u v3monitor -l authPriv` (user has no privacy) | `Report` with `usmStatsUnsupportedSecLevels.0` |
| Replay of an old authenticated frame | `Report` with `usmStatsNotInTimeWindows.0` (after the 150 s window) |
| v2c `-c public` against the same instance | still answers (v2c is enabled on purpose) |

### 5. v3 traps

```bash
# Collector
sudo snmptrapd -f -Lo -C -c /etc/snmp/snmptrapd.conf

# In /etc/snmp/snmptrapd.conf (createUser must match the sample's pass phrases)
#   createUser -e 0x80001F88805A455048595231 v3test SHA-256 \
#       v3-auth-passphrase-test-only AES v3-priv-passphrase-test-only
#   authUser log,execute,net v3test
```

The engine ID in `createUser` must be the one the agent reports in its
discovery Report; the sample logs it at boot as
`snmpEngineID: 0x... (use as -e in snmptrapd createUser)`. Pressing `sw0` or
running `app button` in the shell then emits `buttonPressed`
(`1.3.6.1.4.1.54321.1.2.1`) carrying `buttonCounter.0` and `ledState.0`.

### 6. Shell

`app sensor`, `app led [0|1]`, `app button`, `net iface` — same as the v1/v2c
sample.

---

## Adapting for production

1. Replace both pass phrases with per-device secrets provisioned at
   manufacturing time (do not compile them into the image). Keep
   `CONFIG_SNMP_V3_MAX_USERS` at the real number of accounts.
2. Persist `snmpEngineBoots` (enable a settings backend, or call
   `snmp_usm_set_engine_boots()` with a value read from secure storage before
   `snmp_agent_start()`).
3. Review the default VACM tables in `src/snmp_vacm.c`: `v3test`/`admin` gets
   all of `1.3.6.1`, `v3monitor`/`readonly` only the system group. Add
   `snmp_vacm_add_access_rule()` calls for the accounts your product needs.
4. Replace the simulated telemetry in `src/app_sensor.c` with real drivers and
   the enterprise ID with your IANA-assigned number.
5. DES-CBC privacy is not implemented (RFC 3414's DES is deprecated); use AES.
