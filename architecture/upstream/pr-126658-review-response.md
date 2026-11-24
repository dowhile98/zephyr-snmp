# Response to the PR 126658 / PR 125643 comparison review

Author: StructCore Embedded
Date: 2026-11-23
Basis: the maintainer review in `temp/PR 126658 vs PR 125643.md` (not published)
Scope: this document records what was changed in this module, what was deliberately
left for the staged port, and how the port onto PR 125643 is proposed to work.

## Position

We accept the proposed direction:

- PR 125643 becomes the base: Zephyr object model (`SNMP_SCALAR_DEFINE` in iterable
  sections), request path, IPv6, reply source address from `pktinfo`, the
  `struct snmp_storage` hook, and SET off by default.
- PR 126658 contributes the v3 layer on top as follow-up work: USM key
  localization, HMAC over PSA, AES-128-CFB, discovery and Reports, VACM tables,
  the extra MIB-II groups, and `snmpEngine`/`usmStats`.
- No wholesale merge of the two trees. Two BER codecs, two registries and two
  instance models in one tree would double the code and inherit both sets of
  defects.

This module keeps working as the out-of-tree reference implementation while the
split is settled. The fixes below are worth having regardless of which base wins,
because they are security and correctness fixes rather than structural choices.

## Finding disposition

| # | Finding (weight) | Status in this tree | Where it lands |
|---|---|---|---|
| 1 | Default read-write v3 user and default write community (blocking) | Fixed (including v3 SET gate) | Current module and port |
| 2 | VACM view escape on GETNEXT/GETBULK (blocking) | Fixed | Current module; re-done inside `fetch_next()` on the port |
| 3 | engineBoots not persisted (blocking) | Fixed (`struct snmp_storage` + two-slot CRC-32 EEPROM backend, fallback to `settings_prefix`) | Current module and port |
| 4 | v3 path needs ~8 KiB stack frames (blocking) | Fixed (`current_v3_msg` + `scratch.usm` in `struct snmp_agent`; max frame 352 B on `nucleo_h743zi`) | Current module; in-place BER reader on the port |
| 5 | Rate limiter spins the service thread (blocking) | Fixed | Current module; port keeps the drain-first order |
| 6 | Shared `"ZEPHYR1"` engine ID without HWINFO (blocking) | Fixed | Current module and port |
| 7 | VACM table writes not under the agent lock (low) | Fixed (`snmp_vacm_add_*` acquire `inst->lock`) | Current module and port |
| 8 | Pass phrases stay in RAM, Kconfig values in flash (low) | Fixed (defaults removed; pass phrases zeroized after localization) | Current module and port |
| 9 | No Report on a wrong digest (optional) | Fixed | Current module and port |
| 10 | UBSAN left shift of a negative `int32_t` (nit) | Fixed | Current module and port |
| 11 | Offloaded interface binding fails `start` (comparison note) | Fixed | Current module |
| 12 | SET has no switch (blocking, part of 1) | Fixed (v1/v2c and v3) | Current module and port |
| 13 | POSIX socket names in public header + `CONFIG_SNMP_AGENT` leftovers | Fixed (`net_sockaddr_in`, `NET_*`/`ZSOCK_*` names, `CONFIG_SNMP` only) | Current module |

## What changed, with evidence

### 1. No shipped credentials, SET off by default

- `CONFIG_SNMP_V3_USER_NAME`, `CONFIG_SNMP_V3_AUTH_PASS` and
  `CONFIG_SNMP_V3_PRIV_PASS` default to the empty string.
- `snmp_usm_init()` creates no user when the name is empty, so a v3 agent with
  only `CONFIG_SNMP_VERSION_3=y` rejects every request until the application
  calls `snmp_usm_add_user()`.
- `snmp_vacm_init()` no longer maps an identity to the `admin` group by
  default. The `admin`/`readonly` groups and their views still exist, but no
  user reaches them until the application adds a mapping.
- `CONFIG_SNMP_COMMUNITY_WRITE` defaults to empty.
- SET is compiled out unless `CONFIG_SNMP_SET_ENABLE=y` (new, default `n`).
  When it is off, a SET is answered with `noSuchName` for SNMPv1 and
  `notWritable` for v2c/v3, and no MIB write callback is reachable.
- Samples enable `CONFIG_SNMP_SET_ENABLE=y` because they document writable
  objects; the module default stays read-only.

A default build of the v3 sample now prints the identity it registered at run
time, and the Kconfig values that used to be the default user are gone from
`samples/snmp_agent_v3/prj.conf`.

### 2. VACM filters every returned OID

VACM used to be checked only on the request OIDs, which is why GETNEXT and
GETBULK could walk outside a user's view.

- `snmp_core.c` now authorizes a walk as a class: it checks that the identity
  has a read rule and a view (with `target_oid = NULL`, a view-presence check),
  then arms `agent->view_filter` with the context, security model, security
  name, level and access type.
- `snmp_mib_get_next_visible()` calls the plain `snmp_mib_get_next()` and then
  filters each candidate through `snmp_vacm_oid_allowed()`, advancing until an
  OID inside the view is found or the walk reports `endOfMibView`.
- `snmp_vacm_oid_allowed()` is a no-op when no filter is armed, so v1/v2c and
  internal callers keep their old behavior.
- The dispatch path clears `view_filter.active` on every exit, including error
  paths, so a filter cannot leak into the next request.

This is also the shape the review asks for on 125643: put the view check inside
the `fetch_next()` loop. On this module it lives in `snmp_mib.c` because that is
where the loop is.

New regression test: `tests/unit/test_vacm.c:test_vacm_getnext_view_filter_skips_hidden_oids`
registers a system-group scalar and an enterprise scalar, arms the `monitor`
restricted view, and asserts that the walk returns the system scalar first and
then `endOfMibView`, never the enterprise OID. With the filter inactive the same
step returns the enterprise OID, which proves the test is measuring the filter
and not a registry limit.

### 3. engineBoots (`struct snmp_storage` + EEPROM backend)

`struct snmp_agent_cfg` now exposes the generic `struct snmp_storage` hook
(`read`/`write`/`ctx`), matching the interface used in PR 125643. A built-in
power-loss-safe two-slot CRC-32 EEPROM backend (`snmp_storage_eeprom_read` /
`snmp_storage_eeprom_write`, `CONFIG_SNMP_STORAGE_EEPROM`) persists
`snmpEngineBoots` across reboots on `zephyr,sim-eeprom` (`native_sim`),
`zephyr,emu-eeprom`, and hardware EEPROM shields (`x_nucleo_eeprma2`), with
`cfg.settings_prefix` retained as fallback.

### 4. v3 stack frames (`<= 352 B` per frame in `src/`)

`current_pdu` and `current_v3_msg` now share a union inside `struct snmp_agent`,
and USM plaintext/signing buffers use `scratch.usm` under `agent->lock`.
Measured with `-fstack-usage` on `nucleo_h743zi`, the largest single frame across
`src/*.c` is now **352 B** (`snmp_usm_build_outgoing`, `snmp_ber_decode_v3_msg`,
`snmp_mib_get_next`), down from 8,224 B in `process_v3`. Parsing `msgGlobalData`
and `msgSecurityParameters` in place with `snmp_ber_reader` remains the clean
structural design for the port onto PR 125643.

### 5. Rate limiter drains before it drops

`snmp_service_cb()` now calls `zsock_recvfrom()` first and only then applies the
token bucket. Previously a rate-limited datagram stayed queued, the next poll
reported `POLLIN` immediately, and the socket-service thread spun. A dropped
datagram still increments `snmpSilentDrops` exactly once on the receiving agent.

### 6. Engine ID without a hardware ID

Without a `hwinfo` device ID the module used the fixed `0x80001F88 05 "ZEPHYR1"`
value, so devices with the same pass phrase localized the same keys. It now
draws eight octets from `sys_csrand_get()` and appends them to the RFC 3411
format-5 prefix. `snmp_usm_init()` returns `-EIO` if no random source is
available instead of silently sharing an identity.

A random ID changes across reboots, so managers redo discovery. Applications
that need a stable identity (or more than one instance) must pin
`cfg.engine_id`; the sample derives a stable ID from the STM32H7 UID through
`hwinfo` and documents that.

### 9. Report on a wrong digest

`snmp_usm_verify_incoming()` now returns a Report carrying
`usmStatsWrongDigests.0` when the digest does not verify, with the
`noAuthNoPriv` level the failed message allows, and still drops the message
silently when the reportable flag is clear. The counter is incremented in both
cases. This matches RFC 3414 §3.2 step 6 plus RFC 3412 §7.2 step 6a and fixes the
interop timeout pysnmp showed.

`tests/src/test_usm.c` now has two tests: a reportable bad digest produces a
Report with the right OID and counter, and a non-reportable bad digest is
dropped with the counter incremented.

### 10. UBSAN shift

`snmp_ber_decode_int()` accumulates in `uint32_t` and casts once at the end, so
the sign extension no longer shifts a negative `int32_t`.

### 11. Offloaded interface binding

`snmp_sock_bind_to_iface()` returns success without calling
`SO_BINDTODEVICE` when `net_if_is_offloaded(iface)` is true. Offload engines
(NSOS on `native_sim`, vendor drivers) reject the option with `EOPNOTSUPP` and
already tie the socket to that interface, so `cfg.iface` now works there.

## Not changed here, and why

- Structural items (flash iterable-section object model, one-instance model,
  in-place BER reader/writer, MIB-II mocks under `CONFIG_ZTEST`) are the port
  work itself. Patching them in this tree would be a rewrite that competes with
  the base decision.
- Informs are still fire-and-forget. The review lists retransmission as a later
  feature, not a defect.
- The `SET with read community` difference (this agent drops it and counts
  `snmpBadCommunityUses`; 125643 answers `authorizationError`/`noSuchName`) is
  left as a design question for the port, where communities map to security
  names and go through VACM like any other identity.

## Additional hardening applied on top of `56d4bfc`

- `SNMP_SET_ENABLED` is now also enforced in `process_v3()` and
  `snmp_mib_dispatch()`.
- `process_v3()` now bounds response encoding to `min(max_resp_len, msgMaxSize)`.
- `snmp_vacm_add_*()` mutations acquire `inst->lock`.
- `auth_pass` and `priv_pass` are zeroized from `struct snmp_usm_user` and stack
  temporaries immediately after key localization.
- `sizeof(struct snmp_agent)` on 32-bit `qemu_x86` dropped to **28,692 B**
  (v1/v2c) and **35,152 B** (v3) by removing `scratch.bulk.current_oids` and
  tuning VACM default table capacities (`4/8/8/16`).
- Public header and transport code switched from POSIX socket types to Zephyr
  native `net_sockaddr_in` / `NET_*` / `ZSOCK_*` symbols, and legacy
  `CONFIG_SNMP_AGENT` guards were removed.

## Port plan onto PR 125643

1. Base lands first. Fix 125643's three review comments and its `recvmsg`
   fallback before it leaves draft; keep it EXPERIMENTAL.
2. v3 message processing and USM:
   - version dispatch in `snmp_process_message()`;
   - parse `msgGlobalData` and USM parameters in place, no `struct snmp_v3_msg`
     copies;
   - reuse this module's key localization, HMAC and AES-CFB over PSA;
   - `engineBoots` in `struct snmp_storage`;
   - no default users, no shared engine-ID fallback;
   - Reports including `usmStatsWrongDigests` and `msgMaxSize`;
   - `snmpEngine`/`usmStats` as `SNMP_SCALAR_DEFINE()`.
3. VACM:
   - one access check per security name, replacing `community_access()`;
   - view check inside `fetch_next()` and in `process_get()`/`process_set()`;
   - communities mapped to security names per RFC 3584 so v1/v2c use the same
     path;
   - tables ported under the agent lock.
4. MIB-II `interfaces`, `ip`, `icmp`, `tcp`, `udp` as 125643 table providers,
   fed by `net_mgmt` statistics rather than the private `net_stats` API.

Steps 2 to 4 are the code worth taking from this module (USM, VACM, MIB-II
groups, `usmStats`/`snmpEngine`). The copyright line stays with the code and the
work should come from this author with tpambor reviewing, as the maintainer
proposed.

## Verification run for this change set

| Gate | Result |
|---|---|
| Host unit tests (`tests/unit`) | 49 + 11 passed |
| Twister `native_sim/native/64 --integration` | 74/74 test cases passed |
| Samples, six matrix entries (`snmp_agent`, `snmp_agent_v3` x `native_sim/native/64`, `qemu_x86`, `nucleo_h743zi`) | all build |
| `clang-format --dry-run --Werror` over `src include samples tests/src tests/unit` | clean |
| Doxygen (`docs/Doxyfile`, `WARN_AS_ERROR = YES`) | 0 warnings |
| HIL on NUCLEO-H743ZI | not run in this change set; hardware behavior is UNKNOWN here |

The Twister run covers the `snmp_vacm` ztests, which now create the `admin`
mapping explicitly because the module no longer creates one. The host VACM suite
does the same, so both exercises the "no default identity" path.

## Open questions for the maintainers

- Should v1/v2c requests go through VACM on the base (RFC 3584 mapping), or keep
  the community check and apply VACM only to v3? We propose the former, because
  it is the only way one access-control model covers all versions.
- Is `CONFIG_SNMP_SET_ENABLE` acceptable as the base's SET switch, or does the
  base prefer a per-object writable flag with the global switch as a second
  gate? This module uses the global switch plus the existing per-node `set_cb`.
- For the engine ID, is a random per-boot fallback acceptable when no hardware
  ID exists, or should the base refuse to start v3 until the application pins
  `cfg.engine_id`? This module chose the random fallback and logs a warning.
