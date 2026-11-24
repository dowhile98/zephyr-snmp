# Re-review of `temp/documentation-audit.md` — findings, engineBoots persistence, RAM footprint

Author: StructCore Embedded
Date: 2026-11-23
Reviewed artifacts: `temp/documentation-audit.md` (256-line report) and
`docs/superpowers/plans/2026-10-14-documentation-audit.md` (472-line plan), both committed in
`f3cda2e`. The report is deleted in the working tree and is also listed in `.gitignore` while still
being tracked, so this review reads the `HEAD` copy.
Method: every quantitative claim was re-measured on the current tree (`56d4bfc`) — host suites,
Twister, Doxygen 1.9.8, `-fstack-usage` on the NUCLEO-H743ZI build, and `gdb ptype /o` on the
`qemu_x86` ELFs. Claims that could not be re-measured are marked UNKNOWN.

---

## 1. Findings

| # | Claim in the audit | Current reality | Verdict |
|---|---|---|---|
| F1 | Host suite: 37 + 10 = 47 tests; `tests/unit/*.c` = 7 files | 49 + 11 = 60 tests; 9 files | **Outdated** |
| F2 | Ztest: 47 cases in `tests/src/*.c` (7 files) | 70 `ZTEST()` cases in 10 files | **Outdated** |
| F3 | `docs/Doxyfile` verified with `WARN_AS_ERROR = NO` | `WARN_AS_ERROR = YES` since `f3cda2e`; CI fails on any warning | **Outdated (stricter now)** |
| F4 | `sizeof(struct snmp_agent)` = 30,220 B / 39,480 B | 30,228 B / 39,556 B (+8 / +76 B from `view_filter`) | **Stale by one commit** |
| F5 | "Stack usage during packet processing is strictly bounded (< 800 bytes)" | `process_v3` = **8,224 B**, `snmp_usm_build_outgoing` = 2,208 B, `snmp_usm_verify_incoming` = 1,232 B, `snmp_mib_get_next` = 352 B (`-fstack-usage`, NUCLEO-H743ZI build) | **False**; independently confirms the review's 8 KiB v3 finding |
| F6 | Scratch-union snippet shows `uint8_t buf[CONFIG_SNMP_BUFFER_SIZE]` | No `CONFIG_SNMP_BUFFER_SIZE` exists; the member is `CONFIG_SNMP_MAX_PDU_SIZE` | **Incorrect example** |
| F7 | "136 of 137 DAECGE occurrences corrected, 1 retained in `CHANGELOG.md`" | 21 tracked occurrences: 1 `CHANGELOG.md`, 1 sample MIB module name, 3 `samples/brightc_sensor/README.md`, **16 in `docs/superpowers/plans/2026-10-14-documentation-audit.md`** | **Outdated** |
| F8 | engineBoots: "load + increment + save through `cfg.settings_prefix`" | True only with `CONFIG_SETTINGS` **plus** a settings backend; otherwise `-ENOTSUP` and the compile-time value is used (the `-95` the review saw) | **Misleading**; the gap is still open (§2) |
| F9 | HIL report is authoritative, users `v3test` / defaults | Valid for `f3cda2e`; the module now ships no default user and no default write community, and SET is gated | **Historical**, annotated in the wiki page |
| F10 | "0 undocumented items" among public headers | `WARN_IF_UNDOCUMENTED = NO`, so Doxygen cannot fail on that; the statement is an assertion, not a gate | **Method limitation** |
| F11 | Acceptance checklist "100% satisfied" | Describes `f3cda2e`; `56d4bfc` changed defaults, SET behaviour, VACM semantics and engine IDs | **Time-boxed** |
| F12 | Zero heap in `src/`; multi-instance; `CONFIG_ZVFS_POLL_MAX` budget | Re-verified: no `malloc`/`k_malloc` in `src/`, `BUILD_ASSERT` present, no mutable globals beyond the documented set | **Still valid** |
| F13 | MIB-II interfaces group is "built-in" (`docs/wiki/Home.md`) | `snmp_mib2_register_all()` has **no caller** in `src/` or `samples/`; only tests call the group registrars. A default build exposes system + snmp only (37 nodes) | **Overstated** |

Repo hygiene issues found while checking the above, independent of the accuracy findings:

- `docs/superpowers/plans/2026-10-14-documentation-audit.md` (472 lines) is tracked. It is the agent
  plan for the audit, not user documentation, and it is the source of most of the remaining
  DAECGE text. It belongs in `architecture/` (gitignored except `architecture/upstream/`) or
  nowhere.
- `temp/documentation-audit.md` is both tracked and listed in `.gitignore`. One of the two is
  wrong; the file is deleted in the worktree, so the next commit either records the deletion or
  un-ignores the path.
- The Doxygen tree under `docs/_build_doxygen/` is untracked (verified: 0 tracked files), so no
  action needed there.

None of the findings question the audit's core conclusions (English-only, instance-explicit API,
`user_data` invariant, ISR offload rule, poll budget). What is stale is every number: test counts,
struct size, stack bound, and the persistence claim.

---

## 2. Closing the engineBoots persistence gap

### 2.1 Why it is still open

`snmp_agent_load_engine_boots()` requires `CONFIG_SETTINGS` *and* a settings backend that a board
sample may not enable. The v3 sample sets `cfg.settings_prefix = "snmp/lan"` and NUCLEO-H743ZI has
no settings backend in its default config, so the call returns `-ENOTSUP`, the compile-time value
is used, and the replay window repeats after a reboot. That is exactly the review's finding.

The fix is not "add settings"; it is "give the module a storage port it can actually satisfy on a
board". PR 125643 already has the right shape: a generic `struct snmp_storage` hook. Porting the
hook now means the v3 layer arrives on the base with persistence already solved.

### 2.2 Design

```c
/* Public: the same shape 125643 uses, so the port needs no adapter rewrite. */
struct snmp_storage {
	int (*read)(void *ctx, uint8_t *buf, size_t len);
	int (*write)(void *ctx, const uint8_t *buf, size_t len);
	void *ctx;   /* caller-owned, never the agent */
};

/* struct snmp_agent_cfg gains: */
const struct snmp_storage *storage;   /* NULL = fall back to settings, then compile time */
```

Two bundled backends, both heap-free and global-free:

1. `src/snmp_storage_eeprom.c` — `CONFIG_SNMP_STORAGE_EEPROM`. Uses
   `<zephyr/drivers/eeprom.h>`; the device comes from `DT_ALIAS(eeprom_0)` unless the application
   passes a `struct device *`. Record layout, two slots of 16 bytes each:

   | bytes | field |
   |---|---|
   | 0..3 | magic `"SNMP"` |
   | 4 | format version (1) |
   | 5..7 | reserved, zero |
   | 8..11 | engineBoots, little endian |
   | 12..15 | CRC-32 (IEEE) over bytes 0..11 |

   Two slots give power-loss safety without a journal: a save always writes the slot holding the
   *lower* valid value, so a torn write leaves the other slot intact and the loader takes the
   maximum of the valid slots. A slot is valid when magic, version, CRC and the RFC 3414 range
   (1..2 147 483 647) all check out. Neither valid → `-ENOENT` (first boot).
   Slots are page-aligned by the caller choosing an offset that is a multiple of the EEPROM page
   size (16 B on the M24C02 shield), so drivers that require page granularity are satisfied.

2. `src/snmp_storage_settings.c` — the existing `settings_save_one`/`settings_load_one` path,
   moved behind the same interface. Kept for boards that already run `CONFIG_SETTINGS`.

Resolution order in `snmp_agent_load_engine_boots()`: explicit `cfg.storage` → settings prefix →
compile-time constant. The RFC 3414 logic (`max(stored, configured)`, increment below the ceiling,
persist before serving) moves into one helper shared by both backends, so there is a single place
where the "must increase on every boot" rule lives.

Policy question to settle: with `cfg.storage` set and the backend failing, should `snmp_agent_init()`
fail (`-EIO`, no silent replay window reuse) or warn and continue? Proposal: a
`CONFIG_SNMP_V3_REQUIRE_STORAGE` option, default `n` for compatibility, which samples turn on.

### 2.3 Which EEPROM each board actually has

| Target | Device | Note |
|---|---|---|
| `native_sim/native/64` | `zephyr,sim-eeprom`, alias `eeprom-0`, 32 KB, file-backed | persists across runs, which is what the "boot twice" test needs |
| `qemu_x86` | `zephyr,sim-eeprom` (`eeprom0`, 4 KB) and `zephyr,emu-eeprom` (`eeprom1` over a flash partition) | both usable; the emulated one exercises the flash path |
| NUCLEO-H743ZI | **no on-chip EEPROM**: `st,stm32-eeprom` covers L0/L1 only, and there is no `st,stm32-eeprom` node for H7 in the DT | see below |
| Any board with `zephyr,emu-eeprom` | flash-backed EEPROM | needs a partition whose page size matches the flash erase unit |
| Any board with I2C/SPI EEPROM or FRAM | `at2x`, `mb85rcxx`, `mb85rsxx`, `fm25xxx` drivers | same API, no module change |

For NUCLEO-H743ZI specifically:

- **Recommended:** the in-tree `x_nucleo_eeprma2` shield (ST M24C02 at I2C 0x54). Its overlay already
  sets `eeprom-0 = &eeprom0_x_nucleo_eeprma2`, which is exactly the alias the backend looks for, so
  the sample builds with `--shield x_nucleo_eeprma2` and the persistence path is real hardware.
- `zephyr,emu-eeprom` on internal flash is **not** attractive on H7: erase sectors are 128 KB, so
  the emulated device needs at least 2 × 128 KB = 256 KB of flash to store 16 bytes.
- Backup SRAM (`backup_sram` is enabled on this board) is a valid alternative, but this Zephyr
  version has no `stm32` retained-memory driver, so it would be application code behind the same
  `struct snmp_storage` hook. Document it, do not build it into the module.

Wear: one write per boot, alternating slots. AT24C02 is rated 1 M write cycles per page, so 2 M
boots — about 270 years at 10 boots a day. The emulated EEPROM rotates whole pages internally.

### 2.4 Test plan

| Level | Test |
|---|---|
| Host (`tests/unit`) | In-RAM fake `struct snmp_storage`: first boot returns `-ENOENT` and writes `compile-time + 1`; second "boot" reads it back and increments; corrupted primary slot falls back to the secondary; both corrupt → `-ENOENT`, no crash; CRC mismatch rejected; value at the RFC ceiling stays clamped |
| Ztest (`tests/src`) | native_sim with `zephyr,sim-eeprom`: init → stop → re-init the same device, assert boots strictly increased |
| Ztest | qemu_x86 with `zephyr,emu-eeprom`: same, plus a torn-write simulation through the fake |
| Sample | `samples/snmp_agent_v3` with `--shield x_nucleo_eeprma2`, banner prints the persisted boots |
| HIL | NUCLEO reset twice, read `snmpEngineBoots` with `snmpget`; needs explicit approval before flashing |

Effort: the port type plus the EEPROM backend is roughly 300 lines including the CRC record, and
the host tests about 200 lines. No new heap, no new globals.

---

## 3. RAM footprint reduction

### 3.1 Measured baseline (`qemu_x86`, default Kconfig, `gdb ptype /o`)

| Variant | `sizeof(struct snmp_agent)` | vs docs |
|---|---|---|
| v1/v2c | 30,228 B | +8 B |
| v3 | 39,556 B | +76 B |

Dominant members:

| Member | v1/v2c | v3 | Notes |
|---|---|---|---|
| `mib_nodes[128]` | 11,264 B | 11,264 B | 88 B per node: `snmp_oid` 68 + type/flags 4 + 3 callbacks 12 + `user_data` 4 |
| `scratch` union | 8,704 B | 8,704 B | `bulk`: `res_vb[32]` 6,528 + `current_oids[32]` 2,176; `tx_items[32]` 7,168 |
| `current_pdu` | 6,708 B | 6,708 B | `varbinds[32]` 6,528 |
| `rx_buf` + `tx_buf` | 2,048 B | 2,048 B | `CONFIG_SNMP_MAX_PDU_SIZE` each |
| `if_table` + `if_rows[8]` | 736 B | 736 B | MIB-II ifTable |
| system strings + `sys_object_id` | 388 B | 388 B | 128 + 3 × 64 + 68 |
| VACM tables | — | 8,264 B | contexts 264, groups 1,152, rules 2,752, views 4,096 |
| `users[4]` (USM) | — | 880 B | 220 B each, including 128 B of pass phrases |
| `view_filter`, stats, engine | — | ~164 B | new `view_filter` is 68 B |

The default build registers 37 nodes (30 snmp counters + 7 system) and, under v3, the usmStats and
snmpEngine objects. The other 91 array slots are unused unless the application adds nodes.

### 3.2 Ranked reductions

| # | Change | Saving | Risk |
|---|---|---|---|
| R1 | Delete `scratch.bulk.current_oids`. The cursor is always the OID of the varbind produced for that repeater in the previous repetition, so `res_vb[base + r].oid` can serve as the cursor (`base` = `new_cnt` at the start of each repetition; repetition 0 uses the request OID). | **−2,176 B** both variants | Low; GetBulk logic only, already covered by the pruning test |
| R2 | Keep built-in MIB-II nodes in flash. `snmp_mib_register_defaults()` and the `snmp_mib2_*` groups know their OIDs and callbacks at compile time, so they can live in a `static const` table that the lookups merge with the RAM array. | **−88 B per built-in node**: −3,256 B (37 default) up to −6,072 B (69 with all MIB-II) | Medium; touches `snmp_mib_get`/`get_next` search, needs the table kept sorted |
| R3 | `CONFIG_SNMP_MAX_MIB_NODES` 128 → 64 once R2 lands (the samples register 6 scalars + 1 table). | **−5,632 B** | Medium; a caller registering more than 64 app nodes gets `-ENOMEM` (visible, not silent) |
| R4 | Leaner VACM defaults: contexts 8→4, groups 16→8, rules 16→8, views 32→16. | **−4,132 B** (v3) | Low; the defaults already use 1 context, 2 groups, 2 rules, 3 views; applications can still raise them |
| R5 | `CONFIG_SNMP_V3_MAX_USERS` 4 → 2 in samples. | **−440 B** (v3) | Low |
| R6 | `CONFIG_SNMP_MAX_PDU_SIZE` 1024 → 512 in the samples. | **−1,024 B** both variants | Low; 484 is the RFC 3412 floor, so 512 stays legal, but large GetBulk responses truncate earlier |
| R7 | Drop `auth_pass`/`priv_pass` from the stored user after localization (port item: needs a separate stored type, the current struct is public API). | **−128 B per user** (−512 B at 4 users) and removes the pass phrases from RAM | Port; API change |

### 3.3 Projected totals

Assumes R1 + R6 always, R2 with the 37 default built-ins, R3 and the v3 items where they apply.

| Stage | v1/v2c | v3 |
|---|---|---|
| Today | 30,228 B | 39,556 B |
| R1 + R6 | 27,028 B | 36,356 B |
| + R2 (37 nodes in flash) | 23,772 B | 33,100 B |
| + R4 + R5 | 23,772 B | 28,528 B |
| + R3 (64 node slots) | **18,140 B** (−40 %) | **22,896 B** (−42 %) |

With all MIB-II groups registered (69 const nodes, −6,072 B instead of −3,256 B) the v3 figure
drops to about **20,080 B**.

The struct is not the only RAM cost. The v3 sample's 16 KB socket-service stack exists because
`process_v3` has an 8,224 B frame (it copies a whole `struct snmp_v3_msg`, 7,968 B). Parsing the
message in place removes that frame and lets the stack drop toward 4 KB — a ~12 KB saving per
instance that no struct trimming can match. That is port work (step 2 of the staged plan), and it
is the single largest RAM item in a v3 build.

### 3.4 What not to do

- Do not lower `CONFIG_SNMP_MAX_VARBINDS` or `CONFIG_SNMP_MAX_PDU_SIZE` by default: both change
  wire behaviour for every user of the module. Ship them as sample settings plus a documented
  "lean build" table instead.
- Do not remove `if_rows`/`if_table` from the struct; they are the only mutable MIB-II state and
  the table path needs them.
- Do not merge `current_pdu.varbinds` and `scratch.bulk.res_vb` in this tree. It would touch the
  encode path and the 2PC rollback; the port's in-place parsing supersedes it.

---

## 4. Proposed order of work

1. Fix the audit drift that costs nothing: F1, F2, F3, F4, F6, F7 (move the plan out of `docs/`,
   resolve `temp/` tracking), F13 wording, and the stack claim (F5) replaced by measured numbers.
2. Persistence, as a self-contained change: `struct snmp_storage`, the EEPROM backend, the shared
   RFC 3414 helper, host + native_sim + qemu_x86 tests, sample built with the EEPROM shield.
3. RAM: R1 (independent, measurable today), then R4/R5/R6 as sample and default tuning, then R2/R3
   as one change with the registry search tests.
4. Keep R7 and the in-place v3 parsing for the port onto 125643, where they are structural anyway.

Steps 2 and 3 change Kconfig defaults and, for R2, the MIB registry internals, so they need a
decision before implementation. Step 1 is documentation only.

## 5. Not verified here

- HIL on NUCLEO-H743ZI (flashing requires explicit approval): the EEPROM shield path and the
  double-reset engineBoots check are UNKNOWN until run.
- CI's clang-format 23.1.1 and Doxygen 1.14.0: only local 23.1.3 and 1.9.8 were run.
- The audit's Spanish-to-English completeness claim was spot-checked, not re-audited file by file.

## 6. Resolution status (follow-up commits `371f812` .. Step 3)

- **Audit drift & repo hygiene:** `temp/documentation-audit.md` and `docs/superpowers/plans/2026-10-14-documentation-audit.md` removed from git tracking; counts (`49 + 11`, `74/74` Ztest), `sizeof(struct snmp_agent)` (`28,692 B` v1/v2c, `35,152 B` v3), stack frame figures (`<= 352 B` in `src/*.c`), and MIB-II opt-in wording updated across `AGENTS.md`, `README.md`, `Kconfig`, and `docs/wiki/`.
- **`engineBoots` persistence (§2):** Implemented `struct snmp_storage` in `struct snmp_agent_cfg`, the power-loss-safe two-slot CRC-32 EEPROM backend (`snmp_storage_eeprom_read/write`, `CONFIG_SNMP_STORAGE_EEPROM`), and RAM + `zephyr,sim-eeprom` Ztests.
- **RAM & stack (§3):** Eliminated 8 KiB v3 stack frames (`current_v3_msg` + `scratch.usm` in `struct snmp_agent`), removed `scratch.bulk.current_oids`, tuned VACM defaults (`4/8/8/16`), zeroized USM pass phrases after key localization, locked `snmp_vacm_add_*()`, enforced `CONFIG_SNMP_SET_ENABLE` and `msgMaxSize` on v3, and migrated socket types to `net_sockaddr_in` / `NET_*` / `ZSOCK_*`.
