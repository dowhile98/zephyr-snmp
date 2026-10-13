# AGENTS.md — zephyr-snmp

Embedded SNMP agent (v1/v2c/v3) for Zephyr RTOS. This repo **is a Zephyr module**
(`zephyr/module.yml`, module name `snmp`) — it is not a standalone application.
Zero dynamic allocation: never introduce `malloc`/heap in `src/`.

## Environment (this machine)

- Zephyr workspace: `~/zephyrproject` (Zephyr v4.4.0+), SDK: `~/zephyr-sdk-1.0.1`.
- This repo is **not** imported into the workspace manifest. The sample registers it
  itself via `EXTRA_ZEPHYR_MODULES` in `samples/snmp_agent/CMakeLists.txt`, so build
  from the repo root with `ZEPHYR_BASE` set:

```bash
# west is NOT on PATH; it lives in the Zephyr Workbench venv (west v1.5.0)
export PATH=/home/jeffry/.zinstaller/.venv/bin:$PATH
source ~/zephyrproject/zephyr/zephyr-env.sh     # sets ZEPHYR_BASE
west build -p always -b qemu_x86 samples/snmp_agent
west build -p always -b nucleo_h743zi samples/snmp_agent   # hardware sample
```

- **Plain `native_sim` cannot be built on this machine** (no `gcc-multilib`; it fails
  inside Zephyr's own `lib/heap/heap_constants.c` before any SNMP file compiles — also
  on old baselines). Use the 64-bit variant: `west build -b native_sim/native/64`.
  CI still runs `native_sim`, so CI-only failures may be invisible locally.
- **Multi-instance needs a poll budget**: `CONFIG_ZVFS_POLL_MAX >=
  CONFIG_SNMP_MAX_INSTANCES * SNMP_SVC_FDS + 1` (`FDS=2` with IPv6). A `BUILD_ASSERT`
  enforces it; 2 instances ⇒ `-DCONFIG_ZVFS_POLL_MAX=5` (default 3 is too small).
- `~/zephyrproject` paths replace the old `/home/tecna/...` references, which came
  from a different machine and are gone.

## API shape (post-Phase-8: no singleton)

- Public API is instance-explicit: `snmp_agent_init(struct snmp_agent *, const struct
  snmp_agent_cfg *)`, `snmp_agent_start/stop/deinit`, `snmp_mib_register(agent, …)`,
  `snmp_trap_send(agent, …)`. **No function name ends in `_inst` and there is no
  `snmp_agent_get_default()`** — never reintroduce a default agent.
- All 5 MIB callback typedefs take `struct snmp_agent *agent` as the **first**
  parameter. `node->user_data` / `row->user_data` may point only at application-owned
  state or compile-time constants — **never at a `snmp_agent` or a field inside one**
  (that aliasing is how counters leaked across instances before).
- Contract for these decisions: `temp/snmp-multi-instance-design.md` (§4 transport,
  §6 counters, §9 invariants). Keep it updated when you deviate.

## Tests

zephyr-snmp includes two testing suites:

1. **Native Zephyr Ztest / Twister Suite (`tests/`)**: Ztest cases in `tests/src/`
   (BER, OID, MIB engine, VACM, 2PC SET, MIB-II groups, multi-instance). Config:
   `tests/testcase.yaml` allows `native_sim`, `native_sim/native/64`, `qemu_x86`, with
   `integration_platforms: native_sim/native/64`. `twister-out/` is gitignored.
   ```bash
   # On this machine only native_sim/native/64 works (see Environment):
   west twister -T tests/ -p native_sim/native/64 -v --inline-logs --integration
   # ~40 s; verified: 1 testsuite, 47/47 ztest cases pass
   ```

2. **Host Unit Tests (`tests/unit/`)**:
   Two plain host CMake/POSIX binaries providing fast-gate local verification without Zephyr kernel dependencies:
   `snmp_unit_tests` links `src/snmp_ber.c`, `snmp_mib.c`, `snmp_core.c`, `snmp_mib2.c`;
   `vacm_unit_tests` links `snmp_ber.c`, `snmp_mib.c`, `snmp_vacm.c` and has its own `main()`. Both compile against stub headers in `tests/unit/zephyr/` (`kernel.h`, `sys/atomic.h`).
   ```bash
   cd tests/unit
   cmake -S . -B build && cmake --build build
   ./build/snmp_unit_tests && ./build/vacm_unit_tests   # you must run BOTH
   ```

Gotchas an agent will otherwise miss:
- Custom `ASSERT*` macros call `exit(1)` in host unit tests — the **first failure aborts the whole run**;
  later tests never execute. A short "N passed" list can mean truncated, not clean.
- Adding a host test requires three edits: define it in a `test_*.c`, add `extern`
  declaration + `RUN_TEST(...)` in `main.c`, and (for new source under test) add the
  `.c` file plus any needed `CONFIG_SNMP_*` defines in `tests/unit/CMakeLists.txt`.
  Currently 47 host unit tests verified (37 in `snmp_unit_tests` and 10 in `vacm_unit_tests`).
- Adding a native Ztest requires adding/updating test cases in `tests/src/` with `ztest` APIs.
- Compiled with `-Wall -Wextra -Werror`; `snmp_service.c`/`snmp_usm.c`/`snmp_trap.c`
  rely on sockets/crypto/networking and are tested via the Zephyr Ztest / Twister suite and target builds.
- Integration testing is manual, via Net-SNMP CLI against a running board/QEMU
  (see `README.md` "Testing" and `samples/snmp_agent/README.md`).

## CI gates (`.github/workflows/ci.yml` & `docs.yml`) — verified facts

1. `compliance` — `clang-format --dry-run --Werror` over `src include samples tests/src tests/unit`, strict (no bypass). CI installs `pip install clang-format==23.1.1` matching the local development environment, and uses proper `find` grouping `\( -name '*.c' -o -name '*.h' \)`, eliminating local vs CI version drift.
2. `host-unit-tests` — builds and runs **both** host binaries (`./snmp_unit_tests`, `./vacm_unit_tests`).
3. `twister-tests` — runs `west twister -T tests/ -p native_sim/native/64 -v --inline-logs --integration`, correctly matching `tests/testcase.yaml` (`integration_platforms: native_sim/native/64`), and uploads test reports and `twister.json`.
4. `sample-builds` — build matrix targeting `[native_sim/native/64, qemu_x86, nucleo_h743zi]` with target-specific toolchains (`""` for native_sim, `x86_64-zephyr-elf` for qemu_x86, `arm-zephyr-eabi` for nucleo_h743zi), executed with `working-directory: zephyr-snmp` and `-p always`.
5. `documentation` (`.github/workflows/docs.yml`) — builds Doxygen 1.14.0 and Sphinx HTML documentation with `-W --keep-going`, generates preview artifacts on pull requests, and deploys to GitHub Pages on push to `main`.

## Style & structure

- `.clang-format` at root: LLVM base, tabs width 8, `ColumnLimit: 100`, Linux braces.
- Public API prefix `snmp_`, headers under `include/snmp/`, Doxygen `/** */` on public
  functions. Internal functions `static`. Conventional Commits (`fix(usm): ...`).
- Layout: `src/` core (`snmp_ber`, `snmp_mib` — engine + system/SNMP groups, `snmp_core`,
  `snmp_service`, `snmp_mib2` — MIB-II network groups ifTable/ip/icmp/tcp/udp, plus v3
  `snmp_usm`/`snmp_vacm` and `snmp_trap` — each guarded by Kconfig in root
  `CMakeLists.txt`). `CONFIG_SNMP_AGENT` depends on `NETWORKING`/`NET_UDP`/`NET_SOCKETS`
  and selects `NET_SOCKETS_SERVICE`; the agent listens on UDP :161.
- `samples/snmp_agent/src/app_*.c` (app_led, app_button, app_sensor, app_mib) show the
  intended consumption pattern — custom MIB registration, traps, DHCP/LED/button glue.
- `samples/brightc_sensor/` is MIB-definition documentation only (no code, no build).
- **RAM cost of multi-instance**: `sizeof(struct snmp_agent)` is **23,840 B (~23 KiB)
  with v1/v2c** and **33,320 B (~32.5 KiB) with `CONFIG_SNMP_VERSION_3=y`** (Kconfig
  defaults incl. `CONFIG_SNMP_MAX_IFACES=8` — `if_rows[8]` now lives in the struct).
  The USM/VACM/engine members are `#if`-guarded, so a v1/v2c build no longer pays for
  them. Dominant terms: `mib_nodes[128]` 13.3 KiB, `current_pdu` 6.8 KiB, `rx_buf`+
  `tx_buf` 2 KiB. Measured end-to-end on `qemu_x86` (`west build` RAM report):
  389,060 B with 1 instance (v1/v2c); each extra instance adds roughly one struct.
  Size `CONFIG_SNMP_MAX_INSTANCES` (range 1..8) against this.
- Enforce the no-globals invariant mechanically: `nm --defined-only <obj>` filtered on
  ` [DdBbWwVv] ` lists mutable file-scope state. Run it on **firmware objects** (a Zephyr
  build) — production `src/*.obj` must be **empty** except `snmp_service.o`'s
  platform-mandated `s_slot_owner`, `s_slot_lock`, Zephyr-generated
  `__z_net_socket_service*` and `log_const_/log_dynamic_snmp_service`. On **host/Ztest
  objects** `snmp_mib2.o` legitimately also shows `s_mock_ifaces`/`s_mock_iface_cnt`
  (test-only mock, guarded by `#if !defined(__ZEPHYR__) || defined(CONFIG_ZTEST)`).
  `s_slot_desc[]` is `static const` — `R` on Zephyr builds, `.data.rel.ro` (`d`) on host,
  so an audit script must not assume one section. `static const` OID/counter maps are fine.

## Known stale spots (don't trust these as references)

- `docs/` Doxygen and Sphinx documentation is now fully modernized and synchronized with
  `zephyr-snmp` (previously referenced `zephyr-dgus`).
- `task.md` and `temp/` are gitignored scratch files, not specs.
- `dts/`, `scripts/`, `reference/` are currently empty placeholders.

## Design priorities

1. Correctness over performance; RFC 3412/3414/3415/3416/3418 compliance first.
2. Testability — protocol logic must stay host-testable without hardware or sockets.
3. Static memory only; respect `CONFIG_SNMP_MAX_*` bounds on all buffer writes.
4. Follow Zephyr conventions; keep code format-checkable under `-Werror`.
