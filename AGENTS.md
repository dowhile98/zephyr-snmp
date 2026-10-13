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

## Tests — do not use Twister or ztest

The unit suite in `tests/unit/` is **two plain host CMake/POSIX binaries**, not Zephyr
tests. There is no `testcase.yaml`; `west twister -T tests/` finds nothing.
`snmp_unit_tests` links `src/snmp_ber.c`, `snmp_mib.c`, `snmp_core.c`;
`vacm_unit_tests` links `snmp_ber.c`, `snmp_mib.c`, `snmp_vacm.c` and has its **own
`main()`** (it does not use `main.c`). Both compile against stub headers in
`tests/unit/zephyr/` (`kernel.h`, `sys/atomic.h`).

```bash
cd tests/unit
cmake -S . -B build && cmake --build build
./build/snmp_unit_tests && ./build/vacm_unit_tests   # you must run BOTH
```

Gotchas an agent will otherwise miss:
- Custom `ASSERT*` macros call `exit(1)` — the **first failure aborts the whole run**;
  later tests never execute. A short "N passed" list can mean truncated, not clean.
- Adding a test requires three edits: define it in a `test_*.c`, add `extern`
  declaration + `RUN_TEST(...)` in `main.c`, and (for new source under test) add the
  `.c` file plus any needed `CONFIG_SNMP_*` defines in `tests/unit/CMakeLists.txt`.
  Nothing auto-discovers tests — currently 47 host unit tests verified (37 in
  `snmp_unit_tests` and 10 in `vacm_unit_tests`).
- Compiled with `-Wall -Wextra -Werror`; `snmp_service.c`/`snmp_usm.c`/`snmp_trap.c`
  are not host-compilable (sockets/crypto/deps), so v3 USM and the transport layer
  have no host coverage.
- Integration testing is manual, via Net-SNMP CLI against a running board/QEMU
  (see `README.md` "Testing" and `samples/snmp_agent/README.md`).

## CI gates (`.github/workflows/ci.yml`)

1. `unit-tests` — host cmake build + runs both `./snmp_unit_tests` and `./vacm_unit_tests` (all 47 tests verified).
2. `check-format` — `clang-format --dry-run --Werror` over `src include samples tests/unit` (strict, no bypass).
3. `build-zephyr` — builds `samples/snmp_agent` for `native_sim` and `qemu_x86` only;
   hardware boards are not covered, so verify STM32 changes yourself.

## Style & structure

- `.clang-format` at root: LLVM base, tabs width 8, `ColumnLimit: 100`, Linux braces.
- Public API prefix `snmp_`, headers under `include/snmp/`, Doxygen `/** */` on public
  functions. Internal functions `static`. Conventional Commits (`fix(usm): ...`).
- Layout: `src/` core (`snmp_ber`, `snmp_mib`, `snmp_core`, `snmp_service`, plus v3
  `snmp_usm`/`snmp_vacm` and `snmp_trap` — each guarded by Kconfig in root
  `CMakeLists.txt`). `CONFIG_SNMP_AGENT` depends on `NETWORKING`/`NET_UDP`/`NET_SOCKETS`
  and selects `NET_SOCKETS_SERVICE`; the agent listens on UDP :161.
- `samples/snmp_agent/src/app_*.c` (app_led, app_button, app_sensor, app_mib) show the
  intended consumption pattern — custom MIB registration, traps, DHCP/LED/button glue.
- `samples/brightc_sensor/` is MIB-definition documentation only (no code, no build).
- **RAM cost of multi-instance**: `sizeof(struct snmp_agent)` is **23,016 B (~22.5 KiB)
  with v1/v2c** and **32,440 B (~31.7 KiB) with `CONFIG_SNMP_VERSION_3=y`** — the
  USM/VACM/engine members are `#if`-guarded, so a v1/v2c build no longer pays for them.
  Dominant terms: `mib_nodes[128]` 13.3 KiB, `current_pdu` 6.8 KiB, `rx_buf`+`tx_buf`
  2 KiB. Measured end-to-end on `qemu_x86` (`west build` RAM report): 1 instance
  384,228 B → 2 instances 405,092 B (v1/v2c); 474,436 B for 2 instances with v3.
  Size `CONFIG_SNMP_MAX_INSTANCES` (range 1..8) against this.
- Enforce the no-globals invariant mechanically: `nm --defined-only <obj>` filtered on
  ` [DdBbWwVv] ` lists mutable file-scope state. Production `src/*.o` must be **empty**;
  the only allowed hits live in `snmp_service.o` and are platform-mandated:
  `s_slot_owner`, `s_slot_lock`, Zephyr-generated `__z_net_socket_service*`, and
  `log_const_/log_dynamic_snmp_service`. `s_slot_desc[]` is `static const` — it lands in
  `R` on Zephyr builds but in `.data.rel.ro` (`d`) on host x86-64, so an audit script
  must not assume one section for it. `static const` OID/counter maps are fine.

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
