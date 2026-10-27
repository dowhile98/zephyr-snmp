# AGENTS.md — zephyr-snmp

Embedded SNMP agent (v1/v2c/v3) for Zephyr RTOS. This repo **is a Zephyr module**
(`zephyr/module.yml`, module name `snmp`), not an application. `src/` must stay
heap-free: never introduce `malloc`/`k_malloc`.

## Build environment (this machine)

- Zephyr workspace `~/zephyrproject` (v4.4.0-15809-g55303e23f59d), SDK
  `~/zephyr-sdk-1.0.1`. `west` is not on PATH; use the venv at
  `/home/jeffry/.zinstaller/.venv` (west v1.5.0). The `~/zephyrproject/.venv` path in
  some sample docs does not exist.
- This repo is **not** in the workspace manifest. Samples and tests register it
  themselves via `EXTRA_ZEPHYR_MODULES`, so build from the repo root:

```bash
export PATH=/home/jeffry/.zinstaller/.venv/bin:$PATH
source ~/zephyrproject/zephyr/zephyr-env.sh     # sets ZEPHYR_BASE
west build -p always -b native_sim/native/64 samples/snmp_agent
west build -p always -b qemu_x86 samples/snmp_agent
west build -p always -b nucleo_h743zi samples/snmp_agent   # hardware sample
```

- Both `native_sim` (32-bit) and `native_sim/native/64` build and pass here; CI and
  `integration_platforms` use `native_sim/native/64`.
- v3 is off by default and pulls in mbedTLS/PSA Crypto. Enable it per build with
  `west build ... -- -DCONFIG_SNMP_VERSION_3=y`; the sample's `prj.conf` stays v1/v2c.
- Multi-instance poll budget: `CONFIG_ZVFS_POLL_MAX >= CONFIG_SNMP_MAX_INSTANCES *
  SNMP_SVC_FDS + 1`, where `SNMP_SVC_FDS` is 1 for IPv4-only and 2 with IPv6. A
  `BUILD_ASSERT` in `src/snmp_service.c` enforces it. The sample's dual-instance command
  uses 5 (IPv6 assumption); 3 is the hard minimum for 2 IPv4-only instances (add
  headroom for other socket services).
- Physical NUCLEO board (flash/reset/UART/CAN) goes through the `agentic-hil` MCP tools,
  not `west flash`, `openocd`, `st-flash`, or a serial terminal.

## API shape (no singleton)

- Instance-explicit: `snmp_agent_init(&agent, &cfg)`, `start/stop/deinit`,
  `snmp_mib_register*`, `snmp_trap_*`. There is no `snmp_agent_get_default()` and no
  function name ending in `_inst`; do not add one.
- All 5 MIB callback typedefs take `struct snmp_agent *agent` as the **first** parameter.
  `node->user_data` / `row->user_data` may point only at application-owned state or
  compile-time constants — **never at a `snmp_agent` or a field inside one** (that
  aliasing is how counters leaked across instances).
- Agent APIs take a non-recursive `k_mutex` (exceptions: `snmp_agent_get_counters`,
  `snmp_usm_get_engine_boots`). Never call them from inside a MIB callback, an ISR, or
  while already holding that agent's lock — it deadlocks.
- On host (`!__ZEPHYR__`) builds there are no sockets: `snmp_agent_start()` returns
  `-ENOTSUP`; inject frames with `snmp_agent_process_pdu()` in unit tests.

## Tests (run both suites)

### Host unit tests — `tests/unit/`

Plain CMake/POSIX, no Zephyr kernel. `snmp_unit_tests` links `snmp_ber`, `snmp_mib`,
`snmp_core`, `snmp_mib2`; `vacm_unit_tests` links `snmp_ber`, `snmp_mib`, `snmp_vacm`
and has its own `main()`.

```bash
cd tests/unit
cmake -S . -B build && cmake --build build
./build/snmp_unit_tests && ./build/vacm_unit_tests   # both: 48 + 10 = 58 tests
```

- The custom `ASSERT*` macros call `exit(1)`: the **first** failure aborts the whole
  binary, so a short "N passed" list means truncated, not clean.
- Adding a host test needs three edits: define it in a `test_*.c`, add an `extern` +
  `RUN_TEST()` in `main.c`, and add any new source file / `CONFIG_SNMP_*` define to
  `tests/unit/CMakeLists.txt`. Host builds use the hand-written stubs in
  `tests/unit/zephyr/` (`kernel.h`, `sys/atomic.h`); code needing more Zephyr APIs needs
  a new stub or belongs in the Ztest suite.

### Ztest / Twister — `tests/`

```bash
west twister -T tests/ -p native_sim/native/64 -v --inline-logs --integration  # CI, 58/58
west twister -T tests/ -p native_sim -v --inline-logs                          # no --integration
```

- `--integration` selects **only** `integration_platforms` from `tests/testcase.yaml`
  (`native_sim/native/64`). With `-p native_sim` it filters everything out — drop
  `--integration` for the 32-bit run.
- `tests/prj.conf` already sets `CONFIG_SNMP_MAX_INSTANCES=2` and
  `CONFIG_ZVFS_POLL_MAX=5`; keep those budgets when changing instance counts.
- `snmp_service.c`, `snmp_usm.c`, and `snmp_trap.c` are only covered by this suite and
  target builds, not the host binaries.

## CI gates (`.github/workflows/`)

- `compliance` — `clang-format --dry-run --Werror` over `src include samples tests/src
  tests/unit`. CI pins clang-format **23.1.1**; local may be 23.1.3.

```bash
find src include samples tests/src tests/unit \( -name '*.c' -o -name '*.h' \) \
  | xargs clang-format --dry-run --Werror
```

- `host-unit-tests` — builds and runs **both** host binaries.
- `twister-tests` — `native_sim/native/64` with `--integration`, uploads the reports.
- `sample-builds` — `samples/snmp_agent` and `samples/snmp_agent_v3`, each for
  `native_sim/native/64`, `qemu_x86` and `nucleo_h743zi` (six matrix entries). A new
  sample is not built until added to the matrix; workflow files are
  governance-sensitive, so changes there need explicit human approval.
- `documentation` — Doxygen 1.14.0 with `WARN_AS_ERROR = YES` in `docs/Doxyfile`, plus
  Sphinx `-W --keep-going`. Doxygen warnings (e.g. malformed `/** */` or bad `@param`)
  fail CI; `WARN_IF_UNDOCUMENTED = NO`, so an undocumented symbol alone does not.
  `wiki` is a symlink to `docs/wiki`.

## Memory, globals, layout

- Measured `sizeof(struct snmp_agent)` on 32-bit `qemu_x86` with default Kconfig:
  **30,220 B** for v1/v2c and **39,432 B** with `CONFIG_SNMP_VERSION_3=y`. The
  README/Kconfig per-instance figures (~23.8/33.3 KiB, ~21 KiB v3-off) are stale;
  size `CONFIG_SNMP_MAX_INSTANCES` (range 1..8) against ~30 KiB per v1/v2c instance.
  Dominant members: `mib_nodes[128]` 11.0 KiB, `scratch` union 8.5 KiB,
  `current_pdu` 6.5 KiB, `rx_buf`+`tx_buf` 2 KiB.
- Kconfig asks for `CONFIG_NET_SOCKETS_SERVICE_STACK_SIZE >= 12 KiB` with v3 or GetBulk,
  but `samples/snmp_agent/prj.conf` sets 4096. Raise the stack before enabling v3/GetBulk
  in that sample.
- No mutable file-scope state in `src/`: audit firmware objects with
  `nm --defined-only <obj> | grep ' [DdBbWwVv] '`. Allowed exceptions are
  `snmp_service.o`'s `s_slot_owner`, `s_slot_lock`, Zephyr-generated
  `__z_net_socket_service*`, and `log_dynamic_snmp_service` (`log_const_*` is read-only
  `R`); host/Ztest `snmp_mib2.o` also has test-only
  `s_mock_ifaces`/`s_mock_iface_cnt`. `s_slot_desc` is `static const` (`R` on Zephyr,
  `.data.rel.ro`/`d` on host).
- Layout: root `CMakeLists.txt` compiles `snmp_ber`, `snmp_mib`, `snmp_core`,
  `snmp_service`, `snmp_mib2`; `snmp_usm`/`snmp_vacm` under `CONFIG_SNMP_VERSION_3`;
  `snmp_trap` under `CONFIG_SNMP_TRAP_ENABLED`. Add new `src/*.c` there (and to
  `tests/unit/CMakeLists.txt` if host-testable).
- `samples/snmp_agent/src/app_*.c` (app_led, app_button, app_sensor, app_mib) is the
  intended consumption pattern. `samples/brightc_sensor/` is MIB documentation only
  (no code, no build).

## Stale / misleading sources

- `CONTRIBUTING.md` says `west build -b native_posix tests/unit`; `native_posix` is gone
  and `tests/unit` is a host CMake project. Use the commands above.
- README/Kconfig per-instance RAM figures (v1/v2c and v3) are stale; use the measured
  struct sizes above.
- `temp/` and `task.md` are gitignored scratch. The
  `temp/snmp-multi-instance-design.md` referenced by old notes/code comments is not in
  the tree.
- `dts/`, `scripts/`, and `reference/` are empty placeholders.
