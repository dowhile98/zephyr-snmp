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
source ~/zephyrproject/zephyr/zephyr-env.sh
west build -p always -b nucleo_h743zi samples/snmp_agent   # hardware sample
west build -b native_sim samples/snmp_agent                # what CI builds
west build -b qemu_x86   samples/snmp_agent
```

- `~/zephyrproject` paths above replace the old `/home/tecna/...` references — those
  were from a different machine and are gone.

## Tests — do not use Twister or ztest

The unit suite in `tests/unit/` is a **plain host CMake/POSIX binary**, not a Zephyr
test. There is no `testcase.yaml`; `west twister -T tests/` finds nothing. It links
only `src/snmp_ber.c` and `src/snmp_mib.c` against stub headers in
`tests/unit/zephyr/` (`kernel.h`, `sys/atomic.h`).

```bash
cd tests/unit
cmake -S . -B build && cmake --build build
./build/snmp_unit_tests
```

Gotchas an agent will otherwise miss:
- Custom `ASSERT*` macros in `tests/unit/main.c` call `exit(1)` — the **first failure
  aborts the whole run**; later tests never execute.
- Adding a test requires three edits: define it in a `test_*.c`, add `extern`
  declaration + `RUN_TEST(...)` in `main.c`, and (for new source under test) add the
  `.c` file plus any needed `CONFIG_SNMP_*` defines in `tests/unit/CMakeLists.txt`.
- Compiled with `-Wall -Wextra -Werror`; host tests must not pull in networking or
  crypto code (`snmp_core.c`, `snmp_service.c`, `snmp_usm.c`, `snmp_vacm.c` are excluded).
- Integration testing is manual, via Net-SNMP CLI against a running board/QEMU
  (see `README.md` "Testing" and `samples/snmp_agent/README.md`).

## CI gates (`.github/workflows/ci.yml`)

1. `unit-tests` — host cmake build + `./snmp_unit_tests` (blocking).
2. `check-format` — `clang-format --dry-run --Werror` over `src include samples`, but
   suffixed with `|| true`, so it **never fails**; still run clang-format locally.
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

## Known stale spots (don't trust these as references)

- `docs/` Sphinx + Doxygen config still names the project `zephyr-dgus` — copied from
  a different repo; the wiki under `docs/wiki/` is the accurate architecture source.
- `task.md` and `temp/` are gitignored scratch files, not specs.
- `dts/`, `scripts/`, `reference/` are currently empty placeholders.

## Design priorities

1. Correctness over performance; RFC 3412/3414/3415/3416/3418 compliance first.
2. Testability — protocol logic must stay host-testable without hardware or sockets.
3. Static memory only; respect `CONFIG_SNMP_MAX_*` bounds on all buffer writes.
4. Follow Zephyr conventions; keep code format-checkable under `-Werror`.
