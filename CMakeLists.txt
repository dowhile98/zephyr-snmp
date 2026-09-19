# SPDX-License-Identifier: Apache-2.0

if(CONFIG_SNMP_AGENT)
    zephyr_library()
    zephyr_library_include_directories(include)

    zephyr_library_sources(
        src/snmp_ber.c
        src/snmp_mib.c
        src/snmp_core.c
        src/snmp_service.c
    )

    if(CONFIG_SNMP_VERSION_3)
        zephyr_library_sources(
            src/snmp_usm.c
            src/snmp_vacm.c
        )
    endif()

    if(CONFIG_SNMP_TRAP_ENABLED)
        zephyr_library_sources(
            src/snmp_trap.c
        )
    endif()
endif()
