# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20)
project(snmp_unit_tests C)

# Standalone test runner for SNMP Agent
# Build: mkdir build && cd build && cmake .. && make
# Run:   ./snmp_unit_tests

add_executable(snmp_unit_tests
    main.c
    test_ber.c
    test_oid.c
    test_mib.c
    ../../src/snmp_ber.c
    ../../src/snmp_mib.c
)

target_include_directories(snmp_unit_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

target_compile_definitions(snmp_unit_tests PRIVATE
    CONFIG_SNMP_AGENT=1
    CONFIG_SNMP_MAX_OID_LEN=16
    CONFIG_SNMP_MAX_VARBINDS=32
    CONFIG_SNMP_MAX_PDU_SIZE=1024
    CONFIG_SNMP_MAX_MIB_NODES=128
)

target_compile_options(snmp_unit_tests PRIVATE -Wall -Wextra -Werror)
target_link_libraries(snmp_unit_tests PRIVATE rt)
