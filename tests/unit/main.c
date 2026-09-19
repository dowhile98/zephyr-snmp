/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 *
 * SNMP Agent Unit Test Runner
 */

#include <stdio.h>
#include <stdlib.h>

/* Simple test framework */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) void name(void)
#define RUN_TEST(name) do { \
    tests_run++; \
    printf("  %-50s ", #name); \
    fflush(stdout); \
    name(); \
    tests_passed++; \
    printf("PASS\n"); \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAIL (%s:%d: %s)\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while(0)

#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))
#define ASSERT_GT(a, b) ASSERT((a) > (b))
#define ASSERT_LT(a, b) ASSERT((a) < (b))

extern void test_ber_integer_roundtrip(void);
extern void test_ber_octet_string_roundtrip(void);
extern void test_ber_oid_roundtrip(void);
extern void test_ber_uint32_roundtrip(void);
extern void test_ber_uint64_roundtrip(void);
extern void test_ber_null_roundtrip(void);
extern void test_ber_sequence_roundtrip(void);
extern void test_ber_decode_malformed_header(void);
extern void test_ber_decode_truncated_packet(void);
extern void test_ber_encode_buffer_overflow(void);
extern void test_oid_equal(void);
extern void test_oid_compare_lexicographic(void);
extern void test_oid_encode_decode_roundtrip(void);
extern void test_oid_max_depth(void);
extern void test_mib_register_get(void);
extern void test_mib_get_next(void);
extern void test_mib_duplicate_oid(void);
extern void test_table_register_get(void);
extern void test_table_get_next_order(void);
extern void test_table_set(void);
extern void test_interleaved_scalar_and_table_walk(void);

int main(void)
{
    printf("SNMP Agent Unit Tests\n");
    printf("=====================\n\n");

    printf("BER Encode/Decode:\n");
    RUN_TEST(test_ber_integer_roundtrip);
    RUN_TEST(test_ber_octet_string_roundtrip);
    RUN_TEST(test_ber_oid_roundtrip);
    RUN_TEST(test_ber_uint32_roundtrip);
    RUN_TEST(test_ber_uint64_roundtrip);
    RUN_TEST(test_ber_null_roundtrip);
    RUN_TEST(test_ber_sequence_roundtrip);
    RUN_TEST(test_ber_decode_malformed_header);
    RUN_TEST(test_ber_decode_truncated_packet);
    RUN_TEST(test_ber_encode_buffer_overflow);

    printf("\nOID Handling:\n");
    RUN_TEST(test_oid_equal);
    RUN_TEST(test_oid_compare_lexicographic);
    RUN_TEST(test_oid_encode_decode_roundtrip);
    RUN_TEST(test_oid_max_depth);

    printf("\nMIB Engine:\n");
    RUN_TEST(test_mib_register_get);
    RUN_TEST(test_mib_get_next);
    RUN_TEST(test_mib_duplicate_oid);
    RUN_TEST(test_table_register_get);
    RUN_TEST(test_table_get_next_order);
    RUN_TEST(test_table_set);
    RUN_TEST(test_interleaved_scalar_and_table_walk);

    printf("\n=====================\n");
    printf("Results: %d passed, 0 failed, %d total\n", tests_passed, tests_run);

    return tests_failed > 0 ? 1 : 0;
}
