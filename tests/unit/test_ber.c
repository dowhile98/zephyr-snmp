/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 *
 * BER Encode/Decode Unit Tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "snmp/snmp_ber.h"

#define BUF_SIZE 256
#define ASSERT(cond) do { if (!(cond)) { printf("FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); exit(1); } } while(0)
#define ASSERT_EQ(a, b) ASSERT((a) == (b))

void test_ber_integer_roundtrip(void)
{
    uint8_t buf[BUF_SIZE];
    size_t off = 0;
    int32_t values[] = {0, 1, -1, 127, -128, 32767, -32768, 2147483647, -2147483648};

    for (int i = 0; i < 9; i++) {
        off = 0;
        int ret = snmp_ber_encode_int(buf, BUF_SIZE, &off, ASN1_TAG_INTEGER, values[i]);
        ASSERT_EQ(ret, 0);

        size_t dec_off = 0;
        int32_t decoded;
        ret = snmp_ber_decode_int(buf, off, &dec_off, &decoded);
        ASSERT_EQ(ret, 0);
        ASSERT_EQ(decoded, values[i]);
    }
}

void test_ber_octet_string_roundtrip(void)
{
    uint8_t buf[BUF_SIZE];
    size_t off = 0;

    const uint8_t test_data[] = "Hello SNMP";
    int ret = snmp_ber_encode_octet_string(buf, BUF_SIZE, &off, ASN1_TAG_OCTET_STRING, test_data, 10);
    ASSERT_EQ(ret, 0);

    size_t dec_off = 0;
    uint8_t decoded[128];
    uint16_t decoded_len;
    memset(decoded, 0, sizeof(decoded));
    ret = snmp_ber_decode_octet_string(buf, off, &dec_off, decoded, sizeof(decoded), &decoded_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(decoded_len, 10);
    ASSERT(memcmp(decoded, test_data, 10) == 0);
}

void test_ber_oid_roundtrip(void)
{
    uint8_t buf[BUF_SIZE];
    size_t off = 0;

    struct snmp_oid oid = {
        .len = 10,
        .ids = {1, 3, 6, 1, 2, 1, 1, 1, 0, 0}
    };

    int ret = snmp_ber_encode_oid(buf, BUF_SIZE, &off, &oid);
    ASSERT_EQ(ret, 0);

    size_t dec_off = 0;
    struct snmp_oid decoded = {0};
    ret = snmp_ber_decode_oid(buf, off, &dec_off, &decoded);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(decoded.len, 10);
    for (int i = 0; i < 10; i++) {
        ASSERT_EQ(decoded.ids[i], oid.ids[i]);
    }
}

void test_ber_uint32_roundtrip(void)
{
    uint8_t buf[BUF_SIZE];
    size_t off = 0;

    uint32_t values[] = {0, 1, 127, 128, 255, 256, 65535, 4294967295U};

    for (int i = 0; i < 8; i++) {
        off = 0;
        int ret = snmp_ber_encode_uint(buf, BUF_SIZE, &off, SNMP_TAG_COUNTER32, values[i]);
        ASSERT_EQ(ret, 0);

        size_t dec_off = 0;
        uint32_t decoded;
        ret = snmp_ber_decode_uint(buf, off, &dec_off, &decoded);
        ASSERT_EQ(ret, 0);
        ASSERT_EQ(decoded, values[i]);
    }
}

void test_ber_uint64_roundtrip(void)
{
    uint8_t buf[BUF_SIZE];
    size_t off = 0;

    uint64_t values[] = {0, 1, 4294967296ULL, 18446744073709551615ULL};

    for (int i = 0; i < 4; i++) {
        off = 0;
        int ret = snmp_ber_encode_uint64(buf, BUF_SIZE, &off, SNMP_TAG_COUNTER64, values[i]);
        ASSERT_EQ(ret, 0);

        size_t dec_off = 0;
        uint64_t decoded;
        ret = snmp_ber_decode_uint64(buf, off, &dec_off, &decoded);
        ASSERT_EQ(ret, 0);
        ASSERT_EQ(decoded, values[i]);
    }
}

void test_ber_null_roundtrip(void)
{
    uint8_t buf[BUF_SIZE];
    size_t off = 0;

    int ret = snmp_ber_encode_null(buf, BUF_SIZE, &off, ASN1_TAG_NULL);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(off, 2);
    ASSERT_EQ(buf[0], ASN1_TAG_NULL);
    ASSERT_EQ(buf[1], 0);
}

void test_ber_sequence_roundtrip(void)
{
    uint8_t buf[BUF_SIZE];
    size_t off = 0;
    uint8_t inner[] = {0x02, 0x01, 0x05};

    int ret = snmp_ber_encode_header(buf, BUF_SIZE, &off, ASN1_TAG_SEQUENCE, sizeof(inner));
    ASSERT_EQ(ret, 0);
    memcpy(&buf[off], inner, sizeof(inner));
    off += sizeof(inner);

    size_t dec_off = 0;
    uint8_t tag;
    size_t len;
    ret = snmp_ber_decode_header(buf, 256, &dec_off, &tag, &len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(tag, ASN1_TAG_SEQUENCE);
    ASSERT_EQ(len, sizeof(inner));
}

void test_ber_decode_malformed_header(void)
{
    uint8_t tag;
    size_t len;
    size_t off;

    off = 0;
    int ret = snmp_ber_decode_header(NULL, 0, &off, &tag, &len);
    ASSERT_EQ(ret, -EINVAL);

    uint8_t short_buf[] = {0x02, 0x82};
    off = 0;
    ret = snmp_ber_decode_header(short_buf, 2, &off, &tag, &len);
    ASSERT_EQ(ret, -EBADMSG);

    uint8_t long_form_buf[] = {0x02, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05};
    off = 0;
    ret = snmp_ber_decode_header(long_form_buf, 7, &off, &tag, &len);
    ASSERT_EQ(ret, -EBADMSG);
}

void test_ber_decode_truncated_packet(void)
{
    uint8_t truncated[] = {0x02, 0x04, 0x00, 0x00};
    size_t off = 0;
    uint8_t tag;
    size_t len;

    int ret = snmp_ber_decode_header(truncated, 4, &off, &tag, &len);
    ASSERT_EQ(ret, -EBADMSG);
}

void test_ber_encode_buffer_overflow(void)
{
    uint8_t tiny_buf[2];
    size_t off = 0;

    int ret = snmp_ber_encode_int(tiny_buf, 2, &off, ASN1_TAG_INTEGER, 12345);
    ASSERT_EQ(ret, -ENOBUFS);
}
