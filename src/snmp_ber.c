/*
 * Copyright (c) 2026 StructCore Embedded
 * SPDX-License-Identifier: Apache-2.0
 */

#include <snmp/snmp_ber.h>
#include <string.h>
#include <errno.h>

#ifdef CONFIG_SNMP_AGENT

bool snmp_oid_equal(const struct snmp_oid *o1, const struct snmp_oid *o2)
{
	if (!o1 || !o2 || o1->len != o2->len) {
		return false;
	}
	for (uint8_t i = 0; i < o1->len; i++) {
		if (o1->ids[i] != o2->ids[i]) {
			return false;
		}
	}
	return true;
}

int snmp_oid_compare(const struct snmp_oid *o1, const struct snmp_oid *o2)
{
	if (!o1 && !o2)
		return 0;
	if (!o1)
		return -1;
	if (!o2)
		return 1;

	uint8_t min_len = (o1->len < o2->len) ? o1->len : o2->len;
	for (uint8_t i = 0; i < min_len; i++) {
		if (o1->ids[i] < o2->ids[i])
			return -1;
		if (o1->ids[i] > o2->ids[i])
			return 1;
	}
	if (o1->len < o2->len)
		return -1;
	if (o1->len > o2->len)
		return 1;
	return 0;
}

int snmp_ber_decode_header(const uint8_t *buf, size_t buf_len, size_t *off, uint8_t *tag,
			   size_t *len)
{
	if (!buf || !off || !tag || !len || *off >= buf_len) {
		return -EINVAL;
	}

	*tag = buf[(*off)++];
	if (*off >= buf_len) {
		return -EINVAL;
	}

	uint8_t len_byte = buf[(*off)++];
	if ((len_byte & 0x80) == 0) {
		*len = len_byte;
	} else {
		/* RFC 1157 §3.2.1 & RFC 3416 §3: Indefinite length (0x80) prohibited */
		uint8_t num_bytes = len_byte & 0x7F;
		if (num_bytes == 0 || num_bytes > 4 || (*off + num_bytes) > buf_len) {
			return -EBADMSG;
		}
		*len = 0;
		for (uint8_t i = 0; i < num_bytes; i++) {
			*len = (*len << 8) | buf[(*off)++];
		}
	}

	if (*off + *len > buf_len) {
		return -EBADMSG;
	}
	return 0;
}

int snmp_ber_encode_header(uint8_t *buf, size_t buf_len, size_t *off, uint8_t tag, size_t len)
{
	if (!buf || !off) {
		return -EINVAL;
	}

	size_t needed = 1;
	if (len < 128) {
		needed += 1;
	} else if (len <= 0xFF) {
		needed += 2;
	} else if (len <= 0xFFFF) {
		needed += 3;
	} else {
		needed += 5;
	}

	if (*off + needed > buf_len) {
		return -ENOBUFS;
	}

	buf[(*off)++] = tag;
	if (len < 128) {
		buf[(*off)++] = (uint8_t)len;
	} else if (len <= 0xFF) {
		buf[(*off)++] = 0x81;
		buf[(*off)++] = (uint8_t)len;
	} else if (len <= 0xFFFF) {
		buf[(*off)++] = 0x82;
		buf[(*off)++] = (uint8_t)(len >> 8);
		buf[(*off)++] = (uint8_t)(len & 0xFF);
	} else {
		buf[(*off)++] = 0x84;
		buf[(*off)++] = (uint8_t)(len >> 24);
		buf[(*off)++] = (uint8_t)(len >> 16);
		buf[(*off)++] = (uint8_t)(len >> 8);
		buf[(*off)++] = (uint8_t)(len & 0xFF);
	}

	return 0;
}

int snmp_ber_decode_int(const uint8_t *buf, size_t buf_len, size_t *off, int32_t *val)
{
	uint8_t tag;
	size_t len;
	int ret = snmp_ber_decode_header(buf, buf_len, off, &tag, &len);
	if (ret < 0)
		return ret;
	if (tag != ASN1_TAG_INTEGER || len > 4 || len == 0)
		return -EBADMSG;

	int32_t res = (buf[*off] & 0x80) ? -1 : 0;
	for (size_t i = 0; i < len; i++) {
		res = (res << 8) | buf[(*off)++];
	}
	*val = res;
	return 0;
}

int snmp_ber_encode_int(uint8_t *buf, size_t buf_len, size_t *off, uint8_t tag, int32_t val)
{
	uint8_t tmp[4];
	size_t len = 0;

	if (val >= -128 && val <= 127) {
		tmp[0] = (uint8_t)val;
		len = 1;
	} else if (val >= -32768 && val <= 32767) {
		tmp[0] = (uint8_t)(val >> 8);
		tmp[1] = (uint8_t)val;
		len = 2;
	} else if (val >= -8388608 && val <= 8388607) {
		tmp[0] = (uint8_t)(val >> 16);
		tmp[1] = (uint8_t)(val >> 8);
		tmp[2] = (uint8_t)val;
		len = 3;
	} else {
		tmp[0] = (uint8_t)(val >> 24);
		tmp[1] = (uint8_t)(val >> 16);
		tmp[2] = (uint8_t)(val >> 8);
		tmp[3] = (uint8_t)val;
		len = 4;
	}

	int ret = snmp_ber_encode_header(buf, buf_len, off, tag, len);
	if (ret < 0)
		return ret;
	if (*off + len > buf_len)
		return -ENOBUFS;

	memcpy(&buf[*off], tmp, len);
	*off += len;
	return 0;
}

int snmp_ber_decode_uint(const uint8_t *buf, size_t buf_len, size_t *off, uint32_t *val)
{
	uint8_t tag;
	size_t len;
	int ret = snmp_ber_decode_header(buf, buf_len, off, &tag, &len);
	if (ret < 0)
		return ret;
	if (len > 5 || len == 0)
		return -EBADMSG;

	if (len == 5) {
		if (*off >= buf_len || buf[*off] != 0x00)
			return -EBADMSG;
	}

	uint32_t res = 0;
	for (size_t i = 0; i < len; i++) {
		res = (res << 8) | buf[(*off)++];
	}
	*val = res;
	return 0;
}

int snmp_ber_encode_uint(uint8_t *buf, size_t buf_len, size_t *off, uint8_t tag, uint32_t val)
{
	uint8_t tmp[5];
	size_t len = 0;

	if ((val & 0x80000000) != 0) {
		tmp[0] = 0x00;
		tmp[1] = (uint8_t)(val >> 24);
		tmp[2] = (uint8_t)(val >> 16);
		tmp[3] = (uint8_t)(val >> 8);
		tmp[4] = (uint8_t)val;
		len = 5;
	} else if (val >= 0x800000) {
		tmp[0] = (uint8_t)(val >> 24);
		tmp[1] = (uint8_t)(val >> 16);
		tmp[2] = (uint8_t)(val >> 8);
		tmp[3] = (uint8_t)val;
		len = 4;
	} else if (val >= 0x8000) {
		tmp[0] = (uint8_t)(val >> 16);
		tmp[1] = (uint8_t)(val >> 8);
		tmp[2] = (uint8_t)val;
		len = 3;
	} else if (val >= 0x80) {
		tmp[0] = (uint8_t)(val >> 8);
		tmp[1] = (uint8_t)val;
		len = 2;
	} else {
		tmp[0] = (uint8_t)val;
		len = 1;
	}

	int ret = snmp_ber_encode_header(buf, buf_len, off, tag, len);
	if (ret < 0)
		return ret;
	if (*off + len > buf_len)
		return -ENOBUFS;

	memcpy(&buf[*off], tmp, len);
	*off += len;
	return 0;
}

int snmp_ber_decode_uint64(const uint8_t *buf, size_t buf_len, size_t *off, uint64_t *val)
{
	uint8_t tag;
	size_t len;
	int ret = snmp_ber_decode_header(buf, buf_len, off, &tag, &len);
	if (ret < 0)
		return ret;
	if (len > 9 || len == 0)
		return -EBADMSG;

	uint64_t res = 0;
	for (size_t i = 0; i < len; i++) {
		res = (res << 8) | buf[(*off)++];
	}
	*val = res;
	return 0;
}

int snmp_ber_encode_uint64(uint8_t *buf, size_t buf_len, size_t *off, uint8_t tag, uint64_t val)
{
	uint8_t tmp[9];
	size_t len = 0;

	if ((val & 0x8000000000000000ULL) != 0) {
		tmp[0] = 0x00;
		for (int i = 0; i < 8; i++) {
			tmp[1 + i] = (uint8_t)(val >> (56 - i * 8));
		}
		len = 9;
	} else {
		uint8_t raw[8];
		for (int i = 0; i < 8; i++) {
			raw[i] = (uint8_t)(val >> (56 - i * 8));
		}
		size_t start = 0;
		while (start < 7 && raw[start] == 0 && (raw[start + 1] & 0x80) == 0) {
			start++;
		}
		len = 8 - start;
		memcpy(tmp, &raw[start], len);
	}

	int ret = snmp_ber_encode_header(buf, buf_len, off, tag, len);
	if (ret < 0)
		return ret;
	if (*off + len > buf_len)
		return -ENOBUFS;

	memcpy(&buf[*off], tmp, len);
	*off += len;
	return 0;
}

int snmp_ber_decode_octet_string(const uint8_t *buf, size_t buf_len, size_t *off, uint8_t *out,
				 uint16_t max_out, uint16_t *out_len)
{
	uint8_t tag;
	size_t len;
	int ret = snmp_ber_decode_header(buf, buf_len, off, &tag, &len);
	if (ret < 0)
		return ret;
	if (tag != ASN1_TAG_OCTET_STRING && tag != SNMP_TAG_IPADDRESS && tag != SNMP_TAG_OPAQUE)
		return -EBADMSG;

	if (len > max_out)
		return -ENOBUFS;
	memcpy(out, &buf[*off], len);
	*off += len;
	if (out_len)
		*out_len = (uint16_t)len;
	return 0;
}

int snmp_ber_encode_octet_string(uint8_t *buf, size_t buf_len, size_t *off, uint8_t tag,
				 const uint8_t *str, uint16_t str_len)
{
	int ret = snmp_ber_encode_header(buf, buf_len, off, tag, str_len);
	if (ret < 0)
		return ret;
	if (*off + str_len > buf_len)
		return -ENOBUFS;

	if (str && str_len > 0) {
		memcpy(&buf[*off], str, str_len);
		*off += str_len;
	}
	return 0;
}

int snmp_ber_decode_oid(const uint8_t *buf, size_t buf_len, size_t *off, struct snmp_oid *oid)
{
	uint8_t tag;
	size_t len;
	int ret = snmp_ber_decode_header(buf, buf_len, off, &tag, &len);
	if (ret < 0)
		return ret;
	if (tag != ASN1_TAG_OID || len == 0)
		return -EBADMSG;

	size_t start_off = *off;
	size_t end_off = start_off + len;

	oid->len = 0;
	if (start_off < end_off) {
		uint8_t first = buf[start_off++];
		oid->ids[0] = first / 40;
		oid->ids[1] = first % 40;
		oid->len = 2;
	}

	while (start_off < end_off) {
		uint32_t val = 0;
		while (start_off < end_off) {
			uint8_t b = buf[start_off++];
			val = (val << 7) | (b & 0x7F);
			if ((b & 0x80) == 0)
				break;
		}
		if (oid->len >= CONFIG_SNMP_MAX_OID_LEN)
			return -E2BIG;
		oid->ids[oid->len++] = val;
	}

	*off = end_off;
	return 0;
}

int snmp_ber_encode_oid(uint8_t *buf, size_t buf_len, size_t *off, const struct snmp_oid *oid)
{
	if (!oid || oid->len < 2)
		return -EINVAL;

	if (oid->ids[0] > 2 || (oid->ids[0] < 2 && oid->ids[1] > 39))
		return -EINVAL;

	uint8_t tmp[CONFIG_SNMP_MAX_OID_LEN * 5];
	size_t tmp_len = 0;

	tmp[tmp_len++] = (uint8_t)(oid->ids[0] * 40 + oid->ids[1]);
	for (uint8_t i = 2; i < oid->len; i++) {
		uint32_t val = oid->ids[i];
		uint8_t sub_tmp[5];
		int sub_len = 0;

		do {
			sub_tmp[sub_len++] = (uint8_t)(val & 0x7F);
			val >>= 7;
		} while (val > 0);

		for (int j = sub_len - 1; j >= 0; j--) {
			uint8_t b = sub_tmp[j];
			if (j > 0)
				b |= 0x80;
			tmp[tmp_len++] = b;
		}
	}

	int ret = snmp_ber_encode_header(buf, buf_len, off, ASN1_TAG_OID, tmp_len);
	if (ret < 0)
		return ret;
	if (*off + tmp_len > buf_len)
		return -ENOBUFS;

	memcpy(&buf[*off], tmp, tmp_len);
	*off += tmp_len;
	return 0;
}

int snmp_ber_encode_null(uint8_t *buf, size_t buf_len, size_t *off, uint8_t tag)
{
	return snmp_ber_encode_header(buf, buf_len, off, tag, 0);
}

int snmp_ber_decode_pdu_body(const uint8_t *buf, size_t buf_len, size_t *in_out_off,
			     struct snmp_pdu *pdu)
{
	if (!buf || !in_out_off || !pdu)
		return -EINVAL;

	size_t off = *in_out_off;
	uint8_t tag;
	size_t len;

	int ret = snmp_ber_decode_header(buf, buf_len, &off, &pdu->type, &len);
	if (ret < 0)
		return ret;

	if (pdu->type == SNMP_PDU_TRAP_V1) {
		ret = snmp_ber_decode_oid(buf, buf_len, &off, &pdu->enterprise);
		if (ret < 0)
			return ret;

		uint16_t ip_len = 0;
		ret = snmp_ber_decode_octet_string(buf, buf_len, &off, pdu->agent_addr, 4, &ip_len);
		if (ret < 0)
			return ret;

		ret = snmp_ber_decode_int(buf, buf_len, &off, &pdu->generic_trap);
		if (ret < 0)
			return ret;

		ret = snmp_ber_decode_int(buf, buf_len, &off, &pdu->specific_trap);
		if (ret < 0)
			return ret;

		ret = snmp_ber_decode_uint(buf, buf_len, &off, &pdu->timestamp);
		if (ret < 0)
			return ret;
	} else {
		ret = snmp_ber_decode_int(buf, buf_len, &off, &pdu->request_id);
		if (ret < 0)
			return ret;

		if (pdu->type == SNMP_PDU_GET_BULK_REQ) {
			ret = snmp_ber_decode_int(buf, buf_len, &off, &pdu->non_repeaters);
			if (ret < 0)
				return ret;
			ret = snmp_ber_decode_int(buf, buf_len, &off, &pdu->max_repetitions);
			if (ret < 0)
				return ret;
		} else {
			ret = snmp_ber_decode_int(buf, buf_len, &off, &pdu->error_status);
			if (ret < 0)
				return ret;
			ret = snmp_ber_decode_int(buf, buf_len, &off, &pdu->error_index);
			if (ret < 0)
				return ret;
		}
	}

	size_t vb_seq_len;
	ret = snmp_ber_decode_header(buf, buf_len, &off, &tag, &vb_seq_len);
	if (ret < 0 || tag != ASN1_TAG_SEQUENCE)
		return -EBADMSG;

	size_t vb_end = off + vb_seq_len;
	if (vb_end > buf_len)
		return -EBADMSG;

	while (off < vb_end && pdu->varbind_cnt < CONFIG_SNMP_MAX_VARBINDS) {
		size_t vb_len;
		ret = snmp_ber_decode_header(buf, buf_len, &off, &tag, &vb_len);
		if (ret < 0 || tag != ASN1_TAG_SEQUENCE)
			return -EBADMSG;

		struct snmp_varbind *vb = &pdu->varbinds[pdu->varbind_cnt];
		ret = snmp_ber_decode_oid(buf, buf_len, &off, &vb->oid);
		if (ret < 0)
			return ret;

		size_t val_start = off;
		ret = snmp_ber_decode_header(buf, buf_len, &off, &vb->type, &len);
		if (ret < 0)
			return ret;
		off = val_start;

		switch (vb->type) {
		case ASN1_TAG_INTEGER:
			ret = snmp_ber_decode_int(buf, buf_len, &off, &vb->val.int_val);
			break;
		case ASN1_TAG_OCTET_STRING:
		case SNMP_TAG_OPAQUE:
			ret = snmp_ber_decode_octet_string(
			    buf, buf_len, &off, vb->val.octet_str.data,
			    sizeof(vb->val.octet_str.data), &vb->val.octet_str.len);
			break;

		case SNMP_TAG_IPADDRESS:
			ret = snmp_ber_decode_octet_string(buf, buf_len, &off, vb->val.ip_addr, 4,
							   NULL);
			break;
		case ASN1_TAG_NULL:
		case SNMP_TAG_EXCEPT_NO_SUCH_OBJ:
		case SNMP_TAG_EXCEPT_NO_SUCH_INST:
		case SNMP_TAG_EXCEPT_END_MIB_VIEW:
			snmp_ber_decode_header(buf, buf_len, &off, &tag, &len);
			break;
		case ASN1_TAG_OID:
			ret = snmp_ber_decode_oid(buf, buf_len, &off, &vb->val.oid);
			break;
		case SNMP_TAG_COUNTER32:
		case SNMP_TAG_GAUGE32:
		case SNMP_TAG_TIMETICKS:
		case SNMP_TAG_UNSIGNED32:
			ret = snmp_ber_decode_uint(buf, buf_len, &off, &vb->val.uint_val);
			break;
		case SNMP_TAG_COUNTER64:
			ret = snmp_ber_decode_uint64(buf, buf_len, &off, &vb->val.uint64_val);
			break;
		default:
			return -EBADMSG;
		}

		if (ret < 0)
			return ret;
		pdu->varbind_cnt++;
	}

	*in_out_off = off;
	return 0;
}

int snmp_ber_decode_pdu(const uint8_t *buf, size_t buf_len, struct snmp_pdu *pdu)
{
	if (!buf || !pdu)
		return -EINVAL;

	size_t off = 0;
	uint8_t tag;
	size_t len;

	memset(pdu, 0, sizeof(*pdu));

	int ret = snmp_ber_decode_header(buf, buf_len, &off, &tag, &len);
	if (ret < 0 || tag != ASN1_TAG_SEQUENCE)
		return -EBADMSG;

	ret = snmp_ber_decode_int(buf, buf_len, &off, &pdu->version);
	if (ret < 0)
		return ret;

	uint16_t comm_len = 0;
	ret = snmp_ber_decode_octet_string(buf, buf_len, &off, pdu->community,
					   sizeof(pdu->community) - 1, &comm_len);
	if (ret < 0)
		return ret;
	pdu->community_len = comm_len;
	pdu->community[comm_len] = '\0';

	return snmp_ber_decode_pdu_body(buf, buf_len, &off, pdu);
}

/* ---- Reverse BER Encoder Helpers (Zero Heap, Zero Static BSS, Reentrant) ---- */

static int ber_push_bytes(uint8_t *buf, size_t *pos, const uint8_t *data, size_t len)
{
	if (*pos < len) {
		return -ENOBUFS;
	}
	*pos -= len;
	if (data && len > 0) {
		memcpy(&buf[*pos], data, len);
	}
	return 0;
}

static int ber_push_header(uint8_t *buf, size_t *pos, uint8_t tag, size_t len)
{
	uint8_t hdr[6];
	size_t hlen = 0;

	hdr[hlen++] = tag;
	if (len < 128) {
		hdr[hlen++] = (uint8_t)len;
	} else if (len <= 0xFF) {
		hdr[hlen++] = 0x81;
		hdr[hlen++] = (uint8_t)len;
	} else if (len <= 0xFFFF) {
		hdr[hlen++] = 0x82;
		hdr[hlen++] = (uint8_t)(len >> 8);
		hdr[hlen++] = (uint8_t)(len & 0xFF);
	} else {
		hdr[hlen++] = 0x84;
		hdr[hlen++] = (uint8_t)(len >> 24);
		hdr[hlen++] = (uint8_t)(len >> 16);
		hdr[hlen++] = (uint8_t)(len >> 8);
		hdr[hlen++] = (uint8_t)(len & 0xFF);
	}

	return ber_push_bytes(buf, pos, hdr, hlen);
}

static int ber_push_int(uint8_t *buf, size_t *pos, uint8_t tag, int32_t val)
{
	uint8_t tmp[4];
	size_t len = 0;

	if (val >= -128 && val <= 127) {
		tmp[0] = (uint8_t)val;
		len = 1;
	} else if (val >= -32768 && val <= 32767) {
		tmp[0] = (uint8_t)(val >> 8);
		tmp[1] = (uint8_t)val;
		len = 2;
	} else if (val >= -8388608 && val <= 8388607) {
		tmp[0] = (uint8_t)(val >> 16);
		tmp[1] = (uint8_t)(val >> 8);
		tmp[2] = (uint8_t)val;
		len = 3;
	} else {
		tmp[0] = (uint8_t)(val >> 24);
		tmp[1] = (uint8_t)(val >> 16);
		tmp[2] = (uint8_t)(val >> 8);
		tmp[3] = (uint8_t)val;
		len = 4;
	}

	int ret = ber_push_bytes(buf, pos, tmp, len);
	if (ret < 0) {
		return ret;
	}
	return ber_push_header(buf, pos, tag, len);
}

static int ber_push_uint(uint8_t *buf, size_t *pos, uint8_t tag, uint32_t val)
{
	uint8_t tmp[5];
	size_t len = 0;

	if ((val & 0x80000000) != 0) {
		tmp[0] = 0x00;
		tmp[1] = (uint8_t)(val >> 24);
		tmp[2] = (uint8_t)(val >> 16);
		tmp[3] = (uint8_t)(val >> 8);
		tmp[4] = (uint8_t)val;
		len = 5;
	} else if (val >= 0x800000) {
		tmp[0] = (uint8_t)(val >> 24);
		tmp[1] = (uint8_t)(val >> 16);
		tmp[2] = (uint8_t)(val >> 8);
		tmp[3] = (uint8_t)val;
		len = 4;
	} else if (val >= 0x8000) {
		tmp[0] = (uint8_t)(val >> 16);
		tmp[1] = (uint8_t)(val >> 8);
		tmp[2] = (uint8_t)val;
		len = 3;
	} else if (val >= 0x80) {
		tmp[0] = (uint8_t)(val >> 8);
		tmp[1] = (uint8_t)val;
		len = 2;
	} else {
		tmp[0] = (uint8_t)val;
		len = 1;
	}

	int ret = ber_push_bytes(buf, pos, tmp, len);
	if (ret < 0) {
		return ret;
	}
	return ber_push_header(buf, pos, tag, len);
}

static int ber_push_uint64(uint8_t *buf, size_t *pos, uint8_t tag, uint64_t val)
{
	uint8_t tmp[9];
	size_t len = 0;

	if ((val & 0x8000000000000000ULL) != 0) {
		tmp[0] = 0x00;
		for (int i = 0; i < 8; i++) {
			tmp[1 + i] = (uint8_t)(val >> (56 - i * 8));
		}
		len = 9;
	} else {
		int first_nonzero = -1;
		for (int i = 7; i >= 0; i--) {
			if ((val >> (i * 8)) & 0xFF) {
				first_nonzero = i;
				break;
			}
		}
		if (first_nonzero == -1) {
			tmp[0] = 0x00;
			len = 1;
		} else {
			uint8_t top_byte = (uint8_t)((val >> (first_nonzero * 8)) & 0xFF);
			if (top_byte & 0x80) {
				tmp[len++] = 0x00;
			}
			for (int i = first_nonzero; i >= 0; i--) {
				tmp[len++] = (uint8_t)((val >> (i * 8)) & 0xFF);
			}
		}
	}

	int ret = ber_push_bytes(buf, pos, tmp, len);
	if (ret < 0) {
		return ret;
	}
	return ber_push_header(buf, pos, tag, len);
}

static int ber_push_octet_string(uint8_t *buf, size_t *pos, uint8_t tag, const uint8_t *data,
				 size_t len)
{
	int ret = ber_push_bytes(buf, pos, data, len);
	if (ret < 0) {
		return ret;
	}
	return ber_push_header(buf, pos, tag, len);
}

static int ber_push_null(uint8_t *buf, size_t *pos, uint8_t tag)
{
	return ber_push_header(buf, pos, tag, 0);
}

static int ber_push_oid(uint8_t *buf, size_t *pos, const struct snmp_oid *oid)
{
	if (!oid || oid->len < 2) {
		return -EINVAL;
	}

	uint8_t tmp[128];
	size_t off = 0;
	int ret = snmp_ber_encode_oid(tmp, sizeof(tmp), &off, oid);
	if (ret < 0) {
		return ret;
	}

	return ber_push_bytes(buf, pos, tmp, off);
}

static int ber_push_pdu_body(uint8_t *buf, size_t *pos, const struct snmp_pdu *pdu)
{
	size_t vb_list_end = *pos;

	for (int i = (int)pdu->varbind_cnt - 1; i >= 0; i--) {
		const struct snmp_varbind *vb = &pdu->varbinds[i];
		size_t vb_end = *pos;
		int ret = 0;

		switch (vb->type) {
		case ASN1_TAG_INTEGER:
			ret = ber_push_int(buf, pos, vb->type, vb->val.int_val);
			break;
		case ASN1_TAG_OCTET_STRING:
		case SNMP_TAG_OPAQUE:
			ret = ber_push_octet_string(buf, pos, vb->type, vb->val.octet_str.data,
						    vb->val.octet_str.len);
			break;
		case SNMP_TAG_IPADDRESS:
			ret = ber_push_octet_string(buf, pos, vb->type, vb->val.ip_addr, 4);
			break;
		case ASN1_TAG_NULL:
		case SNMP_TAG_EXCEPT_NO_SUCH_OBJ:
		case SNMP_TAG_EXCEPT_NO_SUCH_INST:
		case SNMP_TAG_EXCEPT_END_MIB_VIEW:
			ret = ber_push_null(buf, pos, vb->type);
			break;
		case ASN1_TAG_OID:
			ret = ber_push_oid(buf, pos, &vb->val.oid);
			break;
		case SNMP_TAG_COUNTER32:
		case SNMP_TAG_GAUGE32:
		case SNMP_TAG_TIMETICKS:
		case SNMP_TAG_UNSIGNED32:
			ret = ber_push_uint(buf, pos, vb->type, vb->val.uint_val);
			break;
		case SNMP_TAG_COUNTER64:
			ret = ber_push_uint64(buf, pos, vb->type, vb->val.uint64_val);
			break;
		default:
			return -EINVAL;
		}

		if (ret < 0) {
			return ret;
		}

		ret = ber_push_oid(buf, pos, &vb->oid);
		if (ret < 0) {
			return ret;
		}

		size_t vb_len = vb_end - *pos;
		ret = ber_push_header(buf, pos, ASN1_TAG_SEQUENCE, vb_len);
		if (ret < 0) {
			return ret;
		}
	}

	size_t vb_list_len = vb_list_end - *pos;
	int ret = ber_push_header(buf, pos, ASN1_TAG_SEQUENCE, vb_list_len);
	if (ret < 0) {
		return ret;
	}

	if (pdu->type == SNMP_PDU_TRAP_V1) {
		ret = ber_push_uint(buf, pos, SNMP_TAG_TIMETICKS, pdu->timestamp);
		if (ret < 0)
			return ret;
		ret = ber_push_int(buf, pos, ASN1_TAG_INTEGER, pdu->specific_trap);
		if (ret < 0)
			return ret;
		ret = ber_push_int(buf, pos, ASN1_TAG_INTEGER, pdu->generic_trap);
		if (ret < 0)
			return ret;
		ret = ber_push_octet_string(buf, pos, SNMP_TAG_IPADDRESS, pdu->agent_addr, 4);
		if (ret < 0)
			return ret;
		ret = ber_push_oid(buf, pos, &pdu->enterprise);
		if (ret < 0)
			return ret;
	} else if (pdu->type == SNMP_PDU_GET_BULK_REQ) {
		ret = ber_push_int(buf, pos, ASN1_TAG_INTEGER, pdu->max_repetitions);
		if (ret < 0)
			return ret;
		ret = ber_push_int(buf, pos, ASN1_TAG_INTEGER, pdu->non_repeaters);
		if (ret < 0)
			return ret;
		ret = ber_push_int(buf, pos, ASN1_TAG_INTEGER, pdu->request_id);
		if (ret < 0)
			return ret;
	} else {
		ret = ber_push_int(buf, pos, ASN1_TAG_INTEGER, pdu->error_index);
		if (ret < 0)
			return ret;
		ret = ber_push_int(buf, pos, ASN1_TAG_INTEGER, pdu->error_status);
		if (ret < 0)
			return ret;
		ret = ber_push_int(buf, pos, ASN1_TAG_INTEGER, pdu->request_id);
		if (ret < 0)
			return ret;
	}

	size_t pdu_len = vb_list_end - *pos;
	return ber_push_header(buf, pos, pdu->type, pdu_len);
}

int snmp_ber_encode_pdu_body(uint8_t *buf, size_t buf_len, size_t *out_len,
			     const struct snmp_pdu *pdu)
{
	if (!buf || !pdu || !out_len) {
		return -EINVAL;
	}

	size_t pos = buf_len;
	int ret = ber_push_pdu_body(buf, &pos, pdu);
	if (ret < 0) {
		return ret;
	}

	size_t total_len = buf_len - pos;
	if (pos > 0) {
		memmove(buf, &buf[pos], total_len);
	}
	*out_len = total_len;
	return 0;
}

int snmp_ber_encode_pdu(uint8_t *buf, size_t buf_len, size_t *out_len, const struct snmp_pdu *pdu)
{
	if (!buf || !pdu || !out_len) {
		return -EINVAL;
	}

	size_t pos = buf_len;
	size_t msg_end = pos;

	int ret = ber_push_pdu_body(buf, &pos, pdu);
	if (ret < 0) {
		return ret;
	}

	ret = ber_push_octet_string(buf, &pos, ASN1_TAG_OCTET_STRING, pdu->community,
				    pdu->community_len);
	if (ret < 0) {
		return ret;
	}

	ret = ber_push_int(buf, &pos, ASN1_TAG_INTEGER, pdu->version);
	if (ret < 0) {
		return ret;
	}

	size_t msg_len = msg_end - pos;
	ret = ber_push_header(buf, &pos, ASN1_TAG_SEQUENCE, msg_len);
	if (ret < 0) {
		return ret;
	}

	size_t total_len = buf_len - pos;
	if (pos > 0) {
		memmove(buf, &buf[pos], total_len);
	}
	*out_len = total_len;
	return 0;
}

/* ---- SNMPv3 message decode / encode (RFC 3412) ---- */

int snmp_ber_decode_v3_msg(const uint8_t *buf, size_t buf_len, struct snmp_v3_msg *msg)
{
	if (!buf || !msg)
		return -EINVAL;

	size_t off = 0;
	uint8_t tag;
	size_t len;

	memset(msg, 0, sizeof(*msg));

	/* Outer SEQUENCE */
	int ret = snmp_ber_decode_header(buf, buf_len, &off, &tag, &len);
	if (ret < 0 || tag != ASN1_TAG_SEQUENCE)
		return -EBADMSG;

	/* Version = 3 */
	int32_t version = 0;
	ret = snmp_ber_decode_int(buf, buf_len, &off, &version);
	if (ret < 0 || version != 3)
		return -EBADMSG;

	/* msgGlobalData SEQUENCE */
	ret = snmp_ber_decode_header(buf, buf_len, &off, &tag, &len);
	if (ret < 0 || tag != ASN1_TAG_SEQUENCE)
		return -EBADMSG;

	ret = snmp_ber_decode_int(buf, buf_len, &off, &msg->global.msg_id);
	if (ret < 0)
		return ret;

	ret = snmp_ber_decode_int(buf, buf_len, &off, &msg->global.msg_max_size);
	if (ret < 0)
		return ret;

	/* msgFlags: OCTET STRING of size 1 */
	uint16_t flags_len = 0;
	uint8_t flags_byte = 0;
	ret = snmp_ber_decode_octet_string(buf, buf_len, &off, &flags_byte, 1, &flags_len);
	if (ret < 0 || flags_len != 1)
		return -EBADMSG;
	msg->global.msg_flags = flags_byte;

	ret = snmp_ber_decode_int(buf, buf_len, &off, &msg->global.msg_security_model);
	if (ret < 0)
		return ret;

	/* msgSecurityParameters: OCTET STRING wrapper, then decode inner USM SEQUENCE */
	uint8_t sec_raw[256];
	uint16_t sec_len = 0;
	ret = snmp_ber_decode_octet_string(buf, buf_len, &off, sec_raw, sizeof(sec_raw), &sec_len);
	if (ret < 0)
		return ret;

	/* Decode USM SEQUENCE inside */
	size_t usm_off = 0;
	ret = snmp_ber_decode_header(sec_raw, sec_len, &usm_off, &tag, &len);
	if (ret < 0 || tag != ASN1_TAG_SEQUENCE)
		return -EBADMSG;

	uint16_t tmp_len;
	ret = snmp_ber_decode_octet_string(sec_raw, sec_len, &usm_off, msg->usm.engine_id,
					   SNMP_V3_ENGINE_ID_MAX_LEN, &tmp_len);
	if (ret < 0)
		return ret;
	msg->usm.engine_id_len = tmp_len;

	ret = snmp_ber_decode_int(sec_raw, sec_len, &usm_off, &msg->usm.engine_boots);
	if (ret < 0)
		return ret;

	ret = snmp_ber_decode_int(sec_raw, sec_len, &usm_off, &msg->usm.engine_time);
	if (ret < 0)
		return ret;

	ret = snmp_ber_decode_octet_string(sec_raw, sec_len, &usm_off, msg->usm.user_name,
					   sizeof(msg->usm.user_name) - 1, &tmp_len);
	if (ret < 0)
		return ret;
	msg->usm.user_name_len = tmp_len;
	msg->usm.user_name[tmp_len] = '\0';

	ret = snmp_ber_decode_octet_string(sec_raw, sec_len, &usm_off, msg->usm.auth_params,
					   SNMP_V3_AUTH_PARAMS_LEN, &tmp_len);
	if (ret < 0)
		return ret;
	msg->usm.auth_params_len = tmp_len;

	ret = snmp_ber_decode_octet_string(sec_raw, sec_len, &usm_off, msg->usm.priv_params,
					   SNMP_V3_PRIV_PARAMS_LEN, &tmp_len);
	if (ret < 0)
		return ret;
	msg->usm.priv_params_len = tmp_len;

	/* msgData: ScopedPDU */
	ret = snmp_ber_decode_header(buf, buf_len, &off, &tag, &len);
	if (ret < 0 || tag != ASN1_TAG_SEQUENCE)
		return -EBADMSG;

	/* When priv flag is set, scopedPDU contains a single OCTET STRING
	 * (encrypted data). Store offset/length for later decryption. */
	if (msg->global.msg_flags & 0x02) {
		ret = snmp_ber_decode_header(buf, buf_len, &off, &tag, &len);
		if (ret < 0 || tag != ASN1_TAG_OCTET_STRING)
			return -EBADMSG;
		msg->scoped.encrypted_raw_off = off;
		msg->scoped.encrypted_raw_len = len;
		return 0;
	}

	ret = snmp_ber_decode_octet_string(buf, buf_len, &off, msg->scoped.context_engine_id,
					   SNMP_V3_ENGINE_ID_MAX_LEN, &tmp_len);
	if (ret < 0)
		return ret;
	msg->scoped.context_engine_id_len = tmp_len;

	ret = snmp_ber_decode_octet_string(buf, buf_len, &off, msg->scoped.context_name,
					   sizeof(msg->scoped.context_name) - 1, &tmp_len);
	if (ret < 0)
		return ret;
	msg->scoped.context_name_len = tmp_len;
	msg->scoped.context_name[tmp_len] = '\0';

	/* Inner PDU — decode directly using snmp_ber_decode_pdu_body */
	ret = snmp_ber_decode_pdu_body(buf, buf_len, &off, &msg->scoped.pdu);
	if (ret < 0)
		return ret;

	return 0;
}

int snmp_ber_encode_v3_msg(uint8_t *buf, size_t buf_len, size_t *out_len,
			   const struct snmp_v3_msg *msg)
{
	if (!buf || !msg || !out_len) {
		return -EINVAL;
	}

	size_t pos = buf_len;
	size_t outer_end = pos;
	int ret;

	/* 1. ScopedPDU */
	size_t scoped_end = pos;
	if (msg->global.msg_flags & 0x02) {
		ret = ber_push_octet_string(buf, &pos, ASN1_TAG_OCTET_STRING,
					    msg->scoped.priv_ciphertext,
					    msg->scoped.priv_ciphertext_len);
		if (ret < 0) {
			return ret;
		}
	} else {
		ret = ber_push_pdu_body(buf, &pos, &msg->scoped.pdu);
		if (ret < 0) {
			return ret;
		}
		ret = ber_push_octet_string(buf, &pos, ASN1_TAG_OCTET_STRING,
					    msg->scoped.context_name, msg->scoped.context_name_len);
		if (ret < 0) {
			return ret;
		}
		ret = ber_push_octet_string(buf, &pos, ASN1_TAG_OCTET_STRING,
					    msg->scoped.context_engine_id,
					    msg->scoped.context_engine_id_len);
		if (ret < 0) {
			return ret;
		}
	}
	size_t scoped_len = scoped_end - pos;
	ret = ber_push_header(buf, &pos, ASN1_TAG_SEQUENCE, scoped_len);
	if (ret < 0) {
		return ret;
	}

	/* 2. msgSecurityParameters (USM SEQUENCE inside OCTET STRING) */
	size_t sec_params_end = pos;
	size_t usm_end = pos;
	ret = ber_push_octet_string(buf, &pos, ASN1_TAG_OCTET_STRING, msg->usm.priv_params,
				    msg->usm.priv_params_len);
	if (ret < 0) {
		return ret;
	}
	ret = ber_push_octet_string(buf, &pos, ASN1_TAG_OCTET_STRING, msg->usm.auth_params,
				    msg->usm.auth_params_len);
	if (ret < 0) {
		return ret;
	}
	ret = ber_push_octet_string(buf, &pos, ASN1_TAG_OCTET_STRING,
				    (const uint8_t *)msg->usm.user_name, msg->usm.user_name_len);
	if (ret < 0) {
		return ret;
	}
	ret = ber_push_int(buf, &pos, ASN1_TAG_INTEGER, msg->usm.engine_time);
	if (ret < 0) {
		return ret;
	}
	ret = ber_push_int(buf, &pos, ASN1_TAG_INTEGER, msg->usm.engine_boots);
	if (ret < 0) {
		return ret;
	}
	ret = ber_push_octet_string(buf, &pos, ASN1_TAG_OCTET_STRING, msg->usm.engine_id,
				    msg->usm.engine_id_len);
	if (ret < 0) {
		return ret;
	}
	size_t usm_len = usm_end - pos;
	ret = ber_push_header(buf, &pos, ASN1_TAG_SEQUENCE, usm_len);
	if (ret < 0) {
		return ret;
	}

	size_t sec_len = sec_params_end - pos;
	ret = ber_push_header(buf, &pos, ASN1_TAG_OCTET_STRING, sec_len);
	if (ret < 0) {
		return ret;
	}

	/* 3. msgGlobalData */
	size_t gl_end = pos;
	ret = ber_push_int(buf, &pos, ASN1_TAG_INTEGER, msg->global.msg_security_model);
	if (ret < 0) {
		return ret;
	}
	uint8_t flags_byte = msg->global.msg_flags;
	ret = ber_push_octet_string(buf, &pos, ASN1_TAG_OCTET_STRING, &flags_byte, 1);
	if (ret < 0) {
		return ret;
	}
	ret = ber_push_int(buf, &pos, ASN1_TAG_INTEGER, msg->global.msg_max_size);
	if (ret < 0) {
		return ret;
	}
	ret = ber_push_int(buf, &pos, ASN1_TAG_INTEGER, msg->global.msg_id);
	if (ret < 0) {
		return ret;
	}
	size_t gl_len = gl_end - pos;
	ret = ber_push_header(buf, &pos, ASN1_TAG_SEQUENCE, gl_len);
	if (ret < 0) {
		return ret;
	}

	/* 4. SNMP Version 3 */
	ret = ber_push_int(buf, &pos, ASN1_TAG_INTEGER, 3);
	if (ret < 0) {
		return ret;
	}

	/* 5. Outer SEQUENCE */
	size_t total_payload_len = outer_end - pos;
	ret = ber_push_header(buf, &pos, ASN1_TAG_SEQUENCE, total_payload_len);
	if (ret < 0) {
		return ret;
	}

	size_t total_len = buf_len - pos;
	if (pos > 0) {
		memmove(buf, &buf[pos], total_len);
	}
	*out_len = total_len;
	return 0;
}

#endif /* CONFIG_SNMP_AGENT */
