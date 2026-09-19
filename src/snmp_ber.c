/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 */

#include <snmp/snmp_ber.h>
#include <string.h>
#include <errno.h>

#ifdef CONFIG_SNMP_AGENT

bool snmp_oid_equal(const struct snmp_oid *o1, const struct snmp_oid *o2)
{
	if (!o1 || !o2 || o1->len != o2->len)
	{
		return false;
	}
	for (uint8_t i = 0; i < o1->len; i++)
	{
		if (o1->ids[i] != o2->ids[i])
		{
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
	for (uint8_t i = 0; i < min_len; i++)
	{
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

int snmp_ber_decode_header(const uint8_t *buf, size_t buf_len, size_t *off, uint8_t *tag, size_t *len)
{
	if (!buf || !off || !tag || !len || *off >= buf_len)
	{
		return -EINVAL;
	}

	*tag = buf[(*off)++];
	if (*off >= buf_len)
	{
		return -EINVAL;
	}

	uint8_t len_byte = buf[(*off)++];
	if ((len_byte & 0x80) == 0)
	{
		*len = len_byte;
	}
	else
	{
		uint8_t num_bytes = len_byte & 0x7F;
		if (num_bytes > 4 || (*off + num_bytes) > buf_len)
		{
			return -EBADMSG;
		}
		*len = 0;
		for (uint8_t i = 0; i < num_bytes; i++)
		{
			*len = (*len << 8) | buf[(*off)++];
		}
	}

	if (*off + *len > buf_len)
	{
		return -EBADMSG;
	}
	return 0;
}

int snmp_ber_encode_header(uint8_t *buf, size_t buf_len, size_t *off, uint8_t tag, size_t len)
{
	if (!buf || !off)
	{
		return -EINVAL;
	}

	size_t needed = 1;
	if (len < 128)
	{
		needed += 1;
	}
	else if (len <= 0xFF)
	{
		needed += 2;
	}
	else if (len <= 0xFFFF)
	{
		needed += 3;
	}
	else
	{
		needed += 5;
	}

	if (*off + needed > buf_len)
	{
		return -ENOBUFS;
	}

	buf[(*off)++] = tag;
	if (len < 128)
	{
		buf[(*off)++] = (uint8_t)len;
	}
	else if (len <= 0xFF)
	{
		buf[(*off)++] = 0x81;
		buf[(*off)++] = (uint8_t)len;
	}
	else if (len <= 0xFFFF)
	{
		buf[(*off)++] = 0x82;
		buf[(*off)++] = (uint8_t)(len >> 8);
		buf[(*off)++] = (uint8_t)(len & 0xFF);
	}
	else
	{
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
	for (size_t i = 0; i < len; i++)
	{
		res = (res << 8) | buf[(*off)++];
	}
	*val = res;
	return 0;
}

int snmp_ber_encode_int(uint8_t *buf, size_t buf_len, size_t *off, uint8_t tag, int32_t val)
{
	uint8_t tmp[4];
	size_t len = 0;

	if (val >= -128 && val <= 127)
	{
		tmp[0] = (uint8_t)val;
		len = 1;
	}
	else if (val >= -32768 && val <= 32767)
	{
		tmp[0] = (uint8_t)(val >> 8);
		tmp[1] = (uint8_t)val;
		len = 2;
	}
	else if (val >= -8388608 && val <= 8388607)
	{
		tmp[0] = (uint8_t)(val >> 16);
		tmp[1] = (uint8_t)(val >> 8);
		tmp[2] = (uint8_t)val;
		len = 3;
	}
	else
	{
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
	for (size_t i = 0; i < len; i++)
	{
		res = (res << 8) | buf[(*off)++];
	}
	*val = res;
	return 0;
}

int snmp_ber_encode_uint(uint8_t *buf, size_t buf_len, size_t *off, uint8_t tag, uint32_t val)
{
	uint8_t tmp[5];
	size_t len = 0;

	if ((val & 0x80000000) != 0)
	{
		tmp[0] = 0x00;
		tmp[1] = (uint8_t)(val >> 24);
		tmp[2] = (uint8_t)(val >> 16);
		tmp[3] = (uint8_t)(val >> 8);
		tmp[4] = (uint8_t)val;
		len = 5;
	}
	else if (val >= 0x800000)
	{
		tmp[0] = (uint8_t)(val >> 24);
		tmp[1] = (uint8_t)(val >> 16);
		tmp[2] = (uint8_t)(val >> 8);
		tmp[3] = (uint8_t)val;
		len = 4;
	}
	else if (val >= 0x8000)
	{
		tmp[0] = (uint8_t)(val >> 16);
		tmp[1] = (uint8_t)(val >> 8);
		tmp[2] = (uint8_t)val;
		len = 3;
	}
	else if (val >= 0x80)
	{
		tmp[0] = (uint8_t)(val >> 8);
		tmp[1] = (uint8_t)val;
		len = 2;
	}
	else
	{
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
	for (size_t i = 0; i < len; i++)
	{
		res = (res << 8) | buf[(*off)++];
	}
	*val = res;
	return 0;
}

int snmp_ber_encode_uint64(uint8_t *buf, size_t buf_len, size_t *off, uint8_t tag, uint64_t val)
{
	uint8_t tmp[9];
	size_t len = 0;

	if ((val & 0x8000000000000000ULL) != 0)
	{
		tmp[0] = 0x00;
		for (int i = 0; i < 8; i++)
		{
			tmp[1 + i] = (uint8_t)(val >> (56 - i * 8));
		}
		len = 9;
	}
	else
	{
		uint8_t raw[8];
		for (int i = 0; i < 8; i++)
		{
			raw[i] = (uint8_t)(val >> (56 - i * 8));
		}
		size_t start = 0;
		while (start < 7 && raw[start] == 0 && (raw[start + 1] & 0x80) == 0)
		{
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

int snmp_ber_decode_octet_string(const uint8_t *buf, size_t buf_len, size_t *off, uint8_t *out, uint16_t max_out, uint16_t *out_len)
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

int snmp_ber_encode_octet_string(uint8_t *buf, size_t buf_len, size_t *off, uint8_t tag, const uint8_t *str, uint16_t str_len)
{
	int ret = snmp_ber_encode_header(buf, buf_len, off, tag, str_len);
	if (ret < 0)
		return ret;
	if (*off + str_len > buf_len)
		return -ENOBUFS;

	if (str && str_len > 0)
	{
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
	if (start_off < end_off)
	{
		uint8_t first = buf[start_off++];
		oid->ids[0] = first / 40;
		oid->ids[1] = first % 40;
		oid->len = 2;
	}

	while (start_off < end_off)
	{
		uint32_t val = 0;
		while (start_off < end_off)
		{
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
	for (uint8_t i = 2; i < oid->len; i++)
	{
		uint32_t val = oid->ids[i];
		uint8_t sub_tmp[5];
		int sub_len = 0;

		do
		{
			sub_tmp[sub_len++] = (uint8_t)(val & 0x7F);
			val >>= 7;
		} while (val > 0);

		for (int j = sub_len - 1; j >= 0; j--)
		{
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

int snmp_ber_decode_pdu_body(const uint8_t *buf, size_t buf_len, size_t *in_out_off, struct snmp_pdu *pdu)
{
	if (!buf || !in_out_off || !pdu)
		return -EINVAL;

	size_t off = *in_out_off;
	uint8_t tag;
	size_t len;

	int ret = snmp_ber_decode_header(buf, buf_len, &off, &pdu->type, &len);
	if (ret < 0)
		return ret;

	if (pdu->type == SNMP_PDU_TRAP_V1)
	{
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
	}
	else
	{
		ret = snmp_ber_decode_int(buf, buf_len, &off, &pdu->request_id);
		if (ret < 0)
			return ret;

		if (pdu->type == SNMP_PDU_GET_BULK_REQ)
		{
			ret = snmp_ber_decode_int(buf, buf_len, &off, &pdu->non_repeaters);
			if (ret < 0)
				return ret;
			ret = snmp_ber_decode_int(buf, buf_len, &off, &pdu->max_repetitions);
			if (ret < 0)
				return ret;
		}
		else
		{
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

	while (off < vb_end && pdu->varbind_cnt < CONFIG_SNMP_MAX_VARBINDS)
	{
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

		switch (vb->type)
		{
		case ASN1_TAG_INTEGER:
			ret = snmp_ber_decode_int(buf, buf_len, &off, &vb->val.int_val);
			break;
		case ASN1_TAG_OCTET_STRING:
		case SNMP_TAG_OPAQUE:
			ret = snmp_ber_decode_octet_string(buf, buf_len, &off, vb->val.octet_str.data, sizeof(vb->val.octet_str.data), &vb->val.octet_str.len);
			break;

		case SNMP_TAG_IPADDRESS:
			ret = snmp_ber_decode_octet_string(buf, buf_len, &off, vb->val.ip_addr, 4, NULL);
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
	ret = snmp_ber_decode_octet_string(buf, buf_len, &off, pdu->community, sizeof(pdu->community) - 1, &comm_len);
	if (ret < 0)
		return ret;
	pdu->community_len = comm_len;
	pdu->community[comm_len] = '\0';

	return snmp_ber_decode_pdu_body(buf, buf_len, &off, pdu);
}

static K_MUTEX_DEFINE(g_snmp_ber_enc_mutex);
static uint8_t g_enc_payload[CONFIG_SNMP_MAX_PDU_SIZE];
static uint8_t g_enc_pdu_body[CONFIG_SNMP_MAX_PDU_SIZE];
static uint8_t g_enc_vb_buf[CONFIG_SNMP_MAX_PDU_SIZE];
static uint8_t g_enc_single_vb[512];

static int snmp_ber_encode_pdu_body_internal(uint8_t *buf, size_t buf_len, size_t *out_len, const struct snmp_pdu *pdu)
{
	if (!buf || !pdu || !out_len)
		return -EINVAL;

	size_t pb_off = 0;

	if (pdu->type == SNMP_PDU_TRAP_V1)
	{
		int ret = snmp_ber_encode_oid(g_enc_pdu_body, sizeof(g_enc_pdu_body), &pb_off, &pdu->enterprise);
		if (ret < 0)
			return ret;
		ret = snmp_ber_encode_octet_string(g_enc_pdu_body, sizeof(g_enc_pdu_body), &pb_off, SNMP_TAG_IPADDRESS, pdu->agent_addr, 4);
		if (ret < 0)
			return ret;
		ret = snmp_ber_encode_int(g_enc_pdu_body, sizeof(g_enc_pdu_body), &pb_off, ASN1_TAG_INTEGER, pdu->generic_trap);
		if (ret < 0)
			return ret;
		ret = snmp_ber_encode_int(g_enc_pdu_body, sizeof(g_enc_pdu_body), &pb_off, ASN1_TAG_INTEGER, pdu->specific_trap);
		if (ret < 0)
			return ret;
		ret = snmp_ber_encode_uint(g_enc_pdu_body, sizeof(g_enc_pdu_body), &pb_off, SNMP_TAG_TIMETICKS, pdu->timestamp);
		if (ret < 0)
			return ret;
	}
	else
	{
		int ret = snmp_ber_encode_int(g_enc_pdu_body, sizeof(g_enc_pdu_body), &pb_off, ASN1_TAG_INTEGER, pdu->request_id);
		if (ret < 0)
			return ret;

		if (pdu->type == SNMP_PDU_GET_BULK_REQ)
		{
			ret = snmp_ber_encode_int(g_enc_pdu_body, sizeof(g_enc_pdu_body), &pb_off, ASN1_TAG_INTEGER, pdu->non_repeaters);
			if (ret < 0)
				return ret;
			ret = snmp_ber_encode_int(g_enc_pdu_body, sizeof(g_enc_pdu_body), &pb_off, ASN1_TAG_INTEGER, pdu->max_repetitions);
			if (ret < 0)
				return ret;
		}
		else
		{
			ret = snmp_ber_encode_int(g_enc_pdu_body, sizeof(g_enc_pdu_body), &pb_off, ASN1_TAG_INTEGER, pdu->error_status);
			if (ret < 0)
				return ret;
			ret = snmp_ber_encode_int(g_enc_pdu_body, sizeof(g_enc_pdu_body), &pb_off, ASN1_TAG_INTEGER, pdu->error_index);
			if (ret < 0)
				return ret;
		}
	}

	size_t vb_off = 0;

	for (uint8_t i = 0; i < pdu->varbind_cnt; i++)
	{
		const struct snmp_varbind *vb = &pdu->varbinds[i];
		size_t svb_off = 0;

		int ret = snmp_ber_encode_oid(g_enc_single_vb, sizeof(g_enc_single_vb), &svb_off, &vb->oid);
		if (ret < 0)
			return ret;

		switch (vb->type)
		{
		case ASN1_TAG_INTEGER:
			ret = snmp_ber_encode_int(g_enc_single_vb, sizeof(g_enc_single_vb), &svb_off, vb->type, vb->val.int_val);
			break;
		case ASN1_TAG_OCTET_STRING:
		case SNMP_TAG_OPAQUE:
			ret = snmp_ber_encode_octet_string(g_enc_single_vb, sizeof(g_enc_single_vb), &svb_off, vb->type, vb->val.octet_str.data, vb->val.octet_str.len);
			break;
		case SNMP_TAG_IPADDRESS:
			ret = snmp_ber_encode_octet_string(g_enc_single_vb, sizeof(g_enc_single_vb), &svb_off, vb->type, vb->val.ip_addr, 4);
			break;
		case ASN1_TAG_NULL:
		case SNMP_TAG_EXCEPT_NO_SUCH_OBJ:
		case SNMP_TAG_EXCEPT_NO_SUCH_INST:
		case SNMP_TAG_EXCEPT_END_MIB_VIEW:
			ret = snmp_ber_encode_null(g_enc_single_vb, sizeof(g_enc_single_vb), &svb_off, vb->type);
			break;
		case ASN1_TAG_OID:
			ret = snmp_ber_encode_oid(g_enc_single_vb, sizeof(g_enc_single_vb), &svb_off, &vb->val.oid);
			break;
		case SNMP_TAG_COUNTER32:
		case SNMP_TAG_GAUGE32:
		case SNMP_TAG_TIMETICKS:
		case SNMP_TAG_UNSIGNED32:
			ret = snmp_ber_encode_uint(g_enc_single_vb, sizeof(g_enc_single_vb), &svb_off, vb->type, vb->val.uint_val);
			break;
		case SNMP_TAG_COUNTER64:
			ret = snmp_ber_encode_uint64(g_enc_single_vb, sizeof(g_enc_single_vb), &svb_off, vb->type, vb->val.uint64_val);
			break;
		default:
			return -EINVAL;
		}

		if (ret < 0)
			return ret;
		ret = snmp_ber_encode_header(g_enc_vb_buf, sizeof(g_enc_vb_buf), &vb_off, ASN1_TAG_SEQUENCE, svb_off);
		if (ret < 0)
			return ret;
		memcpy(&g_enc_vb_buf[vb_off], g_enc_single_vb, svb_off);
		vb_off += svb_off;
	}

	int ret = snmp_ber_encode_header(g_enc_pdu_body, sizeof(g_enc_pdu_body), &pb_off, ASN1_TAG_SEQUENCE, vb_off);
	if (ret < 0)
		return ret;
	memcpy(&g_enc_pdu_body[pb_off], g_enc_vb_buf, vb_off);
	pb_off += vb_off;

	size_t body_hdr_off = 0;
	ret = snmp_ber_encode_header(buf, buf_len, &body_hdr_off, pdu->type, pb_off);
	if (ret < 0)
		return ret;
	if (body_hdr_off + pb_off > buf_len)
		return -ENOBUFS;
	memcpy(&buf[body_hdr_off], g_enc_pdu_body, pb_off);

	*out_len = body_hdr_off + pb_off;
	return 0;
}

int snmp_ber_encode_pdu_body(uint8_t *buf, size_t buf_len, size_t *out_len, const struct snmp_pdu *pdu)
{
	k_mutex_lock(&g_snmp_ber_enc_mutex, K_FOREVER);
	int ret = snmp_ber_encode_pdu_body_internal(buf, buf_len, out_len, pdu);
	k_mutex_unlock(&g_snmp_ber_enc_mutex);
	return ret;
}

static int snmp_ber_encode_pdu_internal(uint8_t *buf, size_t buf_len, size_t *out_len, const struct snmp_pdu *pdu)
{
	if (!buf || !pdu || !out_len)
		return -EINVAL;

	size_t p_off = 0;

	int ret = snmp_ber_encode_int(g_enc_payload, sizeof(g_enc_payload), &p_off, ASN1_TAG_INTEGER, pdu->version);
	if (ret < 0)
		return ret;

	ret = snmp_ber_encode_octet_string(g_enc_payload, sizeof(g_enc_payload), &p_off, ASN1_TAG_OCTET_STRING, pdu->community, pdu->community_len);
	if (ret < 0)
		return ret;

	size_t body_len = 0;
	ret = snmp_ber_encode_pdu_body_internal(&g_enc_payload[p_off], sizeof(g_enc_payload) - p_off, &body_len, pdu);
	if (ret < 0)
		return ret;
	p_off += body_len;

	size_t final_off = 0;
	ret = snmp_ber_encode_header(buf, buf_len, &final_off, ASN1_TAG_SEQUENCE, p_off);
	if (ret < 0)
		return ret;
	if (final_off + p_off > buf_len)
		return -ENOBUFS;
	memcpy(&buf[final_off], g_enc_payload, p_off);
	final_off += p_off;

	*out_len = final_off;
	return 0;
}

int snmp_ber_encode_pdu(uint8_t *buf, size_t buf_len, size_t *out_len, const struct snmp_pdu *pdu)
{
	k_mutex_lock(&g_snmp_ber_enc_mutex, K_FOREVER);
	int ret = snmp_ber_encode_pdu_internal(buf, buf_len, out_len, pdu);
	k_mutex_unlock(&g_snmp_ber_enc_mutex);
	return ret;
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
	ret = snmp_ber_decode_octet_string(sec_raw, sec_len, &usm_off,
					   msg->usm.engine_id, SNMP_V3_ENGINE_ID_MAX_LEN, &tmp_len);
	if (ret < 0)
		return ret;
	msg->usm.engine_id_len = tmp_len;

	ret = snmp_ber_decode_int(sec_raw, sec_len, &usm_off, &msg->usm.engine_boots);
	if (ret < 0)
		return ret;

	ret = snmp_ber_decode_int(sec_raw, sec_len, &usm_off, &msg->usm.engine_time);
	if (ret < 0)
		return ret;

	ret = snmp_ber_decode_octet_string(sec_raw, sec_len, &usm_off,
					   msg->usm.user_name, sizeof(msg->usm.user_name) - 1, &tmp_len);
	if (ret < 0)
		return ret;
	msg->usm.user_name_len = tmp_len;
	msg->usm.user_name[tmp_len] = '\0';

	ret = snmp_ber_decode_octet_string(sec_raw, sec_len, &usm_off,
					   msg->usm.auth_params, SNMP_V3_AUTH_PARAMS_LEN, &tmp_len);
	if (ret < 0)
		return ret;
	msg->usm.auth_params_len = tmp_len;

	ret = snmp_ber_decode_octet_string(sec_raw, sec_len, &usm_off,
					   msg->usm.priv_params, SNMP_V3_PRIV_PARAMS_LEN, &tmp_len);
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

	ret = snmp_ber_decode_octet_string(buf, buf_len, &off,
					   msg->scoped.context_engine_id,
					   SNMP_V3_ENGINE_ID_MAX_LEN, &tmp_len);
	if (ret < 0)
		return ret;
	msg->scoped.context_engine_id_len = tmp_len;

	ret = snmp_ber_decode_octet_string(buf, buf_len, &off,
					   msg->scoped.context_name,
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

int snmp_ber_encode_v3_msg(uint8_t *buf, size_t buf_len, size_t *out_len, const struct snmp_v3_msg *msg)
{
	if (!buf || !msg || !out_len)
		return -EINVAL;

	int ret;

	/* 1. Encode the inner PDU (skip if priv/encrypted) */
	uint8_t pdu_raw[CONFIG_SNMP_MAX_PDU_SIZE];
	size_t pdu_len = 0;
	if (!(msg->global.msg_flags & 0x02)) {
		ret = snmp_ber_encode_pdu_body(pdu_raw, sizeof(pdu_raw), &pdu_len, &msg->scoped.pdu);
		if (ret < 0)
			return ret;
	}

	/* 2. ScopedPDU SEQUENCE (or single OCTET STRING if encrypted) */
	uint8_t scoped[CONFIG_SNMP_MAX_PDU_SIZE];
	size_t sc_off = 0;
	if (msg->global.msg_flags & 0x02) {
		ret = snmp_ber_encode_octet_string(scoped, sizeof(scoped), &sc_off, ASN1_TAG_OCTET_STRING,
						   msg->scoped.priv_ciphertext, (uint16_t)msg->scoped.priv_ciphertext_len);
		if (ret < 0)
			return ret;
	} else {
		ret = snmp_ber_encode_octet_string(scoped, sizeof(scoped), &sc_off, ASN1_TAG_OCTET_STRING,
						   msg->scoped.context_engine_id, msg->scoped.context_engine_id_len);
		if (ret < 0)
			return ret;
		ret = snmp_ber_encode_octet_string(scoped, sizeof(scoped), &sc_off, ASN1_TAG_OCTET_STRING,
						   msg->scoped.context_name, msg->scoped.context_name_len);
		if (ret < 0)
			return ret;
		memcpy(&scoped[sc_off], pdu_raw, pdu_len);
		sc_off += pdu_len;
	}

	/* 3. msgSecurityParameters — encode USM SEQUENCE */
	uint8_t usm_seq[256];
	size_t usm_off = 0;
	ret = snmp_ber_encode_octet_string(usm_seq, sizeof(usm_seq), &usm_off, ASN1_TAG_OCTET_STRING,
					   msg->usm.engine_id, msg->usm.engine_id_len);
	if (ret < 0)
		return ret;
	ret = snmp_ber_encode_int(usm_seq, sizeof(usm_seq), &usm_off, ASN1_TAG_INTEGER, msg->usm.engine_boots);
	if (ret < 0)
		return ret;
	ret = snmp_ber_encode_int(usm_seq, sizeof(usm_seq), &usm_off, ASN1_TAG_INTEGER, msg->usm.engine_time);
	if (ret < 0)
		return ret;
	ret = snmp_ber_encode_octet_string(usm_seq, sizeof(usm_seq), &usm_off, ASN1_TAG_OCTET_STRING,
					   msg->usm.user_name, msg->usm.user_name_len);
	if (ret < 0)
		return ret;
	ret = snmp_ber_encode_octet_string(usm_seq, sizeof(usm_seq), &usm_off, ASN1_TAG_OCTET_STRING,
					   msg->usm.auth_params, msg->usm.auth_params_len);
	if (ret < 0)
		return ret;
	ret = snmp_ber_encode_octet_string(usm_seq, sizeof(usm_seq), &usm_off, ASN1_TAG_OCTET_STRING,
					   msg->usm.priv_params, msg->usm.priv_params_len);
	if (ret < 0)
		return ret;

	/* Wrap USM SEQUENCE in header */
	uint8_t usm_wrapped[300];
	size_t uw_off = 0;
	ret = snmp_ber_encode_header(usm_wrapped, sizeof(usm_wrapped), &uw_off, ASN1_TAG_SEQUENCE, usm_off);
	if (ret < 0)
		return ret;
	memcpy(&usm_wrapped[uw_off], usm_seq, usm_off);
	uw_off += usm_off;

	/* msgSecurityParameters as OCTET STRING */
	uint8_t sec_params[300];
	size_t sp_off = 0;
	ret = snmp_ber_encode_octet_string(sec_params, sizeof(sec_params), &sp_off,
					   ASN1_TAG_OCTET_STRING, usm_wrapped, (uint16_t)uw_off);
	if (ret < 0)
		return ret;

	/* 4. msgGlobalData SEQUENCE */
	uint8_t flags_byte = msg->global.msg_flags;
	uint8_t global_seq[128];
	size_t gl_off = 0;
	ret = snmp_ber_encode_int(global_seq, sizeof(global_seq), &gl_off, ASN1_TAG_INTEGER, msg->global.msg_id);
	if (ret < 0)
		return ret;
	ret = snmp_ber_encode_int(global_seq, sizeof(global_seq), &gl_off, ASN1_TAG_INTEGER, msg->global.msg_max_size);
	if (ret < 0)
		return ret;
	ret = snmp_ber_encode_octet_string(global_seq, sizeof(global_seq), &gl_off, ASN1_TAG_OCTET_STRING, &flags_byte, 1);
	if (ret < 0)
		return ret;
	ret = snmp_ber_encode_int(global_seq, sizeof(global_seq), &gl_off, ASN1_TAG_INTEGER, msg->global.msg_security_model);
	if (ret < 0)
		return ret;

	uint8_t global_wrapped[200];
	size_t gw_off = 0;
	ret = snmp_ber_encode_header(global_wrapped, sizeof(global_wrapped), &gw_off, ASN1_TAG_SEQUENCE, gl_off);
	if (ret < 0)
		return ret;
	memcpy(&global_wrapped[gw_off], global_seq, gl_off);
	gw_off += gl_off;

	/* 5. Build payload: version + global + securityParams + scopedPDU */
	uint8_t payload[CONFIG_SNMP_MAX_PDU_SIZE];
	size_t pl_off = 0;
	ret = snmp_ber_encode_int(payload, sizeof(payload), &pl_off, ASN1_TAG_INTEGER, 3);
	if (ret < 0)
		return ret;

	memcpy(&payload[pl_off], global_wrapped, gw_off);
	pl_off += gw_off;

	memcpy(&payload[pl_off], sec_params, sp_off);
	pl_off += sp_off;

	/* ScopedPDU wrapped in SEQUENCE */
	uint8_t scoped_wrapped[CONFIG_SNMP_MAX_PDU_SIZE];
	size_t sw_off = 0;
	ret = snmp_ber_encode_header(scoped_wrapped, sizeof(scoped_wrapped), &sw_off, ASN1_TAG_SEQUENCE, sc_off);
	if (ret < 0)
		return ret;
	memcpy(&scoped_wrapped[sw_off], scoped, sc_off);
	sw_off += sc_off;

	memcpy(&payload[pl_off], scoped_wrapped, sw_off);
	pl_off += sw_off;

	/* 6. Outer SEQUENCE wrapper */
	size_t final_off = 0;
	ret = snmp_ber_encode_header(buf, buf_len, &final_off, ASN1_TAG_SEQUENCE, pl_off);
	if (ret < 0)
		return ret;
	memcpy(&buf[final_off], payload, pl_off);
	final_off += pl_off;

	*out_len = final_off;
	return 0;
}

#endif /* CONFIG_SNMP_AGENT */
