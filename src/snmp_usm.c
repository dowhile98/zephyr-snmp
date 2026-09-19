/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 *
 * SNMPv3 User-based Security Model (RFC 3414)
 * HMAC-SHA1/MD5 authentication + AES-128-CFB privacy via PSA Crypto (mbedtls v4.x).
 */

#include <snmp/snmp_usm.h>
#include <snmp/snmp_mib.h>
#include <string.h>
#include <errno.h>
#include <zephyr/random/random.h>

#if defined(CONFIG_SNMP_AGENT) && defined(CONFIG_SNMP_VERSION_3)

#define HMAC_SHA1_LEN 12
#define HMAC_MD5_LEN 12
#define AES_IV_LEN    16

/* ---- Engine state ---- */
static uint32_t g_engine_boots = 1;
static uint8_t g_engine_id[SNMP_V3_ENGINE_ID_MAX_LEN] = {
	0x80, 0x00, 0x1F, 0x88, 0x80, 'Z', 'E', 'P', 'H', 'Y', 'R', '1'};
static uint8_t g_engine_id_len = 12;

static struct snmp_usm_user g_users[] = {
	{
		.user_name     = CONFIG_SNMP_V3_USER_NAME,
		.auth_protocol = 1,
		.auth_pass     = CONFIG_SNMP_V3_AUTH_PASS,
		.priv_protocol = 1,
		.priv_pass     = CONFIG_SNMP_V3_PRIV_PASS,
	},
};
#define USM_USER_COUNT (sizeof(g_users) / sizeof(g_users[0]))

/* ---- HMAC computation ---- */

static int hmac_compute(psa_algorithm_t alg, const uint8_t *key, size_t key_len,
			const uint8_t *in, size_t in_len,
			uint8_t *mac, size_t mac_sz, size_t *mac_len)
{
	psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attrs, alg);
	psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);

	psa_key_id_t key_id;
	psa_status_t status = psa_import_key(&attrs, key, key_len, &key_id);
	if (status != PSA_SUCCESS)
		return -EIO;

	psa_mac_operation_t op = psa_mac_operation_init();

	status = psa_mac_sign_setup(&op, key_id, alg);
	if (status != PSA_SUCCESS) {
		psa_mac_abort(&op);
		psa_destroy_key(key_id);
		return -EIO;
	}

	status = psa_mac_update(&op, in, in_len);
	if (status != PSA_SUCCESS) {
		psa_mac_abort(&op);
		psa_destroy_key(key_id);
		return -EIO;
	}

	status = psa_mac_sign_finish(&op, mac, mac_sz, mac_len);
	psa_destroy_key(key_id);

	if (status != PSA_SUCCESS)
		return -EIO;

	return 0;
}

/* ---- Password-to-Key (RFC 3414 A.2.1) ---- */

static int usm_password_to_key(psa_algorithm_t hash_alg,
			       const char *password, size_t pw_len,
			       uint8_t *ku, size_t ku_sz, size_t *ku_len)
{
	if (!password || !pw_len || !ku || !ku_len)
		return -EINVAL;

	uint8_t buf[64];
	for (size_t i = 0; i < 64; i++)
		buf[i] = (uint8_t)password[i % pw_len];

	psa_status_t status = psa_hash_compute(hash_alg, buf, 64, ku, ku_sz, ku_len);
	if (status != PSA_SUCCESS)
		return -EIO;

	size_t hash_size = *ku_len;
	uint8_t tmp[128];

	for (uint32_t i = 0; i < 1000000; i++) {
		memcpy(tmp, ku, hash_size);
		memcpy(tmp + hash_size, password, pw_len);
		status = psa_hash_compute(hash_alg, tmp, hash_size + pw_len,
					  ku, ku_sz, ku_len);
		if (status != PSA_SUCCESS)
			return -EIO;
	}

	return 0;
}

/* ---- Key localization (RFC 3414 A.2) ---- */

static int usm_key_localize(uint8_t *out_key, uint16_t *out_len,
			    const char *password, uint8_t algo,
			    const uint8_t *engine_id, uint16_t engine_id_len,
			    bool is_priv)
{
	if (!out_key || !out_len || !password || !engine_id)
		return -EINVAL;

	psa_algorithm_t hash_alg = (algo == 1) ? PSA_ALG_SHA_1 : PSA_ALG_MD5;
	size_t hash_size = (algo == 1) ? 20 : 16;

	uint8_t ku[64];
	size_t ku_len;
	int ret = usm_password_to_key(hash_alg, password, strlen(password),
				      ku, sizeof(ku), &ku_len);
	if (ret < 0)
		return ret;

	uint8_t kul[64];
	size_t kul_len;
	hmac_compute(hash_alg, ku, ku_len, engine_id, engine_id_len,
		     kul, sizeof(kul), &kul_len);

	static const uint8_t auth_const[] = {
		0x01, 'a', 'u', 't', 'h', 'e', 'n', 't', 'i', 'c', 'a',
		't', 'i', 'o', 'n', ' ', 'k', 'e', 'y', 0x00};
	static const uint8_t priv_const[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		'p', 'r', 'i', 'v', 'a', 'c', 'y', ' ', 'k', 'e', 'y', 0x00};

	const uint8_t *c = is_priv ? priv_const : auth_const;
	size_t clen = 20;

	hmac_compute(hash_alg, kul, kul_len, c, clen, out_key, 64, &hash_size);

	if (is_priv)
		*out_len = 16;
	else
		*out_len = (algo == 1) ? HMAC_SHA1_LEN : HMAC_MD5_LEN;

	return 0;
}

/* ---- AES-128-CFB Encrypt ---- */

static int aes128_cfb_encrypt(const uint8_t *key, const uint8_t *iv,
			      const uint8_t *plaintext, size_t pt_len,
			      uint8_t *ciphertext, size_t ct_sz, size_t *ct_len)
{
	psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&attrs, PSA_ALG_CFB_NO_PADDING);
	psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attrs, 128);

	psa_key_id_t key_id;
	psa_status_t status = psa_import_key(&attrs, key, 16, &key_id);
	if (status != PSA_SUCCESS)
		return -EIO;

	psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
	status = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CFB_NO_PADDING);
	if (status != PSA_SUCCESS) {
		psa_cipher_abort(&op);
		psa_destroy_key(key_id);
		return -EIO;
	}

	status = psa_cipher_set_iv(&op, iv, AES_IV_LEN);
	if (status != PSA_SUCCESS) {
		psa_cipher_abort(&op);
		psa_destroy_key(key_id);
		return -EIO;
	}

	size_t out_len = 0;
	status = psa_cipher_update(&op, plaintext, pt_len, ciphertext, ct_sz, &out_len);
	if (status != PSA_SUCCESS) {
		psa_cipher_abort(&op);
		psa_destroy_key(key_id);
		return -EIO;
	}

	size_t final_len = 0;
	status = psa_cipher_finish(&op, ciphertext + out_len, ct_sz - out_len, &final_len);
	psa_cipher_abort(&op);
	psa_destroy_key(key_id);

	if (status != PSA_SUCCESS)
		return -EIO;

	*ct_len = out_len + final_len;
	return 0;
}

/* ---- AES-128-CFB Decrypt ---- */

static int aes128_cfb_decrypt(const uint8_t *key, const uint8_t *iv,
			      const uint8_t *ciphertext, size_t ct_len,
			      uint8_t *plaintext, size_t pt_sz, size_t *pt_len)
{
	psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attrs, PSA_ALG_CFB_NO_PADDING);
	psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attrs, 128);

	psa_key_id_t key_id;
	psa_status_t status = psa_import_key(&attrs, key, 16, &key_id);
	if (status != PSA_SUCCESS)
		return -EIO;

	psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
	status = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CFB_NO_PADDING);
	if (status != PSA_SUCCESS) {
		psa_cipher_abort(&op);
		psa_destroy_key(key_id);
		return -EIO;
	}

	status = psa_cipher_set_iv(&op, iv, AES_IV_LEN);
	if (status != PSA_SUCCESS) {
		psa_cipher_abort(&op);
		psa_destroy_key(key_id);
		return -EIO;
	}

	size_t out_len = 0;
	status = psa_cipher_update(&op, ciphertext, ct_len, plaintext, pt_sz, &out_len);
	if (status != PSA_SUCCESS) {
		psa_cipher_abort(&op);
		psa_destroy_key(key_id);
		return -EIO;
	}

	size_t final_len = 0;
	status = psa_cipher_finish(&op, plaintext + out_len, pt_sz - out_len, &final_len);
	psa_cipher_abort(&op);
	psa_destroy_key(key_id);

	if (status != PSA_SUCCESS)
		return -EIO;

	*pt_len = out_len + final_len;
	return 0;
}

/* ---- Find encrypted scopedPDU OCTET STRING in raw buffer ---- */

static int find_encrypted_scopedpdu(const uint8_t *buf, size_t buf_len,
				    const uint8_t **ct_data, size_t *ct_len)
{
	size_t off = 0;
	uint8_t tag;
	size_t len;
	int ret;

	ret = snmp_ber_decode_header(buf, buf_len, &off, &tag, &len);
	if (ret < 0 || tag != ASN1_TAG_SEQUENCE)
		return -EBADMSG;

	ret = snmp_ber_decode_header(buf, buf_len, &off, &tag, &len);
	if (ret < 0 || tag != ASN1_TAG_INTEGER)
		return -EBADMSG;
	off += len;

	ret = snmp_ber_decode_header(buf, buf_len, &off, &tag, &len);
	if (ret < 0 || tag != ASN1_TAG_SEQUENCE)
		return -EBADMSG;
	off += len;

	ret = snmp_ber_decode_header(buf, buf_len, &off, &tag, &len);
	if (ret < 0 || tag != ASN1_TAG_OCTET_STRING)
		return -EBADMSG;
	off += len;

	ret = snmp_ber_decode_header(buf, buf_len, &off, &tag, &len);
	if (ret < 0 || tag != ASN1_TAG_SEQUENCE)
		return -EBADMSG;

	ret = snmp_ber_decode_header(buf, buf_len, &off, &tag, &len);
	if (ret < 0)
		return -EBADMSG;

	if (tag == ASN1_TAG_OCTET_STRING) {
		*ct_data = &buf[off];
		*ct_len = len;
		return 0;
	}

	return -EBADMSG;
}

/* ---- Parse decrypted scopedPDU plaintext into msg->scoped ---- */

static int parse_scopedpdu_plaintext(const uint8_t *data, size_t data_len,
				     struct snmp_v3_scoped_pdu *scoped)
{
	size_t off = 0;
	uint8_t tag;
	size_t len;
	int ret;
	uint16_t tmp_len;

	ret = snmp_ber_decode_header(data, data_len, &off, &tag, &len);
	if (ret < 0 || tag != ASN1_TAG_SEQUENCE)
		return -EBADMSG;

	ret = snmp_ber_decode_octet_string(data, data_len, &off,
					   scoped->context_engine_id,
					   SNMP_V3_ENGINE_ID_MAX_LEN, &tmp_len);
	if (ret < 0)
		return ret;
	scoped->context_engine_id_len = tmp_len;

	ret = snmp_ber_decode_octet_string(data, data_len, &off,
					   scoped->context_name,
					   sizeof(scoped->context_name) - 1, &tmp_len);
	if (ret < 0)
		return ret;
	scoped->context_name_len = tmp_len;
	scoped->context_name[tmp_len] = '\0';

	return snmp_ber_decode_pdu_body(data, data_len, &off, &scoped->pdu);
}

/* ---- Build plaintext scopedPDU bytes for encryption ---- */

static int build_scopedpdu_plaintext(const struct snmp_v3_msg *msg,
				     uint8_t *out, size_t out_sz, size_t *out_len)
{
	int ret;
	uint8_t body[CONFIG_SNMP_MAX_PDU_SIZE];
	size_t body_off = 0;

	ret = snmp_ber_encode_octet_string(body, sizeof(body), &body_off, ASN1_TAG_OCTET_STRING,
					   msg->scoped.context_engine_id,
					   msg->scoped.context_engine_id_len);
	if (ret < 0)
		return ret;

	ret = snmp_ber_encode_octet_string(body, sizeof(body), &body_off, ASN1_TAG_OCTET_STRING,
					   (const uint8_t *)msg->scoped.context_name,
					   msg->scoped.context_name_len);
	if (ret < 0)
		return ret;

	size_t pdu_len = 0;
	ret = snmp_ber_encode_pdu_body(&body[body_off], sizeof(body) - body_off, &pdu_len, &msg->scoped.pdu);
	if (ret < 0)
		return ret;
	body_off += pdu_len;

	size_t hdr_off = 0;
	ret = snmp_ber_encode_header(out, out_sz, &hdr_off, ASN1_TAG_SEQUENCE, body_off);
	if (ret < 0)
		return ret;

	if (hdr_off + body_off > out_sz)
		return -ENOBUFS;
	memcpy(&out[hdr_off], body, body_off);
	*out_len = hdr_off + body_off;
	return 0;
}

/* ---- User lookup ---- */

static struct snmp_usm_user *usm_find_user(const char *name)
{
	if (!name)
		return NULL;
	for (size_t i = 0; i < USM_USER_COUNT; i++) {
		if (strcmp(g_users[i].user_name, name) == 0)
			return &g_users[i];
	}
	return NULL;
}

/* ---- HMAC verification ---- */

static int usm_verify_auth(const struct snmp_v3_msg *msg,
			   struct snmp_usm_user *user)
{
	if (!msg || !user || user->auth_protocol == 0)
		return 0;

	psa_algorithm_t alg = (user->auth_protocol == 1) ? PSA_ALG_HMAC(PSA_ALG_SHA_1)
							 : PSA_ALG_HMAC(PSA_ALG_MD5);

	struct snmp_v3_msg hash_msg = *msg;
	memset(hash_msg.usm.auth_params, 0, sizeof(hash_msg.usm.auth_params));
	hash_msg.usm.auth_params_len = (user->auth_protocol == 1) ? HMAC_SHA1_LEN : HMAC_MD5_LEN;
	hash_msg.usm.priv_params_len = (user->priv_protocol > 0) ? AES_IV_LEN : 0;

	uint8_t encoded[CONFIG_SNMP_MAX_PDU_SIZE];
	size_t encoded_len = 0;
	int ret = snmp_ber_encode_v3_msg(encoded, sizeof(encoded), &encoded_len, &hash_msg);
	if (ret < 0)
		return ret;

	uint8_t computed_hash[20];
	size_t hash_len;
	ret = hmac_compute(alg, user->auth_key, user->auth_key_len,
			   encoded, encoded_len,
			   computed_hash, sizeof(computed_hash), &hash_len);
	if (ret < 0)
		return ret;

	uint8_t trunc = (user->auth_protocol == 1) ? HMAC_SHA1_LEN : HMAC_MD5_LEN;
	if (hash_len < trunc)
		return -EACCES;
	if (memcmp(computed_hash, msg->usm.auth_params, trunc) != 0)
		return -EACCES;

	return 0;
}

/* ---- Init ---- */

int snmp_usm_init(void)
{
	psa_crypto_init();

	g_engine_boots = CONFIG_SNMP_V3_ENGINE_BOOTS;

	for (size_t i = 0; i < USM_USER_COUNT; i++) {
		if (g_users[i].auth_protocol > 0) {
			usm_key_localize(g_users[i].auth_key, &g_users[i].auth_key_len,
					 g_users[i].auth_pass, g_users[i].auth_protocol,
					 g_engine_id, g_engine_id_len, false);
		}
		if (g_users[i].priv_protocol > 0) {
			usm_key_localize(g_users[i].priv_key, &g_users[i].priv_key_len,
					 g_users[i].priv_pass, g_users[i].priv_protocol,
					 g_engine_id, g_engine_id_len, true);
		}
	}

	return 0;
}

/* ---- Main API: verify incoming ---- */

int snmp_usm_verify_incoming(struct snmp_v3_msg *msg, const uint8_t *raw_buf, size_t raw_len)
{
	if (!msg || !raw_buf)
		return -EINVAL;

	if ((msg->usm.engine_boots == 0 && msg->usm.engine_time == 0) || msg->usm.engine_id_len == 0) {
		memset(&msg->scoped.pdu, 0, sizeof(msg->scoped.pdu));
		msg->scoped.pdu.type = SNMP_PDU_REPORT;
		msg->scoped.pdu.version = 3;
		return 0;
	}

	struct snmp_usm_user *user = usm_find_user((const char *)msg->usm.user_name);
	if (!user) {
		snmp_counter_inc(&g_snmp_counters.snmpSilentDrops);
		return -EACCES;
	}

	int ret = usm_verify_auth(msg, user);
	if (ret < 0) {
		snmp_counter_inc(&g_snmp_counters.snmpSilentDrops);
		return ret;
	}

	if (msg->global.msg_flags & 0x02) {
		if (user->priv_protocol == 0) {
			snmp_counter_inc(&g_snmp_counters.snmpSilentDrops);
			return -EACCES;
		}

		const uint8_t *ct_data;
		size_t ct_len;
		ret = find_encrypted_scopedpdu(raw_buf, raw_len, &ct_data, &ct_len);
		if (ret < 0) {
			snmp_counter_inc(&g_snmp_counters.snmpSilentDrops);
			return ret;
		}

		uint8_t iv[AES_IV_LEN];
		memcpy(iv, msg->usm.priv_params, AES_IV_LEN);

		uint8_t pt[CONFIG_SNMP_MAX_PDU_SIZE];
		size_t pt_len;
		ret = aes128_cfb_decrypt(user->priv_key, iv, ct_data, ct_len,
					 pt, sizeof(pt), &pt_len);
		if (ret < 0) {
			snmp_counter_inc(&g_snmp_counters.snmpSilentDrops);
			return ret;
		}

		ret = parse_scopedpdu_plaintext(pt, pt_len, &msg->scoped);
		if (ret < 0) {
			snmp_counter_inc(&g_snmp_counters.snmpSilentDrops);
			return ret;
		}
	}

	int32_t local_time = (int32_t)(k_uptime_get() / 1000);
	int32_t diff = (int32_t)msg->usm.engine_time - local_time;
	if (diff < -150 || diff > 150) {
		snmp_counter_inc(&g_snmp_counters.snmpSilentDrops);
		return -EACCES;
	}
	if (msg->usm.engine_boots != g_engine_boots) {
		snmp_counter_inc(&g_snmp_counters.snmpSilentDrops);
		return -EACCES;
	}

	return 0;
}

/* ---- Main API: build outgoing ---- */

int snmp_usm_build_outgoing(struct snmp_v3_msg *msg)
{
	if (!msg)
		return -EINVAL;

	if (msg->scoped.pdu.type == SNMP_PDU_REPORT) {
		memcpy(msg->usm.engine_id, g_engine_id, g_engine_id_len);
		msg->usm.engine_id_len = g_engine_id_len;
		msg->usm.engine_boots = g_engine_boots;
		msg->usm.engine_time = (uint32_t)(k_uptime_get() / 1000);
		msg->global.msg_flags = 0x00;
		msg->usm.auth_params_len = 0;
		msg->usm.priv_params_len = 0;
		return 0;
	}

	struct snmp_usm_user *user = usm_find_user((const char *)msg->usm.user_name);
	if (!user)
		return -EACCES;

	memcpy(msg->usm.engine_id, g_engine_id, g_engine_id_len);
	msg->usm.engine_id_len = g_engine_id_len;
	msg->usm.engine_boots = g_engine_boots;
	msg->usm.engine_time = (uint32_t)(k_uptime_get() / 1000);

	uint8_t pdu_type = msg->scoped.pdu.type;
	if (pdu_type == SNMP_PDU_TRAP_V2 || pdu_type == SNMP_PDU_RESPONSE || pdu_type == SNMP_PDU_REPORT) {
		msg->global.msg_flags = 0x00;
	} else {
		msg->global.msg_flags = 0x04;
	}
	if (user->auth_protocol > 0) {
		msg->global.msg_flags |= 0x01;
		msg->usm.auth_params_len = (user->auth_protocol == 1) ? HMAC_SHA1_LEN : HMAC_MD5_LEN;
	}
	if (user->priv_protocol > 0) {
		msg->global.msg_flags |= 0x02;
		msg->usm.priv_params_len = AES_IV_LEN;

		msg->usm.priv_params[0] = (uint8_t)(msg->usm.engine_boots >> 24);
		msg->usm.priv_params[1] = (uint8_t)(msg->usm.engine_boots >> 16);
		msg->usm.priv_params[2] = (uint8_t)(msg->usm.engine_boots >> 8);
		msg->usm.priv_params[3] = (uint8_t)(msg->usm.engine_boots);
		msg->usm.priv_params[4] = (uint8_t)(msg->usm.engine_time >> 24);
		msg->usm.priv_params[5] = (uint8_t)(msg->usm.engine_time >> 16);
		msg->usm.priv_params[6] = (uint8_t)(msg->usm.engine_time >> 8);
		msg->usm.priv_params[7] = (uint8_t)(msg->usm.engine_time);

		uint32_t salt = (uint32_t)sys_rand32_get();
		msg->usm.priv_params[8] = (uint8_t)(salt >> 24);
		msg->usm.priv_params[9] = (uint8_t)(salt >> 16);
		msg->usm.priv_params[10] = (uint8_t)(salt >> 8);
		msg->usm.priv_params[11] = (uint8_t)(salt);
		salt = sys_rand32_get();
		msg->usm.priv_params[12] = (uint8_t)(salt >> 24);
		msg->usm.priv_params[13] = (uint8_t)(salt >> 16);
		msg->usm.priv_params[14] = (uint8_t)(salt >> 8);
		msg->usm.priv_params[15] = (uint8_t)(salt);

		uint8_t plaintext[CONFIG_SNMP_MAX_PDU_SIZE];
		size_t pt_len;
		int ret = build_scopedpdu_plaintext(msg, plaintext, sizeof(plaintext), &pt_len);
		if (ret < 0)
			return ret;

		uint8_t ciphertext[CONFIG_SNMP_MAX_PDU_SIZE];
		size_t ct_len;
		ret = aes128_cfb_encrypt(user->priv_key, msg->usm.priv_params,
					 plaintext, pt_len,
					 ciphertext, sizeof(ciphertext), &ct_len);
		if (ret < 0)
			return ret;

		if (ct_len > sizeof(msg->scoped.priv_ciphertext)) {
			return -ENOBUFS;
		}
		memcpy(msg->scoped.priv_ciphertext, ciphertext, ct_len);
		msg->scoped.priv_ciphertext_len = ct_len;
		msg->scoped.context_name_len = 0;
		memset(&msg->scoped.pdu, 0, sizeof(msg->scoped.pdu));
	}

	memset(msg->usm.auth_params, 0, sizeof(msg->usm.auth_params));

	uint8_t hash_target[CONFIG_SNMP_MAX_PDU_SIZE];
	size_t hash_len = 0;
	int ret = snmp_ber_encode_v3_msg(hash_target, sizeof(hash_target), &hash_len, msg);
	if (ret < 0)
		return ret;

	if (user->auth_protocol > 0) {
		psa_algorithm_t alg = (user->auth_protocol == 1) ? PSA_ALG_HMAC(PSA_ALG_SHA_1)
								 : PSA_ALG_HMAC(PSA_ALG_MD5);
		uint8_t full_hash[20];
		size_t fh_len;
		ret = hmac_compute(alg, user->auth_key, user->auth_key_len,
				   hash_target, hash_len,
				   full_hash, sizeof(full_hash), &fh_len);
		if (ret < 0)
			return ret;

		uint8_t trunc = (user->auth_protocol == 1) ? HMAC_SHA1_LEN : HMAC_MD5_LEN;
		memcpy(msg->usm.auth_params, full_hash, trunc);
	}

	return 0;
}

int snmp_usm_get_engine_id(uint8_t *engine_id, uint8_t *len)
{
	if (!engine_id || !len) {
		return -EINVAL;
	}
	if (*len < g_engine_id_len) {
		return -ENOBUFS;
	}
	memcpy(engine_id, g_engine_id, g_engine_id_len);
	*len = g_engine_id_len;
	return 0;
}

#endif /* CONFIG_SNMP_AGENT && CONFIG_SNMP_VERSION_3 */
