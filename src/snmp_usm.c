/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 *
 * SNMPv3 User-based Security Model (RFC 3414)
 * HMAC-SHA1/MD5 authentication + AES-128-CFB privacy via PSA Crypto (mbedtls v4.x).
 */

#include <snmp/snmp_usm.h>
#include <snmp/snmp_mib.h>
#include <snmp/snmp_core.h>
#include <string.h>
#include <errno.h>
#include <zephyr/random/random.h>

#if defined(CONFIG_SNMP_AGENT) && defined(CONFIG_SNMP_VERSION_3)

#if defined(CONFIG_SETTINGS)
#include <zephyr/settings/settings.h>
#endif

#define HMAC_SHA1_LEN 12
#define HMAC_MD5_LEN 12
#define AES_IV_LEN    16
#define SNMP_ENGINE_BOOTS_MAX 2147483647U

#define INC_STAT(inst, field) do { \
		if (inst) { snmp_counter_inc(&(inst)->counters.field); } \
		snmp_counter_inc(&g_snmp_counters.field); \
	} while (0)

#if defined(CONFIG_SETTINGS)
static int usm_settings_set(const char *name, size_t len,
			    settings_read_cb read_cb, void *cb_arg)
{
	const char *next;
	if (settings_name_steq(name, "boots", &next) && !next) {
		struct snmp_agent_inst *def = snmp_agent_get_default();
		if (!def || len != sizeof(def->engine_boots)) {
			return -EINVAL;
		}
		int ret = read_cb(cb_arg, &def->engine_boots, sizeof(def->engine_boots));
		if (ret < 0) {
			return ret;
		}
		return 0;
	}
	return -ENOENT;
}

SETTINGS_STATIC_HANDLER_DEFINE(snmp_usm, "snmp", NULL, usm_settings_set, NULL, NULL);
#endif

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

	psa_hash_operation_t op = psa_hash_operation_init();
	psa_status_t status = psa_hash_setup(&op, hash_alg);
	if (status != PSA_SUCCESS)
		return -EIO;

	uint8_t buf[64];
	size_t password_index = 0;
	size_t count = 0;

	/* RFC 3414 A.2.1: Process 1,048,576 octets of password cycling in 64-byte chunks */
	while (count < 1048576) {
		for (size_t i = 0; i < 64; i++) {
			buf[i] = (uint8_t)password[password_index++ % pw_len];
		}
		status = psa_hash_update(&op, buf, 64);
		if (status != PSA_SUCCESS) {
			psa_hash_abort(&op);
			return -EIO;
		}
		count += 64;
	}

	status = psa_hash_finish(&op, ku, ku_sz, ku_len);
	if (status != PSA_SUCCESS) {
		psa_hash_abort(&op);
		return -EIO;
	}

	return 0;
}

/* ---- Key localization (RFC 3414 A.2.2 & RFC 3826 §2.4) ---- */

static int usm_key_localize(uint8_t *out_key, uint16_t *out_len,
			    const char *password, uint8_t algo,
			    const uint8_t *engine_id, uint16_t engine_id_len,
			    bool is_priv)
{
	if (!out_key || !out_len || !password || !engine_id)
		return -EINVAL;

	psa_algorithm_t hash_alg = (algo == 1) ? PSA_ALG_SHA_1 : PSA_ALG_MD5;

	uint8_t ku[64];
	size_t ku_len = 0;
	int ret = usm_password_to_key(hash_alg, password, strlen(password),
				      ku, sizeof(ku), &ku_len);
	if (ret < 0)
		return ret;

	/* RFC 3414 A.2.2: Buffer = Ku (hash_size) || engine_id (engine_id_len) || Ku (hash_size) */
	size_t total_len = ku_len + engine_id_len + ku_len;
	uint8_t buffer[128];
	if (total_len > sizeof(buffer))
		return -ENOBUFS;

	memcpy(buffer, ku, ku_len);
	memcpy(buffer + ku_len, engine_id, engine_id_len);
	memcpy(buffer + ku_len + engine_id_len, ku, ku_len);

	uint8_t kul[64];
	size_t kul_len = 0;
	psa_status_t status = psa_hash_compute(hash_alg, buffer, total_len,
					       kul, sizeof(kul), &kul_len);
	if (status != PSA_SUCCESS)
		return -EIO;

	if (is_priv) {
		/* RFC 3826 §2.4: AES-128 priv key uses first 16 octets (128 bits) */
		if (kul_len < 16)
			return -EIO;
		memcpy(out_key, kul, 16);
		*out_len = 16;
	} else {
		/* RFC 3414 §6.2.4 / §7.2.4: localized auth key (20 octets for SHA-1, 16 for MD5) */
		memcpy(out_key, kul, kul_len);
		*out_len = (uint16_t)kul_len;
	}

	return 0;
}

/* ---- AES-128-CFB Encrypt ---- */

static int aes128_cfb_encrypt(const uint8_t *key, const uint8_t *iv,
			      const uint8_t *plaintext, size_t pt_len,
			      uint8_t *ciphertext, size_t ct_sz, size_t *ct_len)
{
	psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&attrs, PSA_ALG_CFB);
	psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attrs, 128);

	psa_key_id_t key_id;
	psa_status_t status = psa_import_key(&attrs, key, 16, &key_id);
	if (status != PSA_SUCCESS)
		return -EIO;

	psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
	status = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CFB);
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
	psa_set_key_algorithm(&attrs, PSA_ALG_CFB);
	psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attrs, 128);

	psa_key_id_t key_id;
	psa_status_t status = psa_import_key(&attrs, key, 16, &key_id);
	if (status != PSA_SUCCESS)
		return -EIO;

	psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
	status = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CFB);
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

static struct snmp_usm_user *usm_find_user(struct snmp_agent_inst *inst, const char *name)
{
	if (!inst || !name)
		return NULL;
	for (size_t i = 0; i < CONFIG_SNMP_V3_MAX_USERS; i++) {
		if (inst->users[i].in_use && strcmp(inst->users[i].user_name, name) == 0)
			return &inst->users[i];
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

/* ---- Instance-based APIs ---- */

int snmp_usm_add_user_inst(struct snmp_agent_inst *inst, const struct snmp_usm_user *user)
{
	if (!inst || !user) {
		return -EINVAL;
	}
	if (strlen(user->user_name) >= sizeof(inst->users[0].user_name)) {
		return -EINVAL;
	}

	/* Update existing if found */
	for (size_t i = 0; i < CONFIG_SNMP_V3_MAX_USERS; i++) {
		if (inst->users[i].in_use && strcmp(inst->users[i].user_name, user->user_name) == 0) {
			inst->users[i] = *user;
			inst->users[i].in_use = true;
			if (inst->users[i].auth_protocol > 0) {
				usm_key_localize(inst->users[i].auth_key, &inst->users[i].auth_key_len,
						 inst->users[i].auth_pass, inst->users[i].auth_protocol,
						 inst->engine_id, inst->engine_id_len, false);
			}
			if (inst->users[i].priv_protocol > 0) {
				usm_key_localize(inst->users[i].priv_key, &inst->users[i].priv_key_len,
						 inst->users[i].priv_pass, inst->users[i].priv_protocol,
						 inst->engine_id, inst->engine_id_len, true);
			}
			return 0;
		}
	}

	/* Find free slot */
	for (size_t i = 0; i < CONFIG_SNMP_V3_MAX_USERS; i++) {
		if (!inst->users[i].in_use) {
			inst->users[i] = *user;
			inst->users[i].in_use = true;
			if (inst->users[i].auth_protocol > 0) {
				usm_key_localize(inst->users[i].auth_key, &inst->users[i].auth_key_len,
						 inst->users[i].auth_pass, inst->users[i].auth_protocol,
						 inst->engine_id, inst->engine_id_len, false);
			}
			if (inst->users[i].priv_protocol > 0) {
				usm_key_localize(inst->users[i].priv_key, &inst->users[i].priv_key_len,
						 inst->users[i].priv_pass, inst->users[i].priv_protocol,
						 inst->engine_id, inst->engine_id_len, true);
			}
			inst->user_cnt++;
			return 0;
		}
	}

	return -ENOMEM;
}

int snmp_usm_init_inst(struct snmp_agent_inst *inst)
{
	if (!inst) {
		return -EINVAL;
	}
	psa_crypto_init();

	if (inst->engine_id_len == 0) {
		static const uint8_t default_engine_id[12] = {
			0x80, 0x00, 0x1F, 0x88, 0x80, 'Z', 'E', 'P', 'H', 'Y', 'R', '1'
		};
		memcpy(inst->engine_id, default_engine_id, sizeof(default_engine_id));
		inst->engine_id_len = sizeof(default_engine_id);
	}

#if defined(CONFIG_SETTINGS)
	settings_subsys_init();
	settings_load_subtree("snmp");
	if (inst->engine_boots < SNMP_ENGINE_BOOTS_MAX) {
		inst->engine_boots++;
		settings_save_one("snmp/boots", &inst->engine_boots, sizeof(inst->engine_boots));
	}
#else
	if (inst->engine_boots == 0) {
#if defined(CONFIG_SNMP_V3_ENGINE_BOOTS)
		inst->engine_boots = CONFIG_SNMP_V3_ENGINE_BOOTS;
#else
		inst->engine_boots = 1;
#endif
	}
#endif

	if (inst->user_cnt == 0) {
		struct snmp_usm_user default_user = {
			.auth_protocol = 1,
			.priv_protocol = 1,
			.in_use = true,
		};
		strncpy(default_user.user_name, CONFIG_SNMP_V3_USER_NAME, sizeof(default_user.user_name) - 1);
		default_user.user_name[sizeof(default_user.user_name) - 1] = '\0';
		strncpy(default_user.auth_pass, CONFIG_SNMP_V3_AUTH_PASS, sizeof(default_user.auth_pass) - 1);
		default_user.auth_pass[sizeof(default_user.auth_pass) - 1] = '\0';
		strncpy(default_user.priv_pass, CONFIG_SNMP_V3_PRIV_PASS, sizeof(default_user.priv_pass) - 1);
		default_user.priv_pass[sizeof(default_user.priv_pass) - 1] = '\0';
		snmp_usm_add_user_inst(inst, &default_user);
	} else {
		/* Re-localize existing users with current engine_id */
		for (size_t i = 0; i < CONFIG_SNMP_V3_MAX_USERS; i++) {
			if (inst->users[i].in_use) {
				if (inst->users[i].auth_protocol > 0) {
					usm_key_localize(inst->users[i].auth_key, &inst->users[i].auth_key_len,
							 inst->users[i].auth_pass, inst->users[i].auth_protocol,
							 inst->engine_id, inst->engine_id_len, false);
				}
				if (inst->users[i].priv_protocol > 0) {
					usm_key_localize(inst->users[i].priv_key, &inst->users[i].priv_key_len,
							 inst->users[i].priv_pass, inst->users[i].priv_protocol,
							 inst->engine_id, inst->engine_id_len, true);
				}
			}
		}
	}

	return 0;
}

int snmp_usm_verify_incoming_inst(struct snmp_agent_inst *inst, struct snmp_v3_msg *msg,
				  const uint8_t *raw_buf, size_t raw_len)
{
	if (!inst || !msg || !raw_buf)
		return -EINVAL;

	/* RFC 3414 §2.2: if engine boots reaches 2147483647, stop processing */
	if (inst->engine_boots >= SNMP_ENGINE_BOOTS_MAX || msg->usm.engine_boots >= SNMP_ENGINE_BOOTS_MAX) {
		INC_STAT(inst, snmpSilentDrops);
		return -EACCES;
	}

	if ((msg->usm.engine_boots == 0 && msg->usm.engine_time == 0) || msg->usm.engine_id_len == 0) {
		memset(&msg->scoped.pdu, 0, sizeof(msg->scoped.pdu));
		msg->scoped.pdu.type = SNMP_PDU_REPORT;
		msg->scoped.pdu.version = 3;
		return 0;
	}

	struct snmp_usm_user *user = usm_find_user(inst, (const char *)msg->usm.user_name);
	if (!user) {
		INC_STAT(inst, snmpSilentDrops);
		return -EACCES;
	}

	int ret = usm_verify_auth(msg, user);
	if (ret < 0) {
		INC_STAT(inst, snmpSilentDrops);
		return ret;
	}

	if (msg->global.msg_flags & 0x02) {
		if (user->priv_protocol == 0) {
			INC_STAT(inst, snmpSilentDrops);
			return -EACCES;
		}

		/* RFC 3826 §3.1.2: msgPrivacyParameters is strictly 8 octets (salt) */
		if (msg->usm.priv_params_len != 8) {
			INC_STAT(inst, snmpSilentDrops);
			return -EBADMSG;
		}

		const uint8_t *ct_data;
		size_t ct_len;
		ret = find_encrypted_scopedpdu(raw_buf, raw_len, &ct_data, &ct_len);
		if (ret < 0) {
			INC_STAT(inst, snmpSilentDrops);
			return ret;
		}

		/* RFC 3826 §3.1.1.1 & §3.1.4: 16-byte IV = boots (4 BE) || time (4 BE) || salt (8) */
		uint8_t iv[AES_IV_LEN];
		iv[0] = (uint8_t)(msg->usm.engine_boots >> 24);
		iv[1] = (uint8_t)(msg->usm.engine_boots >> 16);
		iv[2] = (uint8_t)(msg->usm.engine_boots >> 8);
		iv[3] = (uint8_t)(msg->usm.engine_boots);
		iv[4] = (uint8_t)(msg->usm.engine_time >> 24);
		iv[5] = (uint8_t)(msg->usm.engine_time >> 16);
		iv[6] = (uint8_t)(msg->usm.engine_time >> 8);
		iv[7] = (uint8_t)(msg->usm.engine_time);
		memcpy(&iv[8], msg->usm.priv_params, 8);

		uint8_t pt[CONFIG_SNMP_MAX_PDU_SIZE];
		size_t pt_len;
		ret = aes128_cfb_decrypt(user->priv_key, iv, ct_data, ct_len,
					 pt, sizeof(pt), &pt_len);
		if (ret < 0) {
			INC_STAT(inst, snmpSilentDrops);
			return ret;
		}

		ret = parse_scopedpdu_plaintext(pt, pt_len, &msg->scoped);
		if (ret < 0) {
			INC_STAT(inst, snmpSilentDrops);
			return ret;
		}
	}

	int32_t local_time = (int32_t)(k_uptime_get() / 1000);
	int32_t diff = (int32_t)msg->usm.engine_time - local_time;
	if (diff < -150 || diff > 150) {
		INC_STAT(inst, snmpSilentDrops);
		return -EACCES;
	}
	if (msg->usm.engine_boots != inst->engine_boots) {
		INC_STAT(inst, snmpSilentDrops);
		return -EACCES;
	}

	return 0;
}

int snmp_usm_build_outgoing_inst(struct snmp_agent_inst *inst, struct snmp_v3_msg *msg)
{
	if (!inst || !msg)
		return -EINVAL;

	/* RFC 3414 §2.2: if engine boots reaches 2147483647, stop processing */
	if (inst->engine_boots >= SNMP_ENGINE_BOOTS_MAX) {
		return -EACCES;
	}

	if (msg->scoped.pdu.type == SNMP_PDU_REPORT) {
		memcpy(msg->usm.engine_id, inst->engine_id, inst->engine_id_len);
		msg->usm.engine_id_len = inst->engine_id_len;
		msg->usm.engine_boots = inst->engine_boots;
		msg->usm.engine_time = (uint32_t)(k_uptime_get() / 1000);
		msg->global.msg_flags = 0x00;
		msg->usm.auth_params_len = 0;
		msg->usm.priv_params_len = 0;
		return 0;
	}

	struct snmp_usm_user *user = usm_find_user(inst, (const char *)msg->usm.user_name);
	if (!user)
		return -EACCES;

	memcpy(msg->usm.engine_id, inst->engine_id, inst->engine_id_len);
	msg->usm.engine_id_len = inst->engine_id_len;
	msg->usm.engine_boots = inst->engine_boots;
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

		/* RFC 3826 §3.1.1.3 & §3.1.2: msgPrivacyParameters is strictly 8 octets (salt) */
		uint32_t salt_hi = sys_rand32_get();
		uint32_t salt_lo = sys_rand32_get();
		msg->usm.priv_params[0] = (uint8_t)(salt_hi >> 24);
		msg->usm.priv_params[1] = (uint8_t)(salt_hi >> 16);
		msg->usm.priv_params[2] = (uint8_t)(salt_hi >> 8);
		msg->usm.priv_params[3] = (uint8_t)(salt_hi);
		msg->usm.priv_params[4] = (uint8_t)(salt_lo >> 24);
		msg->usm.priv_params[5] = (uint8_t)(salt_lo >> 16);
		msg->usm.priv_params[6] = (uint8_t)(salt_lo >> 8);
		msg->usm.priv_params[7] = (uint8_t)(salt_lo);
		msg->usm.priv_params_len = 8;

		/* RFC 3826 §3.1.1.1: 16-byte IV = boots (4 BE) || time (4 BE) || salt (8) */
		uint8_t iv[AES_IV_LEN];
		iv[0] = (uint8_t)(inst->engine_boots >> 24);
		iv[1] = (uint8_t)(inst->engine_boots >> 16);
		iv[2] = (uint8_t)(inst->engine_boots >> 8);
		iv[3] = (uint8_t)(inst->engine_boots);
		iv[4] = (uint8_t)(msg->usm.engine_time >> 24);
		iv[5] = (uint8_t)(msg->usm.engine_time >> 16);
		iv[6] = (uint8_t)(msg->usm.engine_time >> 8);
		iv[7] = (uint8_t)(msg->usm.engine_time);
		memcpy(&iv[8], msg->usm.priv_params, 8);

		uint8_t plaintext[CONFIG_SNMP_MAX_PDU_SIZE];
		size_t pt_len;
		int ret = build_scopedpdu_plaintext(msg, plaintext, sizeof(plaintext), &pt_len);
		if (ret < 0)
			return ret;

		uint8_t ciphertext[CONFIG_SNMP_MAX_PDU_SIZE];
		size_t ct_len;
		ret = aes128_cfb_encrypt(user->priv_key, iv,
					 plaintext, pt_len,
					 ciphertext, sizeof(ciphertext), &ct_len);
		if (ret < 0)
			return ret;

		if (ct_len > sizeof(msg->scoped.priv_ciphertext)) {
			return -ENOBUFS;
		}
		memcpy(msg->scoped.priv_ciphertext, ciphertext, ct_len);
		msg->scoped.priv_ciphertext_len = ct_len;
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

int snmp_usm_get_engine_id_inst(struct snmp_agent_inst *inst, uint8_t *engine_id, uint8_t *len)
{
	if (!inst || !engine_id || !len) {
		return -EINVAL;
	}
	if (*len < inst->engine_id_len) {
		return -ENOBUFS;
	}
	memcpy(engine_id, inst->engine_id, inst->engine_id_len);
	*len = inst->engine_id_len;
	return 0;
}

int snmp_usm_set_engine_boots_inst(struct snmp_agent_inst *inst, uint32_t boots)
{
	if (!inst || boots > SNMP_ENGINE_BOOTS_MAX) {
		return -EINVAL;
	}
	inst->engine_boots = boots;
#if defined(CONFIG_SETTINGS)
	if (inst == snmp_agent_get_default()) {
		settings_save_one("snmp/boots", &inst->engine_boots, sizeof(inst->engine_boots));
	}
#endif
	return 0;
}

uint32_t snmp_usm_get_engine_boots_inst(struct snmp_agent_inst *inst)
{
	return inst ? inst->engine_boots : 0;
}

/* ---- Legacy API Facade (delegates to default agent) ---- */

int snmp_usm_init(void)
{
	return snmp_usm_init_inst(snmp_agent_get_default());
}

int snmp_usm_add_user(const struct snmp_usm_user *user)
{
	return snmp_usm_add_user_inst(snmp_agent_get_default(), user);
}

int snmp_usm_get_engine_id(uint8_t *engine_id, uint8_t *len)
{
	return snmp_usm_get_engine_id_inst(snmp_agent_get_default(), engine_id, len);
}

int snmp_usm_verify_incoming(struct snmp_v3_msg *msg, const uint8_t *raw_buf, size_t raw_len)
{
	return snmp_usm_verify_incoming_inst(snmp_agent_get_default(), msg, raw_buf, raw_len);
}

int snmp_usm_build_outgoing(struct snmp_v3_msg *msg)
{
	return snmp_usm_build_outgoing_inst(snmp_agent_get_default(), msg);
}

int snmp_usm_set_engine_boots(uint32_t boots)
{
	return snmp_usm_set_engine_boots_inst(snmp_agent_get_default(), boots);
}

uint32_t snmp_usm_get_engine_boots(void)
{
	return snmp_usm_get_engine_boots_inst(snmp_agent_get_default());
}

#endif /* CONFIG_SNMP_AGENT && CONFIG_SNMP_VERSION_3 */
