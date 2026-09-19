/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_USM_H_
#define ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_USM_H_

#include <zephyr/kernel.h>
#include <snmp/snmp_ber.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CONFIG_SNMP_AGENT) && defined(CONFIG_SNMP_VERSION_3)

#include <psa/crypto.h>

struct snmp_usm_user {
	const char *user_name;
	uint8_t     auth_protocol;  /* 0=none, 1=SHA, 2=MD5 */
	const char *auth_pass;
	uint8_t     priv_protocol;  /* 0=none, 1=AES, 2=DES */
	const char *priv_pass;

	/* Localized keys (derived at init) */
	uint8_t  auth_key[20];       /* SHA1=20, MD5=16 */
	uint16_t auth_key_len;
	uint8_t  priv_key[20];       /* AES=16, DES=16 */
	uint16_t priv_key_len;
};

int snmp_usm_init(void);

/**
 * @brief Get the local authoritative SNMPv3 engine ID.
 * @param engine_id Buffer to receive the engine ID.
 * @param len In: buffer capacity; Out: actual engine ID length.
 * @return 0 on success, negative errno on error.
 */
int snmp_usm_get_engine_id(uint8_t *engine_id, uint8_t *len);


/**
 * @brief Verify incoming v3 message: check HMAC, decrypt scopedPDU if priv enabled.
 * @param msg   Decoded v3 message (msg->usm populated from wire).
 * @param raw_buf Raw received packet (full SNMP message, outer SEQUENCE included).
 * @param raw_len Length of raw_buf.
 * @return 0 on success, -EAUTH on auth failure (silent drop), other negative on error.
 */
int snmp_usm_verify_incoming(struct snmp_v3_msg *msg, const uint8_t *raw_buf, size_t raw_len);

/**
 * @brief Prepare outgoing v3 message: encrypt scopedPDU if priv enabled,
 *        compute HMAC, populate auth_params. The msg is ready for BER encode.
 * @param msg   Response v3 message (scoped.pdu must be populated).
 * @return 0 on success, negative on error.
 */
int snmp_usm_build_outgoing(struct snmp_v3_msg *msg);

#endif /* CONFIG_SNMP_AGENT && CONFIG_SNMP_VERSION_3 */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_USM_H_ */
