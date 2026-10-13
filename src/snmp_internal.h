/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 *
 * Module-internal declarations for the SNMP agent.
 *
 * NOT INSTALLED: this header lives under src/ and is never part of the public API
 * surface (include/snmp/). It exists for symbols that must cross translation units
 * and therefore cannot be static, yet must not be reachable by applications.
 */

#ifndef ZEPHYR_MODULES_SNMP_SRC_SNMP_INTERNAL_H_
#define ZEPHYR_MODULES_SNMP_SRC_SNMP_INTERNAL_H_

#include <snmp/snmp_core.h>

#ifdef CONFIG_SNMP_AGENT

#if defined(CONFIG_SNMP_VERSION_3)
/**
 * @brief USM incoming-message check for one agent (RFC 3414 section 2.2): engine
 *        discovery, timeliness, key-localization-aware HMAC verification and, when the
 *        privacy flag is set, AES-128-CFB decryption of the scopedPDU.
 *
 * Cross-TU caller: src/snmp_core.c. Increments the receiving agent's counters only.
 *
 * @param inst    Target agent instance (owner of the local keys table).
 * @param msg     Decoded incoming message; filled in with the plaintext scopedPDU.
 * @param raw_buf Raw datagram (needed to locate the ciphertext).
 * @param raw_len Length of @p raw_buf.
 * @return 0 to continue processing, -EACCES to drop silently, other negative errno on
 *         parse failure.
 */
int snmp_usm_verify_incoming(struct snmp_agent *inst, struct snmp_v3_msg *msg,
			     const uint8_t *raw_buf, size_t raw_len);

/**
 * @brief USM outgoing-message preparation for one agent: fills the security parameters,
 *        encrypts the scopedPDU when privacy is in use and stamps the msgAuthentication
 *        Parameters (RFC 3414 section 7).
 *
 * Cross-TU callers: src/snmp_core.c, src/snmp_trap.c.
 *
 * @param inst Target agent instance.
 * @param msg  Message to secure in place.
 * @return 0 on success, negative errno otherwise.
 */
int snmp_usm_build_outgoing(struct snmp_agent *inst, struct snmp_v3_msg *msg);
#endif /* CONFIG_SNMP_VERSION_3 */

#endif /* CONFIG_SNMP_AGENT */

#endif /* ZEPHYR_MODULES_SNMP_SRC_SNMP_INTERNAL_H_ */
