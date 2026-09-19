/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_CORE_H_
#define ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_CORE_H_

#include <zephyr/kernel.h>
#include <snmp/snmp_ber.h>
#include <snmp/snmp_mib.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_SNMP_AGENT

/**
 * @brief Process raw UDP packet payload through SNMP decoding, version check,
 *        USM/VACM security (if v3), MIB dispatch, and BER response encoding.
 *
 * @param req_buf Pointer to incoming raw UDP payload.
 * @param req_len Length of incoming payload.
 * @param resp_buf Pointer to output buffer for SNMP response.
 * @param max_resp_len Capacity of output buffer.
 * @param out_resp_len Pointer where output response length will be stored.
 *
 * @return 0 on success (or silent drop with out_resp_len=0), negative errno on error.
 */
int snmp_core_process_pdu(const uint8_t *req_buf, size_t req_len,
                          uint8_t *resp_buf, size_t max_resp_len,
                          size_t *out_resp_len);

#endif /* CONFIG_SNMP_AGENT */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_CORE_H_ */
