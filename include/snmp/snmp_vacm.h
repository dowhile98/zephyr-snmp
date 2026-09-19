/*
 * Copyright (c) 2026 DAECGE
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_VACM_H_
#define ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_VACM_H_

#include <zephyr/kernel.h>
#include <snmp/snmp_ber.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CONFIG_SNMP_AGENT) && defined(CONFIG_SNMP_VERSION_3)

/**
 * @brief Initialize VACM with default admin/readonly groups.
 */
int snmp_vacm_init(void);

/**
 * @brief Check if the user in this v3 message is authorized for the requested access.
 *
 * @param msg  Decoded v3 message (user_name extracted from msg->usm).
 * @param is_write  true for SET requests, false for GET/GETNEXT/GETBULK.
 * @return 0 if authorized, -EACCES if denied.
 */
int snmp_vacm_check_access(const struct snmp_v3_msg *msg, bool is_write);

/**
 * @brief Add a user to group mapping at runtime in VACM.
 *
 * @param user_name User name string.
 * @param group_name Group name string ("admin" or "readonly").
 * @return 0 on success, negative errno on failure.
 */
int snmp_vacm_add_user(const char *user_name, const char *group_name);

#endif /* CONFIG_SNMP_AGENT && CONFIG_SNMP_VERSION_3 */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_MODULES_SNMP_INCLUDE_SNMP_VACM_H_ */
