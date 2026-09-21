/*
 * Copyright (c) 2026 Zephyr SNMP Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef APP_MIB_H_
#define APP_MIB_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize and register the Private MIB for the sample:
 *        1.3.6.1.4.1.<enterprise>.1 (nucleoH743)
 *        - device (1)
 *          - sensorValue (1.0)
 *          - ledState (2.0)
 *          - buttonCounter (3.0)
 *          - sensorHumidity (4.0)
 *          - sensorDescription (5.0)
 *          - sensorStatusOid (6.0)
 *        - sensorTable (3)
 * @return 0 on success, negative errno on failure.
 */
int app_mib_init(void);

#ifdef __cplusplus
}
#endif

#endif /* APP_MIB_H_ */
