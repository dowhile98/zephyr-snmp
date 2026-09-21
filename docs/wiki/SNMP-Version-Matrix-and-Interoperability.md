# Matriz de Versiones SNMP y Auditoría de Interoperabilidad

Este documento establece la comparativa técnica formal entre las tres versiones del protocolo (**SNMPv1**, **SNMPv2c** y **SNMPv3**), documentando con total transparencia qué características están completamente operativas en producción y cuáles presentan limitaciones o desviaciones de estándar en la implementación actual.

---

## 1. Matriz Comparativa Exhaustiva

| Característica / Protocolo | SNMPv1 (RFC 1157) | SNMPv2c (RFC 3416) | SNMPv3 (RFC 3412 / 3414) | Estado en la Librería Actual |
| :--- | :---: | :---: | :---: | :--- |
| **Modelo de Seguridad** | Comunidad en texto plano | Comunidad en texto plano | Basado en Usuarios (USM) | v1/v2c 100% operativos. v3 requiere ajustes en derivación de claves. |
| **PDU: GetRequest** | Soportado | Soportado | Parcial | Funcional en v1/v2c. En v3 responde report PDU si engine discovery. |
| **PDU: GetNextRequest** | Soportado | Soportado | Parcial | Totalmente funcional para recorridos (`snmpwalk`) en v1/v2c. |
| **PDU: GetBulkRequest** | No soportado por RFC | Soportado | Parcial | Operativo en v2c (`snmpbulkget`, `snmpbulkwalk`, `snmptable`). |
| **PDU: SetRequest** | Soportado | Soportado | Parcial | Valida comunidad de escritura, tipos ASN.1 y rangos en v1/v2c. |
| **PDU: Trap** | TRAPv1 (RFC 1157) | SNMPv2-Trap (RFC 3418) | Trapv3 / Inform | Trampas v1 y v2c verificadas sobre la red y decodificadas con éxito. |
| **PDU: InformRequest** | No soportado por RFC | Soportado | Soportado | Envía acuse de recibo en v2c. |
| **Manejo de Tablas** | GETNEXT | GETBULK / GETNEXT | GETBULK / GETNEXT | Tablas multi-columna operativas y alineadas con MIBs SMIv2. |
| **Cifrado (Privacidad)** | Inexistente en RFC | Inexistente en RFC | AES-128-CFB / DES-CBC | Primitivas PSA Crypto (mbedtls) presentes en código. |
| **Control de Acceso** | Filtro binario de comunidad | Filtro binario de comunidad | VACM (RFC 3415) | Implementado en `src/snmp_vacm.c`. |
| **Descubrimiento de Motor**| N/A | N/A | Soportado | Genera Report PDU con `snmpUnknownEngineIDs` y `usmStatsUnknownEngineIDs`. |

---

## 2. Auditoría Técnica de SNMPv3 (Sin Simulaciones)

De acuerdo a la directriz de integridad técnica, no se simula soporte donde no existe total conformidad con el RFC. A continuación se desglosa el estado exacto del código de `src/snmp_usm.c`:

### A. Divergencia en Algoritmo Password-to-Key (RFC 3414 Apéndice A.2.1)
* **Requisito RFC 3414**:
  El estándar define que la contraseña de texto plano se expande cíclicamente hasta completar un búfer lineal de **1 Megabyte** (1,048,576 octetos). Dicho búfer se alimenta mediante streaming a una **única instancia** de función hash (SHA-1 o MD5) procesada en bloques de 64 bytes (16,384 actualizaciones).
* **Implementación Actual (`src/snmp_usm.c`, líneas 99-106)**:
  ```c
  for (uint32_t i = 0; i < 1000000; i++) {
      memcpy(tmp, ku, hash_size);
      memcpy(tmp + hash_size, password, pw_len);
      status = psa_hash_compute(hash_alg, tmp, hash_size + pw_len, ku, ku_sz, ku_len);
      if (status != PSA_SUCCESS) return -EIO;
  }
  ```
  **Impacto**:
  1. Ejecuta 1,000,000 de operaciones completas de hashing independientes en bucle. En un microcontrolador Cortex-M7 a 480 MHz, esto consume aproximadamente **8 a 12 segundos de CPU ininterrumpida**, causando timeouts en cualquier gestor NMS comercial.
  2. El resultado matemático del hash digest difiere del vector de prueba oficial del RFC 3414, imposibilitando que clientes estándar como Net-SNMP calculen la misma clave maestra ($K_u$).

### B. Divergencia en Derivación de Clave Localizada (RFC 3414 Apéndice A.2.2)
* **Requisito RFC 3414**:
  La clave localizada para un agente específico ($K_{ul}$) se calcula concatenando la clave maestra ($K_u$), el `snmpEngineID` y la clave maestra nuevamente, aplicándoles una sola pasada de hash:
  $$K_{ul} = \text{Hash}(K_u \parallel \text{snmpEngineID} \parallel K_u)$$
* **Implementación Actual (`src/snmp_usm.c`, líneas 131-140)**:
  Ejecuta una función HMAC personalizada sobre el `engine_id` y mezcla constantes arbitrarias (`auth_const = {0x01, 'a', 'u', 't', 'h', ...}`).
* **Impacto**:
  La clave derivada no coincide con la calculada por herramientas estándar de gestión (Net-SNMP, Wireshark, iReasoning).

### C. Módulos SNMPv3 que Funcionan Correctamente
* **Motor de Descubrimiento (Engine Discovery)**: Responde adecuadamente a peticiones vacías con `snmpUnknownEngineIDs` y el `contextEngineID` del nodo.
* **Modelo VACM (`src/snmp_vacm.c`)**: Estructura de vistas y niveles de seguridad (noAuthNoPriv, authNoPriv, authPriv) correctamente modelada.

> [!TIP]
> **Plan de Acción para Compatibilidad Total con SNMPv3**:
> 1. Modificar `usm_password_to_key` para utilizar `psa_hash_setup`, `psa_hash_update` iterando hasta 1,048,576 bytes en bloques de 64 bytes, y un solo `psa_hash_finish`.
> 2. Reemplazar `usm_key_localize` por el cálculo estricto $\text{Hash}(K_u \parallel \text{engineID} \parallel K_u)$.

---

## 3. Guía de Interoperabilidad con Clientes Estándar

### A. Net-SNMP (Linux / macOS)

```bash
# SNMPv1
snmpget -v1 -c public <TARGET_IP> 1.3.6.1.4.1.54321.1.1.1.0
snmpwalk -v1 -c public <TARGET_IP> 1.3.6.1.4.1.54321.1

# SNMPv2c
snmpget -v2c -c public -m ./NUCLEO-H743-MIB.txt <TARGET_IP> sensorValue.0 ledState.0
snmpset -v2c -c private -m ./NUCLEO-H743-MIB.txt <TARGET_IP> ledState.0 i 1
snmpbulkget -v2c -c public -m ./NUCLEO-H743-MIB.txt -Cn0 -Cr9 <TARGET_IP> sensorTable
snmptable -v2c -c public -m ./NUCLEO-H743-MIB.txt <TARGET_IP> sensorTable
```

### B. iReasoning MIB Browser (GUI)
1. Abrir iReasoning MIB Browser.
2. Ir a **File -> Load MIBs** y seleccionar `NUCLEO-H743-MIB.txt`.
3. Configurar **Address**: Dirección IP de la placa (ej. `192.168.16.100`).
4. Configurar **Read Community**: `public`, **Write Community**: `private`.
5. Seleccionar **SNMP Version**: `2c`.
6. En el árbol izquierdo, expandir `iso -> org -> dod -> internet -> private -> enterprises -> nucleoH743`.
7. Hacer clic derecho sobre `sensorTable` y seleccionar **View Table**.

### C. Captura y Análisis en Wireshark
Para inspeccionar el tráfico en Wireshark:
1. Filtro de captura: `udp port 161 or udp port 1162`.
2. En Wireshark, el protocolo se identifica automáticamente como **SNMP**.
3. En el árbol de disección del paquete se pueden inspeccionar los varbinds, el Request-ID, y la estructura ASN.1 BER completa.
