# Guía de Depuración y Resolución de Problemas (Troubleshooting)

Este documento recopila los problemas comunes observados durante el desarrollo y despliegue del agente SNMP en Zephyr RTOS, junto con sus causas raíz y soluciones definitivas.

---

## 1. Problemas de Comunicación y Timeouts

### Síntoma: `Timeout: No Response from <IP>`

```text
$ snmpget -v2c -c public 192.168.16.100 1.3.6.1.2.1.1.1.0
Timeout: No Response from 192.168.16.100
```

#### Causas y Diagnóstico:
1. **Comunidad Incorrecta (Silent Drop)**:
   - Según RFC 1213 y RFC 3416, si una solicitud SNMP entrante contiene una comunidad que no coincide con `CONFIG_SNMP_COMMUNITY_READ` o `CONFIG_SNMP_COMMUNITY_WRITE`, el agente **no debe enviar un mensaje de error**, sino descartar el datagrama silenciosamente e incrementar `snmpInBadCommunityNames`.
   - **Solución**: Verifique que el parámetro `-c` coincida con la configuración en `prj.conf`.
2. **Enlace Ethernet Físico Caído (LINK DOWN)**:
   - Si el cable Ethernet no está conectado o el switch no negoció el enlace, el controlador MII no procesará tramas.
   - **Diagnóstico en consola serial**:
     ```text
     <inf> snmp_sample: Ethernet Carrier  : LINK DOWN (check Ethernet cable)
     ```
   - **Solución**: Conecte el cable a un switch/router y verifique que aparezca en el log:
     ```text
     <inf> phy_mii: PHY (0) Link speed 100 Mb, full duplex
     ```
3. **Dirección IP no Asignada o Desfasada**:
   - Si el agente espera DHCP pero el servidor no responde, usará la IP estática configurada en `CONFIG_NET_CONFIG_MY_IPV4_ADDR` (por defecto `192.0.2.1`).
   - **Diagnóstico en Zephyr Shell**:
     ```text
     uart:~$ net iface
     ```
     Verifique en la salida la dirección `IPv4 unicast addresses`.
4. **Colisión en `net_socket_service` (Bug Histórico Resuelto)**:
   - Si se activa IPv6 junto con IPv4, una versión antigua de `snmp_service.c` sobrescribía el slot de sondeo de IPv4.
   - **Solución**: Asegúrese de contar con la versión corregida de `src/snmp_service.c` donde `SNMP_SVC_SOCKET_COUNT` se dimensiona adecuadamente.

---

## 2. Errores Fatales de Zephyr (Kernel Panics)

### Síntoma: `ZEPHYR FATAL ERROR 2: Stack overflow`

```text
[00:00:01.810,000] <err> os: ***** STACK OVERFLOW *****
[00:00:01.810,000] <err> os: Current thread: 0x20000840 (net_mgmt)
[00:00:01.810,000] <err> os: Faulting instruction at 0x08012a4c
[00:00:01.810,000] <err> os: Fatal fault in ISR! Jumping to fatal handler
```

#### Causa Raíz:
El hilo de eventos de gestión de red (`net_mgmt`) se crea por defecto con un stack reducido (768 o 1024 bytes). Si dentro del callback `net_event_handler` se ejecutan funciones complejas como formateo de logs extensos (`LOG_INF`) o envío de trampas UDP (`snmp_trap_send`), el stack se desborda inmediatamente.

#### Solución:
1. Incrementar el stack en `prj.conf`:
   ```ini
   CONFIG_NET_MGMT_EVENT_STACK_SIZE=2048
   ```
2. **Mejor Práctica de Diseño**: No ejecutar lógica de red dentro del callback de eventos. Utilice un semáforo (`k_sem_give(&s_ip_ready_sem)`) y despache las tareas en el contexto del hilo principal (`main()`).

---

### Síntoma: Fallo de Memoria / HardFault con Logging Diferido

#### Causa Raíz:
Con el modo de logging diferido (`CONFIG_LOG_MODE_DEFERRED=y`), los punteros a cadenas temporales en el stack pueden ser invalidados antes de que el hilo de log los procese.

#### Solución:
En `prj.conf`, activar el modo de log inmediato para desarrollo y depuración:
```ini
CONFIG_LOG=y
CONFIG_LOG_MODE_IMMEDIATE=y
```

---

## 3. Errores SNMP Comunes y su Significado

| Error Devuelto por el Gestor | Causa Raíz | Solución |
| :--- | :--- | :--- |
| `Reason: (noSuchName)` / `No Such Instance` | Se consultó un escalar sin el subidentificador `.0` (ej: `1.3.6.1.4.1.54321.1.1.1` en vez de `.1.1.1.0`). | Agregar siempre `.0` al final de cualquier OID escalar. |
| `Reason: (badValue)` / `Value out of range` | En una operación SET, el valor numérico está fuera del rango permitido o el tipo ASN.1 no concuerda. | Verificar el tipo de dato (`i` para Integer, `s` para String, `u` para Gauge32) y que respete las cotas del callback `set_cb`. |
| `Reason: (notWritable)` | Se intentó realizar un SET sobre un objeto registrado con `set_cb = NULL` (solo lectura). | Configurar `set_cb` válido si el objeto debe ser modificable. |

---

## 4. Captura de Trampas en el Host sin Privilegios de Root

En sistemas Linux, los puertos UDP inferiores a 1024 (como el puerto estándar de traps 162) requieren privilegios de superusuario (`sudo`).

Si no dispone de permisos de root o desea evitar ejecutar servicios como root:
1. Configure el puerto de destino en `prj.conf`:
   ```ini
   CONFIG_SNMP_TRAP_PORT=1162
   ```
2. Ejecute un receptor ligero en Python en el host para verificar las trampas en tiempo real:

```python
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 1162))
print("Esperando Traps SNMP en UDP :1162...")

while True:
    data, addr = sock.recvfrom(2048)
    print(f"Trap recibido ({len(data)} bytes) desde {addr}")
    print(f"Hex: {data.hex()}\n")
```
