# SNMP Validation Sample Application (NUCLEO-H743ZI)

Este sample proporciona una implementación de referencia completa, modular y verificada en hardware para el agente SNMP de **Zephyr RTOS**.

Diseñado para la placa de evaluación **ST NUCLEO-H743ZI** con interfaz Ethernet RMII a 100 Mbps, este proyecto valida de manera práctica y sistemática todas las capacidades operativas de **SNMPv1 y SNMPv2c**, el manejo de periféricos físicos reales (LED y Pulsador), la simulación de telemetría multi-tipo, el uso de tablas dinámicas multidimensionales, y el despacho asíncrono de notificaciones (**Traps / Informs**).

---

## 📋 Características Demostradas

- **Protocolos SNMP**:
  - **SNMPv1** (RFC 1157): GET, GETNEXT, SET, y TRAP-v1.
  - **SNMPv2c** (RFC 3416): GET, GETNEXT, GETBULK (`snmpbulkget`, `snmpbulkwalk`), SET, y SNMPv2-Trap.
- **MIB-II Estándar** (RFC 1213 / RFC 3418):
  - Consulta de grupos `system` (`sysDescr`, `sysObjectID`, `sysUpTime`, `sysContact`, `sysName`, `sysLocation`) y contadores de tráfico `snmp`.
- **MIB Privada Empresarial** (`1.3.6.1.4.1.54321.1`):
  - Integración con el archivo de definición formal [NUCLEO-H743-MIB.txt](file:///media/jeffry/jqb/GitHub/zephyr-snmp/samples/snmp_agent/NUCLEO-H743-MIB.txt).
  - Escalares con diversos tipos de datos ASN.1: `INTEGER`, `Gauge32`, `Counter32`, `OCTET STRING`, y `OBJECT IDENTIFIER`.
  - Tabla de sensores multidimensional (`sensorTable`) con 3 columnas e indexación dinámica.
- **Integración con Periféricos Físicos de Zephyr**:
  - **Actuador (User LED `led0`)**: Control bidireccional mediante SNMP SET/GET con verificación visual física.
  - **Sensor de Eventos (User Button `sw0`)**: Interrupción GPIO con filtro de rebote por software (debounce) que delega a un hilo de `k_work` para despachar Traps de red sin bloquear la ISR.
- **Consola Interactiva Shell**:
  - Comandos integrados en terminal UART para inspección y simulación (`app led`, `app button`, `app sensor`).

---

## 🗂️ Arquitectura Modular del Sample

```
samples/snmp_agent/
├── CMakeLists.txt              # Fuentes y configuración de compilación de Zephyr
├── Kconfig                     # Opciones declarativas del sample
├── prj.conf                    # Configuración de red, stacks, logging y SNMP
├── NUCLEO-H743-MIB.txt          # Archivo formal de la MIB en formato SMIv2
├── README.md                   # Este manual exhaustivo
└── src/
    ├── app_led.h / .c          # Driver del LED de usuario (DeviceTree led0)
    ├── app_button.h / .c       # Driver de pulsador (sw0) + Debounce + Trap Dispatcher
    ├── app_sensor.h / .c       # Motor de telemetría simulada (escalares y tabla)
    ├── app_mib.h / .c          # Registro de nodos MIB y callbacks de lectura/escritura
    └── main.c                  # Sincronización DHCP, banner y consola interactiva
```

---

## ⚙️ Opciones de Configuración Kconfig

Todas las características pueden ajustarse en tiempo de compilación o mediante `west build -t menuconfig`:

### Parámetros de Red y Protocolo (`prj.conf`)

| Opción Kconfig | Valor en este Sample | Descripción |
| :--- | :---: | :--- |
| `CONFIG_SNMP_AGENT` | `y` | Habilita el subsistema SNMP completo. |
| `CONFIG_SNMP_AGENT_PORT` | `161` | Puerto UDP de escucha del agente. |
| `CONFIG_SNMP_COMMUNITY_READ` | `"public"` | Comunidad para peticiones de solo lectura (GET/WALK). |
| `CONFIG_SNMP_COMMUNITY_WRITE` | `"private"` | Comunidad requerida para modificaciones (SET). |
| `CONFIG_SNMP_VERSION_1` | `y` | Soporte de peticiones SNMPv1. |
| `CONFIG_SNMP_VERSION_2C` | `y` | Soporte de peticiones SNMPv2c y bulk transfers. |
| `CONFIG_SNMP_TRAP_ENABLED` | `y` | Habilita el motor emisor de Traps. |
| `CONFIG_SNMP_TRAP_PORT` | `1162` | Puerto destino de Traps (1162 para captura sin root en host). |
| `CONFIG_SNMP_TRAP_FORMAT_V2C` | `y` | Formato de trampa según estándar RFC 3416. |

### Parámetros Específicos del Sample

| Opción Kconfig | Valor en este Sample | Descripción |
| :--- | :---: | :--- |
| `CONFIG_SNMP_SAMPLE_ENTERPRISE_ID` | `54321` | ID empresarial bajo `1.3.6.1.4.1.<ID>`. |
| `CONFIG_SNMP_SAMPLE_SENSOR_OBJECT` | `y` | Activa las variables y tabla de telemetría. |
| `CONFIG_SNMP_SAMPLE_LED_OBJECT` | `y` | Activa el nodo de control de LED de hardware. |
| `CONFIG_SNMP_SAMPLE_BUTTON_TRAP` | `y` | Activa la interrupción de botón y despacho de trampas. |
| `CONFIG_SNMP_SAMPLE_TRAP_DEST` | `"192.168.16.101"` | Dirección IP del servidor NMS gestor receptor de Traps. |

---

## 🛠️ Guía de Compilación y Flasheo

### Requisitos Previos
1. Zephyr SDK y entorno virtual de Python activos:
   ```bash
   source ~/zephyrproject/.venv/bin/activate
   export ZEPHYR_BASE=~/zephyrproject/zephyr
   ```
2. Placa **NUCLEO-H743ZI** conectada mediante cable USB (puerto ST-LINK) y cable Ethernet conectado a la misma red de su PC.

### Compilación y Carga en Placa

```bash
# Navegar a la raíz del repositorio
cd /media/jeffry/jqb/GitHub/zephyr-snmp

# Compilar para la placa NUCLEO-H743ZI
west build -p always -b nucleo_h743zi samples/snmp_agent

# Flashear el firmware resultante al microcontrolador
west flash
```

---

## 🖥️ Consola Serial y Comandos Interactivos

Al conectar un emulador de terminal serie (`picocom`, `minicom` o `screen`) a `/dev/ttyACM0` a **115200 baudios (8N1)**, el agente imprimirá su banner de diagnóstico al adquirir IP:

```text
*** Booting Zephyr OS build v4.4.0-15809-g55303e23f59d ***
[00:00:00.059,000] <inf> main: Booting SNMP Validation Sample...
[00:00:00.068,000] <inf> app_led: User LED initialized on gpio@58020400 pin 0
[00:00:00.078,000] <inf> app_sensor: Sensor module initialized (Initial Temp: 25 C, Hum: 55%)
[00:00:00.089,000] <inf> app_button: User Button initialized on gpio@58020800 pin 13 (Interrupt active edge)
[00:00:00.101,000] <inf> app_mib: Private MIB registered under 1.3.6.1.4.1.54321.1 (nucleoH743)
[00:00:00.113,000] <inf> main: Configured SNMP Trap destination: 192.168.16.101 : 1162
[00:00:00.122,000] <inf> main: ================================================================
[00:00:00.134,000] <inf> main:        SNMP VALIDATION SAMPLE ON ZEPHYR RTOS (NUCLEO-H743ZI)    
[00:00:00.145,000] <inf> main: ================================================================
[00:00:00.156,000] <inf> main: Protocol Support:
[00:00:00.163,000] <inf> main:   - SNMPv1  : ENABLED
[00:00:00.171,000] <inf> main:   - SNMPv2c : ENABLED
[00:00:00.179,000] <inf> main:   - SNMPv3  : DISABLED
[00:00:00.186,000] <inf> main: Security & Network:
[00:00:00.194,000] <inf> main:   - Agent IP / Port : 192.168.16.100 : 161
[00:00:00.203,000] <inf> main:   - Read Community  : "public"
[00:00:00.211,000] <inf> main:   - Write Community : "private"
[00:00:00.219,000] <inf> main:   - Trap Destination: 192.168.16.101 : 1162
[00:00:00.384,000] <inf> main: ColdStart Trap dispatched to 192.168.16.101
[00:00:01.752,000] <inf> phy_mii: PHY (0) Link speed 100 Mb, full duplex
uart:~$
```

### Comandos de Shell Disponibles

Escriba en la terminal serie para interactuar:
- `app sensor`: Muestra las lecturas de telemetría internas actuales.
  ```text
  uart:~$ app sensor
  Sensor Readings:
    Temperature : 28 C
    Humidity    : 52 %
    Description : NUCLEO-H743ZI Sensor Node
    Button Count: 3
    LED State   : 1
  ```
- `app led [0|1]`: Lee o conmuta el LED verde de usuario en la placa.
  ```text
  uart:~$ app led 1
  User LED set to: ON (1)
  ```
- `app button`: Simula la pulsación del botón físico `sw0`, incrementa el contador y despacha el Trap SNMP hacia el host.
  ```text
  uart:~$ app button
  Simulating User Button press...
  [00:00:43.085,000] <inf> app_button: SNMP Notification dispatched successfully (buttonCounter=4, ledState=1)
  Button count now: 4
  ```
- `net iface`: Muestra detalles de la interfaz Ethernet, MAC y dirección IP asignada por DHCP.

---

## 🧪 Batería de Validación con Net-SNMP (Comandos Probados)

*(Sustituya `192.168.16.100` por la IP asignada a su placa si difiere)*

### 1. Consulta de Escalares con Nombres Formales de MIB
```bash
snmpget -v2c -c public -m ./NUCLEO-H743-MIB.txt 192.168.16.100 \
  sensorValue.0 ledState.0 buttonCounter.0 sensorHumidity.0 sensorDescription.0 sensorStatusOid.0
```
**Salida esperada:**
```text
NUCLEO-H743-MIB::sensorValue.0 = INTEGER: 28
NUCLEO-H743-MIB::ledState.0 = INTEGER: 0
NUCLEO-H743-MIB::buttonCounter.0 = Counter32: 3
NUCLEO-H743-MIB::sensorHumidity.0 = Gauge32: 52
NUCLEO-H743-MIB::sensorDescription.0 = STRING: NUCLEO-H743ZI Sensor Node
NUCLEO-H743-MIB::sensorStatusOid.0 = OID: NUCLEO-H743-MIB::sensorValue.0
```

### 2. Control del LED Físico mediante SNMP SET
```bash
# Encender LED físico (requiere comunidad 'private')
snmpset -v2c -c private -m ./NUCLEO-H743-MIB.txt 192.168.16.100 ledState.0 i 1

# Apagar LED físico
snmpset -v2c -c private -m ./NUCLEO-H743-MIB.txt 192.168.16.100 ledState.0 i 0
```

### 3. Prueba de Seguridad y Validación de Errores
- **Intento de SET con comunidad no autorizada (`public`):**
  ```bash
  snmpset -v2c -c public -m ./NUCLEO-H743-MIB.txt 192.168.16.100 ledState.0 i 1
  # Salida: Timeout: No Response (descarte silencioso según RFC)
  ```
- **Intento de SET con valor fuera de rango (`99` para booleano `0..1`):**
  ```bash
  snmpset -v2c -c private -m ./NUCLEO-H743-MIB.txt 192.168.16.100 ledState.0 i 99
  # Salida: Error in packet. Reason: (badValue)
  ```

### 4. Consulta de Tabla con Formato Tabular
```bash
snmptable -v2c -c public -m ./NUCLEO-H743-MIB.txt 192.168.16.100 sensorTable
```
**Salida esperada:**
```text
SNMP table: NUCLEO-H743-MIB::sensorTable

 sensorIndex   sensorName sensorVal
           1     CPU Temp        28
           2 Amb Humidity        52
           3 Core Voltage      3300
```

### 5. Transferencia Masiva Eficiente (`snmpbulkget` / `snmpbulkwalk`)
```bash
# Solicitar 9 variables en un solo paquete UDP
snmpbulkget -v2c -c public -m ./NUCLEO-H743-MIB.txt -Cn0 -Cr9 192.168.16.100 sensorTable
```

---

## 📡 Recepción y Verificación de Traps en el Host

El sample envía trampas UDP hacia `CONFIG_SNMP_SAMPLE_TRAP_DEST` en el puerto `CONFIG_SNMP_TRAP_PORT` (`1162`).

Para verificar la llegada de las notificaciones sin requerir privilegios de root en Linux:
1. Cree y ejecute este script en Python en su máquina host:
   ```python
   import socket

   s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   s.bind(('0.0.0.0', 1162))
   print("Receptor de Traps escuchando en UDP :1162...")
   while True:
       data, addr = s.recvfrom(2048)
       print(f"Trap recibido ({len(data)} bytes) desde {addr}")
       print(f"Hex: {data.hex()}\n")
   ```
2. Presione el pulsador azul de la placa (**sw0**) o ejecute `app button` en la consola serial.
3. El paquete recibido contendrá la secuencia ASN.1 con `sysUpTime.0`, `snmpTrapOID.0` (`buttonPressed`), `buttonCounter.0` y `ledState.0`.

---

## 🚀 Guía de Adaptación para Proyectos Reales

Para convertir este sample de validación en su propia aplicación de producción:
1. **Reemplazar `src/app_sensor.c`**: Conecte sus sensores físicos reales (ADC, I2C, SPI o CAN) sustituyendo las variables aleatorias por sus funciones lectoras de hardware.
2. **Personalizar `NUCLEO-H743-MIB.txt`**: Cambie el número de Enterprise `54321` por el número asignado a su organización por IANA y defina sus objetos específicos.
3. **Mantener `app_button.c` y `app_mib.c`**: El esquema de trabajo diferido (`k_work`) y registro tabular implementado en estos archivos es el estándar óptimo y no bloqueante para Zephyr RTOS.
