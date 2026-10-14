Sample Application
==================

The repository includes a complete demonstration sample located in ``samples/snmp_agent/``.

Overview
--------

The sample application demonstrates:

- Initialization and lifecycle management of an SNMP agent instance using ``snmp_agent_init()`` and ``snmp_agent_start()``.
- Automated network configuration via DHCPv4 and network link event monitoring.
- Standard MIB-II network group registration using ``snmp_mib2_register_all()`` (system, snmp, ifTable, ip, icmp, tcp, udp).
- Custom enterprise MIB registration under the private enterprise subtree (``1.3.6.1.4.1.54321.1``):

  - LED state control with Two-Phase Commit (2PC) SET transactional handlers.
  - Button state monitoring and interrupt-driven event capture.
  - Multi-type sensor telemetry reporting (scalars and dynamic table).

- Asynchronous SNMP trap notifications triggered by hardware interrupt events (button push on ``sw0``).

Verified SMIv2 Tree Structure
-----------------------------

The private enterprise MIB (defined formally in ``NUCLEO-H743-MIB.txt``) is rooted at Enterprise ID ``54321`` under ``1.3.6.1.4.1.54321.1`` (``nucleoH743``):

Scalar Objects (``device 1``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- ``.1.1.1.0`` (``sensorValue.0``): ``Integer32`` - Simulated ambient temperature in degrees Celsius (RO/RW via 2PC SET).
- ``.1.1.2.0`` (``ledState.0``): ``Integer32 (0..1)`` - Physical User LED (``led0``) status (0 = OFF, 1 = ON) with hardware feedback.
- ``.1.1.3.0`` (``buttonCounter.0``): ``Counter32`` - Monotonic counter tracking physical User Button (``sw0``) presses.
- ``.1.1.4.0`` (``sensorHumidity.0``): ``Gauge32 (0..100)`` - Simulated relative humidity percentage.
- ``.1.1.5.0`` (``sensorDescription.0``): ``DisplayString (SIZE (0..64))`` - Descriptive node identification string.
- ``.1.1.6.0`` (``sensorStatusOid.0``): ``OBJECT IDENTIFIER`` - Dynamic pointer OID referencing ``sensorValue.0``.

Notifications (``notifications 2``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- ``.1.2.1`` (``buttonPressed``): ``NOTIFICATION-TYPE`` emitted upon hardware button presses, containing varbinds ``buttonCounter.0`` and ``ledState.0``.

Dynamic Table (``sensorTable 3``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- ``.1.3.1`` (``sensorTable``): Multidimensional table indexed by ``sensorIndex`` (1..3):

  - Column 1 (``.1.3.1.1.<idx>``): ``sensorIndex`` (``Integer32``)
  - Column 2 (``.1.3.1.2.<idx>``): ``sensorName`` (``DisplayString``)
  - Column 3 (``.1.3.1.3.<idx>``): ``sensorVal`` (``Integer32``)

Building the Sample
-------------------

For simulated testing in QEMU:

.. code-block:: bash

   source ~/zephyrproject/zephyr/zephyr-env.sh
   west build -p always -b qemu_x86 samples/snmp_agent

For native simulation (64-bit POSIX host):

.. code-block:: bash

   west build -p always -b native_sim/native/64 samples/snmp_agent

For physical hardware targets (e.g. ST NUCLEO-H743ZI / H753ZI):

.. code-block:: bash

   west build -p always -b nucleo_h743zi samples/snmp_agent
   west flash

Verification Commands (Net-SNMP)
--------------------------------

Reading Scalar Variables
^^^^^^^^^^^^^^^^^^^^^^^^

Using formal MIB symbol names:

.. code-block:: bash

   snmpget -v2c -c public -m ./samples/snmp_agent/NUCLEO-H743-MIB.txt <TARGET_IP> \
     sensorValue.0 ledState.0 buttonCounter.0 sensorHumidity.0 sensorDescription.0 sensorStatusOid.0

Using direct numeric SMIv2 OIDs:

.. code-block:: bash

   snmpget -v2c -c public <TARGET_IP> \
     1.3.6.1.4.1.54321.1.1.1.0 \
     1.3.6.1.4.1.54321.1.1.2.0 \
     1.3.6.1.4.1.54321.1.1.3.0 \
     1.3.6.1.4.1.54321.1.1.4.0 \
     1.3.6.1.4.1.54321.1.1.5.0 \
     1.3.6.1.4.1.54321.1.1.6.0

Controlling Hardware Actuators (2PC SET)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Turn ON User LED (requires write community ``private``):

.. code-block:: bash

   snmpset -v2c -c private -m ./samples/snmp_agent/NUCLEO-H743-MIB.txt <TARGET_IP> ledState.0 i 1

Turn OFF User LED:

.. code-block:: bash

   snmpset -v2c -c private -m ./samples/snmp_agent/NUCLEO-H743-MIB.txt <TARGET_IP> ledState.0 i 0

Inspecting Multidimensional Table
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Tabular format query:

.. code-block:: bash

   snmptable -v2c -c public -m ./samples/snmp_agent/NUCLEO-H743-MIB.txt <TARGET_IP> sensorTable

GETBULK multi-repetition query:

.. code-block:: bash

   snmpbulkget -v2c -c public -Cn0 -Cr9 <TARGET_IP> 1.3.6.1.4.1.54321.1.3.1

Interactive UART Shell Commands
-------------------------------

When connected via serial terminal (115200 baud, 8N1), the built-in shell exposes diagnostic and simulation commands:

- ``app sensor``: Displays current sensor readings and actuator states.
- ``app led [0|1]``: Queries or actively toggles the onboard green user LED.
- ``app button``: Simulates a user button press event, increments the press counter, and triggers an SNMP notification.
- ``net iface``: Displays network interface parameters, MAC address, and active IP settings.

Trap Configuration & Host Setup
-------------------------------

The agent emits SNMPv2-Trap UDP datagrams toward ``CONFIG_SNMP_SAMPLE_TRAP_DEST`` on port 162 (or 1162).

Host Reception via ``snmptrapd`` (Option A)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. Allow UDP trap traffic through the firewall:

   .. code-block:: bash

      sudo ufw allow 162/udp

2. Authorize reception in ``/etc/snmp/snmptrapd.conf``:

   .. code-block:: text

      authCommunity log,execute,net public

3. Run ``snmptrapd`` in foreground:

   .. code-block:: bash

      sudo snmptrapd -f -Lo -C -c /etc/snmp/snmptrapd.conf -m ./samples/snmp_agent/NUCLEO-H743-MIB.txt

Non-Root Capture via Python / tcpdump (Option B)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Capture raw packets with ``tcpdump``:

.. code-block:: bash

   sudo tcpdump -i any -nn -vv -X udp port 162

Or use a Python UDP socket listener on port 1162 (when configured with ``CONFIG_SNMP_TRAP_PORT=1162``).
