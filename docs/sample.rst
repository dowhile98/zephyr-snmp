Sample Application
==================

The repository includes a complete demonstration sample located in ``samples/snmp_agent/``.

Overview
--------

The sample application demonstrates:

- Initialization and lifecycle management of an SNMP agent instance using ``snmp_agent_init()`` and ``snmp_agent_start()``.
- Automated network configuration via DHCPv4 and network link event monitoring.
- Standard MIB-II network group registration using ``snmp_mib2_register_all()`` (system, snmp, ifTable, ip, icmp, tcp, udp).
- Custom enterprise MIB registration under the private enterprise subtree (``1.3.6.1.4.1.59999``):

  - LED state control with Two-Phase Commit (2PC) SET transactional handlers.
  - Button state monitoring.
  - Sensor telemetry reporting.

- Asynchronous SNMP trap notifications triggered by hardware interrupt events (button push).

Building the Sample
-------------------

For simulated testing in QEMU:

.. code-block:: bash

   # Remember to set PATH and ZEPHYR_BASE if west is in a venv
   source ~/zephyrproject/zephyr/zephyr-env.sh
   west build -p always -b qemu_x86 samples/snmp_agent

For native simulation (64-bit POSIX host):

.. code-block:: bash

   west build -p always -b native_sim/native/64 samples/snmp_agent

For physical hardware targets (e.g. ST Nucleo-H743ZI):

.. code-block:: bash

   west build -p always -b nucleo_h743zi samples/snmp_agent
