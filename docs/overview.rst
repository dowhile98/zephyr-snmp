Overview
========

The **zephyr-dgus** module provides a Zephyr RTOS out-of-tree driver for DWIN DGUS II smart displays (T5L ASIC family) communicating over UART.

Key Features
------------

- **Multi-Instance Support**: Defined declaratively via Devicetree (``dwin,dgus2``).
- **Layered Architecture**:
  - **Protocol Layer**: Pure C99, hardware-agnostic frame assembler, CRC-16 Modbus engine, and byte-by-byte Finite State Machine (FSM) parser.
  - **Core Driver Layer**: Concurrency management, synchronous request/response polling with timeouts, asynchronous VP event subscriptions (touch controls), and diagnostic telemetry.
  - **HAL Adapter Layer**: Zephyr UART abstraction using interrupt-driven transfers (``CONFIG_UART_INTERRUPT_DRIVEN``), ring buffers, and worker thread offloading.
- **Thread Safety**: Mutexes (``k_mutex``) protect serial access; semaphores (``k_sem``) handle request/response handshakes.
- **Protocol Support**:
  - Variable Pointer (VP) read/write for 16-bit, 32-bit (signed and unsigned integers), strings, and raw payloads.
  - Page switching (``0x5A01`` magic code) and active page querying.
  - Real-time trend curves via Command 0x84.
  - Backlight brightness regulation and buzzer duration pulsing.

Architecture Diagram
--------------------

.. code-block:: text

   +-----------------------------------------------------------+
   |                     Application / Sample                  |
   +-----------------------------------------------------------+
                               |
                               v
   +-----------------------------------------------------------+
   |                 Core Driver (dgus2_core.c)                |
   |   - Thread-safe TX / Synchronous RX with Timeout          |
   |   - Asynchronous Subscriber Table (Touch events)          |
   |   - High-level VP Helpers (u16, u32, i16, i32, str, curve)|
   +-----------------------------+-----------------------------+
                                 |
                                 v
   +-----------------------------------------------------------+
   |               Protocol Layer (dgus2_protocol.c)           |
   |   - C99 Frame Builder (0x80, 0x81, 0x82, 0x83, 0x84)      |
   |   - Non-blocking Byte-by-Byte FSM Parser                  |
   |   - CRC-16 Modbus Engine                                  |
   +-----------------------------+-----------------------------+
                                 |
                                 v
   +-----------------------------------------------------------+
   |                 HAL Adapter (dgus2_hal.c)                 |
   |   - Zephyr UART Device API (CONFIG_UART_INTERRUPT_DRIVEN)  |
   |   - Lockless Ring Buffer & Worker RX Thread               |
   +-----------------------------------------------------------+
