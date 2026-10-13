# zephyr-dgus — DWIN DGUS II Smart Display Driver for Zephyr RTOS {#mainpage}

Welcome to the API and architecture reference documentation for the **zephyr-dgus** out-of-tree module.

## Overview

The `zephyr-dgus` driver provides a robust, multi-instance, production-ready interface for DWIN DGUS II smart displays (based on the T5L ASIC family) communicating over UART in Zephyr RTOS applications.

Key features:
- **Multi-Instance Support**: Defined declaratively via Devicetree (`dwin,dgus2` compatible).
- **Three-Tier Architecture**:
  1. **Protocol Layer (`dgus2_protocol.c / .h`)**: Pure C99, hardware-agnostic frame assembler, CRC-16 Modbus engine, and byte-by-byte Finite State Machine (FSM) parser. Fully testable without physical hardware.
  2. **Core Driver Layer (`dgus2_core.c / .h`)**: Thread-safe transaction management, synchronous request/response polling with timeouts, asynchronous VP event subscriptions (touch controls), and diagnostic telemetry.
  3. **HAL Adapter Layer (`dgus2_hal.c / .h`)**: Zephyr UART abstraction using interrupt-driven transfers (`CONFIG_UART_INTERRUPT_DRIVEN`), ring buffers, and worker thread offloading.
- **Concurrency & Thread Safety**: Uses Zephyr mutexes (`k_mutex`) and semaphores (`k_sem`) to protect serial bus access and route incoming events without blocking ISRs.
- **Rich Protocol Capabilities**:
  - Variable Pointer (VP) read/write for 16-bit, 32-bit (signed and unsigned integers), strings, and raw payloads.
  - Page switching (`0x5A01` magic handshake) and active page querying.
  - Real-time trend curves via Command 0x84.
  - Backlight brightness regulation and buzzer duration pulsing.

## Devicetree Integration

Displays are declared as child nodes of UART peripherals or bus controllers:

```dts
&usart2 {
    status = "okay";
    current-speed = <115200>;

    dgus0: dgus-display@0 {
        compatible = "dwin,dgus2";
        status = "okay";
        rx-buf-size = <256>;
        tx-timeout-ms = <100>;
    };
};
```

Driver instances are acquired using standard Zephyr macros:
```c
const struct device *dgus_dev = DEVICE_DT_GET(DT_NODELABEL(dgus0));
```

## Threading and Concurrency Model

1. **Interrupt Service Routine (ISR)**: The UART ISR collects incoming bytes into a lockless ring buffer (`ring_buf`). Delays and allocations are strictly prohibited in this context.
2. **RX Worker Thread**: A dedicated driver thread (`K_THREAD_DEFINE`) empties the ring buffer, feeds bytes into the FSM parser, and dispatches frames:
   - Synchronous read responses release waiting callers via `k_sem_give(&data->sync_sem)`.
   - Asynchronous touch/VP events are dispatched to registered callbacks under `sub_mutex` protection.
3. **Application Threads**: API calls write to the bus under a mutual exclusion lock (`tx_mutex`).
