Sample Application
==================

The repository includes a complete demonstration sample located in ``samples/dwin-interface/``.

Overview
--------

The sample application demonstrates:
- Initialization and acquisition of a DGUS II device instance from Devicetree.
- Writing 16-bit and 32-bit values to display Variable Pointers (VP).
- Writing text strings to display labels.
- Switching active pages and querying the current page.
- Modifying backlight brightness and triggering the internal buzzer.
- Subscribing to touch button events via asynchronous VP callbacks.
- Plotting real-time trend curve points using Command 0x84.

Building the Sample
-------------------

For simulated testing on host with native_sim:

.. code-block:: bash

   west build -b native_sim samples/dwin-interface/

For physical target boards:

.. code-block:: bash

   # STM32F4-Discovery
   west build -b stm32f4_disco samples/dwin-interface/

   # Nucleo F429ZI
   west build -b nucleo_f429zi samples/dwin-interface/

   # Nucleo H753ZI
   west build -b nucleo_h753zi samples/dwin-interface/
