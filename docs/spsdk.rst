.. SPSDK links definition block

.. NXP Devices location

.. _LPC55S6x_link: https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/general-purpose-mcus/lpc5500-cortex-m33/high-efficiency-arm-cortex-m33-based-microcontroller-family:LPC55S6x
.. _LPC55S3x_link: https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/general-purpose-mcus/lpc5500-cortex-m33:LPC5500_SERIES
.. _LPC55S2x_link: https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/general-purpose-mcus/lpc5500-cortex-m33/lpc552x-s2x-mainstream-arm-cortex-m33-based-microcontroller-family:LPC552x-S2x
.. _LPC55S1x_link: https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/general-purpose-mcus/lpc5500-cortex-m33/lpc551x-s1x-baseline-arm-cortex-m33-based-microcontroller-family:LPC551X-S1X
.. _LPC55S0x_link: https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/general-purpose-mcus/lpc5500-cortex-m33/lpc550x-s0x-baseline-arm-cortex-m33-based-microcontroller-family:LPC550x
.. _RT1160_link: https://www.nxp.com/design/development-boards/i-mx-evaluation-and-development-boards/mimxrt1060-evk-i-mx-rt1060-evaluation-kit:MIMXRT1060-EVK
.. _RT1170_link: https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1170-crossover-mcu-family-first-ghz-mcu-with-arm-cortex-m7-and-cortex-m4-cores:i.MX-RT1170
.. _RT1060_link: https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1060-crossover-mcu-with-arm-cortex-m7-core:i.MX-RT1060
.. _RT1050_link: https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1050-crossover-mcu-with-arm-cortex-m7-core:i.MX-RT1050
.. _RT1020_link: https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1020-crossover-mcu-with-arm-cortex-m7-core:i.MX-RT1020
.. _RT1010_link: https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1010-crossover-mcu-with-arm-cortex-m7-core:i.MX-RT1010
.. _RT600_link: https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt600-crossover-mcu-with-arm-cortex-m33-and-dsp-cores:i.MX-RT600
.. _RT500_link: https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt500-crossover-mcu-with-arm-cortex-m33-core:i.MX-RT500

.. Project location

.. _github_loc: https://github.com/NXPmicro/spsdk
.. _pypi_loc: https://pypi.org/project/spsdk/

.. Start of SPSDK document

============
Introduction
============

**Secure Provisioning SDK (SPSDK)** is a unified, reliable, and easy to use Python SDK library working across the NXP MCU portfolio providing a strong foundation from quick customer prototyping up to production deployment.

The library allows the user to connect and communicate with the device, configure the device, prepare, download, and upload data including security operations.

It is delivered in a form of:

- :ref:`Applications` - applications which could be called from command-line using Python virtual environment,
- :ref:`APIs` - functions in form of Python library.

.. figure:: _static/images/spsdk-architecture.png
    :align: center
    :scale: 40 %

========
Delivery
========

*SPSDK* is delivered to:

- `GitHub <github_loc_>`__
- `PyPI <pypi_loc_>`__

============
Organization
============

*SPSDK* is organized in following directory structure:

.. figure:: _static/images/spsdk-structure.png
    :align: center
    :scale: 50 %

=================
Supported Devices
=================

- LPC55 `S6x <LPC55S6x_link_>`__ / `S3x <LPC55S3x_link_>`__ / `S2x <LPC55S2x_link_>`__ / `S1x <LPC55S1x_link_>`__ / `S0x <LPC55S0x_link_>`__
- i.MX RT `600 <RT600_link_>`__ / `500 <RT500_link_>`__
- i.MX RT `1060 <RT1060_link_>`__ / `1050 <RT1050_link_>`__ / `1020 <RT1020_link_>`__ / `1010 <RT1010_link_>`__
- i.Mx RT `1170 <RT1170_link_>`__ / `1160 <RT1160_link_>`__ (blhost)

============
Supported OS
============

- Windows 10, 64-bit
- Ubuntu 18.04 or above, 64-bit
- Mac OS 10.15 or above, x64, ARM64

=====================
Supported Environment
=====================

SPSDK is tested on *Python 3.6+* interpreter, old version 2.x is not supported.

