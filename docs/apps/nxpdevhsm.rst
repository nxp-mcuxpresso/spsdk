======================
User Guide - nxpdevhsm
======================

This user’s guide describes how to interface with the *MCU bootloader* to provisioned chip using *nxpdevhsm* application.

The *nxpdevhsm* application is a command-line utility used on the host computer to use device HSM process to get provisioning SB3.


-------------
Communication
-------------

The *nxpdevhsm* application is using blhost application and all supported communication interfaces that blhost offers(UART, USB, LPCUSBSIO[IC, SPI])

blhost - USB
============

*blhost* could be connected to MCU Bootloader over USB HID.

:ref:`USB device identification in SPSDK`

blhost - UART
=============

*blhost* could be connected to MCU bootloader over UART.

:ref:`UART device identification in SPSDK`

blhost - LPCUSBSIO
==================

LPCUSBSIO - LPC USB Serial I/O(LPCUSBSIO), a firmware built in LPC Link2. The LPCUSBSIO acts as a bus translator, and establishes connection with *blhost* over USB-HID, and the MCU bootloader device over I2C and SPI.


.. note:: For more information about supported communication interface check the blhost application documentation.

----------------------
Command line interface
----------------------

.. click:: spsdk.apps.nxpdevhsm:main
    :prog: nxpdevhsm
    :nested: full
