======================
User Guide - nxpdevhsm
======================

This user’s guide describes how to interface with the *MCU bootloader* to provisioned chip using *nxpdevhsm* application.

The *nxpdevhsm* application is a command-line utility used on the host computer to use device HSM process to get provisioning SB3.

.. click:: spsdk.apps.nxpdevhsm:main
    :prog: nxpdevhsm
    :nested: none

-------------------------
nxpdevhsm - Communication
-------------------------

The *nxpdevhsm* application is using blhost application and all supported communication interfaces that blhost offers(UART, USB, LPCUSBSIO[IC, SPI])

nxpdevhsm - blhost - USB
========================

*blhost* could be connected to MCU Bootloader over USB HID.

:ref:`USB device identification in SPSDK`

nxpdevhsm - blhost - UART
=========================

*blhost* could be connected to MCU bootloader over UART.

:ref:`UART device identification in SPSDK`

nxpdevhsm - blhost - LPCUSBSIO
==============================

LPCUSBSIO - LPC USB Serial I/O(LPCUSBSIO), a firmware built in LPC Link2. The LPCUSBSIO acts as a bus translator, and establishes connection with *blhost* over USB-HID, and the MCU bootloader device over I2C and SPI.

-------------------------
nxpdevhsm - blhost - Note
-------------------------

For more information about supported communication interface check the blhost application documentation.


------------------------
nxpdevhsm - Sub-commands
------------------------

*nxpdevhsm* consist of a set of sub-commands followed by options and arguments.
The options and the sub-command are separated with a ‘--’.

.. code:: bash

    nxpdevhsm [options] -- [sub-command]

The "help" guide of *nxpdevhsm* lists all of the options and sub-commands supported by the *nxpdevhsm* utility.

.. code:: bash

    nxpdevhsm --help

.. click:: spsdk.apps.nxpdevhsm:generate
    :prog: nxpdevhsm generate
    :nested: full
