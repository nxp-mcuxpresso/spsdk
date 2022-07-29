.. TODO: [SPSDK-686] Add missing sub-commands into sdphost user guide when available

====================
User Guide - sdphost
====================

This document describes the usage of *Serial Download Protocol* Host (*sdphost*), a PC host application.

The *sdphost* tool is a useful tool in the factory programming and manufacturing process. It can be used to test and develop the automation software and test setups. It can be invoked from other applications too.

This document introduces the serial download protocol, typical factory programming setup, and usage of the tool and description of its sub-command line interface. It also provides a set of example usages of *sdphost* tool and its sub-command line arguments with a device.

-------------------------
Serial Download Protocol
-------------------------

*Serial Download Protocol* is a set of commands supported by NXP i.MX RT devices in the Boot ROM application’s serial download mode.

The purpose of *serial download protocol* is to provide means to download bootable images from a PC to the device’s internal or external RAM memory. There are a set of commands to read and write to a memory/register unit, read status of the last command, download images to a given address in internal/external memory, and provide the address to jump and execute the downloaded image.

--------------
Typical setup
--------------

The *sdphost* tool is used in the development phase of the device firmware application, manufacturing, and factory programming process.

The *sdphost* tool would run on the PC host, and the device would run in *Boot ROM serial download mode*. The MCU has BOOT_MODE pins that can be used to boot the device in *serial downloader mode*. The device’s reference manual provides the documentation on booting the device in *serial downloader mode*.

--------------
Communication
--------------

The *sdphost* tool communicates with NXP i.MX RT devices connected on the host PC via USB-HID or UART device.

sdphost - USB
=============

*sdphost* could be connected to MCU over USB HID.

:ref:`USB device identification in SPSDK`

sdphost - UART
==============

*sdphost* could be connected to MCU over UART.

:ref:`UART device identification in SPSDK`

----------------------
Command line interface
----------------------

.. click:: spsdk.apps.sdphost:main
    :prog: sdphost
    :nested: full
