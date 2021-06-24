.. TODO: [SPSDK-686] Add missing sub-commands into sdphost user guide when available

====================
User Guide - sdphost
====================

This document describes the usage of *Serial Download Protocol* Host (*sdphost*), a PC host application.

The *sdphost* tool is a useful tool in the factory programming and manufacturing process. It can be used to test and develop the automation software and test setups. It can be invoked from other applications too.

This document introduces the serial download protocol, typical factory programming setup, and usage of the tool and description of its sub-command line interface. It also provides a set of example usages of *sdphost* tool and its sub-command line arguments with a device.

----------------------------------
sdphost - Serial Download Protocol
----------------------------------

*Serial Download Protocol* is a set of commands supported by NXP i.MX RT devices in the Boot ROM application’s serial download mode.

The purpose of *serial download protocol* is to provide means to download bootable images from a PC to the device’s internal or external RAM memory. There are a set of commands to read and write to a memory/register unit, read status of the last command, download images to a given address in internal/external memory, and provide the address to jump and execute the downloaded image.

-----------------------
sdphost - Typical setup
-----------------------

The *sdphost* tool is used in the development phase of the device firmware application, manufacturing, and factory programming process.

The *sdphost* tool would run on the PC host, and the device would run in *Boot ROM serial download mode*. The MCU has BOOT_MODE pins that can be used to boot the device in *serial downloader mode*. The device’s reference manual provides the documentation on booting the device in *serial downloader mode*.

-----------------------
sdphost - Communication
-----------------------

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
sdphost - Sub-commands
----------------------

*sdphost* consist of a set of sub-commands followed by options and arguments.
The options and the sub-command are separated with a ‘--’.

.. code:: bash

    sdphost [options] -- [sub-command]

The "help" guide of *sdphost* lists all of the options and sub-commands supported by the *sdphost* utility.

.. code:: bash

    sdphost --help

.. click:: spsdk.apps.sdphost:main
    :prog: sdphost
    :nested: none

.. click:: spsdk.apps.sdphost:read_register
    :prog: sdphost read-register
    :nested: full

..  Not supported
    .. click:: spsdk.apps.sdphost:write_register
    :prog: sdphost write-register
    :nested: full

.. click:: spsdk.apps.sdphost:write_file
    :prog: sdphost write-file
    :nested: full

.. note::

    Typically, write-file is used to program the device with boot image and jump-address is used to start execution of boot image on the device.

.. click:: spsdk.apps.sdphost:error_status
    :prog: sdphost error-status
    :nested: full

.. click:: spsdk.apps.sdphost:jump_address
    :prog: sdphost jump-address
    :nested: full

.. note::

    IVT can be part of the image or can be downloaded separately. It is a data structure used by ROM that provides information of the boot image entry point and other parameters used for authenticating the image for secure boot. IVT is described in more detail in device’s reference manual.

