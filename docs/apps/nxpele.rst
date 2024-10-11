===================
User Guide - nxpele
===================

This user guide describes how to use *nxpele* application. *nxpele* is a tool to communicate with
EdgeLock Enclave hardware on target where it is used, for example: i.MX RT1180 or i.MX 93.

Nxpele supports three modes of communication:

- *mboot* mode - nxpele communicates with EdgeLock Enclave using mboot commands (i.MX RT1180).

In order to use the nxpele in mboot mode, flashloader must be loaded to target memory. It relies on mboot
commands (write-memory, read-memory and ele-message), so it contains standard *blhost* options to establish connection
with ISP mboot.

- *uboot_serial* mode - nxpele communicates with EdgeLock Enclave using u-boot serial console.

In order to use the nxpele in uboot mode, u-boot serial console must be enabled. U-Boot must be built with support for AHAB. (CONFIG_AHAB_UBOOT=y)
This implementation relies on "ele_message" command in U-Boot console.


- *uboot_fastboot* mode - nxpele communicates with EdgeLock Enclave using u-boot fastboot.

In order to use the nxpele in uboot_fastboot mode, u-boot fastboot must be enabled. U-Boot must be built with support for AHAB.
(CONFIG_AHAB_UBOOT=y) and console multiplexing must be enabled (CONFIG_CONSOLE_MUX=y). This is the fastest method to communicate with EdgeLock Enclave.


For more information about building the u-boot with AHAB support, please refer to the U-Boot documentation. https://docs.u-boot.org/en/latest/build/gcc.html

Nxpele supports following commands:

.. include:: ../_prebuild/nxpele_commands_table.inc

----------------------
Command line interface
----------------------

.. click:: spsdk.apps.nxpele:main
    :prog: nxpele
    :nested: full
