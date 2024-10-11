===================
User Guide - nxpuuu
===================

nxpuuu
-------
The `nxpuuu` CLI application is designed for image deployment based on the libUUU (universal update utility). This guide provides instructions on how to use the various commands available in the application.


Usage
-----
The `nxpuuu` CLI application provides several subcommands. Below are the available commands and their usage.


Run Command
-----------
The `run` command executes a UUU command, it might be for example fastboot or SDP command.

.. code-block:: bash

    nxpuuu run <COMMAND>

Arguments:
- `COMMAND`: The UUU command to be executed.

Script Command
--------------
The `script` command invokes UUU commands defined in a script file.

.. code-block:: bash

    nxpuuu script <SCRIPT_FILE>

Arguments:
- `SCRIPT_FILE`: Path to the UUU script file.

Write Command
-------------
The `write` command uses built-in UUU scripts to write to various devices.

.. code-block:: bash

    nxpuuu write -b <BOOT_DEVICE> -f <FAMILY> [ARGUMENTS...]

Options:
- `-b`: The boot device (e.g., emmc, sd, qspi).
- `-f`: The family of the device.

Arguments:
- Additional arguments required by the specific boot device script.

Built-in Scripts:
- `emmc`: Burn boot loader to eMMC boot partition.
- `emmc_all`: Burn whole image to eMMC.
- `fat_write`: Update one file in FAT partition.
- `nand`: Burn boot loader to NAND flash.
- `nvme_all`: Burn whole image to NVMe storage.
- `qspi`: Burn boot loader to QSPI NOR flash.
- `sd`: Burn boot loader to SD card.
- `sd_all`: Burn whole image to SD card.
- `spi_nand`: Burn boot loader to SPI NAND flash.
- `spl`: Boot SPL and U-Boot.

List Devices Command
--------------------
The `list_devices` command lists all connected USB devices.

.. code-block:: bash

    nxpuuu list-devices

Error Handling
--------------
The application handles errors and prints appropriate responses and error messages. If an error occurs, an `SPSDKAppError` is raised with details about the error.

Example Usage
-------------
Here are some example usages of the `nxpuuu` CLI application:

1. Run a UUU command:

    .. code-block:: bash

        nxpuuu run "FB:UCMD crc32 0x20480018 0x100"

2. Execute commands from a script file:

    .. code-block:: bash

        nxpuuu script path/to/script.uuu

3. Write to an SD card using built-in scripts:

    .. code-block:: bash

        nxpuuu write --boot-device sd --family <FAMILY> arg0 arg1

4. List all connected USB devices:

    .. code-block:: bash

        nxpuuu list-devices

Conclusion
----------
This guide provides an overview of the `nxpuuu` CLI application and its commands. For more detailed information, refer to the application's documentation or use the `--help` option with any command to see available options and arguments.
