===================
User Guide - nxpuuu
===================

nxpuuu
-------
The `nxpuuu` CLI application is designed for image deployment based on the libUUU (universal update utility). This powerful tool enables flashing bootloaders, kernels, file systems, and complete disk images to various storage devices on NXP processors. It supports multiple protocols including Serial Download Protocol (SDP) and Fastboot.

Overview
--------
nxpuuu provides a unified interface for:

- Loading and executing bootloaders
- Flashing Linux kernels and device trees
- Deploying complete disk images (.wic files)
- Writing to various storage devices (eMMC, SD, QSPI, NAND)
- Executing custom UUU scripts
- Running individual UUU commands

Usage
-----
The `nxpuuu` CLI application provides several subcommands for different deployment scenarios.

Basic syntax:

.. code-block:: bash

    nxpuuu [OPTIONS] COMMAND [ARGS]...

Global Options
--------------

**Timeout and Timing Options:**

- `-t, --wait-timeout INTEGER`: Timeout for waiting in seconds (default: 5)
- `-T, --wait-next-timeout INTEGER`: Timeout for waiting for the next device in seconds (default: 5)
- `-pp, --poll-period INTEGER`: Polling period in milliseconds (default: 200)

**Device Filtering Options:**

- `-up, --usbpath USB_PATH`: Filter UUU devices by USB path
- `-us, --usbserial SERIAL_NUMBER`: Filter UUU devices by USB serial number

**Verbosity and Information Options:**

- `-v, --verbose`: Print more detailed information
- `-vv, --debug`: Display more debugging information
- `--version`: Show the version and exit
- `--help`: Show help message and exit

**Global Options Examples:**

Increase timeout for slow operations:

.. code-block:: bash

    nxpuuu -t 30 write -b emmc_all -f imx8ulp large-image.wic

Filter by specific USB device:

.. code-block:: bash

    nxpuuu -us "1234567890ABCDEF" run "SDP: boot -f u-boot-spl.bin"

Use specific USB path:

.. code-block:: bash

    nxpuuu -up "1:2" write -b emmc -f imx8ulp u-boot-spl.bin u-boot.img

Enable verbose output:

.. code-block:: bash

    nxpuuu -v run "FB: flash kernel zImage"

Enable debug output for troubleshooting:

.. code-block:: bash

    nxpuuu -vv script deploy.uuu

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

5. Complete eMMC Image

    .. code-block:: bash

        nxpuuu write -b emmc_all -f imx8mm core-image-minimal.wic

Conclusion
----------
This guide provides an overview of the `nxpuuu` CLI application and its commands. For more detailed information, refer to the application's documentation or use the `--help` option with any command to see available options and arguments.
