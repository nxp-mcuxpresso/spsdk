#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""CLI application for image deployment based on libUUU (universal update utility)."""
import logging
import os
import sys
from typing import Any, Optional

import click
import colorama
import prettytable

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_apps_common_options,
    spsdk_family_option,
    usbpath_option,
    usbserial_option,
)
from spsdk.apps.utils.utils import INT, SPSDKAppError, catch_spsdk_error
from spsdk.image.bootable_image.bimg import BootableImage
from spsdk.uboot.spsdk_uuu import SPSDKUUU
from spsdk.utils.misc import load_binary, load_text

logger = logging.getLogger(__name__)


# List to store device information
device_list: list[dict[str, Any]] = []


def usb_device_callback(
    path: bytes, chip: bytes, pro: bytes, vid: int, pid: int, bcd: int, serial_no: bytes, p: Any
) -> int:
    """Callback function for uuu_for_each_devices.

    :param path: The path to the USB device.
    :param chip: The chip of the USB device.
    :param pro: The product of the USB device.
    :param vid: The vendor ID of the USB device.
    :param pid: The product ID of the USB device.
    :param bcd: The device release number in binary-coded decimal.
    :param serial_no: The serial number of the USB device.
    :param p: A pointer to additional data.
    :return: 0 on success.
    """
    device_info = {
        "path": path.decode("utf-8"),
        "chip": chip.decode("utf-8"),
        "product": pro.decode("utf-8"),
        "vendor_id": hex(vid),
        "product_id": hex(pid),
        "bcd": hex(bcd),
        "serial_number": serial_no.decode("utf-8"),
    }
    device_list.append(device_info)
    return 0


def handle_uuu_error(exit_code: int, uuu: SPSDKUUU, print_response: bool = True) -> None:
    """Handle UUU error and print response and error message.

    :param exit_code: exit code from the call
    :param uuu: SPSDKUUU handler
    :param print_response: print response
    :raises SPSDKAppError: in case the error occurs
    """
    success = exit_code == 0
    if uuu.response and print_response:
        click.echo(f"Response: {uuu.response}")
    if not success:
        raise SPSDKAppError(
            f"Command exited with {exit_code}, "
            f"error: {uuu.last_error}, error message: {uuu.last_error_str}"
        )


@click.group(name="nxpuuu", no_args_is_help=True, cls=CommandsTreeGroup)
@click.option(
    "-t",
    "--wait-timeout",
    type=INT(),
    default="5",
    help="Timeout for waiting in seconds (default: 5)",
)
@click.option(
    "-T",
    "--wait-next-timeout",
    type=INT(),
    default="5",
    help="Timeout for waiting for the next device in seconds (default: 5)",
)
@click.option(
    "-pp",
    "--poll-period",
    type=INT(),
    default="100",
    help="Polling period in milliseconds (default: 100)",
)
@usbpath_option()
@usbserial_option()
@spsdk_apps_common_options
@click.pass_context
def main(
    ctx: click.Context,
    log_level: int,
    wait_timeout: int,
    wait_next_timeout: int,
    poll_period: int,
    usbpath: str,
    usbserial: str,
) -> None:
    """CLI application for image deployment based on libUUU (universal update utility)."""
    log_level = log_level or logging.WARNING
    spsdk_logger.install(level=log_level)

    uuu = SPSDKUUU(
        wait_timeout=wait_timeout,
        wait_next_timeout=wait_next_timeout,
        poll_period=poll_period,
        usb_path_filter=usbpath,
        usb_serial_no_filter=usbserial,
    )
    logger.debug(f"Initializing libUUU version {uuu.uuu.get_version_string()}")

    ctx.obj = {"uuu": uuu}


@main.command(name="run")
@click.argument("command", type=str, required=True)
@click.pass_context
def run(ctx: click.Context, command: str) -> None:
    """Run UUU command.

    \b
    COMMAND   - command to be executed
    """
    uuu: SPSDKUUU = ctx.obj["uuu"]
    logger.debug(f"Sending command {command}")
    handle_uuu_error(uuu.run_cmd(command), uuu)


@main.command(no_args_is_help=True)
@click.argument("script_file", type=click.Path(file_okay=True))
@click.pass_context
def script(ctx: click.Context, script_file: str) -> None:
    """Invoke UUU commands defined in script file.

    \b
    SCRIPT_FILE    - path to UUU script file
    """
    uuu: SPSDKUUU = ctx.obj["uuu"]
    script_text = load_text(script_file)
    logger.debug(f"Processing script:\n{script_text}")
    handle_uuu_error(uuu.run_script(script_text), uuu)
    handle_uuu_error(uuu.wait_uuu_finish(), uuu, print_response=False)


@main.command(no_args_is_help=True)
@spsdk_family_option(SPSDKUUU.get_supported_families(), required=True)
@click.option(
    "-b",
    "--boot-device",
    type=click.Choice(SPSDKUUU.get_supported_devices(), case_sensitive=False),
    required=False,
    help="Boot device",
)
@click.option(
    "-v / ",
    "--verify/--no-verify",
    is_flag=True,
    default=False,
    help="Verify first passed image (don't verify by default)",
)
@click.argument("arguments", type=str, nargs=-1)
@click.pass_context
def write(
    ctx: click.Context,
    family: str,
    boot_device: Optional[str] = None,
    arguments: Optional[list[str]] = None,
    verify: bool = False,
) -> None:
    """Write using the in-built UUU scripts.

    If the boot device is not provided, the first argument is passed to auto detect function.
    File is loaded to the device using the SDPS/SDP protocol.

    Run Built-in scripts:

    \b
    emmc
    burn boot loader to eMMC boot partition
        arg0: _flash.bin  bootloader
        arg1: _image[Optional]  image burn to emmc, default is the same as bootloader

    \b
    emmc_all
    burn whole image to eMMC
        arg0: _flash.bin  bootloader, which can extract from wic image
        arg1: _image[Optional]  wic image burn to emmc.


    \b
    fat_write
    update one file in fat partition, require uboot fastboot running in board
        arg0: _image  image, which cp to fat partition
        arg1: _device  storage device, mmc/sata
        arg2: _partition  fat partition number, like 1:1
        arg3: _filename[Optional]  file name in target fat partition, only support rootdir now

    \b
    nand
    burn boot loader to NAND flash
        arg0: _flash.bin  bootloader
        arg1: _image[Optional]  image burn to nand, default is the same as bootloader

    \b
    nvme_all
    burn whole image to nvme storage
        arg0: _flash.bin  bootloader, which can extract from wic image
        arg1: _image[Optional]  wic image burn to nvme.

    \b
    qspi
    burn boot loader to qspi nor flash
        arg0: _flexspi.bin  bootloader
        arg1: _image[Optional]  image burn to flexspi, default is the same as bootloader

    \b
    sd
    burn boot loader to sd card
        arg0: _flash.bin  bootloader
        arg1: _image[Optional]  image burn to sd card, default is the same as bootloader

    \b
    sd_all
    burn whole image to sd card
        arg0: _flash.bin  bootloader, which can extract from wic image
        arg1: _image[Optional]  wic image burn to sd card.

    \b
    spi_nand
    burn boot loader to spi nand flash
        arg0: _flexspi.bin  bootloader
        arg1: _image[Optional]  image burn to fspinand, default is the same as bootloader

    \b
    spl
    boot spl and uboot
        arg0: _flash.bin
    """
    uuu: SPSDKUUU = ctx.obj["uuu"]
    if verify and arguments:
        # Verify the first image by parsing it
        BootableImage.parse(load_binary(arguments[0]), family)

    if not boot_device and arguments:
        filename = arguments[0]
        if not os.path.exists(filename):
            raise SPSDKAppError(f"File {filename} does not exist")
        uuu.auto_detect_file(filename)
    elif boot_device:
        processed_script = uuu.get_uuu_script(boot_device, family, arguments)
        logger.debug(f"Processing script:\n{processed_script}")
        handle_uuu_error(uuu.run_script(processed_script), uuu)
    handle_uuu_error(uuu.wait_uuu_finish(), uuu, print_response=False)
    click.echo("Done")


@main.command()
@click.option(
    "-u",
    "--usb",
    type=str,
    required=False,
    help="Filter devices by USB ID in the format VID:PID",
    metavar="VID:PID",
)
@click.pass_context
def list_devices(ctx: click.Context, usb: Optional[str]) -> None:
    """List all connected USB devices."""
    uuu: SPSDKUUU = ctx.obj["uuu"]
    global device_list  # pylint: disable=global-statement
    device_list = []  # Reset the list
    uuu.for_each_devices(usb_device_callback)

    vendor_id, product_id = None, None
    vendor_id_int, product_id_int = None, None
    if usb:
        try:
            vendor_id, product_id = usb.split(":")
            if not isinstance(vendor_id, str) or not isinstance(product_id, str):
                raise SPSDKAppError("Invalid USB ID format. Use VID:PID format.")
            vendor_id_int = int(vendor_id, 16)
            product_id_int = int(product_id, 16)
        except ValueError as exc:
            raise SPSDKAppError("Invalid USB ID format. Use VID:PID format.") from exc

    # Filter devices based on the provided parameters
    filtered_devices = []
    for device in device_list:
        device_vendor_id = int(device["vendor_id"], 16)
        device_product_id = int(device["product_id"], 16)
        if vendor_id_int and vendor_id_int != device_vendor_id:
            continue
        if product_id_int and product_id_int != device_product_id:
            continue
        filtered_devices.append(device)

    if not filtered_devices:
        click.echo("No devices found matching the criteria.")
        sys.exit(2)

    table = prettytable.PrettyTable()
    table.align = "l"
    table.header = True
    table.border = True
    table.hrules = prettytable.HRuleStyle.HEADER
    table.vrules = prettytable.VRuleStyle.NONE
    table.field_names = [
        "Path",
        "Chip",
        "Product",
        "Vendor ID",
        "Product ID",
        "BCD",
        "Serial Number",
    ]
    for device in filtered_devices:
        table.add_row(
            [
                colorama.Fore.YELLOW + device["path"],
                colorama.Fore.WHITE + device["chip"],
                colorama.Fore.CYAN + device["product"],
                colorama.Fore.GREEN + device["vendor_id"],
                colorama.Fore.GREEN + device["product_id"],
                colorama.Fore.WHITE + device["bcd"],
                colorama.Fore.CYAN + device["serial_number"],
            ]
        )

    click.echo(table)


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
