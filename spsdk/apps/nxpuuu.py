#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""CLI application for image deployment based on libUUU (universal update utility)."""
import logging
import sys
from typing import Any, Optional

import click

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_apps_common_options,
    spsdk_family_option,
)
from spsdk.apps.utils.utils import SPSDKAppError, catch_spsdk_error
from spsdk.uboot.spsdk_uuu import SPSDKUUU
from spsdk.utils.misc import load_text

logger = logging.getLogger(__name__)


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
    click.echo(f"Path: {path.decode('utf-8')}")
    click.echo(f"Chip: {chip.decode('utf-8')}")
    click.echo(f"Product: {pro.decode('utf-8')}")
    click.echo(f"Vendor ID: {hex(vid)}")
    click.echo(f"Product ID: {hex(pid)}")
    click.echo(f"BCD: {hex(bcd)}")
    click.echo(f"Serial Number: {serial_no.decode('utf-8')}")
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
@spsdk_apps_common_options
@click.pass_context
def main(ctx: click.Context, log_level: int) -> None:
    """CLI application for image deployment based on libUUU (universal update utility)."""
    log_level = log_level or logging.WARNING
    spsdk_logger.install(level=log_level)

    uuu = SPSDKUUU()
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
    required=True,
    help="Boot device",
)
@click.argument("arguments", type=str, nargs=-1)
@click.pass_context
def write(
    ctx: click.Context,
    boot_device: str,
    family: str,
    arguments: Optional[list[str]] = None,
) -> None:
    """Write using the in-built UUU scripts.

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
    processed_script = uuu.get_uuu_script(boot_device, family, arguments)
    logger.debug(f"Processing script:\n{processed_script}")
    handle_uuu_error(uuu.run_script(processed_script), uuu)
    handle_uuu_error(uuu.wait_uuu_finish(), uuu, print_response=False)
    click.echo("Done")


# Define the new command
@main.command()
@click.pass_context
def list_devices(ctx: click.Context) -> None:
    """List all connected USB devices."""
    uuu: SPSDKUUU = ctx.obj["uuu"]
    uuu.for_each_devices(usb_device_callback)


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
