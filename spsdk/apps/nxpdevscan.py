#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""NXP USB Device Scanner."""

import sys
from typing import IO, Sequence, Union

import click
from click_option_group import MutuallyExclusiveOptionGroup, optgroup

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import spsdk_apps_common_options, timeout_option
from spsdk.apps.utils.utils import catch_spsdk_error
from spsdk.utils import nxpdevscan
from spsdk.utils.devicedescription import (
    SDIODeviceDescription,
    SIODeviceDescription,
    UartDeviceDescription,
    USBDeviceDescription,
    UUUDeviceDescription,
)


@click.command(name="nxpdevscan")
@click.option(
    "-e",
    "--extend-vids",
    multiple=True,
    default=[],
    help="VID in hex to extend search.",
)
@click.option("-o", "--output", default="-", type=click.File("w"))
# NOTE: The MutuallyExclusiveOptionGroup doesn't work for flags, we keep it just for display purposes
@click.option(
    "-n", "--no-scan", is_flag=True, default=True, help="Do not scan UART devices by pinging them."
)
@click.option("--nxp", is_flag=True, default=True, help="Scan only NXP UART devices.")
@click.option("--uboot", is_flag=True, default=False, help="Scan for U-Boot console.")
@click.option(
    "-r",
    "--real-devices",
    is_flag=True,
    default=False,
    help="Check if the serial device is a real device using ioctl TIOCGSERIAL.",
)
@timeout_option(timeout=50)
@optgroup.group("Narrow down the scope of scanning", cls=MutuallyExclusiveOptionGroup)
@optgroup.option(
    "-a",
    "--all",
    "scope",
    flag_value="all",
    default=True,
    help="Search for all NXP devices (default)",
)
@optgroup.option(
    "-u",
    "--usb",
    "scope",
    flag_value="usb",
    help="Search only for USB devices",
)
@optgroup.option(
    "-sd",
    "--sdio",
    "scope",
    flag_value="sdio",
    help="Search only for SDIO devices",
)
@optgroup.option(
    "-p",
    "--port",
    "scope",
    flag_value="port",
    help="Search only for UART devices",
)
@optgroup.option(
    "-l",
    "--lpcusbsio",
    "scope",
    flag_value="lpcusbsio",
    help="Search only for USBSIO devices",
)
@optgroup.option(
    "--uuu",
    "scope",
    flag_value="uuu",
    help="Search only for UUU devices",
)
@spsdk_apps_common_options
def main(
    extend_vids: str,
    output: IO[str],
    scope: str,
    log_level: int,
    no_scan: bool,
    nxp: bool,
    uboot: bool,
    timeout: int = 50,
    real_devices: bool = False,
) -> None:
    """Utility listing all connected NXP USB and UART devices.

    NOTE: This utility lists all NXPs USB and UART devices connected to the host.
    By default it scans UART devices by pinging them (sending the mboot or SDP command).
    This however causes that the device ISP mode is locked to UART.
    Use the -n/--no-scan option to disable this behavior.
    If you want to only scan for NXP UART devices, use the --nxp option.
    """
    spsdk_logger.install(level=log_level)
    additional_vids = [int(vid, 16) for vid in extend_vids]

    def print_devices(
        output: IO[str],
        title: str,
        devices: Sequence[
            Union[
                SDIODeviceDescription,
                USBDeviceDescription,
                UartDeviceDescription,
                SIODeviceDescription,
                UUUDeviceDescription,
            ]
        ],
    ) -> None:
        """Print connected devices using click echo.

        :param output: Output stream
        :param title: title for group print
        :param devices: device descriptors
        """
        if hasattr(output, "name") and output.name == "<stdout>":
            click.echo(8 * "-" + f" {title} " + 8 * "-" + "\n", file=output)
        for device in devices:
            click.echo(str(device), file=output)
            click.echo("", file=output)

    if scope in ["all", "sdio"] and sys.platform != "win32":
        nxp_sdio_devices = nxpdevscan.search_nxp_sdio_devices()
        print_devices(output, "Connected NXP SDIO Devices", nxp_sdio_devices)

    if scope in ["all", "usb"]:
        nxp_usb_devices = nxpdevscan.search_nxp_usb_devices(additional_vids)
        print_devices(output, "Connected NXP USB Devices", nxp_usb_devices)

    if scope in ["all", "port"]:
        nxp_uart_devices = nxpdevscan.search_nxp_uart_devices(
            no_scan, nxp, uboot, timeout, real_devices
        )
        print_devices(output, "Connected NXP UART Devices", nxp_uart_devices)

    if scope in ["all", "lpcusbsio"]:
        nxp_sio_devices = nxpdevscan.search_libusbsio_devices()
        print_devices(output, "Connected NXP SIO Devices", nxp_sio_devices)

    if scope in ["all", "uuu"]:
        nxp_uuu_devices = nxpdevscan.search_uuu_usb_devices()
        print_devices(output, "Connected NXP UUU Devices", nxp_uuu_devices)


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
