#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""NXP USB Device Scanner."""

import sys
from typing import IO

import click
from click_option_group import MutuallyExclusiveOptionGroup, optgroup

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import spsdk_apps_common_options
from spsdk.apps.utils.utils import catch_spsdk_error
from spsdk.utils import nxpdevscan


@click.command(name="nxpdevscan")
@click.option(
    "-e",
    "--extend-vids",
    multiple=True,
    default=[],
    help="VID in hex to extend search.",
)
@click.option("-o", "--out", default="-", type=click.File("w"))
# NOTE: The MutuallyExclusiveOptionGroup doesn't work for flags, we keep it just for display purposes
@optgroup.group("Narrow down the scope of scanning", cls=MutuallyExclusiveOptionGroup)
@optgroup.option(
    "-a",
    "--all",
    "scope",
    flag_value="all",
    default=True,
    help="Search for all devices (default)",
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
@spsdk_apps_common_options
def main(extend_vids: str, out: IO[str], scope: str, log_level: int) -> None:
    """Utility listing all connected NXP USB and UART devices."""
    spsdk_logger.install(level=log_level)
    additional_vids = [int(vid, 16) for vid in extend_vids]

    if scope in ["all", "sdio"]:
        nxp_sdio_devices = nxpdevscan.search_nxp_sdio_devices()
        if out.name == "<stdout>":
            click.echo(8 * "-" + " Connected NXP SDIO Devices " + 8 * "-" + "\n", out)
        for sdio_dev in nxp_sdio_devices:
            click.echo(sdio_dev.info(), out)
            click.echo("", out)

    if scope in ["all", "usb"]:
        nxp_usb_devices = nxpdevscan.search_nxp_usb_devices(additional_vids)
        if out.name == "<stdout>":
            click.echo(8 * "-" + " Connected NXP USB Devices " + 8 * "-" + "\n", out)
        for usb_dev in nxp_usb_devices:
            click.echo(usb_dev.info(), out)
            click.echo("", out)

    if scope in ["all", "port"]:
        nxp_uart_devices = nxpdevscan.search_nxp_uart_devices()
        if out.name == "<stdout>":
            click.echo(8 * "-" + " Connected NXP UART Devices " + 8 * "-" + "\n", out)
        for uart_dev in nxp_uart_devices:
            click.echo(uart_dev.info(), out)
            click.echo("", out)

    if scope in ["all", "lpcusbsio"]:
        nxp_sio_devices = nxpdevscan.search_libusbsio_devices()
        if out.name == "<stdout>":
            click.echo(8 * "-" + " Connected NXP SIO Devices " + 8 * "-" + "\n", out)
        for sio_dev in nxp_sio_devices:
            click.echo(sio_dev.info(), out)
            click.echo("", out)


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
