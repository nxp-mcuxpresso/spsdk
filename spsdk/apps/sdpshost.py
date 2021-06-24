#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for SDPS module aka SDPSHost."""

import logging
import sys

import click
from click_option_group import MutuallyExclusiveOptionGroup, optgroup

from spsdk import __version__ as spsdk_version
from spsdk.apps.utils import get_interface, catch_spsdk_error
from spsdk.sdp import SDPS
from spsdk.sdp.sdps import ROM_INFO


WARNING_MSG = """
!!! THIS IS AN EXPERIMENTAL UTILITY! USE WITH CAUTION !!!
"""


@click.group()
@optgroup.group("Interface configuration", cls=MutuallyExclusiveOptionGroup)
@optgroup.option("-p", "--port", help="Serial port")
@optgroup.option("-u", "--usb", help="USB device's PID:VID")
@click.option("-n", "--name", type=click.Choice(ROM_INFO.keys()), help="Name of the device")
@click.option(
    "-v",
    "--verbose",
    "log_level",
    flag_value=logging.INFO,
    help="Display more verbose output",
)
@click.option(
    "-d",
    "--debug",
    "log_level",
    flag_value=logging.DEBUG,
    help="Display debugging info",
)
@click.option(
    "-t",
    "--timeout",
    metavar="<ms>",
    help="Set packet timeout in milliseconds",
    default=5000,
)
@click.version_option(spsdk_version, "--version")
@click.pass_context
def main(ctx: click.Context, port: str, usb: str, name: str, log_level: int, timeout: int) -> int:
    """Utility for communication with ROM on i.MX targets using SDPS protocol."""
    logging.basicConfig(level=log_level or logging.WARNING)
    click.echo(WARNING_MSG)
    # if --help is provided anywhere on commandline, skip interface lookup and display help message
    if "--help " in sys.argv:
        port, usb = None, None  # type: ignore
    ctx.obj = {
        "interface": get_interface(module="sdp", port=port, usb=usb, timeout=timeout)
        if port or usb
        else None,
        "name": name,
    }
    return 0


@main.command()
@click.argument("bin_file", metavar="FILE", type=click.File("rb"), required=True)
@click.pass_context
def write_file(ctx: click.Context, bin_file: click.File) -> None:
    """Write boot image data.

    \b
    FILE    - binary file to write
    """
    click.echo(WARNING_MSG)
    data = bin_file.read()  # type: ignore
    with SDPS(ctx.obj["interface"], device_name=ctx.obj["name"]) as sdps:
        sdps.write_file(data)


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
