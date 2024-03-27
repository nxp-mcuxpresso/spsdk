#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for SDPS module aka SDPSHost."""

import sys

import click

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    isp_interfaces,
    spsdk_apps_common_options,
)
from spsdk.apps.utils.utils import WARNING_MSG, catch_spsdk_error
from spsdk.sdp.scanner import get_sdp_interface
from spsdk.sdp.sdps import ROM_INFO, SDPS


@click.group(name="sdpshost", no_args_is_help=True, cls=CommandsTreeGroup)
@isp_interfaces(uart=True, usb=True, is_sdp=True, plugin=True, json_option=False)
@click.option("-n", "--name", type=click.Choice(list(ROM_INFO.keys())), help="Name of the device")
@spsdk_apps_common_options
@click.pass_context
def main(
    ctx: click.Context, port: str, usb: str, plugin: str, name: str, log_level: int, timeout: int
) -> int:
    """Utility for communication with ROM on i.MX targets using SDPS protocol (i.MX8/9)."""
    spsdk_logger.install(level=log_level)
    click.echo(WARNING_MSG)
    # if --help is provided anywhere on command line, skip interface lookup and display help message
    if "--help " in sys.argv:
        port, usb = None, None  # type: ignore
    ctx.obj = {
        "interface": (
            get_sdp_interface(port=port, usb=usb, plugin=plugin, timeout=timeout)
            if port or usb
            else None
        ),
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
    data = bin_file.read()  # type: ignore
    with SDPS(ctx.obj["interface"], device_name=ctx.obj["name"]) as sdps:
        sdps.write_file(data)
    click.echo(f"Writing of file '{bin_file.name}' succeeded.")


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
