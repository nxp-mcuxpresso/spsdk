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
    is_click_help,
    spsdk_apps_common_options,
    spsdk_family_option,
    spsdk_sdp_interface,
)
from spsdk.apps.utils.utils import WARNING_MSG, catch_spsdk_error
from spsdk.sdp.protocol.base import SDPProtocolBase
from spsdk.sdp.sdps import SDPS


@click.group(name="sdpshost", no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_sdp_interface(identify_by_family=True)
@spsdk_family_option(families=SDPS.get_supported_families())
@spsdk_apps_common_options
@click.pass_context
def main(ctx: click.Context, interface: SDPProtocolBase, family: str, log_level: int) -> int:
    """Utility for communication with ROM on i.MX targets using SDPS protocol (i.MX8/9)."""
    spsdk_logger.install(level=log_level)
    click.echo(WARNING_MSG)
    # if --help is provided anywhere on command line, skip interface lookup and display help message
    if is_click_help(ctx, sys.argv):
        return 0
    ctx.obj = {
        "interface": interface,
        "family": family,
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
    with SDPS(ctx.obj["interface"], family=ctx.obj["family"]) as sdps:
        sdps.write_file(data)
    click.echo(f"Writing of file '{bin_file.name}' succeeded.")


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
