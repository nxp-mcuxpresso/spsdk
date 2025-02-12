#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Wrapper for all spsdk applications.

Its purpose is to provide easier discoverability.
New users may not be aware of all available apps.
"""
import sys
import textwrap
from typing import Any

import click

from spsdk import __version__ as spsdk_version
from spsdk.apps.blhost import main as blhost_main
from spsdk.apps.dk6prog import main as dk6prog_main
from spsdk.apps.el2go import main as el2go_main
from spsdk.apps.ifr import main as ifr_main
from spsdk.apps.lpcprog import main as lpcprog_main
from spsdk.apps.nxpcrypto import main as nxpcrypto_main
from spsdk.apps.nxpdebugmbox import main as nxpdebugmbox_main
from spsdk.apps.nxpdevhsm import main as nxpdevhsm_main
from spsdk.apps.nxpdevscan import main as nxpdevscan_main
from spsdk.apps.nxpdice import main as nxpdice_main
from spsdk.apps.nxpele import main as nxpele_main
from spsdk.apps.nxpfuses import main as nxpfuses_main
from spsdk.apps.nxpimage import main as nxpimage_main
from spsdk.apps.nxpmemcfg import main as nxpmemcfg_main
from spsdk.apps.nxpuuu import main as nxpuuu_main
from spsdk.apps.nxpwpc import main as nxpwpc_main
from spsdk.apps.pfr import main as pfr_main
from spsdk.apps.sdphost import main as sdphost_main
from spsdk.apps.sdpshost import main as sdpshost_main
from spsdk.apps.shadowregs import main as shadowregs_main
from spsdk.apps.utils.common_cli_options import CommandsTreeGroup, SpsdkClickGroup
from spsdk.exceptions import SPSDKError
from spsdk.utils.database import DatabaseManager, FeaturesEnum, get_families

try:
    TP = True
    from spsdk.apps.tpconfig import main as tpconfig_main
    from spsdk.apps.tphost import main as tphost_main
except SPSDKError:
    TP = False
from spsdk.apps.utils.utils import catch_spsdk_error


@click.group(name="spsdk", no_args_is_help=True, cls=CommandsTreeGroup)
@click.version_option(spsdk_version, "--version")
def main() -> int:
    """Main entry point for all SPSDK applications."""
    return 0


main.add_command(blhost_main, name="blhost")
main.add_command(nxpfuses_main, name="nxpfuses")
main.add_command(ifr_main, name="ifr")
main.add_command(nxpcrypto_main, name="nxpcrypto")
main.add_command(nxpdebugmbox_main, name="nxpdebugmbox")
main.add_command(nxpdevscan_main, name="nxpdevscan")
main.add_command(nxpdevhsm_main, name="nxpdevhsm")
main.add_command(nxpele_main, name="nxpele")
main.add_command(nxpdice_main, name="nxpdice")
main.add_command(nxpimage_main, name="nxpimage")
main.add_command(nxpmemcfg_main, name="nxpmemcfg")
main.add_command(nxpuuu_main, name="nxpuuu")
main.add_command(nxpwpc_main, name="nxpwpc")
main.add_command(pfr_main, name="pfr")
main.add_command(sdphost_main, name="sdphost")
main.add_command(sdpshost_main, name="sdpshost")
main.add_command(shadowregs_main, name="shadowregs")
main.add_command(dk6prog_main, name="dk6prog")
main.add_command(el2go_main, name="el2go-host")
main.add_command(lpcprog_main, name="lpcprog")

if TP:
    main.add_command(tpconfig_main, name="tpconfig")
    main.add_command(tphost_main, name="tphost")
else:
    click.echo(
        "Please install SPSDK with pip install 'spsdk[tp]' in order to use tphost and tpconfig apps"
    )


@main.group("utils", no_args_is_help=True, cls=SpsdkClickGroup)
def utils_group() -> None:
    """Group of commands for working with various general utilities."""


@utils_group.command(name="clear-cache")
@click.pass_context
def clear_cache(ctx: click.Context) -> None:
    """Clear SPSDK cache.

    :param ctx: Click content
    """
    DatabaseManager.clear_cache()
    click.echo("SPSDK cache has been cleared.")
    ctx.exit()


@utils_group.command(name="family-info", no_args_is_help=True)
@click.option(
    "-f",
    "--family",
    type=click.Choice(
        choices=list(DatabaseManager().quick_info.devices.devices.keys()), case_sensitive=False
    ),
    required=True,
    help="Select the chip family.",
)
def family_info(family: str) -> None:
    """Show information of chosen family chip.

    :param family: Name of the device.
    """
    qi_family = DatabaseManager().quick_info.devices.devices[family]

    click.echo(f"Family:            {family}")
    click.echo(f"Purpose:           {qi_family.info.purpose}")
    click.echo(f"Web:               {qi_family.info.web}")
    if qi_family.info.spsdk_predecessor_name:
        click.echo(f"Predecessor name:  {qi_family.info.spsdk_predecessor_name}")
    click.echo(f"ISP:\n{textwrap.indent(str(qi_family.info.isp), '  ')}")
    click.echo(f"Memory map:\n{textwrap.indent(qi_family.info.memory_map.get_table(), '  ')}")

    features_raw = qi_family.features_list
    features_desc = [
        f"{x.upper():<20}{FeaturesEnum.from_label(x).description}" for x in features_raw
    ]
    assert isinstance(features_desc, list)
    printable_list = "\n - ".join(features_desc)
    click.echo(f"The supported features for {family}:\n - {printable_list}")


@utils_group.command(name="families", no_args_is_help=True)
@click.option(
    "-f",
    "--feature",
    type=click.Choice(choices=FeaturesEnum.labels(), case_sensitive=False),
    required=True,
    help="Select the feature to print out all families that supports it.",
)
def families(feature: str) -> None:
    """Show all families that supports chosen feature.

    :param feature: Name of the feature.
    """
    click.echo(f"The supported families for {feature}:\n{', '.join(get_families(feature))}")


@catch_spsdk_error
def safe_main() -> Any:
    """Call the main function."""
    sys.exit(main())


if __name__ == "__main__":
    safe_main()  # pylint: disable=no-value-for-parameter
