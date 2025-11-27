#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK LPC programming utilities for nxpimage application.

This module provides command-line interface for LPC microcontroller programming
operations including CRP (Code Read Protection) level updates and making images
bootable for LPC devices.
"""

import click

from spsdk.apps.utils.common_cli_options import CommandsTreeGroup, spsdk_output_option
from spsdk.lpcprog.protocol import LPCProgCRPLevels
from spsdk.lpcprog.utils import lpcprog_make_image_bootable, lpcprog_update_crp_value
from spsdk.utils.misc import load_binary, write_file


@click.group(name="lpcprog", cls=CommandsTreeGroup)
def lpcprog_group() -> None:
    """Group of sub-commands related to lpcprog tool."""


@lpcprog_group.command(name="set-crp", no_args_is_help=True)
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, readable=True, resolve_path=True),
    required=True,
    help="Path to binary image to update CRP.",
)
@click.option(
    "-l",
    "--level",
    help="level",
    required=True,
    type=click.Choice(choices=LPCProgCRPLevels.labels(), case_sensitive=False),
)
@spsdk_output_option()
def lpcprog_update_crp_command(binary: str, level: str, output: str) -> None:
    """Update CRP value in binary image.

    Code Read Protection is a mechanism that allows the user to enable different levels of
    security in the system so that access to the on-chip flash and use of the ISP can be
    restricted. When needed, CRP is invoked by programming a specific pattern in the flash
    image at offset 0x0000 02FC.
    """
    lpcprog_update_crp(binary, level, output)


def lpcprog_update_crp(binary: str, crp: str, output: str) -> None:
    """Update CRP value in binary image."""
    bin_data = load_binary(binary)
    crp_level = LPCProgCRPLevels.from_label(crp)
    new_data = lpcprog_update_crp_value(bin_data, crp_level.tag)
    write_file(new_data, output, mode="wb")
    click.echo(f"Success. Updated CRP in binary image: {output}")


@lpcprog_group.command(name="make-bootable", no_args_is_help=True)
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, readable=True, resolve_path=True),
    required=True,
    help="Input plain binary application image.",
)
@spsdk_output_option()
def lpcprog_make_bootable_command(binary: str, output: str) -> None:
    """Make binary image bootable by inserting correct checksum of vector table."""
    lpcprog_make_bootable(binary, output)


def lpcprog_make_bootable(binary: str, output: str) -> None:
    """Make binary image bootable by inserting correct checksum of vector table."""
    bin_data = load_binary(binary)
    new_data = lpcprog_make_image_bootable(bin_data)
    write_file(new_data, output, mode="wb")
    click.echo(f"Success. Updated binary image: {output}")
