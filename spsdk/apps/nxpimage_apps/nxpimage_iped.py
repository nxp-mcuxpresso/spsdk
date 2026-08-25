#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK NXP Image IPED table command-line interface."""

import click

from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import print_files
from spsdk.image.iped.iped import Iped
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import get_printable_path, load_binary, write_file


@click.group(name="iped", cls=CommandsTreeGroup)
def iped_group() -> None:
    """Group of sub-commands related to IPED tables."""


@iped_group.command(name="export", no_args_is_help=True)
@spsdk_config_option(klass=Iped)
def iped_export_command(config: Config) -> None:
    """Generate IPED table from YAML/JSON configuration."""
    iped_export(config)


def iped_export(config: Config) -> None:
    """Generate IPED table from YAML/JSON configuration.

    :param config: IPED configuration.
    """
    iped = Iped.load_from_config(config)
    click.echo("Exporting IPED table")
    print_files(iped.post_export(config.get_output_file_name("output_folder")))


@iped_group.command(name="parse", no_args_is_help=True)
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, readable=True, resolve_path=True),
    required=True,
    help="Path to binary IPED table/keyblob to parse.",
)
@spsdk_family_option(families=Iped.get_supported_families())
@spsdk_output_option(force=True)
def iped_parse_command(binary: str, family: FamilyRevision, output: str) -> None:
    """Parse IPED table/keyblob into YAML configuration."""
    iped_parse(binary, family, output)


def iped_parse(binary: str, family: FamilyRevision, output: str) -> None:
    """Parse IPED table/keyblob into YAML configuration.

    :param binary: Path to binary IPED table/keyblob.
    :param family: Target family.
    :param output: Output YAML configuration path.
    """
    iped = Iped.parse(load_binary(binary), family=family)
    write_file(iped.get_config_yaml(), output)
    click.echo(
        f"Success. (IPED table: {get_printable_path(binary)} has been parsed and stored "
        f"into {get_printable_path(output)}.)"
    )


@iped_group.command(name="get-template", no_args_is_help=True)
@spsdk_family_option(families=Iped.get_supported_families())
@spsdk_output_option(force=True)
def iped_get_template(family: FamilyRevision, output: str) -> None:
    """Create template of IPED table configuration in YAML format."""
    click.echo(f"Creating {get_printable_path(output)} template file.")
    write_file(Iped.get_config_template(family), output)
