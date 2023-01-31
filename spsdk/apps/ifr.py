#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for ifr."""

import logging
import sys
from typing import Optional, Union

import click

from spsdk import pfr
from spsdk.apps.utils.common_cli_options import (
    FC,
    CommandsTreeGroupAliasedGetCfgTemplate,
    spsdk_apps_common_options,
)
from spsdk.apps.utils.utils import catch_spsdk_error
from spsdk.pfr.exceptions import SPSDKPfrConfigError
from spsdk.pfr.pfr import ROMCFG
from spsdk.utils.misc import write_file
from spsdk.utils.schema_validator import ConfigTemplate

logger = logging.getLogger(__name__)


def _store_output(data: Union[str, bytes], path: Optional[str], mode: str = "w") -> None:
    """Store the output data; either on stdout or into file if it's provided."""
    if path is None:
        click.echo(data)
    else:
        write_file(data, path=path, mode=mode)


def ifr_device_type_options(options: FC) -> FC:
    """Setup IFR options for device and revision."""
    options = click.option(
        "-r",
        "--revision",
        help="Chip revision; if not specified, most recent one will be used",
    )(options)
    options = click.option(
        "-d",
        "--device",
        type=click.Choice(ROMCFG.devices()),
        help="Device to use",
        required=True,
    )(options)
    return options


@click.group(name="ifr", no_args_is_help=True, cls=CommandsTreeGroupAliasedGetCfgTemplate)
@spsdk_apps_common_options
def main(log_level: int) -> int:
    """Utility for generating and parsing IFR. Please note that IFR0 ROMCFG region is one-time-programmable only."""
    logging.basicConfig(level=log_level or logging.WARNING)
    return 0


@main.command(name="devices", no_args_is_help=False)
def devices() -> None:
    """List supported devices."""
    click.echo("\n".join(ROMCFG.devices()))


@main.command(name="get-template", no_args_is_help=True)
@ifr_device_type_options
@click.option(
    "-o",
    "--output",
    type=str,
    required=False,
    help="Save the output into a file instead of console",
)
@click.option("-f", "--full", is_flag=True, help="Show full config, including computed values")
def get_template(device: str, revision: str, output: str, full: bool) -> None:
    """Generate user configuration template file."""
    ifr_obj = ROMCFG(device=device, revision=revision)
    data = ifr_obj.get_yaml_config(not full)
    yaml_data = ConfigTemplate.convert_cm_to_yaml(data)
    _store_output(yaml_data, output)


@main.command(name="parse-binary", no_args_is_help=True)
@ifr_device_type_options
@click.option(
    "-o",
    "--output",
    type=str,
    required=False,
    help="Save the output into a file instead of console",
)
@click.option("-b", "--binary", type=click.File("rb"), required=True, help="Binary to parse")
@click.option("-f", "--show-diff", is_flag=True, help="Show differences comparing to defaults")
def parse_binary(revision: str, output: str, binary: str, show_diff: bool, device: str) -> None:
    """Parse binary and extract configuration."""
    ifr_obj = ROMCFG(device=device, revision=revision)
    data = binary.read()  # type: ignore
    ifr_obj.parse(data)
    parsed = ifr_obj.get_yaml_config(exclude_computed=False, diff=show_diff)
    yaml_data = ConfigTemplate.convert_cm_to_yaml(parsed)
    _store_output(yaml_data, output)

    click.echo(f"Success. (IFR: {binary} has been parsed and stored into {output}.)")


@main.command(name="generate-binary", no_args_is_help=True)
@click.option(
    "-d",
    "--device",
    type=click.Choice(ROMCFG.devices()),
    help="Device to use",
    required=True,
)
@click.option(
    "-c",
    "--user-config",
    "user_config_file",
    type=str,
    required=True,
    help="YAML/JSON file with user configuration",
)
@click.option(
    "-o",
    "--output",
    type=str,
    required=True,
    help="Save the output into a file instead of console",
)
def generate_binary(output: str, user_config_file: str, device: str) -> None:
    """Generate binary data."""
    ifr_config = pfr.PfrConfiguration(str(user_config_file))
    invalid_reason = ifr_config.is_invalid()
    if invalid_reason:
        raise SPSDKPfrConfigError(
            f"The configuration file is not valid. The reason is: {invalid_reason}"
        )
    assert ifr_config.type

    ifr_obj = ROMCFG(device=device, revision=ifr_config.revision)
    if not ifr_config.revision:
        ifr_config.revision = ifr_obj.revision
    ifr_obj.set_config(ifr_config, raw=False)

    data = ifr_obj.export()
    _store_output(data, output, "wb")

    click.echo(f"Success. (IFR binary has been generated into {output}.)")


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
