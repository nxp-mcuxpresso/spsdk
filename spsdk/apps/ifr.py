#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for ifr."""

import logging
import sys
from typing import Optional, Union

import click

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    FC,
    CommandsTreeGroup,
    isp_interfaces,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import catch_spsdk_error, format_raw_data
from spsdk.exceptions import SPSDKError
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.mboot.scanner import get_mboot_interface
from spsdk.pfr import pfr
from spsdk.utils.misc import load_binary, load_configuration, size_fmt, write_file
from spsdk.utils.schema_validator import CommentedConfig

logger = logging.getLogger(__name__)


def _parse_binary_data(
    data: bytes,
    family: str,
    revision: str = "latest",
    show_diff: bool = False,
) -> str:
    """Parse binary data and extract YAML configuration.

    :param data: Data to parse
    :param family: Family to use
    :param revision: Revision to use, defaults to 'latest'
    :param show_diff: Show only difference to default
    :return: IFR YAML configuration as a string
    """
    ifr_obj = pfr.ROMCFG(family=family, revision=revision)
    ifr_obj.parse(data)
    parsed = ifr_obj.get_config(diff=show_diff)
    schemas = ifr_obj.get_validation_schemas(family=family, revision=revision)
    yaml_data = CommentedConfig("IFR configuration from parsed binary", schemas=schemas).get_config(
        parsed
    )
    return yaml_data


def _store_output(
    data: Union[str, bytes], path: Optional[str], mode: str = "w", msg: Optional[str] = None
) -> None:
    """Store the output data; either on stdout or into file if it's provided."""
    if msg:
        click.echo(msg)
    if path is None:
        click.echo(data)
    else:
        click.echo(f"Result has been stored in: {path}")
        write_file(data, path=path, mode=mode)


def ifr_device_type_options(options: FC) -> FC:
    """Setup IFR options for family and revision."""
    options = click.option(
        "-r",
        "--revision",
        help="Chip revision; if not specified, most recent one will be used",
        default="latest",
    )(options)
    options = click.option(
        "-f",
        "--family",
        type=click.Choice(pfr.ROMCFG.get_supported_families()),
        help="Device to use",
        required=True,
    )(options)
    return options


@click.group(name="ifr", no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> int:
    """Utility for generating and parsing IFR. Please note that IFR0 ROMCFG region is one-time-programmable only."""
    spsdk_logger.install(level=log_level)
    return 0


@main.command(name="get-template", no_args_is_help=True)
@ifr_device_type_options
@spsdk_output_option(
    required=False,
    force=True,
    help="Save the output into a file instead of console",
)
@click.option("--full", is_flag=True, help="Show full config, including computed values")
def get_template(family: str, revision: str, output: str, full: bool) -> None:
    """Generate user configuration template file."""
    schemas = pfr.ROMCFG.get_validation_schemas(family=family, revision=revision)
    yaml_data = CommentedConfig("IFR configuration template", schemas).get_template()
    _store_output(yaml_data, output, msg="IFR configuration template has been created.")


@main.command(name="parse-binary", no_args_is_help=True)
@ifr_device_type_options
@spsdk_output_option(
    required=False,
    help="Save the output into a file instead of console",
)
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, resolve_path=True),
    required=True,
    help="Binary to parse",
)
@click.option("-d", "--show-diff", is_flag=True, help="Show differences comparing to defaults")
def parse_binary(revision: str, output: str, binary: str, show_diff: bool, family: str) -> None:
    """Parse binary and extract configuration."""
    yaml_data = _parse_binary_data(
        data=load_binary(binary), family=family, revision=revision, show_diff=show_diff
    )
    _store_output(yaml_data, output, msg=f"Success. (IFR: {binary} has been parsed.")


@main.command(name="generate-binary", no_args_is_help=True)
@ifr_device_type_options
@spsdk_config_option()
@spsdk_output_option(
    required=False,
    help="Save the output into a file instead of console",
)
def generate_binary(output: str, config: str, family: str, revision: str) -> None:
    """Generate binary data."""
    ifr_config = load_configuration(str(config))
    pfr.ROMCFG.validate_config(ifr_config)
    ifr_obj = pfr.ROMCFG.load_from_config(ifr_config)
    data = ifr_obj.export()
    _store_output(data, output, "wb", msg="Success. (IFR binary has been generated)")


@main.command(name="write", no_args_is_help=True)
@isp_interfaces(
    uart=True,
    usb=True,
    lpcusbsio=True,
    buspal=True,
    json_option=False,
    use_long_timeout_option=True,
)
@ifr_device_type_options
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    required=True,
    help="Path to IFR data to write.",
)
def write(
    port: str,
    usb: str,
    buspal: str,
    lpcusbsio: str,
    timeout: int,
    family: str,
    revision: str,
    binary: str,
) -> None:
    """Write IFR page to the device."""
    ifr_obj = pfr.ROMCFG(family=family, revision=revision)
    ifr_page_address = ifr_obj.reg_config.get_address()
    ifr_page_length = ifr_obj.BINARY_SIZE

    click.echo(f"{ifr_obj.__class__.__name__} page address on {family} is {ifr_page_address:#x}")

    data = load_binary(binary)
    if len(data) != ifr_page_length:
        raise SPSDKError(
            f"IFR page length is {ifr_page_length}. Provided binary has {size_fmt(len(data))}."
        )

    interface = get_mboot_interface(
        port=port, usb=usb, buspal=buspal, lpcusbsio=lpcusbsio, timeout=timeout
    )
    assert isinstance(interface, MbootProtocolBase)
    with McuBoot(interface=interface) as mboot:
        mboot.write_memory(address=ifr_page_address, data=data)
    click.echo(
        f"{ifr_obj.__class__.__name__} data {'written to device.' if mboot.status_code == 0 else 'write failed!'}"
    )


@main.command(name="read", no_args_is_help=True)
@isp_interfaces(
    uart=True,
    usb=True,
    lpcusbsio=True,
    buspal=True,
    json_option=False,
    use_long_timeout_option=True,
)
@ifr_device_type_options
@spsdk_output_option(
    required=False,
    help="Store IFR data into a file. If not specified hexdump data into stdout.",
)
@click.option(
    "-y",
    "--yaml",
    "yaml_output",
    type=click.Path(dir_okay=False, resolve_path=True),
    help="Parse data read from device into YAML config.",
)
@click.option(
    "-d",
    "--show-diff",
    is_flag=True,
    help="(applicable for parsing) Show differences comparing to defaults",
)
@click.option(
    "-c",
    "--show-calc",
    is_flag=True,
    hidden=True,
    help="(applicable for parsing) Show also calculated fields when displaying difference to "
    "defaults (--show-diff)",
)
def read(
    port: str,
    usb: str,
    buspal: str,
    lpcusbsio: str,
    timeout: int,
    family: str,
    revision: str,
    output: str,
    yaml_output: str,
    show_diff: bool,
    show_calc: bool,
) -> None:
    """Read IFR page from the device."""
    if show_calc:
        logger.warning(
            "Show calculated fields is obsolete function for configuration YAML files."
            " In case of debugging those values check the binary data."
        )
    ifr_obj = pfr.ROMCFG(family=family, revision=revision)
    ifr_page_address = ifr_obj.reg_config.get_address()
    ifr_page_length = ifr_obj.BINARY_SIZE
    ifr_page_name = ifr_obj.__class__.__name__

    click.echo(f"{ifr_page_name} page address on {family} is {ifr_page_address:#x}")

    interface = get_mboot_interface(
        port=port, usb=usb, buspal=buspal, lpcusbsio=lpcusbsio, timeout=timeout
    )
    assert isinstance(interface, MbootProtocolBase)
    with McuBoot(interface=interface) as mboot:
        data = mboot.read_memory(address=ifr_page_address, length=ifr_page_length)
    if not data:
        raise SPSDKError(f"Unable to read data from address {ifr_page_address:#x}")

    if output:
        write_file(data, output, "wb")
        click.echo(f"{ifr_page_name} data stored to {output}")
    if yaml_output:
        yaml_data = _parse_binary_data(
            data=data,
            family=family,
            revision=revision,
            show_diff=show_diff,
        )
        write_file(yaml_data, yaml_output)
        click.echo(f"Parsed config stored to {yaml_output}")
    if not output and not yaml_output:
        click.echo(format_raw_data(data=data, use_hexdump=True))


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
