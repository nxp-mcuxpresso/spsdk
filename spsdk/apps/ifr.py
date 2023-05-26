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

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    FC,
    CommandsTreeGroupAliasedGetCfgTemplate,
    isp_interfaces,
    spsdk_apps_common_options,
)
from spsdk.apps.utils.utils import catch_spsdk_error, format_raw_data, get_interface
from spsdk.exceptions import SPSDKError
from spsdk.mboot import McuBoot
from spsdk.mboot.interfaces.base import MBootInterface
from spsdk.pfr import pfr
from spsdk.pfr.exceptions import SPSDKPfrConfigError
from spsdk.pfr.pfr import ROMCFG
from spsdk.utils.misc import load_binary, size_fmt, write_file
from spsdk.utils.schema_validator import ConfigTemplate

logger = logging.getLogger(__name__)


def _parse_binary_data(
    data: bytes,
    device: str,
    revision: Optional[str] = None,
    show_calc: bool = False,
    show_diff: bool = False,
) -> str:
    """Parse binary data and extract YAML configuration.

    :param data: Data to parse
    :param device: Device to use
    :param revision: Revision to use, defaults to 'latest'
    :param show_calc: Also show calculated fields
    :param show_diff: Show only difference to default
    :return: IFR YAML configuration as a string
    """
    ifr_obj = ROMCFG(device=device, revision=revision)
    ifr_obj.parse(data)
    parsed = ifr_obj.get_yaml_config(exclude_computed=not show_calc, diff=show_diff)
    yaml_data = ConfigTemplate.convert_cm_to_yaml(parsed)
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
    spsdk_logger.install(level=log_level)
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
    type=click.Path(resolve_path=True),
    required=False,
    help="Save the output into a file instead of console",
)
@click.option("-f", "--full", is_flag=True, help="Show full config, including computed values")
def get_template(device: str, revision: str, output: str, full: bool) -> None:
    """Generate user configuration template file."""
    ifr_obj = ROMCFG(device=device, revision=revision)
    data = ifr_obj.get_yaml_config(not full)
    yaml_data = ConfigTemplate.convert_cm_to_yaml(data)
    _store_output(yaml_data, output, msg=f"IFR configuration template has been created.")


@main.command(name="parse-binary", no_args_is_help=True)
@ifr_device_type_options
@click.option(
    "-o",
    "--output",
    type=click.Path(resolve_path=True),
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
@click.option("-f", "--show-diff", is_flag=True, help="Show differences comparing to defaults")
def parse_binary(revision: str, output: str, binary: str, show_diff: bool, device: str) -> None:
    """Parse binary and extract configuration."""
    ifr_obj = ROMCFG(device=device, revision=revision)
    data = load_binary(binary)
    ifr_obj.parse(data)
    parsed = ifr_obj.get_yaml_config(exclude_computed=False, diff=show_diff)
    yaml_data = ConfigTemplate.convert_cm_to_yaml(parsed)
    _store_output(yaml_data, output, msg=f"Success. (IFR: {binary} has been parsed.")


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
    type=click.Path(exists=True, resolve_path=True),
    required=True,
    help="YAML/JSON file with user configuration",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(resolve_path=True),
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
    _store_output(data, output, "wb", msg=f"Success. (IFR binary has been generated)")


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
    device: str,
    revision: str,
    binary: str,
) -> None:
    """Write IFR page to the device."""
    ifr_obj = ROMCFG(device=device, revision=revision)
    ifr_page_address = ifr_obj.config.get_address(device)
    ifr_page_length = ifr_obj.BINARY_SIZE

    click.echo(f"{ifr_obj.__class__.__name__} page address on {device} is {ifr_page_address:#x}")

    data = load_binary(binary)
    if len(data) != ifr_page_length:
        raise SPSDKError(
            f"IFR page length is {ifr_page_length}. Provided binary has {size_fmt(len(data))}."
        )

    interface = get_interface(
        module="mboot", port=port, usb=usb, buspal=buspal, lpcusbsio=lpcusbsio, timeout=timeout
    )
    assert isinstance(interface, MBootInterface)
    with McuBoot(device=interface) as mboot:
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
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, resolve_path=True),
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
    "-f",
    "--show-diff",
    is_flag=True,
    help="(applicable for parsing) Show differences comparing to defaults",
)
@click.option(
    "-c",
    "--show-calc",
    is_flag=True,
    help="(applicable for parsing) Show also calculated fields when displaying difference to "
    "defaults (--show-diff)",
)
def read(
    port: str,
    usb: str,
    buspal: str,
    lpcusbsio: str,
    timeout: int,
    device: str,
    revision: str,
    output: str,
    yaml_output: str,
    show_diff: bool,
    show_calc: bool,
) -> None:
    """Read IFR page from the device."""
    ifr_obj = ROMCFG(device=device, revision=revision)
    ifr_page_address = ifr_obj.config.get_address(device)
    ifr_page_length = ifr_obj.BINARY_SIZE
    ifr_page_name = ifr_obj.__class__.__name__

    click.echo(f"{ifr_page_name} page address on {device} is {ifr_page_address:#x}")

    interface = get_interface(
        module="mboot", port=port, usb=usb, buspal=buspal, lpcusbsio=lpcusbsio, timeout=timeout
    )
    assert isinstance(interface, MBootInterface)
    with McuBoot(device=interface) as mboot:
        data = mboot.read_memory(address=ifr_page_address, length=ifr_page_length)
    if not data:
        raise SPSDKError(f"Unable to read data from address {ifr_page_address:#x}")

    if output:
        write_file(data, output, "wb")
        click.echo(f"{ifr_page_name} data stored to {output}")
    if yaml_output:
        yaml_data = _parse_binary_data(
            data=data,
            device=device,
            revision=revision,
            show_calc=show_calc,
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
