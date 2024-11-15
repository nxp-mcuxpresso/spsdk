#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for ifr."""

import logging
import sys
from typing import Callable

import click

from spsdk.apps.pfr import _parse_binary_data, _store_output
from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    FC,
    CommandsTreeGroup,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_mboot_interface,
    spsdk_output_option,
    spsdk_revision_option,
)
from spsdk.apps.utils.utils import (
    SPSDKAppError,
    catch_spsdk_error,
    deprecated_option_warning,
    format_raw_data,
)
from spsdk.exceptions import SPSDKError
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.pfr import pfr
from spsdk.pfr.exceptions import SPSDKPfrError
from spsdk.utils.misc import (
    get_printable_path,
    load_binary,
    load_configuration,
    size_fmt,
    write_file,
)
from spsdk.utils.schema_validator import CommentedConfig

logger = logging.getLogger(__name__)


def ifr_device_type_options(no_type: bool = False) -> Callable:
    """IFR common device click options.

    :param no_type: If true, the type option is not added, defaults to False
    :return: Click decorator
    """

    def decorator(options: Callable[[FC], FC]) -> Callable[[FC], FC]:
        """Setup IFR options for device, revision and sector."""
        options = click.option(
            "-r",
            "--revision",
            help="Chip revision; if not specified, most recent one will be used",
            default="latest",
        )(options)
        if not no_type:
            options = click.option(
                "-s",
                "--sector",
                "sector",
                required=False,
                type=click.Choice(["ROMCFG", "CMACTable"], case_sensitive=False),
                default="ROMCFG",
                help="Select IFR sector",
            )(options)
        return options

    return decorator


@click.group(name="ifr", no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> int:
    """Utility for generating and parsing IFR. Please note that IFR0 ROMCFG region is one-time-programmable only."""
    spsdk_logger.install(level=log_level)
    return 0


@main.command(name="get-template", no_args_is_help=True)
@spsdk_family_option(pfr.ROMCFG.get_supported_families())
@spsdk_output_option(
    required=False,
    force=True,
    help="Save the output into a file instead of console",
)
@ifr_device_type_options()
@click.option("--full", is_flag=True, help="Show full config, including computed values")
def get_template(family: str, revision: str, sector: str, output: str, full: bool) -> None:
    """Generate user configuration template file."""
    if full:
        deprecated_option_warning("full")
    ifr_cls = pfr.get_ifr_pfr_class(sector, family)
    schemas = ifr_cls.get_validation_schemas(family=family, revision=revision)
    yaml_data = CommentedConfig("IFR configuration template", schemas).get_template()
    _store_output(
        yaml_data,
        output,
        msg=f"The IFR template for {family} has been saved into {get_printable_path(output)} YAML file",
    )


@main.command(name="parse-binary", no_args_is_help=True)
@spsdk_family_option(pfr.ROMCFG.get_supported_families())
@ifr_device_type_options()
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
def parse_binary(
    revision: str, output: str, binary: str, sector: str, show_diff: bool, family: str
) -> None:
    """Parse binary and extract configuration."""
    yaml_data = _parse_binary_data(
        data=load_binary(binary),
        family=family,
        revision=revision,
        area=sector,
        show_diff=show_diff,
    )
    _store_output(
        yaml_data, output, msg=f"Success. (IFR: {get_printable_path(binary)} has been parsed."
    )


@main.command(name="generate-binary", no_args_is_help=True)
@spsdk_family_option(families=pfr.ROMCFG.get_supported_families())
@spsdk_revision_option
@spsdk_config_option()
@spsdk_output_option(
    required=False,
    help="Save the output into a file instead of console",
)
def generate_binary(output: str, config: str, family: str, revision: str) -> None:
    """Generate binary data."""
    if family:
        deprecated_option_warning("family")
    if revision:
        deprecated_option_warning("revision")
    ifr_config = load_configuration(str(config))
    description = ifr_config.get("description")
    area: str = ifr_config.get("type", description["type"] if description else "Invalid")
    if description:
        family = description["device"]
    else:
        family = ifr_config.get("family", ifr_config.get("device", family))
    ifr_cls = pfr.get_ifr_pfr_class(area_name=area, family=family)
    ifr_cls.validate_config(ifr_config)
    ifr_obj = ifr_cls.load_from_config(ifr_config)
    data = ifr_obj.export()
    _store_output(data, output, "wb", msg="Success. (IFR binary has been generated)")


@main.command(name="write", no_args_is_help=True)
@spsdk_mboot_interface(use_long_timeout_form=True, identify_by_family=True)
@spsdk_family_option(pfr.ROMCFG.get_supported_families())
@ifr_device_type_options()
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    help="Path to IFR data to write.",
)
@click.option(
    "-y",
    "--yaml",
    "yaml_config",
    type=click.Path(dir_okay=False, resolve_path=True),
    help="Path to the PFR YAML config to write.",
)
def write(
    interface: MbootProtocolBase,
    family: str,
    revision: str,
    binary: str,
    sector: str,
    yaml_config: str,
) -> None:
    """Write IFR page to the device."""
    if not binary and not yaml_config:
        raise SPSDKPfrError("The path to the IFR data file was not specified!")
    data = b""
    if binary:
        ifr_obj = pfr.get_ifr_pfr_class(sector, family)(family=family, revision=revision)
        data = load_binary(binary)
    elif yaml_config:
        cfg = load_configuration(yaml_config)
        description = cfg.get("description")
        cfg_area: str = cfg.get("type", description["type"] if description else "Invalid")
        if sector.lower() != cfg_area.lower():
            raise SPSDKAppError(
                "Configuration area doesn't match CLI value and configuration value."
            )
        ifr_cls = pfr.get_ifr_pfr_class(sector, family)
        ifr_cls.validate_config(cfg)
        ifr_obj = ifr_cls.load_from_config(cfg)
        if family != ifr_obj.family:
            raise SPSDKAppError("Family in configuration doesn't match family from CLI.")
        data = ifr_obj.export()
    ifr_page_address = ifr_obj.db.get_int(ifr_obj.FEATURE_NAME, [ifr_obj.DB_SUB_FEATURE, "address"])
    ifr_page_length = ifr_obj.BINARY_SIZE

    click.echo(f"{ifr_obj.__class__.__name__} page address on {family} is {ifr_page_address:#x}")

    if len(data) != ifr_page_length:
        raise SPSDKError(
            f"IFR page length is {ifr_page_length}. Provided binary has {size_fmt(len(data))}."
        )

    with McuBoot(interface=interface) as mboot:
        mboot.write_memory(address=ifr_page_address, data=data)
    click.echo(
        f"{ifr_obj.__class__.__name__} data {'written to device.' if mboot.status_code == 0 else 'write failed!'}"
    )


@main.command(name="read", no_args_is_help=True)
@spsdk_mboot_interface(use_long_timeout_form=True)
@spsdk_family_option(pfr.ROMCFG.get_supported_families())
@ifr_device_type_options()
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
def read(
    interface: MbootProtocolBase,
    family: str,
    revision: str,
    sector: str,
    output: str,
    yaml_output: str,
    show_diff: bool,
) -> None:
    """Read IFR page from the device."""
    ifr_obj = pfr.get_ifr_pfr_class(sector, family)(family=family, revision=revision)
    ifr_page_address = ifr_obj.db.get_int(ifr_obj.FEATURE_NAME, [ifr_obj.DB_SUB_FEATURE, "address"])
    ifr_page_length = ifr_obj.BINARY_SIZE
    ifr_page_name = ifr_obj.__class__.__name__

    click.echo(f"{ifr_page_name} page address on {family} is {ifr_page_address:#x}")

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
            area=sector,
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
