#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for pfr."""

import logging
import os
import sys
from typing import Optional, Tuple, Type, Union

import click
from click_option_group import MutuallyExclusiveOptionGroup, optgroup

from spsdk import pfr
from spsdk.apps.elftosb_utils.sb_31_helper import RootOfTrustInfo
from spsdk.apps.utils.common_cli_options import (
    FC,
    CommandsTreeGroupAliasedGetCfgTemplate,
    isp_interfaces,
    spsdk_apps_common_options,
)
from spsdk.apps.utils.utils import MBootInterface, catch_spsdk_error, format_raw_data, get_interface
from spsdk.crypto.loaders import extract_public_keys
from spsdk.mboot import McuBoot
from spsdk.pfr.exceptions import SPSDKError, SPSDKPfrConfigError, SPSDKPfrError
from spsdk.pfr.pfrc import Pfrc
from spsdk.utils.misc import find_file, load_configuration, size_fmt, write_file
from spsdk.utils.schema_validator import ConfigTemplate

PFRArea = Union[Type[pfr.CMPA], Type[pfr.CFPA]]
logger = logging.getLogger(__name__)


def _store_output(data: Union[str, bytes], path: Optional[str], mode: str = "w") -> None:
    """Store the output data; either on stdout or into file if it's provided."""
    if path is None:
        click.echo(data)
    else:
        write_file(data, path=path, mode=mode)


def _get_pfr_class(area_name: str) -> PFRArea:
    """Return CMPA/CFPA class based on the name."""
    return getattr(pfr, area_name.upper())


def pfr_device_type_options(options: FC) -> FC:
    """Setup PFR options for device, revision and area (PFR page type)."""
    options = click.option(
        "-r",
        "--revision",
        help="Chip revision; if not specified, most recent one will be used",
    )(options)
    options = click.option(
        "-d",
        "--device",
        type=click.Choice(pfr.CMPA.devices()),
        help="Device to use",
        required=True,
    )(options)
    options = click.option(
        "-t",
        "--type",
        "area",
        required=True,
        type=click.Choice(["cmpa", "cfpa"]),
        help="Select PFR partition",
    )(options)
    return options


@click.group(name="pfr", no_args_is_help=True, cls=CommandsTreeGroupAliasedGetCfgTemplate)
@spsdk_apps_common_options
def main(log_level: int) -> int:
    """Utility for generating and parsing Protected Flash Region data (CMPA, CFPA)."""
    logging.basicConfig(level=log_level or logging.WARNING)
    return 0


@main.command(name="get-template", no_args_is_help=True)
@pfr_device_type_options
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    required=False,
    help="Save the output into a file instead of console",
)
@click.option("-f", "--full", is_flag=True, help="Show full config, including computed values")
def get_template(device: str, revision: str, area: str, output: str, full: bool) -> None:
    """Generate user configuration template file."""
    pfr_obj = _get_pfr_class(area)(device=device, revision=revision)
    data = pfr_obj.get_yaml_config(not full)
    yaml_data = ConfigTemplate.convert_cm_to_yaml(data)
    _store_output(yaml_data, output)


@main.command(name="parse-binary", no_args_is_help=True)
@pfr_device_type_options
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False),
    required=False,
    help="Save the output into a file instead of console",
)
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Binary to parse",
)
@click.option(
    "-f",
    "--show-diff",
    is_flag=True,
    help="Show differences comparing to defaults",
)
@click.option(
    "-c",
    "--show-calc",
    is_flag=True,
    help="Show also calculated fields when displaying difference to " "defaults (--show-diff)",
)
def parse_binary(
    device: str,
    revision: str,
    area: str,
    output: str,
    binary: str,
    show_calc: bool,
    show_diff: bool,
) -> None:
    """Parse binary and extract configuration."""
    with open(binary, "rb") as f:
        data = f.read()
    yaml_data = _parse_binary_data(
        data=data,
        device=device,
        revision=revision,
        area=area,
        show_calc=show_calc,
        show_diff=show_diff,
    )
    _store_output(yaml_data, output)
    click.echo(f"Success. (PFR: {binary} has been parsed and stored into {output}.)")


def _parse_binary_data(
    data: bytes,
    device: str,
    area: str,
    revision: Optional[str] = None,
    show_calc: bool = False,
    show_diff: bool = False,
) -> str:
    """Parse binary data and extract YAML configuration.

    :param data: Data to parse
    :param device: Device to use
    :param revision: Revision to use, defaults to 'latest'
    :param area: PFR are (CMPA, CFPA)
    :param show_calc: Also show calculated fields
    :param show_diff: Show only difference to default
    :return: PFR YAML configuration as a string
    """
    pfr_obj = _get_pfr_class(area)(device=device, revision=revision)
    pfr_obj.parse(data)
    parsed = pfr_obj.get_yaml_config(exclude_computed=not show_calc, diff=show_diff)
    yaml_data = ConfigTemplate.convert_cm_to_yaml(parsed)
    return yaml_data


@main.command(name="generate-binary", no_args_is_help=True)
@optgroup.group("Root Of Trust Configuration", cls=MutuallyExclusiveOptionGroup)
@optgroup.option(
    "-e",
    "--elf2sb-config",
    type=click.Path(exists=True, dir_okay=False),
    help="Specify Root Of Trust from configuration file used by elf2sb tool",
)
@optgroup.option(
    "-f",
    "--secret-file",
    type=click.Path(exists=True, dir_okay=False),
    multiple=True,
    help="Secret file (certificate, public key, private key); can be defined multiple times",
)
@click.option(
    "-c",
    "--user-config",
    "user_config_file",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="YAML/JSON file with user configuration",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False),
    required=True,
    help="Save the output into a file instead of console",
)
@click.option("-a", "--add-seal", is_flag=True, help="Add seal mark digest at the end.")
@click.option(
    "-i",
    "--calc-inverse",
    is_flag=True,
    help="Calculate the INVERSE values CAUTION!!! It locks the settings",
)
@click.option(
    "-p",
    "--password",
    help="Password when using Encrypted private keys as --secret-file",
)
@click.option(
    "-x",
    "--force",
    is_flag=True,
    default=False,
    help="Force to generate binary even the config validation fails.",
)
def generate_binary(
    output: str,
    user_config_file: str,
    add_seal: bool,
    calc_inverse: bool,
    elf2sb_config: str,
    secret_file: Tuple[str],
    password: str,
    force: bool,
) -> None:
    """Generate binary data."""
    pfr_config = pfr.PfrConfiguration(user_config_file)
    invalid_reason = pfr_config.is_invalid()
    if invalid_reason:
        raise SPSDKPfrConfigError(
            f"The configuration file is not valid. The reason is: {invalid_reason}"
        )
    area = pfr_config.type
    assert area
    pfr_obj = _get_pfr_class(area)(device=pfr_config.device, revision=pfr_config.revision)
    pfr_obj.set_config(pfr_config, raw=not calc_inverse)
    if pfr_config.device in Pfrc.get_supported_families():
        try:
            pfrc = Pfrc(
                cmpa=pfr_obj if area.lower() == "cmpa" else None,  # type: ignore
                cfpa=pfr_obj if area.lower() == "cfpa" else None,  # type: ignore
            )
            rules = pfrc.validate_brick_conditions()
        except (SPSDKPfrConfigError, SPSDKPfrError) as e:
            logger.debug(f"PFRC unexpectedly failed: {e}")
        else:
            log_text = f"PFRC results: passed: {len(rules[0])}, failed: {len(rules[1])}, ignored: {len(rules[2])}"
            if rules[1]:
                if force:
                    logger.warning(log_text)
                else:
                    raise SPSDKError(log_text)
            else:
                logger.debug(log_text)
    root_of_trust = None
    keys = None
    if elf2sb_config:
        elf2sb_config_dir = os.path.dirname(elf2sb_config)
        public_keys = RootOfTrustInfo(
            load_configuration(elf2sb_config), search_paths=[elf2sb_config_dir]
        ).public_keys
        root_of_trust = tuple((find_file(x, search_paths=[elf2sb_config_dir]) for x in public_keys))
    if secret_file:
        root_of_trust = secret_file
    if area.lower() == "cmpa" and root_of_trust:
        keys = extract_public_keys(root_of_trust, password)
    if not pfr_config.revision:
        pfr_config.revision = pfr_obj.revision
    data = pfr_obj.export(add_seal=add_seal, keys=keys)
    _store_output(data, output, "wb")
    click.echo(f"Success. (PFR binary has been generated into {output}.)")


@main.command(name="info", no_args_is_help=True)
@pfr_device_type_options
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False),
    required=True,
    help="Save the output into a file instead of console",
)
@click.option(
    "-p",
    "--open",
    "open_result",
    is_flag=True,
    help="Open the generated description file",
)
def info(device: str, revision: str, area: str, output: str, open_result: bool) -> None:
    """Generate HTML page with brief description of CMPA/CFPA configuration fields."""
    pfr_obj = _get_pfr_class(area)(device=device, revision=revision)
    html_output = pfr_obj.registers.generate_html(
        f"{device.upper()} - {area.upper()}",
        pfr_obj.DESCRIPTION,
        regs_exclude=["SHA256_DIGEST"],
        fields_exclude=["FIELD"],
    )
    _store_output(html_output, output)
    if open_result:  # pragma: no cover # can't test opening the html document
        click.launch(f"{output}")


@main.command(name="devices", no_args_is_help=False)
def devices() -> None:
    """List supported devices."""
    click.echo("\n".join(pfr.CMPA.devices()))


@main.command(name="write", no_args_is_help=True)
@isp_interfaces(
    uart=True,
    usb=True,
    lpcusbsio=True,
    buspal=True,
    json_option=False,
    use_long_timeout_option=True,
)
@pfr_device_type_options
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to PFR data to write.",
)
def write(
    port: str,
    usb: str,
    buspal: str,
    lpcusbsio: str,
    timeout: int,
    device: str,
    revision: str,
    area: str,
    binary: str,
) -> None:
    """Write PFR page to the device."""
    pfr_obj = _get_pfr_class(area)(device=device, revision=revision)
    pfr_page_address = pfr_obj.config.get_address(device)
    pfr_page_length = pfr_obj.BINARY_SIZE

    click.echo(f"{pfr_obj.__class__.__name__} page address on {device} is {pfr_page_address:#x}")

    with open(binary, "rb") as f:
        data = f.read()
    if len(data) != pfr_page_length:
        raise SPSDKError(
            f"PFR page length is {pfr_page_length}. Provided binary has {size_fmt(len(data))}."
        )

    interface = get_interface(
        module="mboot", port=port, usb=usb, buspal=buspal, lpcusbsio=lpcusbsio, timeout=timeout
    )
    assert isinstance(interface, MBootInterface)
    with McuBoot(device=interface) as mboot:
        mboot.write_memory(address=pfr_page_address, data=data)
    click.echo(
        f"{pfr_obj.__class__.__name__} data {'written to device.' if mboot.status_code == 0 else 'write failed!'}"
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
@pfr_device_type_options
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False),
    help="Store PFR data into a file. If not specified hexdump data into stdout.",
)
@click.option(
    "-y",
    "--yaml",
    "yaml_output",
    type=click.Path(dir_okay=False),
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
    area: str,
    output: str,
    yaml_output: str,
    show_diff: bool,
    show_calc: bool,
) -> None:
    """Read PFR page from the device."""
    pfr_obj = _get_pfr_class(area)(device=device, revision=revision)
    pfr_page_address = pfr_obj.config.get_address(device)
    pfr_page_length = pfr_obj.BINARY_SIZE
    pfr_page_name = pfr_obj.__class__.__name__

    click.echo(f"{pfr_page_name} page address on {device} is {pfr_page_address:#x}")

    interface = get_interface(
        module="mboot", port=port, usb=usb, buspal=buspal, lpcusbsio=lpcusbsio, timeout=timeout
    )
    assert isinstance(interface, MBootInterface)
    with McuBoot(device=interface) as mboot:
        data = mboot.read_memory(address=pfr_page_address, length=pfr_page_length)
    if not data:
        raise SPSDKError(f"Unable to read data from address {pfr_page_address:#x}")

    if output:
        write_file(data, output, "wb")
        click.echo(f"{pfr_page_name} data stored to {output}")
    if yaml_output:
        yaml_data = _parse_binary_data(
            data=data,
            device=device,
            revision=revision,
            area=area,
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
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
