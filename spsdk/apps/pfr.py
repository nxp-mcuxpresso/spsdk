#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for pfr."""

import io
import logging
import os
import sys
from typing import Optional, Tuple, Type, Union

import click
from click_option_group import MutuallyExclusiveOptionGroup, optgroup
from ruamel.yaml import YAML

from spsdk import SPSDK_YML_INDENT, pfr
from spsdk.apps.elftosb_utils.sb_31_helper import RootOfTrustInfo
from spsdk.apps.utils.common_cli_options import (
    FC,
    CommandsTreeGroup,
    isp_interfaces,
    spsdk_apps_common_options,
)
from spsdk.apps.utils.utils import MBootInterface, catch_spsdk_error, format_raw_data, get_interface
from spsdk.crypto.loaders import extract_public_keys
from spsdk.mboot import McuBoot
from spsdk.pfr.exceptions import SPSDKError, SPSDKPfrConfigError
from spsdk.utils.misc import find_file, load_configuration, size_fmt

PFRArea = Union[Type[pfr.CMPA], Type[pfr.CFPA]]
logger = logging.getLogger(__name__)


def _store_output(data: Union[str, bytes], path: Optional[str], mode: str = "w") -> None:
    """Store the output data; either on stdout or into file if it's provided."""
    if path is None:
        click.echo(data)
    else:
        with open(path, mode) as f:
            f.write(data)


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


@click.group(name="pfr", no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> int:
    """Utility for generating and parsing Protected Flash Region data (CMPA, CFPA)."""
    logging.basicConfig(level=log_level or logging.WARNING)
    return 0


@main.command(name="get-cfg-template", no_args_is_help=True)
@pfr_device_type_options
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    required=False,
    help="Save the output into a file instead of console",
)
@click.option("-f", "--full", is_flag=True, help="Show full config, including computed values")
def get_cfg_template(device: str, revision: str, area: str, output: str, full: bool) -> None:
    """Generate user configuration template file."""
    pfr_obj = _get_pfr_class(area)(device=device, revision=revision)
    yaml = YAML(pure=True)
    yaml.indent(sequence=SPSDK_YML_INDENT * 2, offset=SPSDK_YML_INDENT)
    data = pfr_obj.get_yaml_config(not full)
    stream = io.StringIO()
    yaml.dump(data, stream)
    yaml_data = stream.getvalue()
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
    pfr_obj = _get_pfr_class(area)(device=device, revision=revision)
    with open(binary, "rb") as f:
        data = f.read()
    pfr_obj.parse(data)
    parsed = pfr_obj.get_yaml_config(exclude_computed=not show_calc, diff=show_diff)
    yaml = YAML()
    yaml.indent(sequence=4, offset=2)
    stream = io.StringIO()
    yaml.dump(parsed, stream)
    yaml_data = stream.getvalue()
    _store_output(yaml_data, output)


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
def generate_binary(
    output: str,
    user_config_file: str,
    add_seal: bool,
    calc_inverse: bool,
    elf2sb_config: str,
    secret_file: Tuple[str],
    password: str,
) -> None:
    """Generate binary data."""
    pfr_config = pfr.PfrConfiguration(user_config_file)
    invalid_reason = pfr_config.is_invalid()
    if invalid_reason:
        raise SPSDKPfrConfigError(
            f"The configuration file is not valid. The reason is: {invalid_reason}"
        )
    assert pfr_config.type
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
    area = pfr_config.type
    if area.lower() == "cmpa" and root_of_trust:
        keys = extract_public_keys(root_of_trust, password)
    pfr_obj = _get_pfr_class(area)(device=pfr_config.device, revision=pfr_config.revision)
    if not pfr_config.revision:
        pfr_config.revision = pfr_obj.revision
    pfr_obj.set_config(pfr_config, raw=not calc_inverse)

    data = pfr_obj.export(add_seal=add_seal, keys=keys)
    _store_output(data, output, "wb")


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
@isp_interfaces(uart=True, usb=True, lpcusbsio=True, buspal=True, json_option=False)
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
    # silence warning about missing revision in 'normal' logging mode
    if not logger.isEnabledFor(logging.INFO):
        pfr_logger = logging.getLogger("spsdk.pfr")
        pfr_logger.setLevel(level=logging.ERROR)

    pfr_obj = _get_pfr_class(area)(device=device, revision=revision)
    pfr_page_address = int(pfr_obj.config.get_address(device), 0)
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
@isp_interfaces(uart=True, usb=True, lpcusbsio=True, buspal=True, json_option=False)
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
@click.pass_context
def read(
    ctx: click.Context,
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
    # silence warning about missing revision in 'normal' logging mode
    if not logger.isEnabledFor(logging.INFO):
        pfr_logger = logging.getLogger("spsdk.pfr")
        pfr_logger.setLevel(level=logging.ERROR)

    pfr_obj = _get_pfr_class(area)(device=device, revision=revision)
    pfr_page_address = int(pfr_obj.config.get_address(device), 0)
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
        with open(output, "wb") as f:
            f.write(data)
        click.echo(f"{pfr_page_name} data stored to {output}")
        if yaml_output:
            ctx.invoke(
                parse_binary,
                device=device,
                revision=revision,
                area=area,
                output=yaml_output,
                binary=output,
                show_calc=show_calc,
                show_diff=show_diff,
            )
            click.echo(f"Parsed config stored to {yaml_output}")
    else:
        click.echo(format_raw_data(data=data, use_hexdump=True))


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
