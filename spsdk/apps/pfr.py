#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for pfr."""

import logging
import sys
from typing import Callable, Optional, Tuple, Type, Union

import click
from click_option_group import MutuallyExclusiveOptionGroup, optgroup

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
from spsdk.crypto.utils import extract_public_keys
from spsdk.exceptions import SPSDKError
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.mboot.scanner import get_mboot_interface
from spsdk.pfr import pfr
from spsdk.pfr.exceptions import SPSDKPfrConfigError, SPSDKPfrError
from spsdk.pfr.pfr import CFPA, CMPA, PfrConfiguration
from spsdk.pfr.pfrc import Pfrc
from spsdk.utils.crypto.cert_blocks import get_keys_or_rotkh_from_certblock_config
from spsdk.utils.misc import load_binary, size_fmt, write_file
from spsdk.utils.schema_validator import CommentedConfig

PFRArea = Union[Type[CMPA], Type[CFPA]]
logger = logging.getLogger(__name__)


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


def _get_pfr_class(area_name: str) -> PFRArea:
    """Return CMPA/CFPA class based on the name."""
    return getattr(pfr, area_name.upper())


def pfr_device_type_options(no_type: bool = False) -> Callable:
    """PFR common device click options.

    :param no_type: If true, the type option is not added, defaults to False
    :return: Click decorator
    """

    def decorator(options: Callable[[FC], FC]) -> Callable[[FC], FC]:
        """Setup PFR options for device, revision and area (PFR page type)."""
        options = click.option(
            "-r",
            "--revision",
            help="Chip revision; if not specified, most recent one will be used",
        )(options)
        options = click.option(
            "-f",
            "--family",
            type=click.Choice(CMPA.devices()),
            help="Device to use",
            required=True,
        )(options)
        if not no_type:
            options = click.option(
                "-t",
                "--type",
                "area",
                required=True,
                type=click.Choice(["cmpa", "cfpa"]),
                help="Select PFR partition",
            )(options)
        return options

    return decorator


@click.group(name="pfr", no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> int:
    """Utility for generating and parsing Protected Flash Region data (CMPA, CFPA)."""
    spsdk_logger.install(level=log_level)
    return 0


@main.command(name="get-template", no_args_is_help=True)
@pfr_device_type_options()
@spsdk_output_option(force=True)
@click.option("--full", is_flag=True, help="Show full config, including computed values")
def get_template(family: str, revision: str, area: str, output: str, full: bool) -> None:
    """Generate user configuration template file."""
    pfr_obj = _get_pfr_class(area)(device=family, revision=revision)
    data = pfr_obj.get_yaml_config(not full)
    yaml_data = CommentedConfig.convert_cm_to_yaml(data)
    _store_output(yaml_data, output, msg=f"PFR {area} configuration template has been created.")


@main.command(name="parse-binary", no_args_is_help=True)
@pfr_device_type_options()
@spsdk_output_option(required=False)
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    required=True,
    help="Binary to parse",
)
@click.option(
    "-d",
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
    family: str,
    revision: str,
    area: str,
    output: str,
    binary: str,
    show_calc: bool,
    show_diff: bool,
) -> None:
    """Parse binary and extract configuration."""
    data = load_binary(binary)
    yaml_data = _parse_binary_data(
        data=data,
        device=family,
        revision=revision,
        area=area,
        show_calc=show_calc,
        show_diff=show_diff,
    )
    _store_output(yaml_data, output, msg=f"Success. (PFR: {binary} has been parsed.")


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
    yaml_data = CommentedConfig.convert_cm_to_yaml(parsed)
    return yaml_data


@main.command(name="generate-binary", no_args_is_help=True)
@optgroup.group("Root Of Trust Configuration", cls=MutuallyExclusiveOptionGroup)
@optgroup.option(
    "-e",
    "--rot-config",
    type=click.Path(exists=True, dir_okay=False),
    help="Specify Root Of Trust from MBI or Cert block configuration file",
)
@optgroup.option(
    "-sf",
    "--secret-file",
    type=click.Path(exists=True, dir_okay=False),
    multiple=True,
    help="Secret file (certificate, public key, private key); can be defined multiple times",
)
@spsdk_config_option()
@spsdk_output_option()
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
    config: str,
    add_seal: bool,
    calc_inverse: bool,
    rot_config: str,
    secret_file: Tuple[str],
    password: str,
    force: bool,
) -> None:
    """Generate binary data."""
    pfr_config = PfrConfiguration(config)
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
    keys = None
    root_of_trust, rotkh = get_keys_or_rotkh_from_certblock_config(rot_config, pfr_config.device)
    if secret_file:
        root_of_trust = secret_file
    if area.lower() == "cmpa" and root_of_trust:
        keys = extract_public_keys(root_of_trust, password)
    if not pfr_config.revision:
        pfr_config.revision = pfr_obj.revision
    data = pfr_obj.export(add_seal=add_seal, keys=keys, rotkh=rotkh)
    _store_output(data, output, "wb", msg="Success. (PFR binary has been generated)")


@main.command(name="info", no_args_is_help=True)
@pfr_device_type_options()
@spsdk_output_option()
@click.option(
    "-p",
    "--open",
    "open_result",
    is_flag=True,
    help="Open the generated description file",
)
def info(family: str, revision: str, area: str, output: str, open_result: bool) -> None:
    """Generate HTML page with brief description of CMPA/CFPA configuration fields."""
    pfr_obj = _get_pfr_class(area)(device=family, revision=revision)
    html_output = pfr_obj.registers.generate_html(
        f"{family.upper()} - {area.upper()}",
        pfr_obj.DESCRIPTION,
        regs_exclude=["SHA256_DIGEST"],
        fields_exclude=["FIELD"],
    )
    _store_output(html_output, output, msg="Success. (PFR info HTML page has been generated)")
    if open_result:  # pragma: no cover # can't test opening the html document
        click.launch(f"{output}")


@main.command(name="write", no_args_is_help=True)
@isp_interfaces(
    uart=True,
    usb=True,
    lpcusbsio=True,
    buspal=True,
    json_option=False,
    use_long_timeout_option=True,
)
@pfr_device_type_options()
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
    family: str,
    revision: str,
    area: str,
    binary: str,
) -> None:
    """Write PFR page to the device."""
    pfr_obj = _get_pfr_class(area)(device=family, revision=revision)
    pfr_page_address = pfr_obj.config.get_address(family)
    pfr_page_length = pfr_obj.BINARY_SIZE

    click.echo(f"{pfr_obj.__class__.__name__} page address on {family} is {pfr_page_address:#x}")

    data = load_binary(binary)
    if len(data) != pfr_page_length:
        raise SPSDKError(
            f"PFR page length is {pfr_page_length}. Provided binary has {size_fmt(len(data))}."
        )

    interface = get_mboot_interface(
        port=port, usb=usb, buspal=buspal, lpcusbsio=lpcusbsio, timeout=timeout
    )
    assert isinstance(interface, MbootProtocolBase)
    with McuBoot(interface=interface) as mboot:
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
@pfr_device_type_options()
@spsdk_output_option(
    required=False,
    help="Store PFR data into a file. If not specified hexdump data into stdout.",
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
    area: str,
    output: str,
    yaml_output: str,
    show_diff: bool,
    show_calc: bool,
) -> None:
    """Read PFR page from the device."""
    pfr_obj = _get_pfr_class(area)(device=family, revision=revision)
    pfr_page_address = pfr_obj.config.get_address(family)
    pfr_page_length = pfr_obj.BINARY_SIZE
    pfr_page_name = pfr_obj.__class__.__name__

    click.echo(f"{pfr_page_name} page address on {family} is {pfr_page_address:#x}")

    interface = get_mboot_interface(
        port=port, usb=usb, buspal=buspal, lpcusbsio=lpcusbsio, timeout=timeout
    )
    assert isinstance(interface, MbootProtocolBase)
    with McuBoot(interface=interface) as mboot:
        data = mboot.read_memory(address=pfr_page_address, length=pfr_page_length)
    if not data:
        raise SPSDKError(f"Unable to read data from address {pfr_page_address:#x}")

    if output:
        write_file(data, output, "wb")
        click.echo(f"{pfr_page_name} data stored to {output}")
    if yaml_output:
        yaml_data = _parse_binary_data(
            data=data,
            device=family,
            revision=revision,
            area=area,
            show_calc=show_calc,
            show_diff=show_diff,
        )
        write_file(yaml_data, yaml_output)
        click.echo(f"Parsed config stored to {yaml_output}")
    if not output and not yaml_output:
        click.echo(format_raw_data(data=data, use_hexdump=True))


@main.command(name="erase-cmpa", no_args_is_help=True)
@isp_interfaces(
    uart=True,
    usb=True,
    lpcusbsio=True,
    buspal=True,
    json_option=False,
    use_long_timeout_option=True,
)
@pfr_device_type_options(no_type=True)
def erase_cmpa(
    port: str,
    usb: str,
    buspal: str,
    lpcusbsio: str,
    timeout: int,
    family: str,
    revision: str,
) -> None:
    """Erase CMPA PFR page in the device if is not sealed."""
    pfr_obj = _get_pfr_class("cmpa")(device=family, revision=revision)
    pfr_page_address = pfr_obj.config.get_address(family)
    pfr_page_length = pfr_obj.BINARY_SIZE

    click.echo(f"CMPA page address on {family} is {pfr_page_address:#x}")

    interface = get_mboot_interface(
        port=port, usb=usb, buspal=buspal, lpcusbsio=lpcusbsio, timeout=timeout
    )
    assert isinstance(interface, MbootProtocolBase)
    with McuBoot(interface=interface) as mboot:
        mboot.write_memory(address=pfr_page_address, data=bytes(pfr_page_length))
    click.echo(f"CMPA page {'has been erased.' if mboot.status_code == 0 else 'erase failed!'}")


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
