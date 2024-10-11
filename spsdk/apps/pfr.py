#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for pfr."""

import logging
import sys
from typing import Callable, Optional, Type, Union

import click
from click_option_group import MutuallyExclusiveOptionGroup, optgroup

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    FC,
    CommandsTreeGroup,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_mboot_interface,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import SPSDKAppError, catch_spsdk_error, format_raw_data
from spsdk.crypto.utils import extract_public_keys
from spsdk.exceptions import SPSDKError
from spsdk.mboot.exceptions import McuBootError
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.pfr.exceptions import SPSDKPfrConfigError, SPSDKPfrError
from spsdk.pfr.pfr import CFPA, CMPA, BaseConfigArea, get_ifr_pfr_class
from spsdk.pfr.pfrc import Pfrc
from spsdk.utils.crypto.cert_blocks import get_keys_or_rotkh_from_certblock_config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.misc import (
    get_printable_path,
    load_binary,
    load_configuration,
    size_fmt,
    write_file,
)
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
        if msg is None:
            click.echo(f"Result has been stored in: {get_printable_path(path)}")
        write_file(data, path=path, mode=mode)


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
            default="latest",
        )(options)
        if not no_type:
            options = click.option(
                "-t",
                "--type",
                "area",
                required=True,
                type=click.Choice(["cmpa", "cfpa"], case_sensitive=False),
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
@spsdk_family_option(CMPA.get_supported_families())
@pfr_device_type_options()
@spsdk_output_option(force=True)
@click.option(
    "--full", is_flag=True, hidden=True, help="Show full config, including computed values"
)
def get_template(family: str, revision: str, area: str, output: str, full: bool) -> None:
    """Generate user configuration template file."""
    if full:
        logger.warning("The computed values are not part of configuration of PFR anymore.")
    pfr_cls = get_ifr_pfr_class(area, family)
    schemas = pfr_cls.get_validation_schemas(family=family, revision=revision)
    yaml_data = CommentedConfig(
        f"PFR {area.upper()} configuration template", schemas
    ).get_template()
    _store_output(
        yaml_data,
        output,
        msg=f"The PFR {area} template for {family} has been saved into {get_printable_path(output)} YAML file",
    )


@main.command(name="parse-binary", no_args_is_help=True)
@spsdk_family_option(CMPA.get_supported_families())
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
    hidden=True,
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
    if show_calc:
        logger.warning(
            "Show calculated fields is obsolete function for configuration YAML files."
            " In case of debugging those values check the binary data."
        )
    data = load_binary(binary)
    yaml_data = _parse_binary_data(
        data=data,
        family=family,
        revision=revision,
        area=area,
        show_diff=show_diff,
    )
    _store_output(
        yaml_data, output, msg=f"Success. (PFR: {get_printable_path(binary)} has been parsed."
    )


def _parse_binary_data(
    data: bytes,
    family: str,
    area: str,
    revision: str = "latest",
    show_diff: bool = False,
) -> str:
    """Parse binary data and extract YAML configuration.

    :param data: Data to parse
    :param family: Device to use
    :param revision: Revision to use, defaults to 'latest'
    :param area: PFR are (CMPA, CFPA)
    :param show_calc: Also show calculated fields
    :param show_diff: Show only difference to default
    :return: PFR YAML configuration as a string
    """
    pfr_obj = get_ifr_pfr_class(area, family)(family=family, revision=revision)
    pfr_obj.parse(data)
    parsed = pfr_obj.get_config(diff=show_diff)
    schemas = pfr_obj.get_validation_schemas(family)
    yaml_data = CommentedConfig(
        f"PFR/IFR {area.upper()} configuration from parsed binary", schemas=schemas
    ).get_config(parsed)
    return yaml_data


@main.command(name="generate-binary", no_args_is_help=True)
@optgroup.group("Root Of Trust Configuration", cls=MutuallyExclusiveOptionGroup)
@optgroup.option(
    "-e",
    "--rot-config",
    type=click.Path(exists=True, dir_okay=False),
    help="Specify Root Of Trust from MBI or Cert block configuration file/binary file",
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
    hidden=True,
    help="Calculate the INVERSE values CAUTION!!! It locks the settings",
)
@click.option(
    "-p",
    "--password",
    help="Password when using Encrypted private keys as --secret-file",
)
@click.option(
    "--ignore",
    is_flag=True,
    default=False,
    help="Ignore validation failures and generate the binary.",
)
def generate_binary(
    output: str,
    config: str,
    add_seal: bool,
    calc_inverse: bool,
    rot_config: str,
    secret_file: tuple[str],
    password: str,
    ignore: bool,
) -> None:
    """Generate binary data."""
    if calc_inverse:
        logger.warning(
            "The calc-inverse option is obsolete option. The current behavior is following:\n"
            "In case that the family support also values for computed fields like LPC55s6x"
            "the inverse fields won't be computed when is not used in configuration, otherwise"
            "it will be updated correctly.\n"
            "In case that the inverse values are mandatory, like for LPC55S3x, the inverse values"
            " will be computed always."
        )

    cfg = load_configuration(config)
    description = cfg.get("description")
    area: str = cfg.get("type", description["type"] if description else "Invalid")
    if description:
        family = description["device"]
    else:
        family = cfg.get("family", cfg.get("device", "Unknown"))

    pfr_obj = BaseConfigArea.load_from_config(cfg)
    pfrc_devices = Pfrc.get_supported_families()
    pfrc_devices += list(DatabaseManager().quick_info.devices.get_predecessors(pfrc_devices).keys())
    if family in pfrc_devices:
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
                if ignore:
                    logger.warning(log_text)
                else:
                    raise SPSDKError(log_text)
            else:
                logger.debug(log_text)
    keys = None
    root_of_trust, rotkh = get_keys_or_rotkh_from_certblock_config(rot_config, family)
    if secret_file:
        root_of_trust = secret_file
    if area.lower() == "cmpa" and root_of_trust:
        keys = extract_public_keys(root_of_trust, password)

    data = pfr_obj.export(add_seal=add_seal, keys=keys, rotkh=rotkh)

    _store_output(data, output, "wb", msg="Success. (PFR binary has been generated)")


@main.command(name="write", no_args_is_help=True)
@spsdk_mboot_interface(use_long_timeout_form=True, identify_by_family=True)
@spsdk_family_option(CMPA.get_supported_families())
@pfr_device_type_options()
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, dir_okay=False),
    help="Path to the BIN file with PFR data to write.",
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
    area: str,
    binary: str,
    yaml_config: str,
) -> None:
    """Write PFR page to the device."""
    if not binary and not yaml_config:
        raise SPSDKPfrError("The path to the PFR data file was not specified!")
    data = b""
    if binary:
        pfr_obj = get_ifr_pfr_class(area, family)(family=family, revision=revision)
        data = load_binary(binary)
    elif yaml_config:
        cfg = load_configuration(yaml_config)
        description = cfg.get("description")
        cfg_area: str = cfg.get("type", description["type"] if description else "Invalid")
        if area != cfg_area.lower():
            raise SPSDKAppError(
                "Configuration area doesn't match CLI value and configuration value."
            )
        pfr_cls = get_ifr_pfr_class(area, family)
        pfr_cls.validate_config(cfg)
        pfr_obj = pfr_cls.load_from_config(cfg)
        if family != pfr_obj.family:
            raise SPSDKAppError("Family in configuration doesn't match family from CLI.")
        data = pfr_obj.export()
    pfr_page_address = pfr_obj.db.get_int(pfr_obj.FEATURE_NAME, [pfr_obj.DB_SUB_FEATURE, "address"])
    pfr_page_length = pfr_obj.BINARY_SIZE

    click.echo(f"{pfr_obj.__class__.__name__} page address on {family} is {pfr_page_address:#x}")

    if len(data) != pfr_page_length:
        raise SPSDKError(
            f"PFR page length is {pfr_page_length}. Provided binary has {size_fmt(len(data))}."
        )
    with McuBoot(interface=interface, cmd_exception=True) as mboot:
        try:
            mboot.write_memory(address=pfr_page_address, data=data)
        except McuBootError as exc:
            raise SPSDKAppError(f"{pfr_obj.__class__.__name__} data write failed: {exc}") from exc
    click.echo(f"{pfr_obj.__class__.__name__} data written to device.")


@main.command(name="read", no_args_is_help=True)
@spsdk_mboot_interface(use_long_timeout_form=True, identify_by_family=True)
@spsdk_family_option(CMPA.get_supported_families())
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
    hidden=True,
    is_flag=True,
    help="(applicable for parsing) Show also calculated fields when displaying difference to "
    "defaults (--show-diff)",
)
def read(
    interface: MbootProtocolBase,
    family: str,
    revision: str,
    area: str,
    output: str,
    yaml_output: str,
    show_diff: bool,
    show_calc: bool,
) -> None:
    """Read PFR page from the device."""
    if show_calc:
        logger.warning(
            "Show calculated fields is obsolete function for configuration YAML files."
            " In case of debugging those values check the binary data."
        )
    pfr_obj = get_ifr_pfr_class(area, family)(family=family, revision=revision)
    pfr_page_address = pfr_obj.db.get_int(pfr_obj.FEATURE_NAME, [pfr_obj.DB_SUB_FEATURE, "address"])
    pfr_page_length = pfr_obj.BINARY_SIZE
    pfr_page_name = pfr_obj.__class__.__name__

    click.echo(f"{pfr_page_name} page address on {family} is {pfr_page_address:#x}")

    with McuBoot(interface=interface) as mboot:
        data = mboot.read_memory(address=pfr_page_address, length=pfr_page_length)
    if not data:
        raise SPSDKError(f"Unable to read data from address {pfr_page_address:#x}")

    if output:
        write_file(data, output, "wb")
        click.echo(f"{pfr_page_name} data stored to {get_printable_path(output)}")
    if yaml_output:
        yaml_data = _parse_binary_data(
            data=data,
            family=family,
            revision=revision,
            area=area,
            show_diff=show_diff,
        )
        write_file(yaml_data, yaml_output)
        click.echo(f"Parsed config stored to {get_printable_path(yaml_output)}")
    if not output and not yaml_output:
        click.echo(format_raw_data(data=data, use_hexdump=True))


@main.command(name="erase-cmpa", no_args_is_help=True)
@spsdk_mboot_interface(use_long_timeout_form=True, identify_by_family=True)
@spsdk_family_option(CMPA.get_supported_families())
@pfr_device_type_options(no_type=True)
def erase_cmpa(
    interface: MbootProtocolBase,
    family: str,
    revision: str,
) -> None:
    """Erase CMPA PFR page in the device if is not sealed and write the default values into CMPA page."""
    pfr_obj = get_ifr_pfr_class("cmpa", family)(family=family, revision=revision)
    pfr_page_address = pfr_obj.db.get_int(pfr_obj.FEATURE_NAME, [pfr_obj.DB_SUB_FEATURE, "address"])
    erase_method = pfr_obj.db.get_str(
        pfr_obj.FEATURE_NAME, [pfr_obj.DB_SUB_FEATURE, "erase_method"]
    )
    # Update all possible mandatory fields in PFR block
    pfr_obj.set_config({})

    click.echo(f"CMPA page address on {family} is {pfr_page_address:#x}")

    with McuBoot(interface=interface, cmd_exception=True) as mboot:
        try:
            if erase_method == "write_memory":
                mboot.write_memory(address=pfr_page_address, data=pfr_obj.export())
            elif erase_method == "flash_erase":
                mboot.flash_erase_region(address=pfr_page_address, length=pfr_obj.BINARY_SIZE)
            else:
                raise SPSDKError(f"Unsupported erase method: {erase_method}")
        except McuBootError as exc:
            raise SPSDKAppError(f"CMPA page erase failed: {exc}") from exc
    click.echo("CMPA page has been erased.")


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
