#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK PFR (Protected Flash Region) command-line application.

This module provides a command-line interface for managing Protected Flash Regions
on NXP MCU devices. It supports operations like parsing, exporting, writing,
reading, and erasing CMPA (Customer Manufacturing Programming Area) data.
"""

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
from spsdk.image.cert_block.cert_blocks import get_keys_or_rotkh_from_certblock_config
from spsdk.image.cert_block.rot import Rot, RotCertBlockv1, RotCertBlockv21
from spsdk.mboot.exceptions import McuBootError
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.pfr.exceptions import SPSDKPfrConfigError, SPSDKPfrError
from spsdk.pfr.pfr import CMPA, CONFIG_AREA_CLASSES, BaseConfigArea, get_ifr_pfr_class
from spsdk.pfr.pfrc import Pfrc
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.misc import get_printable_path, load_binary, size_fmt, write_file

PFRArea = Type[BaseConfigArea]
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


def pfr_device_type_options() -> Callable:
    """PFR common device click options.

    :return: Click decorator
    """

    def decorator(options: Callable[[FC], FC]) -> Callable[[FC], FC]:
        """Setup PFR/IFR area <CMPA, CFPA, ROMCFG, CMAC, IFR table>."""
        return click.option(
            "-t",
            "--type",
            "area",
            required=True,
            type=click.Choice(sorted(list(CONFIG_AREA_CLASSES.keys())), case_sensitive=False),
            help="Select PFR/IFR partition",
        )(options)

    return decorator


@click.group(name="pfr", cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> int:
    """Protected Flash Region (PFR) Utility.

    This module provides a command-line interface for managing Protected Flash Region and Internal Flash Region data
    on NXP microcontrollers. It enables generating, parsing, exporting, reading, and writing PFR/IFR configurations.

    Supported areas:
    - PFR pages: CMPA (Customer Manufacturing Configuration Area), CFPA (Customer Field Programmable Area)
    - IFR pages: ROMCFG (ROM Configuration), CMACTABLE (CMAC Table), IFR

    Features:
    - Generate configuration templates
    - Parse binary PFR/IFR data into human-readable YAML
    - Export configurations to binary format
    - Read PFR/IFR data from connected devices
    - Write configurations to devices
    - Special operations like CMPA erasure

    Note: IFR ROMCFG region is one-time-programmable only.
    """
    spsdk_logger.install(level=log_level)
    return 0


@main.command(name="get-template", no_args_is_help=True)
@spsdk_family_option(BaseConfigArea.get_supported_families())
@pfr_device_type_options()
@spsdk_output_option(force=True)
def get_template(family: FamilyRevision, area: str, output: str) -> None:
    """Generate user configuration template file."""
    pfr_cls = get_ifr_pfr_class(area, family)
    _store_output(
        pfr_cls.get_config_template(family),
        output,
        msg=f"The PFR {area} template for {family} has been saved into {get_printable_path(output)} YAML file",
    )


@main.command(name="parse", no_args_is_help=True)
@spsdk_family_option(BaseConfigArea.get_supported_families())
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
def pfr_parse(
    family: FamilyRevision,
    area: str,
    output: str,
    binary: str,
    show_diff: bool,
) -> None:
    """Parse binary and extract configuration."""
    data = load_binary(binary)
    yaml_data = _parse_binary_data(
        data=data,
        family=family,
        area=area,
        show_diff=show_diff,
    )
    _store_output(
        yaml_data, output, msg=f"Success. (PFR/IFR: {get_printable_path(binary)} has been parsed."
    )


def _parse_binary_data(
    data: bytes,
    family: FamilyRevision,
    area: str,
    show_diff: bool = False,
) -> str:
    """Parse binary data and extract YAML configuration.

    :param data: Data to parse
    :param family: Device to use
    :param area: PFR are (CMPA, CFPA)
    :param show_diff: Show only difference to default
    :return: PFR YAML configuration as a string
    """
    pfr_obj = get_ifr_pfr_class(area, family).parse(data, family)
    return pfr_obj.get_config_yaml(diff=show_diff)


@main.command(name="export", no_args_is_help=True)
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
@spsdk_config_option(klass=BaseConfigArea)
@spsdk_output_option()
@click.option("-a", "--add-seal", is_flag=True, help="Add seal mark digest at the end.")
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
def pfr_export(
    output: str,
    config: Config,
    add_seal: bool,
    rot_config: str,
    secret_file: tuple[str],
    password: str,
    ignore: bool,
) -> None:
    """Generate binary data."""
    pfr_obj = BaseConfigArea.load_from_config(config)
    pfrc_devices = Pfrc.get_supported_families(True)
    if pfr_obj.family in pfrc_devices:
        try:
            pfrc = Pfrc(
                cmpa=pfr_obj if pfr_obj.SUB_FEATURE == "cmpa" else None,  # type: ignore
                cfpa=pfr_obj if pfr_obj.SUB_FEATURE == "cfpa" else None,  # type: ignore
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
    if rot_config:
        try:
            rot_class = Rot.get_rot_class(pfr_obj.family)
            if rot_class not in [RotCertBlockv1, RotCertBlockv21]:
                raise ValueError()  # Trigger the except block
        except ValueError as exc:
            raise SPSDKError(
                f"Family: {pfr_obj.family} does not support 'rot-config' option."
            ) from exc
    root_of_trust, rotkh = get_keys_or_rotkh_from_certblock_config(rot_config, pfr_obj.family)
    if secret_file:
        root_of_trust = secret_file
    if pfr_obj.SUB_FEATURE == "cmpa" and root_of_trust:
        keys = extract_public_keys(root_of_trust, password)

    data = pfr_obj.export(add_seal=add_seal, keys=keys, rotkh=rotkh)

    _store_output(
        data,
        output,
        "wb",
        msg=f"Success. ({pfr_obj.SUB_FEATURE.upper()} binary has been generated)",
    )


@main.command(name="write", no_args_is_help=True)
@spsdk_mboot_interface(use_long_timeout_form=True, identify_by_family=True)
@spsdk_family_option(BaseConfigArea.get_supported_families())
@pfr_device_type_options()
@click.option(
    "-bin",
    "--binary",
    type=click.Path(exists=True, dir_okay=False),
    help="Path to the BIN file with PFR data to write.",
)
@spsdk_config_option(required=False, klass=BaseConfigArea)
def write(
    interface: MbootProtocolBase,
    family: FamilyRevision,
    area: str,
    binary: str,
    config: Config,
) -> None:
    """Write PFR/IFR page to the device."""
    if not binary and not config:
        raise SPSDKPfrError("The path to the PFR/IFR data file was not specified!")
    data = b""
    if binary:
        pfr_obj = get_ifr_pfr_class(area, family)(family=family)
        data = load_binary(binary)
    elif config:
        description = config.get("description")
        cfg_area: str = config.get("type", description["type"] if description else "Invalid")
        if area != cfg_area.lower():
            raise SPSDKAppError(
                "Configuration area doesn't match CLI value and configuration value."
            )
        pfr_cls = get_ifr_pfr_class(area, family)
        pfr_cls.pre_check_config(config)
        pfr_obj = pfr_cls.load_from_config(config)
        if family != pfr_obj.family:
            raise SPSDKAppError("Family in configuration doesn't match family from CLI.")
        data = pfr_obj.export()
    pfr_page_address = pfr_obj.db.get_int(pfr_obj.FEATURE, [pfr_obj.SUB_FEATURE, "address"])
    pfr_page_length = pfr_obj.binary_size

    click.echo(
        f"The {pfr_obj.__class__.__name__} page for {family.name} is located at "
        f"address {pfr_page_address:#x} in the {family.revision} revision."
    )

    if len(data) != pfr_page_length:
        raise SPSDKError(
            f"PFR page length is {pfr_page_length}. Provided binary has {size_fmt(len(data))}."
        )
    if pfr_obj.WRITE_METHOD == "write_memory":
        with McuBoot(interface=interface, cmd_exception=True, family=family) as mboot:
            try:
                mboot.write_memory(address=pfr_page_address, data=data)
                requires_reset = get_db(family).get_bool(DatabaseManager.PFR, "requires_reset")
                if requires_reset:
                    logger.info(
                        "The configuration will be applied after reset. Resetting the device."
                    )
                    mboot.reset()
            except McuBootError as exc:
                raise SPSDKAppError(
                    f"{pfr_obj.__class__.__name__} data write failed: {exc}"
                ) from exc
    else:
        raise SPSDKAppError(f"Unsupported write method: {pfr_obj.WRITE_METHOD}")
    click.echo(f"{pfr_obj.__class__.__name__} data written to device.")


@main.command(name="read", no_args_is_help=True)
@spsdk_mboot_interface(use_long_timeout_form=True, identify_by_family=True)
@spsdk_family_option(BaseConfigArea.get_supported_families())
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
    help="Show differences comparing to defaults (applicable for parsing)",
)
def read(
    interface: MbootProtocolBase,
    family: FamilyRevision,
    area: str,
    output: str,
    yaml_output: str,
    show_diff: bool,
) -> None:
    """Read PFR page from the device."""
    pfr_obj = get_ifr_pfr_class(area, family)(family=family)
    pfr_page_address = pfr_obj.db.get_int(pfr_obj.FEATURE, [pfr_obj.SUB_FEATURE, "address"])
    pfr_page_length = pfr_obj.binary_size
    pfr_page_name = pfr_obj.__class__.__name__

    click.echo(f"{pfr_page_name} page address on {family} is {pfr_page_address:#x}")

    if pfr_obj.READ_METHOD == "read_memory":
        with McuBoot(interface=interface, family=family) as mboot:
            data = mboot.read_memory(address=pfr_page_address, length=pfr_page_length)
        if not data:
            raise SPSDKError(f"Unable to read data from address {pfr_page_address:#x}")
    elif pfr_obj.READ_METHOD == "flash_read_resource":
        with McuBoot(interface=interface, family=family) as mboot:
            data = mboot.flash_read_resource(
                address=pfr_page_address, length=pfr_page_length, option=0
            )
        if not data:
            raise SPSDKError(f"Unable to read data from address {pfr_page_address:#x}")
    else:
        raise SPSDKAppError(f"Unsupported read method: {pfr_obj.READ_METHOD}")

    if output:
        write_file(data, output, "wb")
        click.echo(f"{pfr_page_name} data stored to {get_printable_path(output)}")
    if yaml_output:
        yaml_data = _parse_binary_data(
            data=data,
            family=family,
            area=area,
            show_diff=show_diff,
        )
        write_file(yaml_data, yaml_output)
        click.echo(f"Parsed config stored to {get_printable_path(yaml_output)}")
    if not output and not yaml_output:
        click.echo(format_raw_data(data=data, use_hexdump=True))


@main.command(name="erase-cmpa", no_args_is_help=True)
@spsdk_family_option(CMPA.get_supported_families())
@spsdk_mboot_interface(use_long_timeout_form=True, identify_by_family=True)
def erase_cmpa(interface: MbootProtocolBase, family: FamilyRevision) -> None:
    """Erase CMPA PFR page in the device if is not sealed and write the default values into CMPA page."""
    pfr_obj = get_ifr_pfr_class("cmpa", family)(family=family)
    pfr_page_address = pfr_obj.db.get_int(pfr_obj.FEATURE, [pfr_obj.SUB_FEATURE, "address"])
    erase_method = pfr_obj.db.get_str(pfr_obj.FEATURE, [pfr_obj.SUB_FEATURE, "erase_method"])
    # Update all possible mandatory fields in PFR block
    pfr_obj.set_config(Config())

    click.echo(f"CMPA page address on {family} is {pfr_page_address:#x}")

    with McuBoot(interface=interface, cmd_exception=True, family=family) as mboot:
        try:
            if erase_method == "write_memory":
                mboot.write_memory(address=pfr_page_address, data=pfr_obj.export())
            elif erase_method == "flash_erase":
                mboot.flash_erase_region(address=pfr_page_address, length=pfr_obj.binary_size)
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
