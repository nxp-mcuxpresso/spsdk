#!/usr/bin/env python
#
# Copyright 2020-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK PFR (Protected Flash Region) command-line application.

This module provides a command-line interface for managing Protected Flash Regions
on NXP MCU devices. It supports operations like parsing, exporting, writing,
reading, and erasing CMPA (Customer Manufacturing Programming Area) data.
"""

import logging
import os
import sys
from collections.abc import Callable

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
from spsdk.pfr.pfr import (
    CMPA,
    CONFIG_AREA_CLASSES,
    AbstractBaseConfigArea,
    BaseConfigArea,
    MultiRegionBaseConfigArea,
    get_ifr_pfr_class,
    get_ifr_pfr_class_from_config,
)
from spsdk.pfr.pfrc import Pfrc
from spsdk.pfr.secure_installer import (
    SecureInstallerEraser,
    SIStatus,
    get_erase_token_register_names,
    get_supported_families,
)
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.misc import (
    BinaryPattern,
    get_printable_path,
    load_binary,
    load_configuration,
    write_file,
)

PFRArea = type[BaseConfigArea]
logger = logging.getLogger(__name__)


def _store_output(
    data: str | bytes, path: str | None, mode: str = "w", msg: str | None = None
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


def pfr_device_type_options(required: bool = True) -> Callable:
    """PFR common device click options.

    :param required: Whether the option is required (default: True)
    :return: Click decorator
    """

    def decorator(options: Callable[[FC], FC]) -> Callable[[FC], FC]:
        """Setup PFR/IFR area <CMPA, CFPA, ROMCFG, CMAC, IFR table>."""
        return click.option(
            "-t",
            "--type",
            "area",
            required=required,
            type=click.Choice(sorted(CONFIG_AREA_CLASSES.keys()), case_sensitive=False),
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


@main.command(name="get-templates", no_args_is_help=True)
@spsdk_family_option(BaseConfigArea.get_supported_families())
@spsdk_output_option(force=True, directory=True)
def get_templates(family: FamilyRevision, output: str) -> None:
    """Generate all user configuration template files for a family."""
    family_areas: list[str] = get_db(family).get_list(DatabaseManager.PFR, "sub_features")
    for area in family_areas:
        pfr_cls = get_ifr_pfr_class(area, family)
        template_data = pfr_cls.get_config_template(family)
        template_path = f"{output}/{area}.yaml"
        _store_output(
            template_data,
            template_path,
            msg=(
                f"The PFR {area} template for {family} has been saved into "
                f"{get_printable_path(template_path)} YAML file"
            ),
        )


@main.command(name="parse", no_args_is_help=True)
@spsdk_family_option(BaseConfigArea.get_supported_families())
@pfr_device_type_options()
@spsdk_output_option()
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
        output=output,
        show_diff=show_diff,
    )
    _store_output(
        yaml_data, output, msg=f"Success. (PFR/IFR: {get_printable_path(binary)} has been parsed."
    )


@main.command(name="info", no_args_is_help=True)
@spsdk_family_option(BaseConfigArea.get_supported_families())
@pfr_device_type_options()
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, dir_okay=False, readable=True, resolve_path=True),
    required=True,
    help="Binary to analyze",
)
def pfr_info_command(family: FamilyRevision, area: str, binary: str) -> None:
    """Display information about PFR/IFR binary."""
    pfr_info(family=family, area=area, binary=binary)


def pfr_info(family: FamilyRevision, area: str, binary: str) -> None:
    """Display information about PFR/IFR binary.

    :param family: Device to use.
    :param area: PFR/IFR area (CMPA, CFPA, ROMCFG, CMAC, IFR table).
    :param binary: Path to binary to analyze.
    """
    data = load_binary(binary)
    click.echo(_get_binary_info(data=data, family=family, area=area))


def _get_binary_info(data: bytes, family: FamilyRevision, area: str) -> str:
    """Parse binary data and get PFR/IFR information.

    :param data: Data to parse.
    :param family: Device to use.
    :param area: PFR/IFR area (CMPA, CFPA, ROMCFG, CMAC, IFR table).
    :raises SPSDKAppError: Unsupported parsed PFR/IFR object type.
    :return: PFR/IFR information as a string.
    """
    pfr_obj = get_ifr_pfr_class(area, family).parse(data, family)
    if isinstance(pfr_obj, BaseConfigArea):
        return _get_pfr_area_image(pfr_obj).info(no_color=True)
    if isinstance(pfr_obj, MultiRegionBaseConfigArea):
        image = BinaryImage(
            name=f"{pfr_obj.family.name} {pfr_obj.SUB_FEATURE.upper()}",
            size=pfr_obj.binary_size,
            pattern=BinaryPattern("zeros"),
        )
        offset = 0
        for region in pfr_obj.regions:
            image.add_image(_get_pfr_area_image(region, offset=offset))
            offset += region.binary_size
        additional_data = pfr_obj.export_additional_data()
        if len(additional_data):
            additional_data.offset = offset
            image.add_image(additional_data)
        return image.info(no_color=True)
    raise SPSDKAppError(f"Unsupported PFR/IFR object type: {pfr_obj.__class__.__name__}")


def _get_pfr_area_image(pfr_obj: BaseConfigArea, offset: int = 0) -> BinaryImage:
    """Get binary image information for PFR/IFR area.

    :param pfr_obj: Parsed PFR/IFR configuration area.
    :param offset: Image offset in parent image.
    :return: Binary image with parsed register information.
    """
    image = pfr_obj.registers.image_info(
        size=pfr_obj.registers_size,
        pattern=BinaryPattern(pfr_obj.IMAGE_PREFILL_PATTERN),
    )
    image.name = f"{pfr_obj.family.name} {pfr_obj.SUB_FEATURE.upper()}"
    image.description = pfr_obj.DESCRIPTION
    image.offset = offset
    return image


def _parse_binary_data(
    data: bytes,
    family: FamilyRevision,
    area: str,
    output: str,
    show_diff: bool = False,
) -> str:
    """Parse binary data and extract YAML configuration.

    :param data: Data to parse
    :param family: Device to use
    :param area: PFR are (CMPA, CFPA)
    :param output: Output file path
    :param show_diff: Show only difference to default
    :return: PFR YAML configuration as a string
    """
    pfr_obj = get_ifr_pfr_class(area, family).parse(data, family)
    data_path = os.path.dirname(output)
    return pfr_obj.get_config_yaml(data_path=data_path, diff=show_diff)


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
    pfr_class = get_ifr_pfr_class_from_config(config)
    pfr_obj = pfr_class.load_from_config(config)
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
    if pfr_obj.SUB_FEATURE in ["cmpa", "cfpa_cmpa"] and root_of_trust:
        keys = extract_public_keys(root_of_trust, password)

    if keys or rotkh:
        pfr_obj.compute_rotkh(keys=keys, rotkh=rotkh)

    data = pfr_obj.export(add_seal=add_seal)

    _store_output(
        data,
        output,
        "wb",
        msg=(
            f"Success. ({pfr_obj.SUB_FEATURE.upper()} binary has been generated "
            f"and stored into {get_printable_path(output)})"
        ),
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
@click.option("-a", "--add-seal", is_flag=True, help="Add seal mark digest at the end.")
def write(
    interface: MbootProtocolBase,
    family: FamilyRevision,
    area: str,
    binary: str,
    config: Config,
    add_seal: bool,
) -> None:
    """Write PFR/IFR page to the device."""
    if not binary and not config:
        raise SPSDKPfrError("The path to the PFR/IFR data file was not specified!")
    pfr_klass = get_ifr_pfr_class(area, family)
    if binary:
        pfr_obj = pfr_klass.parse(load_binary(binary), family)
    elif config:
        cfg_area: str = config.get("type", "Invalid")
        if area != cfg_area.lower():
            raise SPSDKAppError(
                "Configuration area doesn't match CLI value and configuration value."
            )
        pfr_klass.pre_check_config(config)
        pfr_obj = pfr_klass.load_from_config(config)
        if family != pfr_obj.family:
            raise SPSDKAppError("Family in configuration doesn't match family from CLI.")
    if pfr_obj.WRITE_METHOD != "write_memory":
        raise SPSDKAppError(f"Unsupported write method: {pfr_obj.WRITE_METHOD}")

    db = pfr_obj.db
    try:
        write_method = create_write_method(pfr_obj=pfr_obj, interface=interface)
        read_method = create_read_method(pfr_obj=pfr_obj, interface=interface)
        erase_method = create_erase_method(pfr_obj=pfr_obj, interface=interface)

        # Erase scratch page if needed
        pfr_obj.erase_scratch_if_needed(erase_method=erase_method)

        # Write the PFR into memory
        pfr_obj.write_to_device(
            write_method=write_method, read_method=read_method, add_seal=add_seal
        )

        requires_reset = db.get_bool(DatabaseManager.PFR, "requires_reset", default=False)
        if requires_reset:
            logger.warning(
                "The configuration will be applied after reset. Do reset the device now."
            )

    except SPSDKError as exc:
        raise SPSDKAppError(f"{pfr_obj.__class__.__name__} data write failed: {exc}") from exc

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

    pfr_obj.read_from_device(create_read_method(pfr_obj=pfr_obj, interface=interface))
    data = pfr_obj.export()

    if output:
        write_file(data, output, "wb")
        click.echo(f"{pfr_obj.SUB_FEATURE} data stored to {get_printable_path(output)}")
    if yaml_output:
        # If the area to read differs from the requested area, parse and create the correct object
        yaml_data = pfr_obj.get_config_yaml(data_path=os.path.dirname(yaml_output), diff=show_diff)
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
    pfr_obj.force_update()

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


@main.command(name="erase-secure-installer", no_args_is_help=True)
@spsdk_family_option(families=get_supported_families())
@spsdk_mboot_interface(use_long_timeout_form=True)
@click.option(
    "-nr",
    "--no-reset",
    is_flag=True,
    help="Do not reset device after erasing Secure Installer. (Not recommended)",
)
def erase_secure_installer(
    interface: MbootProtocolBase, family: FamilyRevision, no_reset: bool
) -> None:
    """Erase Secure Installer from the device.

    This command erases the Secure Installer (SI) from devices that support this feature
    by writing the DELETE_INSTALLER_MAGIC value to the DELETE_INSTALLER field in CMPA and
    resetting the device. The ROM completes the erase on the next boot.

    If the DELETE_INSTALLER flash phrase has already been programmed by a prior full CMPA
    write (it reads back as 0xFF but the flash controller rejects an in-place re-program
    with a cumulative-write error), the command automatically falls back to erasing the
    CMPA sector and reprogramming it - preserving the current settings - with the magic,
    while leaving the ERASE_TOKEN phrase erased so the ROM can store its device-unique
    token. Do not power off the device while this recovery runs.

    If the CMPA is entirely blank (e.g. after a full flash erase wiped the factory CMPA),
    a default CMPA carrying the magic is provisioned automatically (the ERASE_TOKEN phrase
    is left erased for the ROM). A CMPA that is not confirmed blank is refused so an
    unexpected/partial CMPA is never overwritten.

    Note: On a 512K flash device the SI flash region is reopened as customer flash
    after the ROM completes the erase. On 128K/256K devices the SI region stays
    hidden (no flash is reclaimed).

    The device will be reset after the magic value is written unless --no-reset is set.
    """
    try:
        with McuBoot(interface=interface, cmd_exception=True, family=family) as mboot:
            eraser = SecureInstallerEraser(mboot, family)

            # Display device information
            info = eraser.get_device_info()
            click.echo(f"Erasing Secure Installer on {family}...")
            click.echo(f"  CMPA Address:               {info['cmpa_address']}")
            click.echo(f"  DELETE_INSTALLER target:    {info['target_address']}")
            click.echo(f"  DELETE_INSTALLER magic:     {info['delete_installer_magic']}")
            click.echo(f"  ERASE_TOKEN offset:         {info['erase_token_offset']}")
            click.echo(f"  SI probe address:           {info['si_probe_address']}")
            if "cmpa_header_marker" in info:
                click.echo(f"  CMPA header marker:         {info['cmpa_header_marker']}")

            # Check the current SI status before proceeding
            si_status, erase_token_programmed = eraser.check_si_status()

            if si_status == SIStatus.PRESENT_VALID:
                click.echo("  SI Status: present and valid (receive-sb-file available)")
            elif si_status == SIStatus.PRESENT_CORRUPTED:
                click.echo(
                    "  SI Status: present but CORRUPTED "
                    "(receive-sb-file not reported by get-property 7 and "
                    "the SI probe read returned a memory-range-invalid status)."
                )
                if erase_token_programmed:
                    click.echo(
                        "WARNING: The SI erase-token field in CMPA is already programmed "
                        "(not all 0xFF). Writing DELETE_INSTALLER_MAGIC again would cause "
                        "a cumulative write to the ERASE_TOKEN flash phrase, which results "
                        "in an infinite reset loop and effectively bricks the device.\n"
                        "Do NOT proceed with SI erasure on this device."
                    )
                raise SPSDKAppError(
                    "Aborting: Secure Installer is present but corrupted "
                    "(receive-sb-file missing and the SI probe read returned a "
                    "memory-range-invalid status)."
                )
            elif si_status == SIStatus.ERASED:
                if erase_token_programmed:
                    click.echo("  SI Status: already erased (ERASE_TOKEN in CMPA is programmed).")
                else:
                    click.echo("  SI Status: already erased.")
                return
            else:
                click.echo(
                    "  SI Status: unknown — Secure Installer does not appear to be "
                    "present on this device, or the device is in an unexpected state."
                )
                raise SPSDKAppError(
                    "Aborting: Secure Installer state could not be confirmed as "
                    "present-and-valid. Refusing to write DELETE_INSTALLER_MAGIC blindly."
                )

            # Erase the Secure Installer
            eraser.erase(reset=not no_reset)

            if not no_reset:
                click.echo("Device has been reset. Secure Installer erasure is complete.")
            else:
                click.echo(
                    "WARNING: Device was not reset. Please reset the device manually "
                    "to apply the Secure Installer removal."
                )

    except SPSDKError as exc:
        raise SPSDKAppError(f"Failed to erase Secure Installer: {exc}") from exc


@main.command(name="read-secure-installer-token", no_args_is_help=True)
@spsdk_family_option(families=get_supported_families())
@spsdk_mboot_interface(use_long_timeout_form=True)
@spsdk_output_option(
    required=False,
    force=True,
    help="Write a ready-to-merge CMPA config snippet with the erase token to this file.",
)
def read_secure_installer_token(
    interface: MbootProtocolBase, family: FamilyRevision, output: str | None
) -> None:
    """Read the device-unique Secure Installer erase token from CMPA.

    After the Secure Installer is erased, the ROM programs a device-unique 16-byte
    erase token into CMPA (the erase-token registers declared for the family). The ROM
    re-validates this token on every boot; if a later ``pfr write`` overwrites it
    with blank/default values, the freed flash region gets locked again.

    This command reads the token back so it can be preserved in your CMPA
    configuration. Use ``--output`` to write a ready-to-merge CMPA config snippet.

    WARNING: The erase token is valid ONLY on the device it was read from. Never
    program it into the CMPA of another device — doing so re-locks that device's
    freed flash region.
    """
    try:
        with McuBoot(interface=interface, cmd_exception=True, family=family) as mboot:
            eraser = SecureInstallerEraser(mboot, family)
            token, programmed = eraser.read_erase_token()

        token_address = eraser.cmpa_address + eraser.erase_token_offset

        if not programmed:
            click.echo(
                f"SI erase token at {token_address:#010x} is blank (all 0x00 or 0xFF).\n"
                "The Secure Installer has not been erased on this device, so there is "
                "no device-unique token to preserve."
            )
            return

        registers = eraser.erase_token_as_registers(token)
        click.echo(f"Device-unique SI erase token read from {family} at {token_address:#010x}:")
        click.echo(f"  Raw (16 bytes): {token.hex()}")
        for name, value in registers.items():
            click.echo(f"  {name}: {value:#010x}")
        click.echo(
            "\nWARNING: This token is valid ONLY on this device. Preserve these "
            "erase-token register values in the CMPA of THIS device to keep the freed flash "
            "region unlocked. Do NOT program them into another device's CMPA."
        )

        if output:
            settings = "\n".join(f"  {name}: '{value:#010x}'" for name, value in registers.items())
            snippet = (
                "# Device-unique Secure Installer erase token.\n"
                f"# Read from {family} at {token_address:#010x}.\n"
                "# WARNING: valid ONLY on this device - do not reuse on other devices.\n"
                f"family: {family.name}\n"
                f"revision: {family.revision}\n"
                "type: CMPA\n"
                "settings:\n"
                f"{settings}\n"
            )
            _store_output(
                snippet,
                output,
                msg=f"\nCMPA config snippet stored in: {get_printable_path(output)}",
            )

    except SPSDKError as exc:
        raise SPSDKAppError(f"Failed to read Secure Installer erase token: {exc}") from exc


def _resolve_merge_registers(
    registers: str | None,
    registers_config: str | None,
    si_erase_token: bool,
    family: FamilyRevision,
) -> list[str]:
    """Resolve the list of register names to merge from CLI options.

    Exactly one source must be provided: an inline comma-separated ``--registers`` list,
    a ``--registers-config`` YAML file, or the ``--si-erase-token`` flag which resolves
    the family's Secure Installer erase-token registers automatically. The YAML file must
    be a mapping with a top-level ``registers`` key holding the list of register names.

    :param registers: Comma-separated register names from ``--registers`` (or None).
    :param registers_config: Path to a YAML register list from ``--registers-config``
        (or None).
    :param si_erase_token: When True, resolve the family's SI erase-token registers.
    :param family: Device family, used to resolve the SI erase-token registers.
    :raises SPSDKAppError: If not exactly one source is provided, the YAML content does
        not hold a list of register names, or the SI erase-token region can't be resolved.
    :return: Ordered, de-duplicated list of register names.
    """
    sources = (bool(registers), bool(registers_config), si_erase_token)
    if sum(sources) != 1:
        raise SPSDKAppError(
            "Specify exactly one of --registers, --registers-config or --si-erase-token."
        )

    if si_erase_token:
        try:
            return get_erase_token_register_names(family)
        except SPSDKError as exc:
            raise SPSDKAppError(
                f"Can't resolve the Secure Installer erase-token registers for {family}: {exc}"
            ) from exc

    if registers:
        names = [name.strip() for name in registers.split(",")]
    else:
        assert registers_config is not None
        try:
            loaded = load_configuration(registers_config)
        except SPSDKError as exc:
            raise SPSDKAppError(
                f"Can't parse register list {get_printable_path(registers_config)}: {exc}"
            ) from exc
        reg_list = loaded.get("registers")
        if not isinstance(reg_list, list) or not all(isinstance(name, str) for name in reg_list):
            raise SPSDKAppError(
                f"The register list in {get_printable_path(registers_config)} must be a YAML "
                "list of register names under a top-level 'registers' key."
            )
        names = [name.strip() for name in reg_list]

    # Preserve order while removing empties and duplicates.
    result: list[str] = []
    for name in names:
        if name and name not in result:
            result.append(name)
    if not result:
        raise SPSDKAppError("No register names were provided for the merge operation.")
    return result


@main.command(name="cmpa-merge", no_args_is_help=True)
@spsdk_family_option(get_supported_families())
@click.option(
    "-m",
    "--main-cmpa",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    required=True,
    help="Finalized (user) CMPA binary that provides all bytes except the merged registers.",
)
@click.option(
    "-d",
    "--device-cmpa",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    required=True,
    help="CMPA binary read back from the device that provides the selected register values.",
)
@click.option(
    "-o",
    "--output-cmpa",
    type=click.Path(dir_okay=False, resolve_path=True),
    required=True,
    help="Path where the merged CMPA binary is written.",
)
@click.option(
    "--registers",
    type=str,
    help=(
        "Comma-separated list of register names copied from the device CMPA "
        "(e.g. the Secure Installer erase-token registers)."
    ),
)
@click.option(
    "--registers-config",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    help="YAML file with the list of register names to merge (alternative to --registers).",
)
@click.option(
    "--si-erase-token",
    is_flag=True,
    help=(
        "Merge the Secure Installer erase-token registers, resolved automatically for "
        "the family from the device database. Use instead of --registers/--registers-config."
    ),
)
def cmpa_merge(
    family: FamilyRevision,
    main_cmpa: str,
    device_cmpa: str,
    output_cmpa: str,
    registers: str | None,
    registers_config: str | None,
    si_erase_token: bool,
) -> None:
    """Merge selected registers from a device CMPA binary into a main CMPA binary.

    This is a pure binary, offline operation intended for a mass-production flow. The
    finalized main CMPA is kept byte-for-byte and only the explicitly selected registers
    are taken from the CMPA read back from the device. No values are recomputed, so any
    CRC, seal or ROTKH fields already present in the main CMPA are preserved.

    Only families that expose the Secure Installer erase functionality in the database
    are supported. Register names must match the CMPA register spec (JSON) exactly.
    Prefer --si-erase-token to preserve the device-unique Secure Installer erase token
    without needing to know the per-family register names.

    Example: pfr cmpa-merge --family <family> --main-cmpa CMPA.bin --device-cmpa
    CMPA_dev.bin --output-cmpa CMPA_out.bin --si-erase-token
    """
    register_names = _resolve_merge_registers(registers, registers_config, si_erase_token, family)
    main_data = load_binary(main_cmpa)
    device_data = load_binary(device_cmpa)

    try:
        merged = CMPA.merge_binary(
            main_data=main_data,
            device_data=device_data,
            register_names=register_names,
            family=family,
        )
    except SPSDKError as exc:
        raise SPSDKAppError(f"CMPA merge failed: {exc}") from exc

    write_file(merged, output_cmpa, mode="wb")
    click.echo(
        f"Merged registers {', '.join(register_names)} from "
        f"{get_printable_path(device_cmpa)} into {get_printable_path(main_cmpa)}."
    )
    click.echo(f"Merged CMPA binary stored in: {get_printable_path(output_cmpa)}")


def create_read_method(
    pfr_obj: AbstractBaseConfigArea,
    interface: MbootProtocolBase,
) -> Callable[[int, int], bytes]:
    """Create a read method callable for PFR write operations.

    This function creates a callable that matches the signature required by
    PFR classes' write_to_device() method. The returned callable uses the
    appropriate read method (read_memory or flash_read_resource) based on
    the PFR object's READ_METHOD attribute.

    :param pfr_obj: PFR/IFR configuration area object containing read method configuration.
    :param interface: MCUBoot protocol interface for device communication.
    :raises SPSDKAppError: If the READ_METHOD specified in pfr_obj is not supported.
    :return: Callable with signature (address: int, length: int) -> bytes
    """

    def read_method(address: int, length: int) -> bytes:
        """Read data from device memory.

        :param address: Memory address to read from.
        :param length: Number of bytes to read.
        :raises SPSDKError: If unable to read data from the device.
        :return: Bytes read from the specified address.
        """
        if pfr_obj.READ_METHOD == "read_memory":
            with McuBoot(interface=interface, family=pfr_obj.family) as mboot:
                data = mboot.read_memory(address=address, length=length)
        else:
            raise SPSDKAppError(f"Unsupported read method: {pfr_obj.READ_METHOD}")

        if not data:
            raise SPSDKError(f"Unable to read data from address {address:#x}")

        return data

    return read_method


def create_write_method(
    pfr_obj: AbstractBaseConfigArea,
    interface: MbootProtocolBase,
) -> Callable[[int, bytes], bool]:
    """Create a write method callable for PFR write operations.

    This function creates a callable that matches the signature required by
    PFR classes' write_to_device() method. The returned callable uses the
    appropriate write method based on the PFR object's WRITE_METHOD attribute.

    :param pfr_obj: PFR/IFR configuration area object containing write method configuration.
    :param interface: MCUBoot protocol interface for device communication.
    :raises SPSDKAppError: If the WRITE_METHOD specified in pfr_obj is not supported.
    :return: Callable with signature (address: int, data: bytes) -> bool
    """

    def write_method(address: int, data: bytes) -> bool:
        """Write data to device memory.

        :param address: Memory address to write to.
        :param data: Data bytes to write.
        :return: True if write succeeded, False otherwise.
        """
        try:
            if pfr_obj.WRITE_METHOD == "write_memory":
                with McuBoot(interface=interface, family=pfr_obj.family) as mboot:
                    mboot.write_memory(address=address, data=data)
            else:
                raise SPSDKAppError(f"Unsupported write method: {pfr_obj.WRITE_METHOD}")

            return True

        except McuBootError as exc:
            logger.error(f"Write failed at address {address:#x}: {exc}")
            return False

    return write_method


def create_erase_method(
    pfr_obj: AbstractBaseConfigArea,
    interface: MbootProtocolBase,
) -> Callable[[int, int], bool]:
    """Create an erase method callable for PFR erase operations.

    This function creates a callable that matches the signature required by
    PFR classes' erase_scratch_if_needed() method. The returned callable uses
    the flash_erase_region method to erase the specified memory region.

    :param pfr_obj: PFR/IFR configuration area object containing erase method configuration.
    :param interface: MCUBoot protocol interface for device communication.
    :return: Callable with signature (address: int, length: int) -> bool
    """

    def erase_method(address: int, length: int) -> bool:
        """Erase flash region on device.

        :param address: Memory address to erase from.
        :param length: Number of bytes to erase.
        :return: True if erase succeeded, False otherwise.
        """
        try:
            with McuBoot(interface=interface, family=pfr_obj.family) as mboot:
                mboot.flash_erase_region(address=address, length=length)
            return True

        except McuBootError as exc:
            logger.error(f"Erase failed at address {address:#x}: {exc}")
            return False

    return erase_method


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
