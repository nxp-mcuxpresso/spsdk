#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK configuration file conversion utilities.

This module provides functionality for converting and cleaning up legacy
configuration files, particularly JSON schemas used across various SPSDK
components and NXP MCU features.
The module supports conversion for multiple SPSDK components including MBI,
SB3.1, DevHSM, certificate blocks, AHAB, and various other MCU-specific
configurations through dedicated schema retrieval functions and a unified
conversion interface.
"""

import os
import sys
from typing import Any, Callable, Optional

import click
import colorama

from spsdk.apps.utils.utils import catch_spsdk_error
from spsdk.dat.dar_packet import DebugAuthenticateResponse
from spsdk.dat.debug_credential import DebugCredentialCertificate
from spsdk.exceptions import SPSDKError
from spsdk.fuses.shadowregs import ShadowRegisters
from spsdk.image.ahab.ahab_image import AHABImage
from spsdk.image.ahab.signed_msg import SignedMessage
from spsdk.image.bee import Bee
from spsdk.image.bootable_image.bimg import BootableImage
from spsdk.image.cert_block.cert_blocks import CertBlockV21
from spsdk.image.fcb.fcb import FCB
from spsdk.image.iee.iee import Iee
from spsdk.image.mbi.mbi import MasterBootImage
from spsdk.image.mem_type import MemoryType
from spsdk.image.otfad.otfad import Otfad
from spsdk.image.trustzone import TrustZone
from spsdk.image.xmcd.xmcd import XMCD
from spsdk.pfr.pfr import CFPA, CMACTABLE, CMPA, ROMCFG
from spsdk.sbfile.sb4.images import SecureBinary4
from spsdk.sbfile.sb31.devhsm import DevHsmSB31
from spsdk.sbfile.sb31.images import SecureBinary31
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_configuration, load_text, write_file
from spsdk.utils.schema_validator import CommentedConfig, check_config

disable_files_dirs_formatters: dict[str, Callable[[str], bool]] = {
    "dir": lambda x: bool(os.path.basename(x.replace("\\", "/"))),
    "file": lambda x: bool(os.path.basename(x.replace("\\", "/"))),
    "file_name": lambda x: os.path.basename(x.replace("\\", "/")) not in ("", None),
    "optional_file": lambda x: not x or bool(os.path.basename(x.replace("\\", "/"))),
    "file-or-hex-value": lambda x: bool(os.path.basename(x.replace("\\", "/")))
    or isinstance(x, (int, str)),
}


def get_all_files(source: str, recursive: bool = False) -> list[str]:
    """Gather all configuration files from the specified source path.

    The method searches for JSON and YAML configuration files in the given source.
    If source is a file, it returns that file. If source is a directory, it searches
    for files with extensions .json, .yaml, or .yml.

    :param source: File path or directory path to search for configuration files.
    :param recursive: If True, search recursively through subdirectories, defaults to False.
    :return: List of paths to found configuration files.
    """
    all_files = []

    if os.path.isfile(source):
        all_files.append(source)
    else:
        for root, _, file_names in os.walk(
            source,
        ):
            for file_name in file_names:
                if os.path.splitext(file_name)[1] in (".json", ".yaml", ".yml"):
                    all_files.append(os.path.join(root, file_name))
            if not recursive:
                break
    return all_files


def get_schemas_mbi(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schemas for MBI configurations.

    This method retrieves the appropriate MBI class based on the configuration,
    gets validation schemas for the specified family revision, validates the
    configuration against those schemas, and returns the schemas.

    :param config: MBI configuration dictionary containing family and revision information.
    :raises SPSDKError: If configuration validation fails or invalid MBI class.
    :return: List of validation JSON schemas for the MBI configuration.
    """
    mbi_cls = MasterBootImage.get_mbi_class(config)
    schemas = mbi_cls.get_validation_schemas(FamilyRevision.load_from_config(config))
    check_config(config=config, schemas=schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_sb31(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schemas for SB3.1 configurations.

    This method validates the provided configuration against basic schemas first,
    then retrieves the complete validation schemas for the specific family revision
    and performs a final validation with disabled file/directory formatters.

    :param config: SB3.1 configuration dictionary to validate and get schemas for.
    :raises SPSDKError: Invalid configuration or validation failure.
    :return: List of validation JSON schemas for the given SB3.1 configuration.
    """
    check_config(config, SecureBinary31.get_validation_schemas_basic())
    schemas = SecureBinary31.get_validation_schemas(FamilyRevision.load_from_config(config))
    check_config(config=config, schemas=schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_sb40(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for SB4.0 configurations.

    :param config: Any configuration of SB4.0
    :return: Validation JSON schemas
    """
    check_config(config, SecureBinary4.get_validation_schemas_basic())
    schemas = SecureBinary4.get_validation_schemas(FamilyRevision.load_from_config(config))
    check_config(config=config, schemas=schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_devhsm(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schemas for DEVHSM configurations.

    This method validates the provided configuration against basic SecureBinary31 schemas,
    then retrieves and validates against DevHsmSB31-specific schemas for the family revision.

    :param config: DEVHSM configuration dictionary containing device and security settings.
    :raises SPSDKError: Invalid configuration or unsupported family revision.
    :return: List of validation JSON schemas for DEVHSM configuration.
    """
    check_config(config, SecureBinary31.get_validation_schemas_basic())

    schemas = DevHsmSB31.get_validation_schemas(FamilyRevision.load_from_config(config))
    check_config(config=config, schemas=schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_cert_block(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schemas for Certification block configurations.

    This method retrieves validation schemas from CertBlockV21 based on the family revision
    loaded from the configuration, adds the cert_block_output schema, validates the
    configuration against all schemas, and returns the complete list of schemas.

    :param config: Configuration dictionary for Certification block containing family and revision information.
    :return: List of validation JSON schema dictionaries used for cert block validation.
    :raises SPSDKError: If configuration validation fails against the schemas.
    """
    schemas = CertBlockV21.get_validation_schemas(FamilyRevision.load_from_config(config))
    schemas.append(get_schema_file(DatabaseManager.CERT_BLOCK)["cert_block_output"])
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_ahab(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schemas for AHAB configurations.

    The method validates the basic configuration first, then retrieves family-specific
    validation schemas and performs additional validation with disabled file/directory
    formatters.

    :param config: AHAB configuration dictionary to validate and get schemas for.
    :raises SPSDKError: Invalid configuration or validation failure.
    :return: List of validation JSON schemas for the AHAB configuration.
    """
    check_config(config, AHABImage.get_validation_schemas_basic())
    schemas = AHABImage.get_validation_schemas(FamilyRevision.load_from_config(config))
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_signed_message(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schemas for Signed Message configurations.

    This method retrieves the validation schemas for Signed Message configurations
    based on the family revision information from the provided config. It also
    performs configuration validation using the retrieved schemas.

    :param config: Configuration dictionary containing Signed Message settings.
    :return: List of validation JSON schemas for the configuration.
    :raises SPSDKError: If configuration validation fails or family revision cannot be loaded.
    """
    schemas = SignedMessage.get_validation_schemas(FamilyRevision.load_from_config(config))

    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_otfad(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schemas for OTFAD configurations.

    The method validates the basic OTFAD configuration, extracts the family information,
    retrieves the appropriate validation schemas for that family, and performs a second
    validation with the complete schemas.

    :param config: OTFAD configuration dictionary to validate and get schemas for.
    :raises SPSDKError: Invalid configuration or unsupported family.
    :return: List of validation JSON schemas for the specified OTFAD configuration.
    """
    check_config(
        config,
        Otfad.get_validation_schemas_basic(),
        extra_formatters=disable_files_dirs_formatters,
    )
    family = FamilyRevision.load_from_config(config)
    schemas = Otfad.get_validation_schemas(family)
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_iee(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for IEE configurations.

    The method validates the basic IEE configuration, extracts the family information,
    retrieves the appropriate validation schemas for that family, and performs a second
    validation with the family-specific schemas.

    :param config: IEE configuration dictionary to validate and get schemas for.
    :raises SPSDKError: Invalid configuration or unsupported family.
    :return: List of validation JSON schemas for the specified IEE family.
    """
    check_config(
        config,
        Iee.get_validation_schemas_basic(),
        extra_formatters=disable_files_dirs_formatters,
    )
    family = FamilyRevision.load_from_config(config)
    schemas = Iee.get_validation_schemas(family)
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_fcb(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schemas for FCB configurations.

    The method validates the basic FCB configuration, extracts chip family and memory type
    information, then retrieves and validates the complete schemas for the specific hardware.

    :param config: FCB configuration dictionary containing chip family, memory type and other settings.
    :raises SPSDKError: Invalid configuration or unsupported chip family/memory type combination.
    :return: List of validation JSON schemas for the FCB configuration.
    """
    check_config(config, FCB.get_validation_schemas_basic())
    chip_family = FamilyRevision.load_from_config(config)
    mem_type = MemoryType.from_label(config.get("type", "Unknown"))
    schemas = FCB.get_validation_schemas(chip_family, mem_type)
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)

    return schemas


def get_schemas_bootable_image(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schemas for Bootable Image configurations.

    The method validates the basic configuration structure, extracts chip family and memory type
    information, then retrieves and validates against the complete validation schemas for the
    specific bootable image configuration.

    :param config: Configuration dictionary containing bootable image settings including
        chip family, revision, and memory type information.
    :raises SPSDKError: Invalid configuration structure or unsupported chip family/memory type.
    :return: List of validation JSON schema dictionaries for the bootable image configuration.
    """
    check_config(config, BootableImage.get_validation_schemas_basic())
    chip_family = FamilyRevision.load_from_config(config)
    mem_type = MemoryType.from_label(config["memory_type"])

    schemas = BootableImage.get_validation_schemas(chip_family, mem_type)
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)

    return schemas


def get_schemas_xmcd(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schemas for XMCD configurations.

    This method validates the basic XMCD configuration, extracts chip family,
    memory type, and configuration type, then retrieves and validates the
    complete validation schemas for the specific XMCD configuration.

    :param config: XMCD configuration dictionary containing chip family, memory type, and configuration type.
    :raises SPSDKError: Invalid configuration or unsupported chip family/memory type combination.
    :return: List of validation JSON schemas for the specified XMCD configuration.
    """
    check_config(config, XMCD.get_validation_schemas_basic())
    chip_family = FamilyRevision.load_from_config(config)
    mem_type = config["mem_type"]
    config_type = config["config_type"]

    schemas = XMCD.get_validation_schemas(chip_family, mem_type, config_type)
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)

    return schemas


def get_schemas_bee(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for BEE configurations.

    The method retrieves validation JSON schemas for BEE (Bus Encryption Engine) configurations
    using a temporary solution with mimxrt1050 family revision for backward compatibility with
    old configurations. It also performs configuration validation against the schemas.

    :param config: BEE configuration dictionary to validate against schemas.
    :raises SPSDKError: Configuration validation fails against the schemas.
    :return: List of validation JSON schemas for BEE configurations.
    """
    schemas = Bee.get_validation_schemas(
        FamilyRevision("mimxrt1050")
    )  # Just temporary solution for old configurations
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_trust_zone(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schemas for Trust Zone configurations.

    The method validates the configuration against basic schemas first, then retrieves
    family-specific validation schemas and performs additional validation with disabled
    file/directory formatters.

    :param config: Trust Zone configuration dictionary to validate and get schemas for.
    :raises SPSDKError: Invalid configuration that doesn't match validation schemas.
    :return: List of validation JSON schemas for the Trust Zone configuration.
    """
    check_config(config, TrustZone.get_validation_schemas_basic())
    schemas = TrustZone.get_validation_schemas(FamilyRevision.load_from_config(config))
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_binary_image(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for Binary Image merge configurations.

    The method retrieves validation schemas from BinaryImage class and validates
    the provided configuration against these schemas using disabled file/directory
    formatters.

    :param config: Configuration dictionary for Binary Image merge operations.
    :raises SPSDKError: If configuration validation fails against the schemas.
    :return: List of validation JSON schema dictionaries.
    """
    schemas = BinaryImage.get_validation_schemas()
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_pfr_cmpa(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schemas for PFR CMPA configurations.

    The method retrieves validation schemas for Protected Flash Region (PFR) Customer Manufacturing
    Programming Area (CMPA) based on the provided configuration and validates the configuration
    against these schemas.

    :param config: Configuration dictionary for PFR CMPA containing family and other settings.
    :raises SPSDKError: Invalid configuration or unsupported family.
    :return: List of validation JSON schemas for the specified family.
    """
    schemas = CMPA.get_validation_schemas(family=FamilyRevision.load_from_config(config))
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_pfr_cfpa(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schemas for PFR CFPA configurations.

    This method retrieves validation schemas for Protected Flash Region (PFR)
    Customer Field Programmable Area (CFPA) configurations and validates the
    provided configuration against these schemas.

    :param config: Configuration dictionary for PFR CFPA containing family and revision information.
    :raises SPSDKError: Invalid configuration or validation failure.
    :return: List of validation JSON schemas for the specified family.
    """
    schemas = CFPA.get_validation_schemas(family=FamilyRevision.load_from_config(config))
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_ifr_romcfg(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schemas for IFR ROMCFG configurations.

    This method retrieves validation schemas for IFR ROMCFG based on the provided
    configuration and validates the configuration against those schemas.

    :param config: Configuration dictionary for IFR ROMCFG containing family and revision information.
    :raises SPSDKError: Invalid configuration or schema validation failure.
    :return: List of validation JSON schema dictionaries.
    """
    schemas = ROMCFG.get_validation_schemas(family=FamilyRevision.load_from_config(config))
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_ifr_cmactable(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schemas for IFR CMACTABLE configurations.

    The method retrieves validation schemas for IFR CMACTABLE based on the provided
    configuration and validates the configuration against those schemas.

    :param config: Configuration dictionary for IFR CMACTABLE containing family and revision information.
    :raises SPSDKError: Invalid configuration or schema validation failure.
    :return: List of validation JSON schema dictionaries.
    """
    schemas = CMACTABLE.get_validation_schemas(family=FamilyRevision.load_from_config(config))
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_shadowregs(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for Shadow register configurations.

    This method retrieves validation schemas for Shadow register configurations based on the
    provided configuration and validates the configuration against those schemas.

    :param config: Configuration dictionary containing Shadow register settings and family information.
    :raises SPSDKError: Invalid configuration or schema validation failure.
    :return: List of validation JSON schema dictionaries for Shadow registers.
    """
    schemas = ShadowRegisters.get_validation_schemas(family=FamilyRevision.load_from_config(config))
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_dc(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schemas for Debug Credential Certificate configurations.

    Retrieves validation schemas for Debug Credential Certificate files based on the
    provided configuration and validates the configuration against these schemas.

    :param config: Configuration dictionary containing family and DC settings
    :raises SPSDKError: Invalid configuration or unsupported family
    :return: List of validation JSON schemas for the specified configuration
    """
    schemas = DebugCredentialCertificate.get_validation_schemas(
        family=FamilyRevision.load_from_config(config)
    )
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_dat(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for DAT configurations.

    This method retrieves and validates the JSON schemas used for Debug Authentication Tool (DAT)
    configurations. It loads the family revision from the provided configuration and performs
    validation using the obtained schemas.

    :param config: Dictionary containing DAT configuration data including family and revision information.
    :raises SPSDKError: If the configuration validation fails or family revision cannot be loaded.
    :return: List of validation JSON schemas for the specified DAT configuration.
    """
    schemas = DebugAuthenticateResponse.get_validation_schemas(
        family=FamilyRevision.load_from_config(config)
    )
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


CONVERTORS = {
    "mbi": (get_schemas_mbi, "Master Boot Image"),
    "sb31": (get_schemas_sb31, "Secure Binary v3.1"),
    "sb40": (get_schemas_sb40, "Secure Binary v4.0"),
    "cert_block": (get_schemas_cert_block, "Certification block"),
    "ahab": (get_schemas_ahab, "AHAB"),
    "signed-msg": (get_schemas_signed_message, "Signed Message"),
    "otfad": (get_schemas_otfad, "OTFAD"),
    "iee": (get_schemas_iee, "IEE"),
    "fcb": (get_schemas_fcb, "FCB"),
    "bootable-image": (get_schemas_bootable_image, "Bootable Image"),
    "xmcd": (get_schemas_xmcd, "XMCD"),
    "bee": (get_schemas_bee, "BEE"),
    "tz": (get_schemas_trust_zone, "Trust Zone"),
    "binary-image": (get_schemas_binary_image, "Binary Image merge"),
    "pfr-cmpa": (get_schemas_pfr_cmpa, "PFR CMPA"),
    "pfr-cfpa": (get_schemas_pfr_cfpa, "PFR CFPA"),
    "ifr-romcfg": (get_schemas_ifr_romcfg, "IFR ROMCFG"),
    "ifr-cmactable": (get_schemas_ifr_cmactable, "IFR CMACTABLE"),
    "shadow-regs": (get_schemas_shadowregs, "Shadow Registers"),
    "dc": (get_schemas_dc, "Debug Credential file"),
    "dat": (get_schemas_dat, "Debug Authentication procedure"),
    "devhsm": (
        get_schemas_devhsm,
        "Device HSM",
    ),  # It is important that SB3.1 config MUST be ahead of devhsm
}


def convert_file(config: str, cfg_type: Optional[str] = None) -> Optional[str]:
    """Convert any type of configuration file to a standardized format.

    This method attempts to load and convert configuration files using available
    convertors. It tries each convertor until one successfully processes the input
    configuration, then formats the result with appropriate titles and family information.

    :param config: Path to the configuration file to be converted.
    :param cfg_type: Optional specific configuration type to convert. If None, all convertors are tried.
    :return: Converted configuration as a string if successful, None if conversion fails.
    """
    click.echo(f"Processing: {config}")
    try:
        configuration = load_configuration(config)
    except SPSDKError as exc:
        click.echo(colorama.Fore.RED + f"Cannot load input file: {str(exc)}" + colorama.Fore.RESET)
        return None

    tool_name = ""
    schemas = None
    for name, info in CONVERTORS.items():
        # try to convert config
        try:
            func = info[0]
            tool_n = info[1]
            if cfg_type is None or (cfg_type and cfg_type.lower() == name):
                schemas = func(configuration)
                tool_name = tool_n
                break
        except SPSDKError:
            pass

    if schemas:
        main_title = f"{tool_name} Configuration"
        family = configuration.get("family")
        if family:
            main_title += f" for {family}"
        ret = CommentedConfig(main_title=main_title, schemas=schemas).get_config(configuration)
        click.echo(
            colorama.Fore.GREEN + f"Converted {tool_name} configuration" + colorama.Fore.RESET
        )
        return ret
    click.echo(colorama.Fore.RED + "Cannot recognize file type." + colorama.Fore.RESET)
    return None


@click.command(name="convert", no_args_is_help=True)
@click.option(
    "-c",
    "--config",
    type=click.Path(exists=True, dir_okay=True, file_okay=True, resolve_path=True),
    required=True,
    multiple=True,
    help="Input configuration file to convert",
)
@click.option(
    "-r",
    "--recursive",
    is_flag=True,
    help="In case that folder is used as a source, it do recursive search.",
)
@click.option(
    "-t",
    "--config-type",
    type=click.Choice(list(CONVERTORS.keys()), case_sensitive=False),
    help="Configuration file type",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=True, file_okay=False, resolve_path=True),
    help="Output configuration YAML file. If not specified, it will be used same file name with YAML extension",
)
@click.option(
    "--rename",
    is_flag=True,
    help="Add to original file additional extension '.converted'",
)
def main(
    config: list[str],
    recursive: bool,
    config_type: Optional[str],
    output: Optional[str],
    rename: bool,
) -> None:
    """Main configuration file conversion utility.

    Converts configuration files from various formats to YAML format. Supports both
    single file and directory processing with optional recursive scanning. Handles
    file renaming and output directory specification.

    :param config: List of source file or directory paths to convert.
    :param recursive: Enable recursive directory scanning for configuration files.
    :param config_type: Specific configuration type to convert, if None auto-detects format.
    :param output: Output directory path, uses source directory if not specified.
    :param rename: Rename original files by adding .converted extension after conversion.
    """
    for source in config:
        source_base_path = source if os.path.isdir(source) else os.path.dirname(source)
        output_folder = output or source_base_path
        all_files = get_all_files(source=source, recursive=recursive)
        click.echo(f"Found {len(all_files)} files to convert in {source} source.")
        for file in all_files:
            out = convert_file(file, config_type)
            if out:
                out_path = (
                    os.path.splitext(file.replace(source_base_path, output_folder))[0] + ".yaml"
                )

                if out_path == file:
                    if out == load_text(file):
                        click.echo(
                            colorama.Fore.YELLOW
                            + "Skipping writing converted file, due no changes."
                            + colorama.Fore.RESET
                        )
                        continue

                if rename:
                    click.echo(
                        colorama.Fore.YELLOW
                        + f"Renamed source file: {file} -> {out_path}"
                        + colorama.Fore.RESET
                    )
                    if os.path.exists(file + ".converted"):
                        os.remove(file + ".converted")
                    os.rename(file, file + ".converted")
                write_file(out, out_path)


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function and exit with its return code.

    This function serves as a safe wrapper around the main function, ensuring
    proper exit code handling and exception management for the CLI application.

    :raises SystemExit: Always raised with the return code from main function.
    """
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
