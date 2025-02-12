#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Convert and clean up old typically JSON SCHEMAS."""

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
from spsdk.image.bee import BeeNxp
from spsdk.image.bootable_image.bimg import BootableImage
from spsdk.image.fcb.fcb import FCB
from spsdk.image.mbi.mbi import get_mbi_class
from spsdk.image.mem_type import MemoryType
from spsdk.image.trustzone import TrustZone
from spsdk.image.xmcd.xmcd import XMCD
from spsdk.pfr.pfr import CFPA, CMACTABLE, CMPA, ROMCFG
from spsdk.sbfile.sb31.devhsm import DevHsmSB31
from spsdk.sbfile.sb31.images import SecureBinary31
from spsdk.utils.crypto.cert_blocks import CertBlockV21
from spsdk.utils.crypto.iee import IeeNxp
from spsdk.utils.crypto.otfad import OtfadNxp
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import load_configuration, load_text, write_file
from spsdk.utils.schema_validator import CommentedConfig, check_config

disable_files_dirs_formatters: dict[str, Callable[[str], bool]] = {
    "dir": lambda x: bool(os.path.basename(x.replace("\\", "/"))),
    "file": lambda x: bool(os.path.basename(x.replace("\\", "/"))),
    "file_name": lambda x: os.path.basename(x.replace("\\", "/")) not in ("", None),
    "optional_file": lambda x: not x or bool(os.path.basename(x.replace("\\", "/"))),
}


def get_all_files(source: str, recursive: bool = False) -> list[str]:
    """Gather all python files in root_folders."""
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
    """Get validation schema for MBI configurations.

    :param config: Any configuration of MBI
    :return: Validation JSON schemas
    """
    mbi_cls = get_mbi_class(config)
    schemas = mbi_cls.get_validation_schemas(config["family"])
    check_config(config=config, schemas=schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_sb31(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for SB3.1 configurations.

    :param config: Any configuration of SB3.1
    :return: Validation JSON schemas
    """
    check_config(config, SecureBinary31.get_validation_schemas_family())
    schemas = SecureBinary31.get_validation_schemas(config["family"])
    check_config(config=config, schemas=schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_devhsm(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for DEVHSM configurations.

    :param config: Any configuration of DEVHSM
    :return: Validation JSON schemas
    """
    check_config(config, SecureBinary31.get_validation_schemas_family())

    schemas = DevHsmSB31.get_validation_schemas(config["family"])
    check_config(config=config, schemas=schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_cert_block(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for Certification block configurations.

    :param config: Any configuration of Certification block
    :return: Validation JSON schemas
    """
    schemas = CertBlockV21.get_validation_schemas()
    schemas.append(get_schema_file(DatabaseManager.CERT_BLOCK)["cert_block_output"])
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_ahab(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for AHAB configurations.

    :param config: Any configuration of AHAB
    :return: Validation JSON schemas
    """
    check_config(config, AHABImage.get_validation_schemas_family())
    schemas = AHABImage.get_validation_schemas(config["family"], config.get("revision", "latest"))
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_signed_message(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for Signed Message configurations.

    :param config: Any configuration of Signed Message
    :return: Validation JSON schemas
    """
    schemas = SignedMessage.get_validation_schemas(
        config["family"], config.get("revision", "latest")
    )

    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_otfad(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for OTFAD configurations.

    :param config: Any configuration of OTFAD
    :return: Validation JSON schemas
    """
    check_config(
        config,
        OtfadNxp.get_validation_schemas_family(),
        extra_formatters=disable_files_dirs_formatters,
    )
    family = config["family"]
    schemas = OtfadNxp.get_validation_schemas(family)
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_iee(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for IEE configurations.

    :param config: Any configuration of IEE
    :return: Validation JSON schemas
    """
    check_config(
        config,
        IeeNxp.get_validation_schemas_family(),
        extra_formatters=disable_files_dirs_formatters,
    )
    family = config["family"]
    schemas = IeeNxp.get_validation_schemas(family)
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_fcb(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for FCB configurations.

    :param config: Any configuration of FCB
    :return: Validation JSON schemas
    """
    check_config(config, FCB.get_validation_schemas_family())
    chip_family = config["family"]
    mem_type = MemoryType.from_label(config.get("type", "Unknown"))
    revision = config.get("revision", "latest")
    schemas = FCB.get_validation_schemas(chip_family, mem_type, revision)
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)

    return schemas


def get_schemas_bootable_image(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for Bootable Image configurations.

    :param config: Any configuration of bootable image
    :return: Validation JSON schemas
    """
    check_config(config, BootableImage.get_validation_schemas_family())
    chip_family = config["family"]
    mem_type = MemoryType.from_label(config["memory_type"])
    revision = config.get("revision", "latest")
    schemas = BootableImage.get_validation_schemas(chip_family, mem_type, revision)
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)

    return schemas


def get_schemas_xmcd(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for XMCD configurations.

    :param config: Any configuration of XMCD
    :return: Validation JSON schemas
    """
    check_config(config, XMCD.get_validation_schemas_family())
    chip_family = config["family"]
    mem_type = config["mem_type"]
    config_type = config["config_type"]
    revision = config.get("revision", "latest")
    schemas = XMCD.get_validation_schemas(chip_family, mem_type, config_type, revision)
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)

    return schemas


def get_schemas_bee(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for BEE configurations.

    :param config: Any configuration of BEE
    :return: Validation JSON schemas
    """
    schemas = BeeNxp.get_validation_schemas()
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_trust_zone(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for Trust Zone configurations.

    :param config: Any configuration of Trust Zone
    :return: Validation JSON schemas
    """
    check_config(config, TrustZone.get_validation_schemas_family())
    schemas = TrustZone.get_validation_schemas(config["family"])
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_binary_image(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for Binary Image merge configurations.

    :param config: Any configuration of Binary Image merge
    :return: Validation JSON schemas
    """
    schemas = BinaryImage.get_validation_schemas()
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_pfr_cmpa(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for PFR CMPA configurations.

    :param config: Any configuration of PFR CMPA
    :return: Validation JSON schemas
    """
    schemas = CMPA.get_validation_schemas(
        family=config["family"], revision=config.get("revision", "latest")
    )
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_pfr_cfpa(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for PFR CFPA configurations.

    :param config: Any configuration of PFR CFPA
    :return: Validation JSON schemas
    """
    schemas = CFPA.get_validation_schemas(
        family=config["family"], revision=config.get("revision", "latest")
    )
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_ifr_romcfg(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for IFR ROMCFG configurations.

    :param config: Any configuration of IFR ROMCFG
    :return: Validation JSON schemas
    """
    schemas = ROMCFG.get_validation_schemas(
        family=config["family"], revision=config.get("revision", "latest")
    )
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_ifr_cmactable(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for IFR CMACTABLE configurations.

    :param config: Any configuration of IFR CMACTABLE
    :return: Validation JSON schemas
    """
    schemas = CMACTABLE.get_validation_schemas(
        family=config["family"], revision=config.get("revision", "latest")
    )
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_shadowregs(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for Shadow register configurations.

    :param config: Any configuration of Shadow  registers
    :return: Validation JSON schemas
    """
    schemas = ShadowRegisters.get_validation_schemas(
        family=config["family"], revision=config.get("revision", "latest")
    )
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_dc(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for DC file configurations.

    :param config: Any configuration of DC file
    :return: Validation JSON schemas
    """
    schemas = DebugCredentialCertificate.get_validation_schemas(
        family=config["family"], revision=config.get("revision", "latest")
    )
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_dat(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Get validation schema for DAT configurations.

    :param config: Any configuration of DAT
    :return: Validation JSON schemas
    """
    schemas = DebugAuthenticateResponse.get_validation_schemas(
        family=config["family"], revision=config.get("revision", "latest")
    )
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


CONVERTORS = {
    "mbi": (get_schemas_mbi, "Master Boot Image"),
    "sb31": (get_schemas_sb31, "Secure Binary v3.1"),
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
    """Convert any type of configuration."""
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
    type=bool,
    help="Add to original file additional extension '.converted'",
)
def main(
    config: list[str],
    recursive: bool,
    config_type: Optional[str],
    output: Optional[str],
    rename: bool,
) -> None:
    """Main convert utility."""
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
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
