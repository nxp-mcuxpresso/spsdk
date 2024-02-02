#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Convert and clean up old typically JSON SCHEMAS."""

import os
import sys
from typing import Any, Callable, Dict, List, Optional

import click
import colorama

from spsdk.apps.utils.utils import catch_spsdk_error
from spsdk.exceptions import SPSDKError
from spsdk.image.ahab.ahab_container import AHABImage
from spsdk.image.ahab.signed_msg import SignedMessage
from spsdk.image.bee import BeeNxp
from spsdk.image.bootable_image.bimg import BootableImage
from spsdk.image.fcb.fcb import FCB
from spsdk.image.mbi.mbi import get_mbi_class
from spsdk.image.trustzone import TrustZone
from spsdk.image.xmcd.xmcd import XMCD
from spsdk.sbfile.sb31.devhsm import DevHsmSB31
from spsdk.sbfile.sb31.images import SecureBinary31
from spsdk.utils.crypto.cert_blocks import CertBlockV21
from spsdk.utils.crypto.iee import IeeNxp
from spsdk.utils.crypto.otfad import OtfadNxp
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import load_configuration, load_text, write_file
from spsdk.utils.schema_validator import CommentedConfig, check_config

disable_files_dirs_formatters: Dict[str, Callable[[str], bool]] = {
    "dir": lambda x: bool(os.path.basename(x.replace("\\", "/"))),
    "file": lambda x: bool(os.path.basename(x.replace("\\", "/"))),
    "file_name": lambda x: os.path.basename(x.replace("\\", "/")) not in ("", None),
    "optional_file": lambda x: not x or bool(os.path.basename(x.replace("\\", "/"))),
}


def get_all_files(source: str, recursive: bool = False) -> List[str]:
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


def get_schemas_mbi(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get validation schema for MBI configurations.

    :param config: Any configuration of MBI
    :return: Validation JSON schemas
    """
    mbi_cls = get_mbi_class(config)
    schemas = mbi_cls.get_validation_schemas()
    check_config(config=config, schemas=schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_sb31(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get validation schema for SB3.1 configurations.

    :param config: Any configuration of SB3.1
    :return: Validation JSON schemas
    """
    check_config(config, SecureBinary31.get_validation_schemas_family())
    schemas = SecureBinary31.get_validation_schemas(config["family"])
    check_config(config=config, schemas=schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_devhsm(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get validation schema for DEVHSM configurations.

    :param config: Any configuration of DEVHSM
    :return: Validation JSON schemas
    """
    sb3_sch_cfg = get_schema_file(DatabaseManager.SB31)
    check_config(config, [sb3_sch_cfg["sb3_family"]])

    schemas = DevHsmSB31.get_validation_schemas(config["family"])
    check_config(config=config, schemas=schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_cert_block(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get validation schema for Certification block configurations.

    :param config: Any configuration of Certification block
    :return: Validation JSON schemas
    """
    schemas = CertBlockV21.get_validation_schemas()
    schemas.append(
        DatabaseManager().db.get_schema_file(DatabaseManager.CERT_BLOCK)["cert_block_output"]
    )
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_ahab(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get validation schema for AHAB configurations.

    :param config: Any configuration of AHAB
    :return: Validation JSON schemas
    """
    schemas = AHABImage.get_validation_schemas()
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_signed_message(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get validation schema for Signed Message configurations.

    :param config: Any configuration of Signed Message
    :return: Validation JSON schemas
    """
    schemas = SignedMessage.get_validation_schemas()

    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_otfad(config: Dict[str, Any]) -> List[Dict[str, Any]]:
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


def get_schemas_iee(config: Dict[str, Any]) -> List[Dict[str, Any]]:
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


def get_schemas_fcb(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get validation schema for FCB configurations.

    :param config: Any configuration of FCB
    :return: Validation JSON schemas
    """
    check_config(config, FCB.get_validation_schemas_family())
    chip_family = config["family"]
    mem_type = config["type"]
    revision = config.get("revision", "latest")
    schemas = FCB.get_validation_schemas(chip_family, mem_type, revision)
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)

    return schemas


def get_schemas_bootable_image(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get validation schema for Bootable Image configurations.

    :param config: Any configuration of bootable image
    :return: Validation JSON schemas
    """
    check_config(config, BootableImage.get_validation_schemas_family())
    chip_family = config["family"]
    mem_type = config["memory_type"]
    revision = config.get("revision", "latest")
    schemas = BootableImage.get_validation_schemas(chip_family, mem_type, revision)
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)

    return schemas


def get_schemas_xmcd(config: Dict[str, Any]) -> List[Dict[str, Any]]:
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


def get_schemas_bee(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get validation schema for BEE configurations.

    :param config: Any configuration of BEE
    :return: Validation JSON schemas
    """
    schemas = BeeNxp.get_validation_schemas()
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_trust_zone(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get validation schema for Trust Zone configurations.

    :param config: Any configuration of Trust Zone
    :return: Validation JSON schemas
    """
    check_config(config, TrustZone.get_validation_schemas_family())
    schemas = TrustZone.get_validation_schemas(config["family"])
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


def get_schemas_binary_image(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get validation schema for Binary Image merge configurations.

    :param config: Any configuration of Binary Image merge
    :return: Validation JSON schemas
    """
    schemas = BinaryImage.get_validation_schemas()
    check_config(config, schemas, extra_formatters=disable_files_dirs_formatters)
    return schemas


CONVERTORS = {
    "mbi": (get_schemas_mbi, "Master Boot Image"),
    "sb31": (get_schemas_sb31, "Secure Binary v3.1"),
    "devhsm": (
        get_schemas_devhsm,
        "Device HSM",
    ),  # It is important that SB3.1 config MUST be ahead of devhsm
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
        ret = CommentedConfig(
            main_title=f"{tool_name} converted config.", schemas=schemas
        ).get_config(configuration)
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
    config: List[str],
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
