#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Nxpimage Secure Binary group."""

import logging
import os
from binascii import unhexlify
from typing import Optional

import click

from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import SPSDKAppError, store_key
from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.signature_provider import get_signature_provider_from_config_str
from spsdk.exceptions import SPSDKError
from spsdk.image.cert_block.cert_blocks import CertBlockV1
from spsdk.image.keystore import KeyStore
from spsdk.sbfile.sb2.commands import CmdLoad
from spsdk.sbfile.sb2.images import BootImageV21
from spsdk.sbfile.sb4.images import SecureBinary4
from spsdk.sbfile.sb31.images import SecureBinary31
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import get_printable_path, load_binary, load_hex_string, load_text, write_file
from spsdk.utils.schema_validator import CommentedConfig

logger = logging.getLogger(__name__)


@click.group(name="sb21", cls=CommandsTreeGroup)
def sb21_group() -> None:
    """Group of sub-commands related to Secure Binary 2.1."""


@sb21_group.command(name="export", no_args_is_help=True)
@click.option(
    "-c",
    "--command",
    type=click.Path(exists=True, resolve_path=True),
    required=True,
    help="BD or YAML configuration file to produce secure binary v2.x",
)
@spsdk_output_option(required=False)
@click.option(
    "-k", "--key", type=click.Path(exists=True), help="Add a key file and enable encryption."
)
@click.option(
    "-s",
    "--pkey",
    type=str,
    help="Path to private key or signature provider configuration used for signing.",
)
@click.option(
    "-S",
    "--cert",
    type=click.Path(exists=True),
    multiple=True,
    help="Path to certificate files for signing. The first certificate will be \
the self signed root key certificate.",
)
@click.option(
    "-R",
    "--root-key-cert",
    type=click.Path(exists=True),
    multiple=True,
    help="Path to root key certificate file(s) for verifying other certificates. \
Only 4 root key certificates are allowed, others are ignored. \
One of the certificates must match the first certificate passed \
with -S/--cert arg.",
)
@click.option(
    "-h",
    "--hash-of-hashes",
    type=click.Path(),
    help="Path to output hash of hashes of root keys.",
)
@click.argument("external", type=click.Path(), nargs=-1)
def sb21_export_command(
    command: str,
    output: Optional[str] = None,
    key: Optional[str] = None,
    pkey: Optional[str] = None,
    cert: Optional[list[str]] = None,
    root_key_cert: Optional[list[str]] = None,
    hash_of_hashes: Optional[str] = None,
    external: Optional[list[str]] = None,
) -> None:
    """Generate Secure Binary v2.1 Image from configuration.

    EXTERNAL is a space separated list of external binary files defined in BD file
    """
    sb21_export(command, output, key, pkey, cert, root_key_cert, hash_of_hashes, external)


def sb21_export(
    command: str,
    output: Optional[str] = None,
    key: Optional[str] = None,
    pkey: Optional[str] = None,
    cert: Optional[list[str]] = None,
    root_key_cert: Optional[list[str]] = None,
    hash_of_hashes: Optional[str] = None,
    external: Optional[list[str]] = None,
) -> None:
    """Generate Secure Binary v2.1 Image from configuration (BD or YAML)."""
    signature_provider = None
    if pkey:
        signature_provider = get_signature_provider_from_config_str(pkey)
    try:
        parsed_config = BootImageV21.parse_sb21_config(command, external_files=external)
        if not output:
            output = parsed_config.get_output_file_name("containerOutputFile")
        sb2 = BootImageV21.load_from_config(
            config=parsed_config,
            key_file_path=key,
            signature_provider=signature_provider,
            signing_certificate_file_paths=cert,
            root_key_certificate_paths=root_key_cert,
            rkth_out_path=hash_of_hashes,
        )
        write_file(sb2.export(), output, mode="wb")
    except (SPSDKError, KeyError) as exc:
        raise SPSDKAppError(f"The SB2.1 file generation failed: ({str(exc)}).") from exc
    if sb2.cert_block:
        click.echo(f"RKTH: {sb2.cert_block.rkth.hex()}")
    click.echo(f"Success. (Secure binary 2.1: {get_printable_path(output)} created.)")


@sb21_group.command(name="parse", no_args_is_help=True)
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, readable=True, resolve_path=True),
    required=True,
    help="Path to the SB2 container that would be parsed.",
)
@click.option(
    "-k",
    "--key",
    type=click.Path(exists=True, readable=True),
    required=True,
    help="Key file for SB2 decryption in plaintext",
)
@spsdk_output_option(directory=True)
def sb21_parse_command(binary: str, key: str, output: str) -> None:
    """Parse Secure Binary v2.1 Image."""
    sb21_parse(binary, key, output)


def sb21_parse(binary: str, key: str, output: str) -> None:
    """Parse Secure Binary v2.1 Image."""
    # transform text-based KEK into bytes
    sb_kek = unhexlify(load_text(key))

    try:
        parsed_sb = BootImageV21.parse(data=load_binary(binary), kek=sb_kek)
    except SPSDKError as exc:
        raise SPSDKAppError(f"SB21 parse: Attempt to parse image failed: {str(exc)}") from exc

    if isinstance(parsed_sb.cert_block, CertBlockV1):
        for cert_idx, certificate in enumerate(parsed_sb.cert_block.certificates):
            file_name = os.path.join(output, f"certificate_{cert_idx}_der.cer")
            logger.debug(f"Dumping certificate {file_name}")
            write_file(certificate.export(SPSDKEncoding.DER), file_name, mode="wb")

    for section_idx, boot_sections in enumerate(parsed_sb.boot_sections):
        for command_idx, command in enumerate(boot_sections._commands):
            if isinstance(command, CmdLoad):
                file_name = os.path.join(
                    output, f"section_{section_idx}_load_command_{command_idx}_data.bin"
                )
                logger.debug(f"Dumping load command data {file_name}")
                write_file(command.data, file_name, mode="wb")

    logger.debug(str(parsed_sb))
    write_file(
        str(parsed_sb),
        os.path.join(output, "parsed_info.txt"),
    )
    click.echo(f"Success. (SB21: {binary} has been parsed and stored into {output}.)")
    click.echo(
        "Please note that the exported binary images from load command might contain padding"
    )


@sb21_group.command(name="get-sbkek", no_args_is_help=False)
@click.option(
    "-k",
    "--master-key",
    type=str,
    help="AES-256 master key as hexadecimal string or path to file containing key in plain text or in binary",
)
@spsdk_output_option(
    required=False,
    directory=True,
    help="Output folder where the sbkek.txt and sbkek.bin will be stored",
)
def get_sbkek_command(master_key: str, output: str) -> None:
    """Compute SBKEK (AES-256) value and optionally store it as plain text and as binary.

    SBKEK is AES-256 symmetric key used for encryption and decryption of SB.
    Plain text version is used for SB generation.
    Binary format is to be written to the keystore.
    The same format is also used for USER KEK.

    For OTP, the SBKEK is derived from OTP master key:
    SB2_KEK = AES256(OTP_MASTER_KEY,
    03000000_00000000_00000000_00000000_04000000_00000000_00000000_00000000)

    Master key is not needed when using PUF as key storage

    The computed SBKEK is shown as hexadecimal text on STDOUT,
    SBKEK is stored in plain text and in binary if the 'output-folder' is specified,
    """
    get_sbkek(master_key, output)


def get_sbkek(master_key: str, output_folder: str) -> None:
    """Compute SBKEK (AES-256) value and optionally store it as plain text and as binary."""
    otp_master_key = load_hex_string(master_key, KeyStore.OTP_MASTER_KEY_SIZE)
    sbkek = KeyStore.derive_sb_kek_key(otp_master_key)

    click.echo(f"SBKEK: {sbkek.hex()}")
    click.echo(f"(OTP) MASTER KEY: {otp_master_key.hex()}")

    if output_folder:
        store_key(os.path.join(output_folder, "sbkek"), sbkek, reverse=True)
        store_key(os.path.join(output_folder, "otp_master_key"), otp_master_key)
        click.echo(f"Keys have been stored to: {get_printable_path(output_folder)}")


@sb21_group.command(name="convert", no_args_is_help=False)
@spsdk_family_option(families=BootImageV21.get_supported_families(), required=True)
@spsdk_output_option(help="Path to converted YAML configuration")
@click.option(
    "-c",
    "--command",
    type=click.Path(resolve_path=True, exists=True),
    help="Path to BD file that will be converted to YAML",
    required=True,
)
@click.option(
    "-k",
    "--key",
    type=click.Path(exists=True),
    help="Add a key file and enable encryption.",
    required=True,
)
@click.option(
    "-s",
    "--pkey",
    type=str,
    help="Path to private key or signature provider configuration used for signing.",
)
@click.option(
    "-S",
    "--cert",
    type=click.Path(exists=True),
    multiple=True,
    help="Path to certificate files for signing. The first certificate will be \
the self signed root key certificate.",
)
@click.option(
    "-R",
    "--root-key-cert",
    type=click.Path(exists=True),
    multiple=True,
    help="Path to root key certificate file(s) for verifying other certificates. \
Only 4 root key certificates are allowed, others are ignored. \
One of the certificates must match the first certificate passed \
with -S/--cert arg.",
)
@click.option(
    "-h",
    "--hash-of-hashes",
    type=click.Path(),
    help="Path to output hash of hashes of root keys. If argument is not \
provided, then by default the tool creates hash.bin in the working directory.",
)
@click.argument("external", type=click.Path(), nargs=-1)
def convert_bd(
    command: str,
    output: str,
    key: str,
    pkey: str,
    cert: list[str],
    root_key_cert: list[str],
    hash_of_hashes: str,
    external: list[str],
    family: FamilyRevision,
) -> None:
    """Convert SB 2.1 BD file to YAML."""
    convert_bd_conf(
        command, output, key, pkey, cert, root_key_cert, hash_of_hashes, external, family
    )


def convert_bd_conf(
    command: str,
    output_conf: str,
    key: str,
    pkey: str,
    cert: list[str],
    root_key_cert: list[str],
    hash_of_hashes: str,
    external: list[str],
    family: FamilyRevision,
) -> None:
    """Convert SB 2.1 BD file to YAML."""
    config = BootImageV21.parse_sb21_config(command, external_files=external)
    cert_config = {}
    for idx, root_cert in enumerate(root_key_cert):
        cert_config[f"rootCertificate{idx}File"] = root_cert
        for crt in cert:
            if root_cert == crt:
                cert_config["mainRootCertId"] = idx  # type: ignore[assignment]
    cert_config["imageBuildNumber"] = config["options"].pop("buildNumber")
    config["signer"] = pkey
    if key:
        config["containerKeyBlobEncryptionKey"] = key
    if hash_of_hashes:
        config["RKHTOutputPath"] = hash_of_hashes

    config["containerOutputFile"] = "output.sb"
    cert_block_file = "cert_block.yaml"
    config["certBlock"] = cert_block_file
    config["family"] = family.name
    config["revision"] = family.revision

    schemas = BootImageV21.get_validation_schemas(family)
    ret = CommentedConfig(main_title="SB 2.1 converted configuration", schemas=schemas).get_config(
        config
    )
    write_file(ret, output_conf)

    schemas = CertBlockV1.get_validation_schemas(family)
    ret = CommentedConfig(main_title="Certificate Block V1", schemas=schemas).get_config(
        cert_config
    )
    write_file(ret, os.path.join(os.path.dirname(output_conf), cert_block_file))
    click.echo(f"Converted YAML configuration written to {output_conf}")


@sb21_group.command(name="get-template", no_args_is_help=True)
@spsdk_output_option(force=True)
@spsdk_family_option(families=BootImageV21.get_supported_families())
def sb21_get_template_command(output: str, family: FamilyRevision) -> None:
    """Create template of configuration in YAML format."""
    sb21_get_template(output, family)


def sb21_get_template(output: str, family: FamilyRevision) -> None:
    """Create template of configuration in YAML format."""
    click.echo(f"Creating {get_printable_path(output)} template file.")
    write_file(BootImageV21.get_config_template(family), output)


@click.group(name="sb31", cls=CommandsTreeGroup)
def sb31_group() -> None:
    """Group of sub-commands related to Secure Binary 3.1."""


@sb31_group.command(name="export", no_args_is_help=True)
@spsdk_config_option(klass=SecureBinary31)
def sb31_export_command(config: Config) -> None:
    """Generate Secure Binary v3.1 Image from YAML/JSON configuration.

    SB3KDK is printed out in verbose mode.

    The configuration template files could be generated by subcommand 'get-template'.
    """
    sb31_export(config)


def sb31_export(config: Config) -> None:
    """Generate Secure Binary v3.1 Image from YAML/JSON configuration."""
    sb3 = SecureBinary31.load_from_config(config)
    sb3_data = sb3.export()
    sb3_output_file_path = config.get_output_file_name("containerOutputFile")
    write_file(sb3_data, sb3_output_file_path, mode="wb")

    click.echo(f"RKTH: {sb3.get_rkth().hex()}")
    click.echo(f"Success. (Secure binary 3.1: {get_printable_path(sb3_output_file_path)} created.)")


@sb31_group.command(name="get-template", no_args_is_help=True)
@spsdk_family_option(families=SecureBinary31.get_supported_families())
@spsdk_output_option(force=True)
def sb31_get_template_command(family: FamilyRevision, output: str) -> None:
    """Create template of configuration in YAML format.

    The template file name is specified as argument of this command.
    """
    sb31_get_template(family, output)


def sb31_get_template(family: FamilyRevision, output: str) -> None:
    """Create template of configuration in YAML format."""
    click.echo(f"Creating {get_printable_path(output)} template file.")
    write_file(SecureBinary31.get_config_template(family), output)


@sb31_group.command(name="parse", no_args_is_help=True)
@spsdk_family_option(families=SecureBinary31.get_supported_families(), required=True)
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, readable=True, resolve_path=True),
    required=True,
    help="Path to the SB3.1 container to parse.",
)
@click.option(
    "-k",
    "--pck",
    type=str,
    help=(
        "Part Common Key file for SB3.1 decryption (hex text, text file or binary PCK)."
        "Alternatively you may provide a configuration string for a Key Derivation plugin"
    ),
)
@click.option(
    "-a",
    "--kdk-access-rights",
    type=click.INT,
    default=0,
    help="Key Derivation Key access rights, defaults to 0",
)
@spsdk_output_option(directory=True)
def sb31_parse_command(
    family: FamilyRevision, binary: str, pck: str, kdk_access_rights: int, output: str
) -> None:
    """Parse Secure Binary v3.1 Image.

    Parses an SB3.1 container and extracts its contents to the specified output directory.
    """
    sb31_parse(family, binary, pck, kdk_access_rights, output)


def sb31_parse(
    family: FamilyRevision, binary: str, pck: str, kdk_access_rights: int, output: str
) -> None:
    """Parse Secure Binary v3.1 Image.

    :param family: Device family and revision
    :param binary: Path to SB3.1 container to parse
    :param pck: Path to Part Common Key file
    :param kdk_access_rights: Key Derivation Key access rights
    :param output: Output directory where extracted contents will be stored
    """
    try:
        # Parse the SB3.1 container
        parsed_sb = SecureBinary31.parse(
            data=load_binary(binary),
            family=family,
            pck=pck,
            kdk_access_rights=kdk_access_rights,
        )
        output_file_name = os.path.join(output, f"sb31_{family.name}_config.yaml")
        write_file(
            parsed_sb.get_config_yaml(output), output_file_name
        )  # Optional: Get YAML configuration if needed

        click.echo(
            f"Success. (SB3.1: {binary} has been parsed and stored into {output_file_name}.)"
        )

    except SPSDKError as exc:
        raise SPSDKAppError(f"SB3.1 parse: Attempt to parse image failed: {str(exc)}") from exc


@click.group(name="sb40", cls=CommandsTreeGroup)
def sb40_group() -> None:
    """Group of sub-commands related to Secure Binary 4.0."""


@sb40_group.command(name="export", no_args_is_help=True)
@spsdk_config_option(klass=SecureBinary4)
def sb40_export_command(config: Config) -> None:
    """Generate Secure Binary v4.0 Image from YAML/JSON configuration.

    SB3KDK is printed out in verbose mode.

    The configuration template files could be generated by subcommand 'get-template'.
    """
    sb40_export(config)


def sb40_export(config: Config) -> None:
    """Generate Secure Binary v4.0 Image from YAML/JSON configuration."""
    sb4 = SecureBinary4.load_from_config(config)
    sb4_data = sb4.export()
    sb4_output_file_path = config.get_output_file_name("containerOutputFile")
    write_file(sb4_data, sb4_output_file_path, mode="wb")

    click.echo(f"SRKH: {sb4.container.srk_hash0.hex()}")
    if sb4.container.srk_count > 1:
        click.echo(f"SRKH PQC: {sb4.container.srk_hash1.hex()}")
    click.echo(f"Success. (Secure binary 4.0: {get_printable_path(sb4_output_file_path)} created.)")


@sb40_group.command(name="get-template", no_args_is_help=True)
@spsdk_family_option(families=SecureBinary4.get_supported_families())
@spsdk_output_option(force=True)
def sb40_get_template_command(family: FamilyRevision, output: str) -> None:
    """Create template of configuration in YAML format.

    The template file name is specified as argument of this command.
    """
    sb40_get_template(family, output)


def sb40_get_template(family: FamilyRevision, output: str) -> None:
    """Create template of configuration in YAML format."""
    click.echo(f"Creating {get_printable_path(output)} template file.")
    write_file(SecureBinary4.get_config_template(family), output)


@sb40_group.command(name="parse", no_args_is_help=True)
@spsdk_family_option(families=SecureBinary4.get_supported_families(), required=True)
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, readable=True, resolve_path=True),
    required=True,
    help="Path to the SB4.0 container to parse.",
)
@click.option(
    "-k",
    "--pck",
    type=str,
    help=(
        "Part Common Key file for SB4.0 decryption (hex text, text file or binary PCK). "
        "Alternatively you may provide a configuration string for a Key Derivation plugin"
    ),
)
@click.option(
    "-a",
    "--kdk-access-rights",
    type=click.INT,
    default=0,
    help="Key Derivation Key access rights, defaults to 0",
)
@spsdk_output_option(directory=True)
def sb40_parse_command(
    family: FamilyRevision, binary: str, pck: str, kdk_access_rights: int, output: str
) -> None:
    """Parse Secure Binary v4.0 Image.

    Parses an SB4.0 container and extracts its contents to the specified output directory.
    """
    sb40_parse(family, binary, pck, kdk_access_rights, output)


def sb40_parse(
    family: FamilyRevision, binary: str, pck: str, kdk_access_rights: int, output: str
) -> None:
    """Parse Secure Binary v4.0 Image.

    :param family: Device family and revision
    :param binary: Path to SB4.0 container to parse
    :param pck: Path to Part Common Key file
    :param kdk_access_rights: Key Derivation Key access rights
    :param output: Output directory where extracted contents will be stored
    """
    try:
        # Parse the SB4.0 container
        parsed_sb = SecureBinary4.parse(
            data=load_binary(binary),
            family=family,
            pck=pck,
            kdk_access_rights=kdk_access_rights,
        )
        output_file_name = os.path.join(output, f"sb4_{family.name}_config.yaml")
        write_file(
            parsed_sb.get_config_yaml(output), output_file_name
        )  # Optional: Get YAML configuration if needed

        click.echo(
            f"Success. (SB4.0: {binary} has been parsed and stored into {output_file_name}.)"
        )

    except SPSDKError as exc:
        raise SPSDKAppError(f"SB4.0 parse: Attempt to parse image failed: {str(exc)}") from exc
