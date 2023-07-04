#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for Elf2SB."""
import os
import sys
from typing import Dict, List

import click
from click_option_group import RequiredMutuallyExclusiveOptionGroup, optgroup

from spsdk import __version__ as spsdk_version
from spsdk.apps.utils.utils import SPSDKAppError, catch_spsdk_error
from spsdk.crypto.signature_provider import get_signature_provider
from spsdk.exceptions import SPSDKError
from spsdk.image import TrustZone, get_mbi_class
from spsdk.image.mbimg import mbi_generate_config_templates, mbi_get_supported_families
from spsdk.sbfile.sb2.images import generate_SB21
from spsdk.sbfile.sb31.images import SB3_SCH_FILE, SecureBinary31
from spsdk.utils.misc import load_configuration, write_file
from spsdk.utils.plugins import load_plugin_from_source
from spsdk.utils.schema_validator import ValidationSchemas, check_config

SUPPORTED_FAMILIES = mbi_get_supported_families()


def generate_trustzone_binary(tzm_conf: str) -> None:
    """Generate TrustZone binary from json configuration file."""
    config_data = load_configuration(tzm_conf)
    check_config(config_data, TrustZone.get_validation_schemas_family())
    check_config(config_data, TrustZone.get_validation_schemas(config_data["family"]))
    trustzone = TrustZone.from_config(config_data)
    tz_data = trustzone.export()
    output_file = os.path.abspath(config_data["tzpOutputFile"])
    write_file(tz_data, output_file, mode="wb")
    click.echo(f"Success. (Trustzone binary: {output_file} created.)")


def generate_config_templates(family: str, output_folder: str) -> None:
    """Generate all possible configuration for selected family."""
    if not family:
        raise SPSDKError("The chip family must be specified.")

    templates: Dict[str, str] = {}
    # 1: Generate all configuration for MBI
    templates.update(mbi_generate_config_templates(family))
    # 2: Optionally add TrustZone Configuration file
    templates.update(TrustZone.generate_config_template(family))
    # 3: Optionally add Secure Binary v3.1 Configuration file
    templates.update(SecureBinary31.generate_config_template(family))

    # And generate all config templates files
    for key, val in templates.items():
        file_name = f"{key}.yaml"
        if os.path.isfile(output_folder):
            raise SPSDKError(f"The specified path {output_folder} is file.")
        if not os.path.isdir(output_folder):
            os.mkdir(output_folder)
        full_file_name = os.path.abspath(os.path.join(output_folder, file_name))
        if not os.path.isfile(full_file_name):
            click.echo(f"Creating {file_name} template file.")
            write_file(val, full_file_name)
        else:
            click.echo(f"Skip creating {full_file_name}, this file already exists.")


def generate_master_boot_image(image_conf: str) -> None:
    """Generate MasterBootImage from json configuration file.

    :param image_conf: master boot image json configuration file.
    """
    config_data = load_configuration(image_conf)
    mbi_cls = get_mbi_class(config_data)
    check_config(config_data, mbi_cls.get_validation_schemas())
    mbi = mbi_cls()
    mbi.load_from_config(config_data)
    mbi_data = mbi.export()

    mbi_output_file_path = os.path.abspath(config_data["masterBootOutputFile"])
    write_file(mbi_data, mbi_output_file_path, mode="wb")

    click.echo(f"Success. (Master Boot Image: {mbi_output_file_path} created.)")


def generate_secure_binary_21(
    bd_file_path: str,
    output_file_path: str,
    key_file_path: str,
    private_key_file_path: str,
    signing_certificate_file_paths: List[str],
    root_key_certificate_paths: List[str],
    hoh_out_path: str,
    plugin: str,
    external_files: List[str],
) -> None:
    """Generate SecureBinary image from BD command file.

    :param bd_file_path: path to BD file.
    :param output_file_path: output path to generated secure binary file.
    :param key_file_path: path to key file.
    :param private_key_file_path: path to private key file for signing. This key
    relates to last certificate from signing certificate chain.
    :param signing_certificate_file_paths: signing certificate chain.
    :param root_key_certificate_paths: paths to root key certificate(s) for
    verifying other certificates. Only 4 root key certificates are allowed,
    others are ignored. One of the certificates must match the first certificate
    passed in signing_certificate_file_paths.
    :param hoh_out_path: output path to hash of hashes of root keys. If set to
    None, 'hash.bin' is created under working directory.
    :param plugin: External python file containing a custom SignatureProvider implementation.
    :param external_files: external files referenced from BD file.

    :raises SPSDKAppError: If incorrect bf file is provided
    """
    if plugin:
        load_plugin_from_source(plugin)
    if output_file_path is None:
        raise SPSDKAppError("Error: no output file was specified")
    signature_provider = (
        get_signature_provider(local_file_key=private_key_file_path)
        if os.path.isfile(private_key_file_path)
        else get_signature_provider(sp_cfg=private_key_file_path)
    )
    try:
        sb2_data = generate_SB21(
            bd_file_path=str(bd_file_path),
            key_file_path=str(key_file_path),
            signature_provider=signature_provider,
            signing_certificate_file_paths=[str(x) for x in signing_certificate_file_paths],
            root_key_certificate_paths=[str(x) for x in root_key_certificate_paths],
            hoh_out_path=str(hoh_out_path),
            external_files=[str(x) for x in external_files],
        )
        output_file_path = os.path.abspath(output_file_path)
        write_file(sb2_data, output_file_path, mode="wb")
    except SPSDKError as exc:
        raise SPSDKAppError(f"The SB2.1 file generation failed: ({str(exc)}).") from exc
    else:
        click.echo(f"Success. (Secure binary 2.1: {output_file_path} created.)")


def generate_secure_binary_31(container_conf: str) -> None:
    """Generate SecureBinary image from json configuration file.

    RoTKTH/SB3KDK is printed out in verbose mode

    :param container_conf: configuration file
    :raises SPSDKError: Raised when there is no signing key
    """
    config_data = load_configuration(container_conf)
    check_config(config_data, SecureBinary31.get_validation_schemas_family())
    schemas = SecureBinary31.get_validation_schemas(
        config_data["family"], include_test_configuration=True
    )
    schemas.append(ValidationSchemas.get_schema_file(SB3_SCH_FILE)["sb3_output"])
    check_config(config_data, schemas)
    sb3 = SecureBinary31.load_from_config(config_data)
    sb3_data = sb3.export(cert_block=None)

    sb3_output_file_path = os.path.abspath(config_data["containerOutputFile"])
    write_file(sb3_data, sb3_output_file_path, mode="wb")

    click.echo(f"Success. (Secure binary 3.1: {sb3_output_file_path} created.)")


@click.command(name="elftosb", no_args_is_help=True)
@optgroup.group("Output file type generation selection.", cls=RequiredMutuallyExclusiveOptionGroup)
@optgroup.option(
    "-c",
    "--command",
    type=click.Path(exists=True, file_okay=True),
    help="BD configuration file to produce secure binary v2.x",
)
@optgroup.option(
    "-J",
    "--image-conf",
    type=click.Path(exists=True, file_okay=True),
    help="YAML/JSON image configuration file to produce master boot image",
)
@optgroup.option(
    "-j",
    "--container-conf",
    type=click.Path(exists=True, file_okay=True),
    help="YAML/JSON  container configuration file to produce secure binary v3.x",
)
@optgroup.option(
    "-T",
    "--tzm-conf",
    type=click.Path(exists=True, file_okay=True),
    help="YAML/JSON trust zone configuration file to produce trust zone binary",
)
@optgroup.option(
    "-Y",
    "--config-template",
    type=click.Path(dir_okay=True, file_okay=False),
    help="Path to store all configuration templates for selected family",
)
@click.option(
    "-f",
    "--chip-family",
    default="lpc55s3x",
    help="Select the chip family (default is lpc55s3x), this field is used with -Y/--config_template option only.",
    type=click.Choice(SUPPORTED_FAMILIES, case_sensitive=False),
)
@optgroup.group("Command file options (SB2.x file format only)")
@optgroup.option("-o", "--output", type=click.Path(), help="Output file path.")
@optgroup.option(
    "-k", "--key", type=click.Path(exists=True), help="Add a key file and enable encryption."
)
@optgroup.option(
    "-s", "--pkey", type=click.Path(exists=True), help="Path to private key for signing."
)
@optgroup.option(
    "-S",
    "--cert",
    type=click.Path(exists=True),
    multiple=True,
    help="Path to certificate files for signing. The first certificate will be \
the self signed root key certificate.",
)
@optgroup.option(
    "-R",
    "--root-key-cert",
    type=click.Path(exists=True),
    multiple=True,
    help="Path to root key certificate file(s) for verifying other certificates. \
Only 4 root key certificates are allowed, others are ignored. \
One of the certificates must match the first certificate passed \
with -S/--cert arg.",
)
@optgroup.option(
    "-h",
    "--hash-of-hashes",
    type=click.Path(),
    help="Path to output hash of hashes of root keys. If argument is not \
provided, then by default the tool creates hash.bin in the working directory.",
)
@click.option(
    "--plugin",
    type=click.Path(exists=True, dir_okay=False),
    required=False,
    help="External python file containing a custom SignatureProvider implementation.",
)
@click.version_option(spsdk_version, "--version")
@click.help_option("--help")
@click.argument("external", type=click.Path(), nargs=-1)
def main(
    chip_family: str,
    command: str,
    output: str,
    key: str,
    pkey: str,
    cert: List[str],
    root_key_cert: List[str],
    image_conf: str,
    container_conf: str,
    tzm_conf: str,
    config_template: str,
    hash_of_hashes: str,
    plugin: str,
    external: List[str],
) -> None:
    """Tool for generating TrustZone, MasterBootImage and SecureBinary images.

    !!! The ELFTOSB tool is deprecated, use new NXPIMAGE tool from SPSDK for new projects !!!
    """
    click.secho("Deprecated tool! Use npximage instead", fg="yellow")
    if command:
        if output is None:
            raise SPSDKAppError("Error: no output file was specified")
        generate_secure_binary_21(
            bd_file_path=command,
            output_file_path=output,
            key_file_path=key,
            private_key_file_path=pkey,
            signing_certificate_file_paths=cert,
            root_key_certificate_paths=root_key_cert,
            hoh_out_path=hash_of_hashes,
            plugin=plugin,
            external_files=external,
        )

    if image_conf:
        generate_master_boot_image(image_conf)

    if container_conf:
        generate_secure_binary_31(container_conf)

    if tzm_conf:
        generate_trustzone_binary(tzm_conf)

    if config_template:
        generate_config_templates(chip_family, config_template)


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
