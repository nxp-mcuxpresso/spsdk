#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""NXP Certificate Generator."""
import logging
import os
import sys
from typing import BinaryIO, TextIO

import click

from spsdk import SPSDK_DATA_FOLDER, SPSDKError
from spsdk import __version__ as spsdk_version
from spsdk.apps.utils import (
    catch_spsdk_error,
    check_destination_dir,
    check_file_exists,
    load_configuration,
)
from spsdk.crypto import (
    Encoding,
    generate_certificate,
    load_private_key,
    load_public_key,
    save_crypto_item,
    x509,
)

NXPCERTGEN_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "nxpcertgen")

logger = logging.getLogger(__name__)


class CertificateParametersConfig:
    """Configuration object for creating the certificate."""

    def __init__(self, config_data: dict) -> None:
        """Initialize cert_config from yml config data."""
        try:
            self.issuer_private_key = config_data["issuer_private_key"]
            self.subject_public_key = config_data["subject_public_key"]
            self.serial_number = config_data["serial_number"]
            self.duration = config_data["duration"]
            self.BasicConstrains_ca = config_data["extensions"]["BASIC_CONSTRAINTS"]["ca"]
            self.BasicConstrains_path_length = config_data["extensions"]["BASIC_CONSTRAINTS"][
                "path_length"
            ]
            self.issuer_name = generate_name(config_data["issuer"])
            self.subject_name = generate_name(config_data["subject"])
        except KeyError as e:
            raise SPSDKError(f"Error found in configuration: {e} not found")


def generate_name(config_data: dict) -> x509.Name:
    """Set the issuer/subject distinguished attribute's."""
    attributes = []
    for key, value in config_data.items():
        if not hasattr(x509.NameOID, key):
            raise SPSDKError(f"Invalid NameOID: {key}")
        attributes.append(x509.NameAttribute(getattr(x509.NameOID, key), str(value)))
    return x509.Name(attributes)


@click.group(no_args_is_help=True)  # type: ignore
@click.option(
    "-v",
    "--verbose",
    "log_level",
    flag_value=logging.INFO,
    help="Prints more detailed information.",
)
@click.option(
    "-d",
    "--debug",
    "log_level",
    flag_value=logging.DEBUG,
    help="Display more debugging info.",
)
@click.version_option(spsdk_version, "--version")
def main(log_level: int) -> None:
    """Utility for certificate generation."""
    logging.basicConfig(level=log_level or logging.WARNING)


@main.command()
@click.option(
    "-j",
    "-c",
    "--config",
    type=click.File("r"),
    required=True,
    help="Path to yaml/json configuration file containing the parameters for certificate.",
)
@click.option(
    "-o",
    "--output",
    type=click.File(mode="wb"),
    required=True,
    help="Path where certificate will be stored.",
)
@click.option(
    "-e",
    "--encoding",
    required=False,
    type=click.Choice(["PEM", "DER"], case_sensitive=False),
    default="PEM",
    help="Encoding type. Default is PEM",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Force overwriting of an existing file. Create destination folder, if doesn't exist already.",
)
def generate(config: TextIO, output: BinaryIO, encoding: str, force: bool) -> None:
    """Generate certificate."""
    logger.info("Generating Certificate...")
    logger.info("Loading configuration from yml file...")

    check_destination_dir(output.name, force)
    check_file_exists(output.name, force)

    config_data = load_configuration(config.name)
    cert_config = CertificateParametersConfig(config_data)

    priv_key = load_private_key(cert_config.issuer_private_key)
    pub_key = load_public_key(cert_config.subject_public_key)

    certificate = generate_certificate(
        subject=cert_config.subject_name,
        issuer=cert_config.issuer_name,
        subject_public_key=pub_key,
        issuer_private_key=priv_key,
        serial_number=cert_config.serial_number,
        duration=cert_config.duration,
        if_ca=cert_config.BasicConstrains_ca,
        path_length=cert_config.BasicConstrains_path_length,
    )
    logger.info("Saving the generated certificate to the specified path...")
    encoding_type = Encoding.PEM if encoding.lower() == "pem" else Encoding.DER
    save_crypto_item(certificate, output.name, encoding_type=encoding_type)
    logger.info("Certificate generated successfully...")
    click.echo(f"The certificate file has been created: {os.path.abspath(output.name)}")


@main.command()
@click.argument("output", metavar="PATH", type=click.Path())
@click.option(
    "-f",
    "--force",
    is_flag=True,
    default=False,
    help="Force overwriting of an existing file. Create destination folder, if doesn't exist already.",
)
def get_cfg_template(output: click.Path, force: bool) -> None:
    """Generate the template of Certificate generation YML configuration file.

    \b
    PATH    - file name path to write template config file
    """
    logger.info("Creating Certificate template...")
    check_destination_dir(str(output), force)
    check_file_exists(str(output), force)

    with open(os.path.join(NXPCERTGEN_DATA_FOLDER, "certgen_config.yml"), "r") as file:
        template = file.read()

    with open(str(output), "w") as file:
        file.write(template)

    click.echo(f"The configuration template file has been created: {os.path.abspath(str(output))}")


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
