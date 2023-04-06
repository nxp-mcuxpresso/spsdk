#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""NXP Certificate Generator."""
import logging
import os
import sys

import click
from click_option_group import optgroup

from spsdk import SPSDK_DATA_FOLDER, SPSDKError
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroupAliasedGetCfgTemplate,
    spsdk_apps_common_options,
)
from spsdk.apps.utils.utils import SPSDKAppError, catch_spsdk_error, check_file_exists
from spsdk.crypto import (
    Encoding,
    ec,
    generate_certificate,
    load_private_key,
    load_public_key,
    save_crypto_item,
)
from spsdk.crypto.certificate_management import generate_name
from spsdk.crypto.loaders import extract_public_key, load_certificate
from spsdk.utils.misc import find_file, load_configuration, load_text, write_file

NXPCERTGEN_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "nxpcertgen")

logger = logging.getLogger(__name__)


class CertificateParametersConfig:  # pylint: disable=too-few-public-methods
    """Configuration object for creating the certificate."""

    def __init__(self, config_data: dict) -> None:
        """Initialize cert_config from yml config data."""
        try:
            self.issuer_private_key = config_data["issuer_private_key"]
            self.subject_public_key = config_data["subject_public_key"]
            self.serial_number = config_data["serial_number"]
            self.duration = config_data["duration"]
            self.basic_constrains_ca = config_data["extensions"]["BASIC_CONSTRAINTS"]["ca"]
            self.basic_constrains_path_length = config_data["extensions"]["BASIC_CONSTRAINTS"][
                "path_length"
            ]
            self.issuer_name = generate_name(config_data["issuer"])
            self.subject_name = generate_name(config_data["subject"])
        except KeyError as e:
            raise SPSDKError(f"Error found in configuration: {e} not found") from e


@click.group(name="nxpcertgen", no_args_is_help=True, cls=CommandsTreeGroupAliasedGetCfgTemplate)  # type: ignore
@spsdk_apps_common_options
def main(log_level: int) -> None:
    """Utility for certificate generation."""
    logging.basicConfig(level=log_level or logging.WARNING)


@main.command(name="generate", no_args_is_help=True)
@click.option(
    "-j",
    "-c",
    "--config",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to yaml/json configuration file containing the parameters for certificate.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(resolve_path=True),
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
def generate(config: str, output: str, encoding: str, force: bool) -> None:
    """Generate certificate."""
    logger.info("Generating Certificate...")
    logger.info("Loading configuration from yml file...")

    check_file_exists(output, force)

    config_data = load_configuration(config)
    cert_config = CertificateParametersConfig(config_data)
    search_paths = [os.path.dirname(config)]

    priv_key = load_private_key(
        find_file(cert_config.issuer_private_key, search_paths=search_paths)
    )
    pub_key = load_public_key(find_file(cert_config.subject_public_key, search_paths=search_paths))

    certificate = generate_certificate(
        subject=cert_config.subject_name,
        issuer=cert_config.issuer_name,
        subject_public_key=pub_key,
        issuer_private_key=priv_key,
        serial_number=cert_config.serial_number,
        duration=cert_config.duration,
        if_ca=cert_config.basic_constrains_ca,
        path_length=cert_config.basic_constrains_path_length,
    )
    logger.info("Saving the generated certificate to the specified path...")
    encoding_type = Encoding.PEM if encoding.lower() == "pem" else Encoding.DER
    save_crypto_item(certificate, output, encoding_type=encoding_type)
    logger.info("Certificate generated successfully...")
    click.echo(f"The certificate file has been created: {output}")


@main.command(name="get-template", no_args_is_help=True)
@click.argument("output", metavar="PATH", type=click.Path(resolve_path=True))
@click.option(
    "-f",
    "--force",
    is_flag=True,
    default=False,
    help="Force overwriting of an existing file. Create destination folder, if doesn't exist already.",
)
def get_template(output: str, force: bool) -> None:
    """Generate the template of Certificate generation YML configuration file.

    \b
    PATH    - file name path to write template config file
    """
    logger.info("Creating Certificate template...")
    check_file_exists(output, force)

    write_file(load_text(os.path.join(NXPCERTGEN_DATA_FOLDER, "certgen_config.yaml")), output)

    click.echo(f"The configuration template file has been created: {output}")


@main.command(name="verify", no_args_is_help=True)
@click.argument("certificate", metavar="PATH", type=click.Path(exists=True, dir_okay=False))
@optgroup.group("Type of verification")
@optgroup.option(
    "-s",
    "--sign",
    type=click.Path(exists=True, dir_okay=False),
    help="Path to key to verify certificate signature",
)
@optgroup.option(
    "-p",
    "--puk",
    type=click.Path(exists=True, dir_okay=False),
    help="Path to key to verify private key in certificate",
)
def verify(certificate: str, sign: str, puk: str) -> None:
    """Verify signature or public key in certificate.

    \b
    PATH    - path to certificate
    """
    logger.info(f"Loading certificate from: {certificate}")
    cert = load_certificate(certificate)
    if sign:
        logger.info("Performing signature verification")
        sign_algorithm = cert.signature_algorithm_oid._name
        logger.debug(f"Signature algorithm: {sign_algorithm}")
        if "ecdsa" not in sign_algorithm:
            raise SPSDKAppError(
                f"Unsupported signature algorithm: {sign_algorithm}. "
                "Only ECDSA signatures are currently supported."
            )
        verification_key = extract_public_key(sign)
        if not isinstance(verification_key, ec.EllipticCurvePublicKey):
            raise SPSDKError("Currently only ECC keys are supported.")
        if not cert.signature_hash_algorithm:
            raise SPSDKError("Certificate doesn't contain info about hashing alg.")
        try:
            verification_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
            click.echo("Signature is OK")
        except Exception as e:
            raise SPSDKAppError("Invalid signature") from e
    if puk:
        logger.info("Performing public key verification")
        cert_puk = cert.public_key()
        if not isinstance(cert_puk, ec.EllipticCurvePublicKey):
            raise SPSDKError("Only ECC-based certificates are supported.")
        cert_puk_numbers = cert_puk.public_numbers()
        other_puk = extract_public_key(puk)
        if not isinstance(other_puk, ec.EllipticCurvePublicKey):
            raise SPSDKError("Only ECC public keys are supported")
        other_puk_numbers = other_puk.public_numbers()
        logger.debug(f"Certificate public numbers: {cert_puk_numbers}")
        logger.debug(f"Other public numbers: {other_puk_numbers}")

        if cert_puk_numbers == other_puk_numbers:
            click.echo("Public key in certificate matches the input")
        else:
            raise SPSDKAppError("Public key in certificate differs from the input")


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
