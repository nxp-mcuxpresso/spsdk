#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""NXP Certificate Generator."""
import json
import logging
import sys

import click

from spsdk import __version__ as spsdk_version
from spsdk.apps.utils import catch_spsdk_error
from spsdk.crypto import (
    generate_certificate,
    load_private_key,
    load_public_key,
    save_crypto_item,
    x509,
)

logger = logging.getLogger(__name__)


class CertificateParametersConfig:
    """Configuration object for creating the certificate."""

    def __init__(self, config_data: dict) -> None:
        """Initialize cert_config from json config data."""
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


def generate_name(config_data: dict) -> x509.Name:
    """Set the issuer/subject distinguished attribute's."""
    attributes = [
        x509.NameAttribute(getattr(x509.NameOID, key), value) for key, value in config_data.items()
    ]
    return x509.Name(attributes)


@click.command()
@click.option(
    "-j",
    "--json-conf",
    type=click.File("r"),
    help="Path to json configuration file containing the parameters for certificate.",
)
@click.option(
    "-c",
    "--cert-path",
    type=click.Path(),
    help="Path where certificate will be stored.",
)
@click.version_option(spsdk_version, "--version")
def main(json_conf: click.File, cert_path: str) -> None:
    """Utility for certificate generation."""
    logger.info("Generating Certificate...")
    logger.info("Loading configuration from json file...")

    json_content = json.load(json_conf)  # type: ignore
    cert_config = CertificateParametersConfig(json_content)

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
    save_crypto_item(certificate, cert_path)
    logger.info("Certificate generated successfully...")


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
