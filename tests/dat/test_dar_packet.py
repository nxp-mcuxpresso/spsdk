#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for Debug Authentication Response (DAR) packet functionality.

This module contains unit tests for the DAR packet implementation in SPSDK,
covering various authentication scenarios and signature provider configurations.
"""

import os

import pytest

from spsdk.crypto.signature_provider import PlainFileSP
from spsdk.dat.dac_packet import DebugAuthenticationChallenge as DAC
from spsdk.dat.dar_packet import DebugAuthenticateResponse
from spsdk.dat.debug_credential import DebugCredentialCertificate as DC
from spsdk.dat.debug_credential import ProtocolVersion
from spsdk.exceptions import SPSDKError
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary, use_working_directory


@pytest.mark.parametrize(
    "family_str, yml_file_name, dac_bin_file, version, dck_key_file, expected_length",
    [
        (
            "lpc55s69",
            "new_dck_rsa2048.yml",
            "sample_dac.bin",
            ProtocolVersion.from_version(1, 0),
            "../../_data/keys/rsa2048/dck_rsa2048.pem",
            1200,
        ),
        (
            "lpc55s36",
            "new_dck_secp256.yml",
            "sample_dac_ecc.bin",
            ProtocolVersion.from_version(2, 0),
            "../../_data/keys/ecc256/dck_ecc256.pem",
            316,
        ),
    ],
)
def test_dar_packet_rsa_ecc(
    data_dir: str,
    family_str: str,
    yml_file_name: str,
    version: ProtocolVersion,
    dck_key_file: str,
    expected_length: int,
    dac_bin_file: str,
) -> None:
    """Test DAR packet creation with RSA/ECC keys for debug authentication.

    This test verifies the creation of Debug Authentication Response (DAR) packets
    using RSA and ECC cryptographic keys. It loads configuration from YAML files,
    creates debug credentials, parses Debug Authentication Challenge (DAC) data,
    and validates the resulting DAR packet structure and length.

    :param data_dir: Directory containing test data files
    :param family_str: Target MCU family identifier string
    :param yml_file_name: YAML configuration file name for debug credentials
    :param version: Protocol version for debug authentication
    :param dck_key_file: Debug credential key file name
    :param expected_length: Expected byte length of the generated DAR packet
    :param dac_bin_file: Binary file containing Debug Authentication Challenge data
    :raises AssertionError: When DC/DAC version mismatch or unexpected DAR packet length
    """
    with use_working_directory(data_dir):
        family = FamilyRevision(family_str)
        dac_bytes = load_binary(os.path.join(data_dir, dac_bin_file))
        yaml_config = Config.create_from_file(yml_file_name)
        dc = DC.load_from_config(config=yaml_config)
        dc.sign()
        assert (
            dc.version == DAC.parse(dac_bytes, family).version
        ), "Version of DC and DAC are different."
        dar_klass = DebugAuthenticateResponse._get_class(family, dc.version)
        dck = PlainFileSP(os.path.join(data_dir, dck_key_file))
        dar = dar_klass(
            family=family,
            debug_credential=dc,
            auth_beacon=0,
            dac=DAC.parse(dac_bytes, family),
            sign_provider=dck,
        )
        dar_bytes = dar.export()
        assert len(dar_bytes) == expected_length
        assert isinstance(dar_bytes, bytes)
        assert "Authentication Beacon" in str(dar)


@pytest.mark.parametrize(
    "yml_file_name, version, file_key, expected_length",
    [
        (
            "new_dck_secp256_lpc55s3x.yml",
            ProtocolVersion("2.0"),
            "../../_data/keys/ecc256/dck_ecc256.pem",
            316,
        ),
        (
            "new_dck_secp384_lpc55s3x.yml",
            ProtocolVersion("2.1"),
            "../../_data/keys/ecc384/dck_ecc384.pem",
            444,
        ),
    ],
)
def test_dar_packet_lpc55s3x_256(
    data_dir: str, yml_file_name: str, version: ProtocolVersion, file_key: str, expected_length: int
) -> None:
    """Test DAR packet creation and export for LPC55S3x with 256-bit configuration.

    This test verifies the Debug Authentication Response (DAR) packet generation
    for LPC55S3x family devices using a 256-bit key configuration. It loads
    debug credentials, creates a DAR instance, and validates the exported packet.

    :param data_dir: Directory path containing test data files
    :param yml_file_name: YAML configuration file name for debug credentials
    :param version: Protocol version to use for DAR packet creation
    :param file_key: File path to the signing key for DAR authentication
    :param expected_length: Expected byte length of the exported DAR packet
    """
    with use_working_directory(data_dir):
        dac_bytes = load_binary(os.path.join(data_dir, "sample_dac_lpc55s3x.bin"))
        yaml_config = Config.create_from_file(yml_file_name)
        dc = DC.load_from_config(yaml_config)
        dc.sign()
        family = FamilyRevision("lpc55s36")
        dar_klass = DebugAuthenticateResponse._get_class(family, dc.version)
        dck = PlainFileSP(os.path.join(data_dir, file_key))
        dar = dar_klass(
            family=family,
            debug_credential=dc,
            auth_beacon=0,
            dac=DAC.parse(dac_bytes, family),
            sign_provider=dck,
        )

        dar_bytes = dar.export()
        assert len(dar_bytes) == expected_length
        assert isinstance(dar_bytes, bytes)
        assert "Authentication Beacon" in str(dar)


def test_dar_packet_no_signature_provider(data_dir: str) -> None:
    """Test DAR packet export without signature provider.

    This test verifies that attempting to export a Debug Authenticate Response (DAR)
    packet without a signature provider raises the appropriate SPSDKError exception.
    The test creates a DAR instance with all required components, then removes the
    signature provider and confirms that export fails with the expected error message.

    :param data_dir: Directory path containing test data files including DAC binary,
                     YAML configuration, and private key files.
    :raises SPSDKError: When signature provider is not set during export operation.
    """
    with use_working_directory(data_dir):
        dac_bin_file = "sample_dac.bin"
        yml_file_name = "new_dck_rsa2048.yml"
        dac_bytes = load_binary(os.path.join(data_dir, dac_bin_file))
        family = FamilyRevision("lpc55s69")
        yaml_config = Config.create_from_file(yml_file_name)
        dc = DC.load_from_config(config=yaml_config)
        dc.sign()
        dar_class = DebugAuthenticateResponse._get_class(family, ProtocolVersion("1.0"))
        dar = dar_class(
            family=family,
            debug_credential=dc,
            auth_beacon=0,
            dac=DAC.parse(dac_bytes, family=family),
            sign_provider=PlainFileSP(
                os.path.join(data_dir, "../../_data/keys/rsa2048/dck_rsa2048.pem")
            ),
        )
        dar.sign_provider = None
        with pytest.raises(SPSDKError, match="Signature provider is not set"):
            dar.export()
