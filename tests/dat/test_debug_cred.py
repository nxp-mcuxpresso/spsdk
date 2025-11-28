#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for SPSDK debug credential functionality.

This module contains comprehensive test cases for debug credential creation,
validation, parsing, and export operations across different NXP MCU families.
The tests cover protocol version determination, RSA and ECC signature verification,
credential export/parse operations, invalid data handling, and ROT metadata
integration for various MCU families including LPC55S3x and ELEv2.
"""


import os

import pytest

from spsdk.crypto.dilithium import IS_DILITHIUM_SUPPORTED
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.keys import PrivateKeyEcc
from spsdk.dat.debug_credential import (
    DebugCredentialCertificate,
    DebugCredentialEdgeLockEnclaveV2,
    ProtocolVersion,
)
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary, use_working_directory


@pytest.mark.parametrize(
    "protocol_version, rsa_detected, invalid",
    [
        ("1.0", True, False),
        ("1.1", True, False),
        ("2.0", False, False),
        ("2.1", False, False),
        ("2.2", False, False),
        ("3.1", False, False),
        ("3.2", False, False),
        ("4.2", False, True),
        ("Invalid", False, True),
    ],
)
def test_determine_protocol_version(
    protocol_version: str, rsa_detected: bool, invalid: bool
) -> None:
    """Test for checking all available protocol versions.

    Validates protocol version instances and verifies RSA detection functionality
    across different protocol versions, including error handling for invalid versions.

    :param protocol_version: The protocol version string to test.
    :param rsa_detected: Expected boolean indicating if RSA should be detected for this protocol version.
    :param invalid: Boolean flag indicating if the protocol version should be invalid and raise an exception.
    :raises SPSDKValueError: When invalid is True and protocol version validation fails.
    """
    if invalid:
        with pytest.raises(SPSDKValueError):
            protocol = ProtocolVersion(protocol_version)
            protocol.validate()
    else:
        protocol = ProtocolVersion(protocol_version)
        assert protocol.is_rsa() is rsa_detected


def test_debugcredential_rsa_compare_with_reference(data_dir: str) -> None:
    """Test RSA debug credential generation against reference implementation.

    Loads a YAML configuration file, creates a debug credential certificate,
    signs it, and compares the generated binary output with a reference file
    to ensure correctness of the implementation.

    :param data_dir: Directory path containing test data files including the YAML config and reference binary.
    :raises AssertionError: When generated debug credential binary differs from reference file.
    """
    with use_working_directory(data_dir):
        yaml_config = Config.create_from_file("new_dck_rsa2048.yml")
        dc = DebugCredentialCertificate.load_from_config(config=yaml_config)
        dc.sign()
        data = dc.export()
        data_loaded = load_binary("new_dck_rsa2048.cert")
        assert (
            data == data_loaded
        ), "The generated dc binary and the referenced one are not the same."


def test_verify_ecc_signature(data_dir: str) -> None:
    """Test ECC signature verification for debug credential certificate.

    This test verifies that an ECC signature can be properly validated by loading
    a debug credential certificate from configuration, signing it, and then
    verifying the signature using the corresponding public key.

    :param data_dir: Directory path containing test data files including the YAML configuration.
    :raises AssertionError: If the signature verification fails.
    """
    with use_working_directory(data_dir):
        yaml_config = Config.create_from_file("new_dck_secp256.yml")
        dc = DebugCredentialCertificate.load_from_config(config=yaml_config)
        dc.sign()
        data = dc.export()
        priv_key = PrivateKeyEcc.load(yaml_config["signer"])
    data_without_signature = data[:-64]
    signature_bytes = data[-64:]
    pub_key = priv_key.get_public_key()
    assert pub_key.verify_signature(
        signature_bytes, data_without_signature, EnumHashAlgorithm.SHA256
    )


def test_verify_ecc_signature_lpc55s3x_256(data_dir: str) -> None:
    """Test ECC256 signature verification for LPC55S3x debug credentials.

    This test verifies that the ECC256 signature generated for LPC55S3x debug
    credentials can be properly validated using the corresponding public key.
    The test loads a debug credential configuration, signs it, extracts the
    signature, and verifies it against the original data using SHA256 hashing.

    :param data_dir: Directory path containing test data files including the
                     configuration file and signing keys.
    """
    with use_working_directory(data_dir):
        yaml_config = Config.create_from_file("new_dck_secp256_lpc55s3x.yml")
        dc = DebugCredentialCertificate.load_from_config(config=yaml_config)
        dc.sign()
        data = dc.export()
        priv_key = PrivateKeyEcc.load(yaml_config["signer"])
    data_without_signature = data[:-64]
    signature_bytes = data[-64:]
    assert len(signature_bytes) == 64
    pub_key = priv_key.get_public_key()
    assert pub_key.verify_signature(
        signature_bytes, data_without_signature, EnumHashAlgorithm.SHA256
    )


def test_verify_ecc_signature_lpc55s3x_384(data_dir: str) -> None:
    """Test ECC384 signature verification for LPC55S3x debug credentials.

    This test verifies that ECC384 signatures are correctly generated and validated
    for debug credential certificates on LPC55S3x devices. It loads a configuration,
    creates and signs a debug credential certificate, then validates the signature
    using the corresponding public key.

    :param data_dir: Directory path containing test data files including the configuration file.
    """
    with use_working_directory(data_dir):
        yaml_config = Config.create_from_file("new_dck_secp384_lpc55s3x.yml")
        dc = DebugCredentialCertificate.load_from_config(config=yaml_config)
        dc.sign()
        data = dc.export()
        priv_key = PrivateKeyEcc.load(yaml_config["signer"])
    data_without_signature = data[:-96]
    signature_bytes = data[-96:]
    pub_key = priv_key.get_public_key()
    assert pub_key.verify_signature(
        signature_bytes, data_without_signature, EnumHashAlgorithm.SHA384
    )


def test_debugcredential_ecc_compare_with_reference(data_dir: str) -> None:
    """Test ECC debug credential generation and validation against reference.

    This test loads a YAML configuration file, creates a debug credential certificate
    using ECC (secp256r1), signs it, and validates the generated binary against a
    reference file. It verifies both the credential data and signature validity.

    :param data_dir: Directory containing test data files including YAML config and reference certificate.
    """
    with use_working_directory(data_dir):
        yaml_config = Config.create_from_file("new_dck_secp256.yml")
        dc = DebugCredentialCertificate.load_from_config(config=yaml_config)
        dc.sign()
        data = dc.export()
        priv_key = PrivateKeyEcc.load(yaml_config["signer"])
        data_without_signature = data[:-64]
        signature_bytes = data[-64:]
        with open("new_dck_secp256r1.cert", "rb") as f:
            data_loaded = f.read()
        ref_data_without_signature = data_loaded[:-64]
        ref_signature_bytes = data_loaded[-64:]
        assert (
            data_without_signature == ref_data_without_signature
        ), "The generated dc binary and the referenced one are not the same."
        pub_key = priv_key.get_public_key()
        assert pub_key.verify_signature(
            signature_bytes, data_without_signature, EnumHashAlgorithm.SHA256
        )
        assert pub_key.verify_signature(
            ref_signature_bytes, data_without_signature, EnumHashAlgorithm.SHA256
        )


@pytest.mark.parametrize(
    "yml_file_name",
    [
        ("new_dck_secp256_lpc55s3x.yml"),
        ("new_dck_secp256_lpc55s3x_not_empty.yml"),
        ("new_dck_secp384_lpc55s3x.yml"),
        ("new_dck_secp384_lpc55s3x_not_empty.yml"),
    ],
)
def test_lpc55s3x_export_parse(data_dir: str, yml_file_name: str) -> None:
    """Test LPC55S3x debug credential export and parse functionality.

    This test verifies that a debug credential certificate can be created from
    configuration, signed, exported, and then parsed back to match the original
    certificate for LPC55S3x family across different versions.

    :param data_dir: Directory path containing test data files
    :param yml_file_name: Name of the YAML configuration file to load
    :raises SPSDKError: If configuration loading, signing, or parsing fails
    :raises AssertionError: If parsed certificate doesn't match original
    """
    with use_working_directory(data_dir):
        yaml_config = Config.create_from_file(yml_file_name)
        dc = DebugCredentialCertificate.load_from_config(config=yaml_config)
        dc.sign()
        data = dc.export()
        dc_parsed = dc.parse(data, dc.family)
        assert dc == dc_parsed


@pytest.mark.parametrize(
    "yml_file_name",
    [
        ("dc_mx95_ecc256.yaml"),
        pytest.param(
            "dc_mx95_ecc256_pqc.yaml",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "dc_mx95_ecc384_pqc.yaml",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "dc_mx95_pqc.yaml",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
    ],
)
def test_elev2_export_parse(data_dir: str, yml_file_name: str) -> None:
    """Test EdgeLock Enclave V2 debug credential export and parse functionality.

    This test verifies that a debug credential can be exported to binary format
    and then parsed back to recreate an equivalent object. The test loads a
    configuration, creates a debug credential, signs it, exports it to binary
    data, and then parses it back to verify the round-trip conversion works
    correctly.

    :param data_dir: Directory containing test data files
    :param yml_file_name: Name of the YAML configuration file to load
    :raises AssertionError: If the parsed debug credential doesn't match the original
    """
    with use_working_directory(data_dir):
        yaml_config = Config.create_from_file(yml_file_name)
        dc = DebugCredentialEdgeLockEnclaveV2.load_from_config(config=yaml_config)
        dc.sign()
        data = dc.export()
        dc_parsed = dc.parse(data, dc.certificate.family)
        assert dc == dc_parsed


def test_lpc55s3x_export_parse_invalid(data_dir: str) -> None:
    """Test invalid parsing of LPC55S3X debug credential certificate export.

    This test verifies that parsing an invalid byte sequence (232 bytes) for an LPC55S3X
    debug credential certificate raises the expected SPSDKValueError exception.

    :param data_dir: Directory path containing test data files including the YAML configuration
    :raises SPSDKValueError: Expected exception when parsing invalid data
    """
    with use_working_directory(data_dir):
        yaml_config = Config.create_from_file("new_dck_secp256_lpc55s3x.yml")
        dc = DebugCredentialCertificate.load_from_config(config=yaml_config)
        dc.sign()
        with pytest.raises(SPSDKValueError):
            dc.parse(bytes(232), dc.family)


@pytest.mark.parametrize(
    "dc_file_name, class_name, family",
    [
        ("new_dck_rsa2048.cert", "DebugCredentialCertificateRsa", "lpc55s69"),
        ("new_dck_secp256r1.cert", "DebugCredentialCertificateEcc", "lpc55s36"),
        ("lpc55s3x_dck_secp384r1.cert", "DebugCredentialCertificateEcc", "lpc55s36"),
    ],
)
def test_parse(data_dir: str, dc_file_name: str, class_name: str, family: str) -> None:
    """Test the parsing mechanisms for Debug Credential Certificate files.

    This test verifies that DC files can be correctly parsed and that the resulting
    object is of the expected class type for the given family.

    :param data_dir: Directory containing the test data files
    :param dc_file_name: Name of the debug credential certificate file to parse
    :param class_name: Expected class name of the parsed debug credential object
    :param family: Target MCU family identifier for parsing context
    :raises AssertionError: When the parsed object class doesn't match expected class name
    :raises FileNotFoundError: When the specified DC file cannot be found
    :raises SPSDKError: When parsing of the DC file fails
    """
    with use_working_directory(data_dir):
        with open(dc_file_name, "rb") as f:
            dc_file = f.read()
        dc = DebugCredentialCertificate.parse(dc_file, FamilyRevision(family))
        assert dc.__class__.__name__ == class_name


@pytest.mark.parametrize(
    "yml_file_name, version, required_values",
    [
        (
            "new_dck_secp256_lpc55s3x.yml",
            ProtocolVersion("2.0"),
            ["E004090E6BDD2155BBCE9E0665805BE3", "4", "0x3ff", "0x5678", "CRTK table not present"],
        ),
        (
            "new_dck_secp256_lpc55s3x_not_empty.yml",
            ProtocolVersion("2.0"),
            [
                "E004090E6BDD2155BBCE9E0665805BE3",
                "4",
                "0x3ff",
                "0x5678",
                "CRTK table has 3 entries",
            ],
        ),
        (
            "new_dck_secp256.yml",
            ProtocolVersion("2.0"),
            ["E004090E6BDD2155BBCE9E0665805BE3", "4", "0x3ff", "0x5678"],
        ),
    ],
)
def test_debugcredential_info_lpc55s3x(
    data_dir: str, yml_file_name: str, version: ProtocolVersion, required_values: list[str]
) -> None:
    """Test debug credential certificate info message for LPC55S3x devices.

    Verifies that the debug credential certificate info output contains all required
    strings and values for proper debug authentication on LPC55S3x devices.

    :param data_dir: Directory path containing test data files
    :param yml_file_name: Name of the YAML configuration file to load
    :param version: Protocol version for debug credential certificate
    :param required_values: List of required values that must be present in output
    """
    with use_working_directory(data_dir):
        yaml_config = Config.create_from_file(yml_file_name)
        dc = DebugCredentialCertificate.load_from_config(config=yaml_config)
        dc.sign()
    output = str(dc)
    req_strings = ["Version", "SOCC", "UUID", "UUID", "CC_SOCC", "CC_VU", "BEACON"]
    req_values = required_values
    for req_string in req_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"
    for req_value in req_values:
        assert req_value in output, f"string {req_value} is not in the output: {output}"


def test_debugcredential_invalid(data_dir: str) -> None:
    """Test debug credential certificate invalid operations.

    Verifies that appropriate exceptions are raised when attempting to export
    an unsigned debug credential certificate or when signing without a
    signature provider.

    :param data_dir: Directory path containing test data files including the YAML configuration.
    :raises SPSDKError: When attempting to export unsigned credential or sign without provider.
    """
    with use_working_directory(data_dir):
        yaml_config = Config.create_from_file("new_dck_rsa2048.yml")
        dc = DebugCredentialCertificate.load_from_config(config=yaml_config)
        with pytest.raises(
            SPSDKError,
            match="Debug Credential signature is not set, call the `sign` method first",
        ):
            dc.export()
        with pytest.raises(SPSDKError, match="Debug Credential Signature provider is not set"):
            dc.signature_provider = None
            dc.sign()


def test_debugcredential_rot_meta_as_cert(data_dir: str) -> None:
    """Test debug credential certificate creation with RoT metadata configuration.

    This test verifies that a debug credential certificate can be properly loaded from
    a YAML configuration file containing RSA2048 RoT metadata, signed, and that all
    certificate properties match expected values including version, beacon, SOCU, VU,
    SOCC, and UUID fields.

    :param data_dir: Directory path containing test data files including the YAML configuration file.
    :raises AssertionError: If any of the certificate properties don't match expected values.
    """
    with use_working_directory(data_dir):
        yaml_config = Config.create_from_file("dck_rsa2048_rot_meta_cert.yaml")
        version = ProtocolVersion("1.0")
        dc = DebugCredentialCertificate.load_from_config(config=yaml_config)
        dc.sign()
        assert dc.version == version
        assert dc.cc_beacon == 0
        assert dc.cc_socu == 1023
        assert dc.cc_vu == 22136
        assert dc.socc == 1
        assert dc.uuid == b"\xe0\x04\t\x0ek\xdd!U\xbb\xce\x9e\x06e\x80[\xe3"


def test_debugcredential_rot_meta_as_cert_not_matching(data_dir: str) -> None:
    """Test that debug credential signing fails when RoT key-pair doesn't match certificate.

    This test verifies that the signing process properly fails when the Root of Trust (RoT)
    key-pair used for signing doesn't match the certificate provided in the rot_meta configuration.

    :param data_dir: Directory path containing test data files including YAML config and certificates.
    :raises SPSDKError: Expected exception when RoT key-pair doesn't match the certificate.
    """
    with use_working_directory(data_dir):
        yaml_config = Config.create_from_file("dck_rsa2048_rot_meta_cert.yaml")
        yaml_config["rot_meta"][0] = "2048b-rsa-example-cert.der"
        dc = DebugCredentialCertificate.load_from_config(config=yaml_config)
        with pytest.raises(SPSDKError):
            dc.sign()


@pytest.mark.parametrize("dc_file_name", ["rt118x_ecc256.dc", "rt118x_rsa2048.dc"])
def test_debugcredential_parse_export(data_dir: str, dc_file_name: str) -> None:
    """Test the parse and export functionality of DebugCredentialCertificate.

    This test verifies that a debug credential certificate can be parsed from binary data
    and then exported back to the same binary format, ensuring round-trip consistency.

    :param data_dir: Directory containing test data files
    :param dc_file_name: Name of the debug credential file to test
    :raises AssertionError: If the exported binary doesn't match the original
    """
    with use_working_directory(data_dir):
        dc_binary = load_binary(dc_file_name)
        dc = DebugCredentialCertificate.parse(dc_binary, FamilyRevision("mimxrt1189"))
        assert dc_binary == dc.export()


def test_debugcredential_parse_invalid_data() -> None:
    """Test that DebugCredentialCertificate.parse raises SPSDKError with invalid data.

    Verifies that the parse method properly handles and rejects malformed input data
    by raising the appropriate exception.

    :raises SPSDKError: When invalid data is passed to the parse method.
    """
    with pytest.raises(SPSDKError):
        DebugCredentialCertificate.parse(b"123456798258963147")


@pytest.mark.parametrize(
    "config, rot_config",
    [
        ("dc_mimxrt595s.yaml", "cert_block_mimxrt595s.yaml"),
        ("dc_mcxn946.yaml", "cert_block_mcxn946.yaml"),
        ("dc_mimxrt595s.yaml", "cert_block_mimxrt595s.bin"),
        ("dc_mcxn946.yaml", "cert_block_mcxn946.bin"),
        ("dc_mimxrt595s.yaml", "mbi_mimxrt595s_as_yaml.yaml"),
        ("dc_mcxn946.yaml", "mbi_mcxn946_as_yaml.yaml"),
        ("dc_mimxrt595s.yaml", "mbi_mimxrt595s_as_bin.yaml"),
        ("dc_mcxn946.yaml", "mbi_mcxn946_as_bin.yaml"),
    ],
)
def test_debugcredential_rot_config_override(data_dir: str, config: str, rot_config: str) -> None:
    """Test debug credential certificate with ROT configuration override.

    This test verifies that a debug credential certificate can be properly loaded and signed
    when the ROT metadata is missing from the configuration but a separate ROT configuration
    file is provided as an override. It ensures that both the original and override methods
    produce identical certificates.

    :param data_dir: Directory path containing test data files.
    :param config: Name of the main configuration file.
    :param rot_config: Name of the ROT configuration file to use as override.
    :raises SPSDKError: When ROT metadata is missing and no override is provided.
    """
    cfg = Config.create_from_file(os.path.join(data_dir, config))
    dc = DebugCredentialCertificate.load_from_config(config=cfg)
    dc.sign()
    del cfg["rot_meta"]
    with pytest.raises(SPSDKError):
        DebugCredentialCertificate.load_from_config(config=cfg)
    cfg["rot_config"] = os.path.join(data_dir, rot_config)
    dc_override = DebugCredentialCertificate.load_from_config(config=cfg)
    dc_override.sign()
    assert dc.calculate_hash() == dc_override.calculate_hash()
    assert dc.export_rot_pub() == dc_override.export_rot_pub()
