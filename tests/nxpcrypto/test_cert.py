#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Certificate management test suite.

This module contains comprehensive test cases for certificate-related functionality
in SPSDK, including certificate generation, validation, chain verification,
and certificate authority operations.
"""

import os
from os import path
from typing import Any

import pytest
import yaml

from spsdk.apps.nxpcrypto import main
from spsdk.crypto.certificate import (
    Certificate,
    SPSDKExtensionOID,
    SPSDKNameOID,
    generate_extensions,
    generate_name,
    validate_ca_flag_in_cert_chain,
    validate_certificate_chain,
)
from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.keys import PrivateKeyRsa, PublicKey
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import load_binary, use_working_directory
from tests.cli_runner import CliRunner


def get_certificate(data_dir: str, cert_file_name: str) -> Certificate:
    """Load a certificate from the test data directory.

    This method loads a certificate file from the specified data directory's cert subdirectory.

    :param data_dir: Base directory path containing test data.
    :param cert_file_name: Name of the certificate file to load.
    :return: Loaded certificate object.
    """
    cert = Certificate.load(path.join(data_dir, "cert", cert_file_name))
    return cert


def get_certificates(data_dir: str, cert_file_names: list[str]) -> list[Certificate]:
    """Get multiple certificates from data directory.

    Loads a list of certificate files from the specified data directory and returns
    them as Certificate objects.

    :param data_dir: Path to the directory containing certificate files.
    :param cert_file_names: List of certificate file names to load.
    :return: List of Certificate objects loaded from the specified files.
    """
    cert_list = [get_certificate(data_dir, cert_name) for cert_name in cert_file_names]
    return cert_list


@pytest.mark.parametrize(
    "file_name, expect_cer",
    [
        ("priv.pem", False),
        ("ca.pem", True),
        ("pub.pem", False),
        ("CA1_key.der", False),
        ("ca1_crt.der", True),
        ("ca_key.pem", False),
        ("NXPEnterpriseCA4.crt", True),
        ("NXPInternalPolicyCAG2.crt", True),
        ("NXPROOTCAG2.crt", True),
    ],
)
def test_is_cert(data_dir: str, file_name: str, expect_cer: bool) -> None:
    """Test certificate loading functionality with valid and invalid certificate files.

    This test verifies that the Certificate.load() method correctly loads valid
    certificate files and raises SPSDKError for invalid or non-certificate files.

    :param data_dir: Base directory path containing test data files
    :param file_name: Name of the certificate file to test
    :param expect_cer: Flag indicating whether the file should be a valid certificate
    :raises SPSDKError: When expect_cer is False and invalid certificate is processed
    """
    cert_path = path.join(data_dir, "cert", file_name)
    if expect_cer:
        Certificate.load(cert_path)
    else:
        with pytest.raises(SPSDKError):
            Certificate.load(cert_path)


@pytest.mark.parametrize(
    "file_name, password, expect_priv_key",
    [("CA1_sha256_2048_65537_v3_ca_key.pem", "test", True), ("ca.pem", "test", False)],
)
def test_is_key_priv(data_dir: str, file_name: str, password: str, expect_priv_key: bool) -> None:
    """Test if a file contains a private key that can be loaded.

    This test function verifies whether a given file contains a valid private RSA key
    that can be successfully loaded with the provided password. If a private key is
    expected, the test ensures successful loading. If not expected, the test verifies
    that loading raises an SPSDKError.

    :param data_dir: Base directory path containing test data files.
    :param file_name: Name of the key file to test.
    :param password: Password to use when attempting to load the private key.
    :param expect_priv_key: Whether the file is expected to contain a valid private key.
    :raises SPSDKError: When expect_priv_key is False and the key loading fails as expected.
    """
    key_path = path.join(data_dir, "cert", file_name)
    if expect_priv_key:
        PrivateKeyRsa.load(key_path, password=password)
    else:
        with pytest.raises(SPSDKError):
            PrivateKeyRsa.load(key_path, password=password)


@pytest.mark.parametrize(
    "file_name,  expect_pub_key",
    [
        ("ca.pem", False),
        ("pub.pem", True),
        ("priv.pem", False),
        ("ca1_crt.der", False),
        ("ca_key.pem", False),
        ("NXPEnterpriseCA4.crt", False),
        ("NXPInternalPolicyCAG2.crt", False),
        ("NXPROOTCAG2.crt", False),
    ],
)
def test_is_key_pub(data_dir: str, file_name: str, expect_pub_key: bool) -> None:
    """Test whether a file contains a public key that can be loaded.

    This test function verifies the PublicKey.load() method behavior by attempting
    to load a key file and checking if it succeeds or fails as expected.

    :param data_dir: Base directory path containing test data files
    :param file_name: Name of the key file to test within the cert subdirectory
    :param expect_pub_key: True if the file should contain a valid public key, False otherwise
    :raises SPSDKError: When expect_pub_key is False and PublicKey.load() is expected to fail
    """
    key_path = path.join(data_dir, "cert", file_name)
    if expect_pub_key:
        PublicKey.load(key_path)
    else:
        with pytest.raises(SPSDKError):
            PublicKey.load(key_path)


@pytest.mark.parametrize(
    "file_name, expected_encoding",
    [
        ("ca.pem", SPSDKEncoding.PEM),
        ("pub.pem", SPSDKEncoding.PEM),
        ("priv.pem", SPSDKEncoding.PEM),
        ("CA1_key.der", SPSDKEncoding.DER),
        ("ca1_crt.der", SPSDKEncoding.DER),
        ("ca_key.pem", SPSDKEncoding.PEM),
        ("NXPEnterpriseCA4.crt", SPSDKEncoding.PEM),
        ("NXPInternalPolicyCAG2.crt", SPSDKEncoding.PEM),
        ("NXPROOTCAG2.crt", SPSDKEncoding.PEM),
    ],
)
def test_get_encoding_type(data_dir: str, file_name: str, expected_encoding: SPSDKEncoding) -> None:
    """Test certificate file encoding type detection.

    Verifies that the SPSDKEncoding.get_file_encodings method correctly identifies
    the encoding type of certificate files by loading a test certificate file
    and comparing the detected encoding with the expected encoding type.

    :param data_dir: Base directory path containing test data files.
    :param file_name: Name of the certificate file to test.
    :param expected_encoding: Expected encoding type that should be detected.
    """
    file = path.join(data_dir, "cert", file_name)
    assert SPSDKEncoding.get_file_encodings(load_binary(file)) == expected_encoding


def test_validate_cert(data_dir: str) -> None:
    """Test certificate validation chain functionality.

    This test validates the certificate chain by checking that parent certificates
    can properly validate their child certificates in the NXP certificate hierarchy.
    It tests the validation from root CA down to end-entity certificates.

    :param data_dir: Directory path containing test certificate files
    :raises AssertionError: If any certificate validation in the chain fails
    """
    nxp_ca = get_certificate(data_dir, "NXPROOTCAG2.crt")
    nxp_international = get_certificate(data_dir, "NXPInternalPolicyCAG2.crt")
    nxp_enterprise = get_certificate(data_dir, "NXPEnterpriseCA4.crt")
    satyr = get_certificate(data_dir, "satyr.crt")

    assert nxp_international.validate_subject(nxp_enterprise)
    assert nxp_ca.validate_subject(nxp_international)
    assert nxp_enterprise.validate_subject(satyr)


def test_validate_invalid_cert(data_dir: str) -> None:
    """Test certificate validation with invalid certificate chains.

    This test verifies that certificate validation correctly fails when attempting
    to validate certificates that are not in the proper chain of trust. It tests
    various combinations of NXP certificates and ensures that invalid subject
    validations are properly rejected.

    :param data_dir: Directory path containing test certificate files
    :raises AssertionError: If any validation incorrectly passes when it should fail
    """
    nxp_ca = get_certificate(data_dir, "NXPROOTCAG2.crt")
    nxp_international = get_certificate(data_dir, "NXPInternalPolicyCAG2.crt")
    nxp_enterprise = get_certificate(data_dir, "NXPEnterpriseCA4.crt")
    satyr = get_certificate(data_dir, "satyr.crt")

    assert not nxp_ca.validate_subject(satyr)
    assert not nxp_ca.validate_subject(nxp_enterprise)
    assert not nxp_international.validate_subject(satyr)


def test_certificate_chain_verification(data_dir: str) -> None:
    """Test certificate chain verification functionality.

    This test verifies that certificate chain validation works correctly for both
    NXP certificate chains and provisioning certificate chains. It tests two
    different certificate chain scenarios to ensure the validation logic handles
    various certificate hierarchies properly.

    :param data_dir: Directory path containing test certificate files
    """
    chain = ["satyr.crt", "NXPEnterpriseCA4.crt", "NXPInternalPolicyCAG2.crt", "NXPROOTCAG2.crt"]
    chain_cert = [
        get_certificate(data_dir, file_name) for file_name in chain if file_name.startswith("NXP")
    ]
    assert all(validate_certificate_chain(chain_cert))

    list_cert_files = ["img.pem", "srk.pem", "ca.pem"]
    chain_prov = get_certificates(data_dir, list_cert_files)
    assert all(validate_certificate_chain(chain_prov))


def test_certificate_chain_verification_error(data_dir: str) -> None:
    """Test certificate chain verification with invalid chains.

    This test verifies that the certificate chain validation correctly identifies
    invalid certificate chains by testing two different scenarios with malformed
    or incorrectly ordered certificate chains.

    :param data_dir: Directory path containing test certificate files.
    """
    chain = ["ca.pem", "NXPInternalPolicyCAG2.crt", "NXPEnterpriseCA4.crt", "NXPROOTCAG2.crt"]
    chain_cert = get_certificates(data_dir, chain)
    assert not all(validate_certificate_chain(chain_cert))

    list_cert_files = ["satyr.crt", "img.pem", "srk.pem"]
    chain_prov = get_certificates(data_dir, list_cert_files)
    assert not all(validate_certificate_chain(chain_prov))


def test_is_ca_flag_set(data_dir: str) -> None:
    """Test CA flag detection in certificates.

    Verifies that the CA flag is correctly identified in both CA and non-CA certificates.
    This test loads a CA certificate and a regular certificate, then asserts that the
    CA flag is properly set for the CA certificate and not set for the regular certificate.

    :param data_dir: Directory path containing test certificate files.
    :raises AssertionError: If CA flag detection fails for either certificate type.
    """
    ca_certificate = get_certificate(data_dir, "ca.pem")
    assert ca_certificate.ca
    no_ca_certificate = get_certificate(data_dir, "img.pem")
    assert not no_ca_certificate.ca


def test_validate_ca_flag_in_cert_chain(data_dir: str) -> None:
    """Test validation of CA flag in certificate chain.

    This test verifies that the validate_ca_flag_in_cert_chain function correctly
    identifies valid and invalid certificate chains based on CA flags. It tests
    both a valid chain with proper CA certificates and an invalid chain with
    non-CA certificates.

    :param data_dir: Directory path containing test certificate files.
    """
    chain = ["ca.pem", "srk.pem"]
    chain_cert = get_certificates(data_dir, chain)
    assert validate_ca_flag_in_cert_chain(chain_cert)
    invalid_chain = ["img.pem", "srk.pem"]
    chain_cert_invalid = get_certificates(data_dir, invalid_chain)
    assert not validate_ca_flag_in_cert_chain(chain_cert_invalid)


def test_certificate_generation(tmpdir: Any) -> None:
    """Test certificate generation functionality with RSA keys and X.509 certificates.

    This test verifies the complete certificate generation workflow including:
    - RSA private/public key pair generation and file persistence
    - Certificate creation with proper subject/issuer configuration
    - Extension handling for CA certificates with path length constraints
    - File output validation for all generated cryptographic artifacts

    :param tmpdir: Temporary directory fixture for test file operations
    """
    ca_priv_key = PrivateKeyRsa.generate_key()
    ca_priv_key.save(path.join(tmpdir, "ca_private_key.pem"))
    ca_pub_key = ca_priv_key.get_public_key()
    ca_pub_key.save(path.join(tmpdir, "ca_pub_key.pem"))
    assert path.isfile(path.join(tmpdir, "ca_private_key.pem"))
    assert path.isfile(path.join(tmpdir, "ca_pub_key.pem"))

    data = yaml.safe_load(
        """
        COMMON_NAME: xyz
        DOMAIN_COMPONENT: [com, nxp, wbi]
        ORGANIZATIONAL_UNIT_NAME: [NXP, CZ, Managed Users, Developers]
        """
    )
    subject = issuer = generate_name(data)
    ca_cert = Certificate.generate_certificate(
        subject,
        issuer,
        ca_pub_key,
        ca_priv_key,
        extensions=generate_extensions(
            {"BASIC_CONSTRAINTS": {"ca": True, "path_length": 3}},
        ),
    )
    ca_cert.save(path.join(tmpdir, "ca_cert.pem"))
    assert path.isfile(path.join(tmpdir, "ca_cert.pem"))

    data = yaml.safe_load(
        """
        - COMMON_NAME: ccccc
        - DOMAIN_COMPONENT: [com, nxp, wbi]
        - ORGANIZATIONAL_UNIT_NAME: NXP
        - ORGANIZATIONAL_UNIT_NAME: CZ
        - ORGANIZATIONAL_UNIT_NAME: Managed Users
        - ORGANIZATIONAL_UNIT_NAME: Developers
        """
    )
    subject = issuer = generate_name(data)
    ca_cert1 = Certificate.generate_certificate(
        subject,
        issuer,
        ca_pub_key,
        ca_priv_key,
        extensions=generate_extensions(
            {"BASIC_CONSTRAINTS": {"ca": True, "path_length": 3}},
        ),
    )
    ca_cert1.save(path.join(tmpdir, "ca_cert_1.pem"))
    assert path.isfile(path.join(tmpdir, "ca_cert_1.pem"))


def test_certificate_generation_invalid() -> None:
    """Test certificate generation with invalid attribute name.

    Verifies that generate_name function properly raises SPSDKError when
    provided with an invalid certificate attribute name 'COMM'.

    :raises SPSDKError: When invalid certificate attribute is provided.
    """
    with pytest.raises(SPSDKError, match="Invalid value of certificate attribute: COMM"):
        generate_name({"COMM": "first"})


@pytest.mark.parametrize("json, encoding", [(True, "PEM"), (False, "Der")])
def test_certificate_generation_cli(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, json: bool, encoding: str
) -> None:
    """Test certificate generation using CLI interface.

    This test verifies that the certificate generation command works correctly
    through the CLI, creating a certificate file with the expected properties
    including issuer, subject, basic constraints, and serial number.

    :param cli_runner: CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for output files.
    :param data_dir: Directory containing test data and configuration files.
    :param json: Flag indicating whether to use JSON or YAML configuration format.
    :param encoding: Certificate encoding format to use for output.
    """
    with use_working_directory(data_dir):
        cert_path = os.path.join(tmpdir, "cert.crt")
        cmd = [
            "cert",
            "generate",
            "-c",
            os.path.join(data_dir, "cert", f"certgen_config.{'json' if json else 'yaml'}"),
            "-o",
            cert_path,
            "-e",
            encoding,
        ]
        cli_runner.invoke(main, cmd)
        assert os.path.isfile(cert_path)

    generated_cert = Certificate.load(cert_path)
    assert (
        generated_cert.issuer.get_attributes_for_oid(SPSDKNameOID.COMMON_NAME).pop(0).value == "ONE"
    )
    assert (
        generated_cert.subject.get_attributes_for_oid(SPSDKNameOID.COMMON_NAME).pop(0).value
        == "TWO"
    )
    basic_constraints_ext = generated_cert.extensions.get_extension_for_oid(
        SPSDKExtensionOID.BASIC_CONSTRAINTS
    )

    assert basic_constraints_ext.value.ca  # type: ignore
    assert generated_cert.serial_number == 777


def test_invalid_certificate_chain() -> None:
    """Test that certificate chain validation fails with empty chain list.

    Verifies that the validate_certificate_chain function properly raises
    SPSDKError when provided with an empty certificate chain, ensuring
    proper input validation.

    :raises SPSDKError: When certificate chain validation fails with empty list.
    """
    with pytest.raises(SPSDKError):
        validate_certificate_chain(chain_list=[])


def test_generate_template(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test certificate template generation functionality.

    Verifies that the CLI command 'cert get-template' successfully creates a YAML
    template file with the expected structure and content.

    :param cli_runner: CLI test runner for invoking command line interface.
    :param tmpdir: Temporary directory fixture for test file operations.
    """
    template = "template.yaml"
    with use_working_directory(tmpdir):
        cli_runner.invoke(main, f"cert get-template -o {template}")
        assert os.path.isfile(template)
        with open(template) as f:
            data = yaml.safe_load(f)
        # there should be at least 5 items in the template
        assert len(data) > 5


def test_certificate_generation_with_encrypted_private_key(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str
) -> None:
    """Test certificate generation using encrypted private key.

    Verifies that the certificate generation command works correctly when using
    an encrypted private key by invoking the CLI command and checking that the
    output certificate file is created successfully.

    :param cli_runner: CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test output files.
    :param data_dir: Directory containing test data files including configuration.
    """
    with use_working_directory(data_dir):
        cert_path = os.path.join(tmpdir, "cert.crt")
        cmd = [
            "cert",
            "generate",
            "-c",
            os.path.join(data_dir, "cert", "certgen_config.yaml"),
            "-o",
            cert_path,
        ]
        cli_runner.invoke(main, cmd)
        assert os.path.isfile(cert_path)
