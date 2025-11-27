#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Certificate Blocks testing module.

This module contains comprehensive tests for certificate block functionality in the SPSDK crypto
package, covering certificate block creation, validation, export operations, and version
compatibility testing.
"""

import os
from typing import Any, Optional, Type, Union

import pytest

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.signature_provider import PlainFileSP
from spsdk.exceptions import SPSDKError
from spsdk.image.cert_block.cert_blocks import (
    CertBlock,
    CertBlockHeader,
    CertBlockV1,
    CertBlockV21,
    CertBlockVx,
    CertificateBlockHeader,
    IskCertificateLite,
    find_root_certificates,
)
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary


def test_cert_block_header() -> None:
    """Test CertBlockHeader default initialization and serialization.

    Verifies that CertBlockHeader creates with correct default values,
    can be exported to binary data with expected size, and can be
    parsed back to an equivalent object.
    """
    header = CertBlockHeader()
    assert header.version == "1.0"
    assert header.flags == 0
    assert header.build_number == 0
    assert header.image_length == 0
    assert header.cert_count == 0
    assert header.cert_table_length == 0

    data = header.export()
    assert len(data) == CertBlockHeader.SIZE

    header_parsed = CertBlockHeader.parse(data)
    assert header == header_parsed


def test_cert_block_header_invalid() -> None:
    """Test that CertBlockHeader raises SPSDKError for invalid version parameter.

    Verifies that creating a CertBlockHeader with an invalid version string
    raises the appropriate SPSDKError with expected error message.

    :raises SPSDKError: When invalid version parameter is provided.
    """
    with pytest.raises(SPSDKError, match="Invalid version"):
        CertBlockHeader(version="bbb")


def test_cert_block_basic() -> None:
    """Test basic functionality of CertBlockV1 class.

    Verifies default values, property setters, and error handling for invalid
    root key hash operations. Tests image length, alignment properties and
    validates that SPSDKError is raised when setting root key hash with
    invalid parameters.

    :raises SPSDKError: When setting root key hash with invalid parameters.
    """
    cb = CertBlockV1(FamilyRevision("Ambassador"))
    # test default values
    assert cb.image_length == 0
    assert cb.alignment == 16
    assert cb.rkh_index is None
    # test setters
    cb.image_length = 1
    cb.alignment = 1
    assert cb.alignment == 1
    assert cb.image_length == 1
    assert cb.header.image_length == 1
    # invalid root key size
    with pytest.raises(SPSDKError):
        cb.set_root_key_hash(0, bytes())


def test_cert_block(data_dir: str) -> None:
    """Test certificate block V1 functionality and validation.

    Tests the creation, configuration, and export of CertBlockV1 objects including
    root key hash table generation, certificate chain validation, and various
    error conditions such as invalid certificate chains, missing certificates,
    CA certificates as leaf nodes, and hash mismatches.

    :param data_dir: Directory path containing test certificate files
    :raises SPSDKError: When certificate validation or export operations fail
    """
    cert_obj = Certificate.load(os.path.join(data_dir, "selfsign_2048_v3.der.crt"))

    cb = CertBlockV1(FamilyRevision("Ambassador"))
    cb.set_root_key_hash(0, cert_obj.public_key_hash())
    cb.add_certificate(cert_obj)
    assert cb.rkh_index == 0
    cb.export()

    # test RKHT
    assert cb.rkth.hex() == "db31d46c717711a8231cbc38b1de8a6e8657e1f733e04c2ee4b62fcea59149fa"
    fuses = cb.rkth_fuses
    assert len(fuses) == 8
    assert fuses[0] == 1825845723

    # test exception if child certificate in chain is not signed by parent certificate
    ca0_cert = Certificate.load(os.path.join(data_dir, "ca0_v3.der.crt"))
    with pytest.raises(SPSDKError):
        cb.add_certificate(ca0_cert)

    # test exception if no certificate specified
    cb = CertBlockV1(FamilyRevision("Ambassador"))
    cb.set_root_key_hash(0, cert_obj.public_key_hash())
    with pytest.raises(SPSDKError):
        cb.export()

    # test exception last certificate is set as CA
    cb = CertBlockV1(FamilyRevision("Ambassador"))
    cb.set_root_key_hash(0, ca0_cert.public_key_hash())
    cb.add_certificate(ca0_cert)
    with pytest.raises(SPSDKError):
        cb.export()

    # test exception if hash does not match any certificate
    cb = CertBlockV1(FamilyRevision("Ambassador"))
    cb.set_root_key_hash(0, ca0_cert.public_key_hash())
    cb.add_certificate(cert_obj)
    with pytest.raises(SPSDKError):
        cb.export()


def test_add_invalid_cert_in_cert_block(data_dir: str) -> None:
    """Test adding invalid certificates to certificate block.

    This test verifies that the CertBlockV1 properly validates certificates
    when they are added. It tests two scenarios: adding a non-certificate
    object (integer) and adding certificates that cannot form a valid chain
    due to verification failure.

    :param data_dir: Directory path containing test certificate files
    :raises SPSDKError: When invalid certificate is added or chain verification fails
    """
    cb = CertBlockV1(FamilyRevision("Ambassador"))
    with open(os.path.join(data_dir, "selfsign_2048_v3.der.crt"), "rb") as f:
        cert_data = f.read()
    with open(os.path.join(data_dir, "ca0_v3.der.crt"), "rb") as f:
        ca0_cert_data = f.read()
    with pytest.raises(SPSDKError):
        cb.add_certificate(cert=5)  # type: ignore
    with pytest.raises(
        SPSDKError, match="Chain certificate cannot be verified using parent public key"
    ):
        cb.add_certificate(cert=cert_data)
        cb.add_certificate(cert=ca0_cert_data)


def test_cert_block_export_invalid(data_dir: str) -> None:
    """Test certificate block export with invalid configuration.

    This test verifies that exporting a certificate block with non-CA certificates
    in the chain (except for the last certificate) raises the appropriate error.
    The test creates a certificate block, adds the same certificate twice, and
    expects an SPSDKError when attempting to export due to invalid chain structure.

    :param data_dir: Directory path containing test certificate files
    :raises SPSDKError: When certificate chain validation fails during export
    """
    cert_obj = Certificate.load(os.path.join(data_dir, "selfsign_2048_v3.der.crt"))
    cb = CertBlockV1(FamilyRevision("Ambassador"))
    cb.set_root_key_hash(0, cert_obj.public_key_hash())
    cb.add_certificate(cert_obj)
    cb.add_certificate(cert_obj)
    assert cb.rkh_index == 0
    with pytest.raises(
        SPSDKError, match="All certificates except the last chain certificate must be CA"
    ):
        cb.export()


def test_invalid_cert_block_header() -> None:
    """Test invalid certificate block header parsing.

    This test verifies that CertificateBlockHeader.parse() properly validates
    the magic number and data size, raising appropriate SPSDKError exceptions
    when invalid data is provided.

    :raises SPSDKError: When magic number is invalid or data size is insufficient.
    """
    ch = CertificateBlockHeader()
    ch.MAGIC = b"chdx"
    data = ch.export()
    with pytest.raises(SPSDKError, match="Magic is not same!"):
        CertificateBlockHeader.parse(data=data)
    with pytest.raises(SPSDKError, match="SIZE is bigger than length of the data without offset"):
        CertificateBlockHeader.parse(data=bytes(8))


def test_cert_block_invalid() -> None:
    """Test certificate block validation with invalid parameters.

    Validates that CertBlockV1 properly raises SPSDKError exceptions when
    invalid values are provided for image_length, alignment, and root key hash.

    :raises SPSDKError: When image_length is negative.
    :raises SPSDKError: When alignment is negative.
    :raises SPSDKError: When root key hash has invalid length.
    """
    cb = CertBlockV1(FamilyRevision("Ambassador"))
    with pytest.raises(SPSDKError, match="Invalid image length"):
        cb.image_length = -2
    with pytest.raises(SPSDKError, match="Invalid alignment"):
        cb.alignment = -2
    cb = CertBlockV1(FamilyRevision("Ambassador"))
    with pytest.raises(SPSDKError, match="Invalid length of key hash"):
        cb.set_root_key_hash(0, bytes(5))


@pytest.mark.parametrize(
    "config,passed,expected_result",
    [
        ({}, False, SPSDKError),
        (
            {
                "signer": "k0_cert0_2048.pem",
                "rootCertificate0File": "root_k0_signed_cert0_noca.der.cert",
                "rootCertificate1File": "root_k1_signed_cert0_noca.der.cert",
            },
            True,
            0,
        ),
        (
            {
                "signer": "k0_cert0_2048.pem",
                "rootCertificate0File": "root_k0_signed_cert0_noca.der.cert",
                "rootCertificate1File": "root_k1_signed_cert0_noca.der.cert",
                "mainRootCertId": 1,
            },
            True,
            1,
        ),
        ({"mainRootCertId": 1}, True, 1),
        ({"mainRootCertId": "2"}, True, 2),
        ({"mainRootCertId": "1abc"}, False, SPSDKError),
        ({"mainRootCertId": "1abc"}, False, SPSDKError),
    ],
)
def test_get_main_cert_index(
    data_dir: str,
    config: dict[str, Any],
    passed: bool,
    expected_result: Union[int, Type[Exception]],
) -> None:
    """Test getting main certificate index from certificate block configuration.

    This test verifies the CertBlockV1.get_main_cert_index method behavior
    with different configurations, checking both successful execution and
    exception handling scenarios.

    :param data_dir: Base directory path containing test data files.
    :param config: Configuration dictionary for certificate block setup.
    :param passed: Flag indicating whether the test should pass or raise exception.
    :param expected_result: Expected return value (int) or exception type to be raised.
    """
    cfg = Config(config)
    cfg.search_paths = [os.path.join(data_dir, "certs_and_keys")]
    if passed:
        result = CertBlockV1.get_main_cert_index(cfg)
        assert result == expected_result
    else:
        with pytest.raises(expected_result):  # type: ignore
            CertBlockV1.get_main_cert_index(cfg)  # type: ignore


@pytest.mark.parametrize(
    "config,index,cert_block_version",
    [
        (
            {
                "signer": "k0_cert0_2048.pem",
                "rootCertificate0File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate1File": "root_k0_signed_cert0_noca.der.cert",
                "rootCertificate2File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate3File": "root_k1_signed_cert0_noca.der.cert",
            },
            1,
            "cert_block_v1",
        ),
        (
            {
                "signer": "k0_cert0_2048.pem",
                "rootCertificate0File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate1File": "root_k0_signed_cert0_noca.der.cert",
                "rootCertificate2File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate3File": "root_k1_signed_cert0_noca.der.cert",
            },
            1,
            "cert_block_v21",
        ),
        (
            {
                "signer": "k0_cert0_2048.pem",
                "rootCertificate0File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate1File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate2File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate3File": "root_k1_signed_cert0_noca.der.cert",
            },
            None,
            "cert_block_v1",
        ),
        (
            {
                "rootCertificate0File": "root_k0_signed_cert0_noca.der.cert",
                "rootCertificate1File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate2File": "root_k2_signed_cert0_noca.der.cert",
                "rootCertificate3File": "root_k3_signed_cert0_noca.der.cert",
            },
            None,
            "cert_block_v1",
        ),
        (
            {
                "signer": "k0_cert0_2048.pem",
                "rootCertificate0File": "non_existing.cert",
                "rootCertificate1File": "another_non_existing.cert",
                "rootCertificate2File": "one_more_non_existing.cert",
            },
            None,
            "cert_block_v1",
        ),
        (
            {
                "signer": "non_existing.pem",
                "rootCertificate0File": "root_k0_signed_cert0_noca.der.cert",
                "rootCertificate1File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate2File": "root_k2_signed_cert0_noca.der.cert",
                "rootCertificate3File": "root_k3_signed_cert0_noca.der.cert",
            },
            None,
            "cert_block_v1",
        ),
    ],
)
def test_find_main_cert_index(
    data_dir: str, config: dict[str, str], index: Optional[int], cert_block_version: str
) -> None:
    """Test finding the main certificate index in certificate blocks.

    This test verifies that the find_main_cert_index method correctly identifies
    the main certificate index for different certificate block versions (v1 and v21).
    It sets up a configuration with certificate paths and validates the returned index.

    :param data_dir: Base directory containing test data files.
    :param config: Dictionary configuration for the certificate block.
    :param index: Expected main certificate index to validate against.
    :param cert_block_version: Version of certificate block to test ("cert_block_v1" or "cert_block_v21").
    """
    cert_block_class = {
        "cert_block_v1": CertBlockV1,
        "cert_block_v21": CertBlockV21,
    }[cert_block_version]
    assert issubclass(cert_block_class, CertBlock)
    cfg = Config(config)
    cfg.search_paths = [os.path.join(data_dir, "certs_and_keys")]
    found_index = cert_block_class.find_main_cert_index(cfg)
    assert found_index == index


@pytest.mark.parametrize(
    "config,error,expected_list",
    [
        (
            {
                "rootCertificate0File": "root_k0.cert",
                "rootCertificate1File": "root_k1.cert",
                "rootCertificate2File": "root_k2.cert",
                "rootCertificate3File": "root_k3.cert",
            },
            None,
            [
                "root_k0.cert",
                "root_k1.cert",
                "root_k2.cert",
                "root_k3.cert",
            ],
        ),
        (
            {
                "rootCertificate0File": "root_k0.cert",
                "rootCertificate1File": "root_k1.cert",
                "rootCertificate2File": "root_k2.cert",
                "rootCertificate3File": "",
            },
            None,
            [
                "root_k0.cert",
                "root_k1.cert",
                "root_k2.cert",
            ],
        ),
        (
            {
                "rootCertificate0File": "root_k0.cert",
                "rootCertificate1File": "root_k1.cert",
                "rootCertificate2File": "",
                "rootCertificate3File": "root_k2.cert",
            },
            SPSDKError,
            None,
        ),
        (
            {
                "rootCertificate0File": "root_k0.cert",
                "rootCertificate3File": "root_k2.cert",
            },
            SPSDKError,
            None,
        ),
        (
            {
                "rootCertificate0File": "root_k0.cert",
                "rootCertificate1File": "root_k1.cert",
            },
            None,
            [
                "root_k0.cert",
                "root_k1.cert",
            ],
        ),
    ],
)
def test_find_root_certificates(
    config: dict[str, str], error: Optional[Type[Exception]], expected_list: Optional[list[str]]
) -> None:
    """Test function for finding root certificates with various configurations.

    This test validates the find_root_certificates function behavior with different
    input configurations, checking both successful execution and error handling.

    :param config: Configuration dictionary containing certificate settings.
    :param error: Expected exception type to be raised, None if no exception expected.
    :param expected_list: Expected list of root certificates when no error occurs.
    """
    if error is not None:
        with pytest.raises(error):
            find_root_certificates(config)
    else:
        certificates = find_root_certificates(config)
        assert certificates == expected_list
        assert certificates == expected_list


def test_isk_cert_lite(data_dir: str) -> None:
    """Test ISK certificate lite functionality.

    This test verifies the creation, signing, and parsing of an ISK (Initial Secure Key)
    certificate in lite format. It loads a private key and public key certificate,
    creates an ISK certificate lite object, signs it with the private key, exports
    the data, and validates that the exported data can be parsed back correctly.

    :param data_dir: Directory path containing test certificate and key files
    :raises AssertionError: If the exported data doesn't match the parsed data
    :raises SPSDKError: If certificate loading or signing operations fail
    """
    main_root_private_key_file = f"{data_dir}/ec_pk_secp256r1_cert0.pem"
    pub_key = f"{data_dir}/ec_secp256r1_cert0.pem"
    isk_cert = load_binary(pub_key)

    signature_provider = PlainFileSP(main_root_private_key_file)

    cert = IskCertificateLite(isk_cert)
    cert.create_isk_signature(signature_provider)
    data = cert.export()
    assert data == IskCertificateLite.parse(data).export()


def test_cert_block_vx(data_dir: str) -> None:
    """Test certificate block VX functionality with export and parse operations.

    This test verifies that a CertBlockVx can be created with EC secp256r1 certificates,
    exported to binary format, parsed back from the binary data, and maintains the
    correct ISK certificate length after round-trip serialization.

    :param data_dir: Directory path containing test certificate and private key files
    :raises AssertionError: If the exported certificate block length doesn't match expected ISK_CERT_LENGTH
    """
    main_root_private_key_file = f"{data_dir}/ec_pk_secp256r1_cert0.pem"
    isk_certificate = f"{data_dir}/ec_secp256r1_cert0.pem"
    signature_provider = PlainFileSP(main_root_private_key_file)
    isk_cert = load_binary(isk_certificate)

    cert_block = CertBlockVx(
        FamilyRevision("Ambassador"),
        signature_provider=signature_provider,
        isk_cert=isk_cert,
        self_signed=True,
    )

    exported = cert_block.export()
    cert_block = CertBlockVx.parse(exported)
    cert_block.signature_provider = signature_provider
    assert len(cert_block.export()) == CertBlockVx.ISK_CERT_LENGTH


def test_cert_block_v31(data_dir: str) -> None:
    """Test certificate block version 3.1 functionality.

    This test verifies the creation, calculation, export, and parsing of a CertBlockV21
    instance using ECC secp256r1 keys and certificates. It tests the complete workflow
    from loading cryptographic materials to exporting and re-parsing the certificate block.

    :param data_dir: Directory path containing test cryptographic files including private keys and certificates.
    :raises SPSDKError: If certificate block creation, calculation, or parsing fails.
    :raises FileNotFoundError: If required cryptographic files are not found in the data directory.
    """
    main_root_private_key_file = f"{data_dir}/ec_pk_secp256r1_cert0.pem"
    isk_certificate = f"{data_dir}/ec_secp256r1_cert0.pem"

    signature_provider = PlainFileSP(main_root_private_key_file)
    isk_cert = load_binary(isk_certificate)

    rot = [load_binary(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem")) for x in range(4)]

    cert = CertBlockV21(
        FamilyRevision("lpc55s36"),
        root_certs=rot,
        signature_provider=signature_provider,
        isk_cert=isk_cert,
    )
    cert.calculate()
    exported = cert.export()
    CertBlockV21.parse(exported)
