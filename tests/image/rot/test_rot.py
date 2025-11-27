#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Root of Trust (RoT) module tests.

This module contains comprehensive test cases for the SPSDK Root of Trust
functionality, including certificate management, key handling, and RoT
class instantiation across different MCU families.
"""

import os
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.keys import PublicKey
from spsdk.exceptions import SPSDKError
from spsdk.image.cert_block.rot import Rot, RotBase, RotCertBlockv1, RotCertBlockv21
from spsdk.utils.family import FamilyRevision


def load_keys(tests_root_dir: str, key_type: str, nr_keys: int = 4) -> List[PublicKey]:
    """Load cryptographic keys from test data directory.

    Loads a specified number of public keys of a given type from the test data
    directory structure. The keys are expected to be in PEM format with filenames
    following the pattern 'srk{index}_{key_type}.pub'.

    :param tests_root_dir: Root directory path for test files
    :param key_type: Type of cryptographic keys to load (e.g., 'rsa', 'ecc')
    :param nr_keys: Number of keys to load, defaults to 4
    :raises SPSDKError: If key files cannot be found or loaded
    :return: List of loaded public key objects
    """
    keys_dir = os.path.join(tests_root_dir, "_data", "keys", key_type)
    keys = []
    for i in range(nr_keys):
        key_path = os.path.join(keys_dir, f"srk{i}_{key_type}.pub")
        keys.append(PublicKey.load(key_path))
    return keys


def load_certs(tests_root_dir: str, cert_type: str, nr_certs: int = 4) -> List[Certificate]:
    """Load certificates from test data directory.

    Loads a specified number of self-signed certificates of a given type from the test data
    directory structure. The certificates are expected to be in DER format with standardized
    naming convention.

    :param tests_root_dir: Root directory path for test files.
    :param cert_type: Type of certificates to load (e.g., 'rsa', 'ecc').
    :param nr_certs: Number of certificates to load, defaults to 4.
    :raises SPSDKError: Certificate file loading fails.
    :return: List of loaded Certificate objects.
    """
    crts_dir = os.path.join(tests_root_dir, "_data", "certs", cert_type)
    certs = []
    for i in range(nr_certs):
        crt_path = os.path.join(crts_dir, f"srk{i}_{cert_type}_self_signed.der")
        certs.append(Certificate.load(crt_path))
    return certs


# Fixtures for test data
@pytest.fixture
def rsa2048_keys(tests_root_dir: str) -> List[PublicKey]:
    """Create test RSA 2048-bit keys for testing purposes.

    Loads a set of RSA 2048-bit public keys from the test data directory
    for use in cryptographic testing scenarios.

    :param tests_root_dir: Root directory path containing test data files.
    :return: List of RSA 2048-bit public keys loaded from test files.
    """
    # Generate a test private key for testing
    return load_keys(tests_root_dir, "rsa2048", 4)


@pytest.fixture
def ecc256_keys(tests_root_dir: str) -> List[PublicKey]:
    """Create test ECC256 keys for testing purposes.

    Loads a set of ECC256 public keys from the test data directory for use in
    cryptographic testing scenarios.

    :param tests_root_dir: Root directory path containing test data files.
    :return: List of ECC256 public keys loaded from test files.
    """
    # Generate a test private key for testing
    return load_keys(tests_root_dir, "ecc256", 4)


@pytest.fixture
def rsa2048_crts(tests_root_dir: str) -> List[Certificate]:
    """Create test RSA 2048-bit certificates for testing purposes.

    This function loads a set of 4 RSA 2048-bit certificates from the test data
    directory to be used in cryptographic testing scenarios.

    :param tests_root_dir: Root directory path containing test certificate files.
    :return: List of Certificate objects loaded from the test data directory.
    """
    # Generate a test private key for testing
    return load_certs(tests_root_dir, "rsa2048", 4)


@pytest.fixture
def mock_family() -> FamilyRevision:
    """Create a mock family revision for testing purposes.

    This function generates a FamilyRevision instance with predefined test values
    that can be used in unit tests and mock scenarios.

    :return: A FamilyRevision object with test family name "test_family" and version "1.0.0".
    """
    return FamilyRevision("test_family", "1.0.0")


def test_get_supported_families() -> None:
    """Test that get_supported_families method returns a list of FamilyRevision objects.

    Verifies that the Rot.get_supported_families() method returns a proper list
    where each element is an instance of FamilyRevision class.
    """
    families = Rot.get_supported_families()
    assert isinstance(families, list)
    for family in families:
        assert isinstance(family, FamilyRevision)


@patch("spsdk.image.cert_block.rot.get_db")
def test_get_rot_class(mock_get_db: MagicMock, mock_family: FamilyRevision) -> None:
    """Test the get_rot_class method functionality.

    Verifies that the get_rot_class method correctly returns the appropriate ROT class
    based on the rot_type value retrieved from the database. Tests both cert_block_1
    and cert_block_21 rot_types to ensure proper class mapping.

    :param mock_get_db: Mock object for the database getter function
    :param mock_family: Mock FamilyRevision object used for testing
    """
    # Mock the database to return a specific rot_type
    mock_db = MagicMock()
    mock_db.get_str.return_value = "cert_block_1"
    mock_get_db.return_value = mock_db

    rot_class = Rot.get_rot_class(mock_family)
    assert rot_class == RotCertBlockv1

    # Test with a different rot_type
    mock_db.get_str.return_value = "cert_block_21"
    rot_class = Rot.get_rot_class(mock_family)
    assert rot_class == RotCertBlockv21


def test_get_rot_class_invalid() -> None:
    """Test get_rot_class method with invalid type.

    Verifies that SPSDKError is raised when attempting to get a ROT class
    with an invalid type name that doesn't exist in the registry.

    :raises SPSDKError: When the specified ROT type does not exist.
    """
    with pytest.raises(SPSDKError, match="A RoT type invalid_type does not exist"):
        RotBase.get_rot_class("invalid_type")


@pytest.mark.parametrize(
    "rot_type, key_fixture, expected_hash",
    [
        (
            "cert_block_1",
            "rsa2048_keys",
            "749c019d97aaffc9bbcf566162c39e9c39572ab8243a0dafeb9aee0f465a8f4f",
        ),
        (
            "cert_block_21",
            "rsa2048_keys",
            "749c019d97aaffc9bbcf566162c39e9c39572ab8243a0dafeb9aee0f465a8f4f",
        ),
        (
            "cert_block_21",
            "ecc256_keys",
            "e2cca7cf09a45d2f1942969fda1c68ecaad78fad416d143292dad2f618291ddd",
        ),
        (
            "srk_table_ahab",
            "rsa2048_keys",
            "cdad53aa483b4719ccd2319c4cb9ab82bcb399d23dcd9c523571cd3311e273fe",
        ),
        (
            "srk_table_ahab",
            "ecc256_keys",
            "cb2cc774b2dcec92c840eca0646b78f8d3661d3a43ed265a490a13aca75e190a",
        ),
        (
            "srk_table_ahab",
            "rsa2048_keys",
            "cdad53aa483b4719ccd2319c4cb9ab82bcb399d23dcd9c523571cd3311e273fe",
        ),
        (
            "srk_table_ahab_v2",
            "rsa2048_keys",
            "2585044c7096bfbf35901436c1cada1df6a5e34cbeee4ac38610f1053a7714c8e9953c9a9fcc0de05d75110bb31dd5f31fe0c771452bbd27385d0093e9f29343",
        ),
        (
            "srk_table_ahab_v2",
            "ecc256_keys",
            "412600fd846385bd8263770692fba46721d30c12aede0dc19cbaf54c5c473948179953bdaf43eb2a3cfdbfde7ae8f17bdcbb3ba79b675c2b5746c41c1f4d2d6b",
        ),
        (
            "srk_table_ahab_v2_48_bytes",
            "rsa2048_keys",
            "2585044c7096bfbf35901436c1cada1df6a5e34cbeee4ac38610f1053a7714c8e9953c9a9fcc0de05d75110bb31dd5f3",
        ),
        (
            "srk_table_ahab_v2_48_bytes",
            "ecc256_keys",
            "412600fd846385bd8263770692fba46721d30c12aede0dc19cbaf54c5c473948179953bdaf43eb2a3cfdbfde7ae8f17b",
        ),
        (
            "srk_table_hab",
            "rsa2048_crts",
            "e7be8a78ed297bbc862cf0b2a72ad37c34f8c1f401114c47f2bd3156f15af733",
        ),
    ],
)
def test_rot_cert_block_with_real_keys(
    rot_type: str, key_fixture: str, expected_hash: str, request: pytest.FixtureRequest
) -> None:
    """Test RoT certificate block functionality with real cryptographic keys.

    Validates that the RoT (Root of Trust) implementation correctly processes real keys
    by verifying hash calculation and export operations produce expected results.

    :param rot_type: Type identifier for the RoT implementation to test.
    :param key_fixture: Name of the pytest fixture containing the cryptographic keys.
    :param expected_hash: Expected hexadecimal hash value for validation.
    :param request: Pytest fixture request object for dynamic fixture access.
    :raises AssertionError: When hash calculation or export validation fails.
    """
    keys = request.getfixturevalue(key_fixture)
    rot = RotBase.get_rot_class(rot_type)(keys)
    hash_result = rot.calculate_hash()
    assert isinstance(hash_result, bytes)
    assert hash_result.hex() == expected_hash
    export_result = rot.export()
    assert isinstance(export_result, bytes)
