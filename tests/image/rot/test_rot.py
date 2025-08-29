#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for the Rot (Root of Trust) module."""

import os
import pytest
from unittest.mock import patch, MagicMock

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.keys import PublicKey
from spsdk.exceptions import SPSDKError
from spsdk.utils.family import FamilyRevision
from spsdk.image.cert_block.rot import (
    Rot,
    RotBase,
    RotCertBlockv1,
    RotCertBlockv21,
)


def load_keys(tests_root_dir, key_type: str, nr_keys: int = 4):
    keys_dir = os.path.join(tests_root_dir, "_data", "keys", key_type)
    keys = []
    for i in range(nr_keys):
        key_path = os.path.join(keys_dir, f"srk{i}_{key_type}.pub")
        keys.append(PublicKey.load(key_path))
    return keys

def load_certs(tests_root_dir, cert_type: str, nr_certs: int = 4):
    crts_dir = os.path.join(tests_root_dir, "_data", "certs", cert_type)
    certs = []
    for i in range(nr_certs):
        crt_path = os.path.join(crts_dir, f"srk{i}_{cert_type}_self_signed.der")
        certs.append(Certificate.load(crt_path))
    return certs

# Fixtures for test data
@pytest.fixture
def rsa2048_keys(tests_root_dir):
    """Create test keys for testing."""
    # Generate a test private key for testing
    return load_keys(tests_root_dir, "rsa2048", 4)


@pytest.fixture
def ecc256_keys(tests_root_dir):
    """Create test keys for testing."""
    # Generate a test private key for testing
    return load_keys(tests_root_dir, "ecc256", 4)


@pytest.fixture
def rsa2048_crts(tests_root_dir):
    """Create test keys for testing."""
    # Generate a test private key for testing
    return load_certs(tests_root_dir, "rsa2048", 4)


@pytest.fixture
def mock_family():
    """Create a mock family revision."""
    return FamilyRevision("test_family", "1.0.0")


def test_get_supported_families():
    """Test get_supported_families method."""
    families = Rot.get_supported_families()
    assert isinstance(families, list)
    for family in families:
        assert isinstance(family, FamilyRevision)


@patch("spsdk.image.cert_block.rot.get_db")
def test_get_rot_class(mock_get_db, mock_family):
    """Test get_rot_class method."""
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


def test_get_rot_class_invalid():
    """Test get_rot_class method with invalid type."""
    with pytest.raises(SPSDKError, match="A ROT type invalid_type does not exist"):
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
def test_rot_cert_block_with_real_keys(rot_type, key_fixture, expected_hash, request):
    """Test RoT with real keys."""
    keys = request.getfixturevalue(key_fixture)
    rot = RotBase.get_rot_class(rot_type)(keys)
    hash_result = rot.calculate_hash()
    assert isinstance(hash_result, bytes)
    assert hash_result.hex() == expected_hash
    export_result = rot.export()
    assert isinstance(export_result, bytes)
