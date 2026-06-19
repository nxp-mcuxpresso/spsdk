#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for spsdk/dice/utils.py covering key utility functions."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from spsdk.dice.exceptions import SPSDKDICEError
from spsdk.dice.utils import (
    HADDiff,
    get_supported_devices,
    get_x509_name,
    reconstruct_ecc_key,
    serialize_ecc_key,
)
from spsdk.utils.family import FamilyRevision

# ---------------------------------------------------------------------------
# get_supported_devices
# ---------------------------------------------------------------------------


def test_get_supported_devices_returns_list() -> None:
    """get_supported_devices must return a non-empty list of FamilyRevision."""
    devices = get_supported_devices()
    assert isinstance(devices, list)
    assert len(devices) > 0
    assert all(isinstance(d, FamilyRevision) for d in devices)


# ---------------------------------------------------------------------------
# reconstruct_ecc_key
# ---------------------------------------------------------------------------


def _make_raw_xy() -> bytes:
    """Generate a valid raw 64-byte X||Y representation of a P-256 point."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    nums = pub.public_numbers()
    x_bytes = nums.x.to_bytes(32, byteorder="big")
    y_bytes = nums.y.to_bytes(32, byteorder="big")
    return x_bytes + y_bytes


def test_reconstruct_ecc_key_from_bytes() -> None:
    """reconstruct_ecc_key should accept raw bytes and return valid key."""
    raw = _make_raw_xy()
    key = reconstruct_ecc_key(raw)
    assert isinstance(key, ec.EllipticCurvePublicKey)


def test_reconstruct_ecc_key_from_hex_string() -> None:
    """reconstruct_ecc_key should accept a hex string."""
    raw = _make_raw_xy()
    hex_str = raw.hex()
    key = reconstruct_ecc_key(hex_str)
    assert isinstance(key, ec.EllipticCurvePublicKey)


def test_reconstruct_ecc_key_round_trip() -> None:
    """Key reconstructed from raw bytes should match the original key."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    nums = pub.public_numbers()
    raw = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")

    reconstructed = reconstruct_ecc_key(raw)
    r_nums = reconstructed.public_numbers()
    assert r_nums.x == nums.x
    assert r_nums.y == nums.y


# ---------------------------------------------------------------------------
# serialize_ecc_key
# ---------------------------------------------------------------------------


def test_serialize_ecc_key_returns_pem() -> None:
    """serialize_ecc_key should return a PEM string."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    pem = serialize_ecc_key(pub)
    assert isinstance(pem, str)
    assert "BEGIN PUBLIC KEY" in pem


def test_serialize_ecc_key_round_trip() -> None:
    """Serialized key can be re-parsed to the same public numbers."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    pem = serialize_ecc_key(pub)

    loaded = load_pem_public_key(pem.encode("utf-8"))
    assert isinstance(loaded, ec.EllipticCurvePublicKey)
    assert loaded.public_numbers() == pub.public_numbers()


# ---------------------------------------------------------------------------
# get_x509_name
# ---------------------------------------------------------------------------


def test_get_x509_name_returns_tuple() -> None:
    """get_x509_name should return (Name, bytes)."""
    from spsdk.crypto.keys import PublicKeyEcc

    priv = ec.generate_private_key(ec.SECP256R1())
    pub_ecc = PublicKeyEcc(priv.public_key())
    name, key_hash = get_x509_name("Test Device", pub_ecc)
    from cryptography import x509

    assert isinstance(name, x509.Name)
    assert isinstance(key_hash, bytes)
    assert len(key_hash) == 20


def test_get_x509_name_common_name() -> None:
    """get_x509_name should embed the given common name in the certificate Name."""
    from cryptography import x509

    from spsdk.crypto.keys import PublicKeyEcc

    priv = ec.generate_private_key(ec.SECP256R1())
    pub_ecc = PublicKeyEcc(priv.public_key())
    cn = "My Custom CN"
    name, _ = get_x509_name(cn, pub_ecc)
    cn_attr = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    assert cn_attr[0].value == cn


def test_get_x509_name_with_full_der() -> None:
    """get_x509_name with use_full_der_for_serial should still produce valid output."""
    from spsdk.crypto.keys import PublicKeyEcc

    priv = ec.generate_private_key(ec.SECP256R1())
    pub_ecc = PublicKeyEcc(priv.public_key())
    name, key_hash = get_x509_name("Test", pub_ecc, use_full_der_for_serial=True)
    assert isinstance(key_hash, bytes)
    assert len(key_hash) == 20


# ---------------------------------------------------------------------------
# HADDiff
# ---------------------------------------------------------------------------


# We need a family that actually supports DICE in the database.
# Use the first one returned by get_supported_devices().
@pytest.fixture(scope="module")
def dice_family() -> FamilyRevision:
    """Return the first DICE-supported family revision that has register specs."""
    from spsdk.utils.family import get_db

    for family in get_supported_devices():
        try:
            db = get_db(family)
            db.get_str("dice", "reg_spec")
            return family
        except Exception:
            continue
    pytest.skip("No DICE-supported family with register specs found")


def test_haddiff_init(dice_family: FamilyRevision) -> None:
    """HADDiff should initialize without error for a supported family."""
    diff = HADDiff(dice_family)
    assert diff.had_length > 0


def test_haddiff_identical_data_no_diffs(dice_family: FamilyRevision) -> None:
    """Identical HAD data should produce zero differences."""
    diff = HADDiff(dice_family)
    data = bytes(diff.had_length)
    differences = diff.get_diff(data, data)
    assert differences == []


def test_haddiff_wrong_expected_length(dice_family: FamilyRevision) -> None:
    """get_diff should raise SPSDKDICEError when expected length is wrong."""
    diff = HADDiff(dice_family)
    wrong = bytes(diff.had_length - 1)
    correct = bytes(diff.had_length)
    with pytest.raises(SPSDKDICEError, match="Expected HAD length"):
        diff.get_diff(wrong, correct)


def test_haddiff_wrong_actual_length(dice_family: FamilyRevision) -> None:
    """get_diff should raise SPSDKDICEError when actual length is wrong."""
    diff = HADDiff(dice_family)
    correct = bytes(diff.had_length)
    wrong = bytes(diff.had_length + 1)
    with pytest.raises(SPSDKDICEError, match="Actual HAD length"):
        diff.get_diff(correct, wrong)


def test_haddiff_from_hex_string(dice_family: FamilyRevision) -> None:
    """get_diff should accept hex strings as arguments."""
    diff = HADDiff(dice_family)
    data_hex = "00" * diff.had_length
    differences = diff.get_diff(data_hex, data_hex)
    assert differences == []


def test_haddiff_critical_only_flag(dice_family: FamilyRevision) -> None:
    """critical_only=True should return a subset of all differences."""
    diff = HADDiff(dice_family)
    data_a = bytes(diff.had_length)
    # Flip a byte to create a difference
    data_b = bytearray(diff.had_length)
    data_b[0] ^= 0xFF

    all_diffs = diff.get_diff(data_a, bytes(data_b), critical_only=False)
    critical_diffs = diff.get_diff(data_a, bytes(data_b), critical_only=True)
    # critical subset must be <= all diffs
    assert len(critical_diffs) <= len(all_diffs)
