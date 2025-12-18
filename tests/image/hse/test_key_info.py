#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for the HSE key information module."""

import os
from typing import Any, Dict

import pytest
import yaml

from spsdk.exceptions import SPSDKParsingError
from spsdk.image.hse.common import HseKeyBits, KeyType
from spsdk.image.hse.key_info import (
    HseAesBlockModeMask,
    HseEccCurveId,
    HseKeyFlags,
    HseSmrFlags,
    KeyCatalogId,
    KeyHandle,
    KeyInfo,
)
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import write_file


@pytest.fixture
def family() -> FamilyRevision:
    """Return a family revision for testing."""
    return FamilyRevision("mcxe31b")


@pytest.fixture
def key_info_config() -> Dict[str, Any]:
    """Return a basic key info configuration for testing."""
    return {
        "family": "mcxe31b",
        "keyType": "AES",
        "keyBitLen": 256,
        "keyCounter": 1,
        "keyFlags": ["USAGE_ENCRYPT", "USAGE_DECRYPT", "ACCESS_EXPORTABLE"],
        "smrFlags": [0, 1],
        "specificData": {"aesBlockModeMask": ["BLOCK_MODE_CBC", "BLOCK_MODE_GCM"]},
    }


def test_key_info_init(family: FamilyRevision) -> None:
    """Test basic initialization of KeyInfo class."""
    key_info = KeyInfo(
        family=family,
        key_flags=HseKeyFlags.USAGE_ENCRYPT | HseKeyFlags.USAGE_DECRYPT,
        key_type=KeyType.AES,
        smr_flags=HseSmrFlags.SMR_0 | HseSmrFlags.SMR_1,
        key_bit_len=HseKeyBits.KEY256_BITS,
        key_counter=1,
    )

    assert key_info.family == family
    assert key_info.key_type == KeyType.AES
    assert key_info.key_bit_len == HseKeyBits.KEY256_BITS
    assert key_info.key_counter == 1
    assert key_info.key_flags & HseKeyFlags.USAGE_ENCRYPT
    assert key_info.key_flags & HseKeyFlags.USAGE_DECRYPT
    assert key_info.smr_flags & HseSmrFlags.SMR_0
    assert key_info.smr_flags & HseSmrFlags.SMR_1


def test_key_info_export_parse(family: FamilyRevision) -> None:
    """Test exporting and importing KeyInfo."""
    # Create a key info object
    key_info = KeyInfo(
        family=family,
        key_flags=HseKeyFlags.USAGE_ENCRYPT | HseKeyFlags.USAGE_DECRYPT,
        key_type=KeyType.AES,
        smr_flags=HseSmrFlags.SMR_0 | HseSmrFlags.SMR_1,
        key_bit_len=HseKeyBits.KEY256_BITS,
        key_counter=1,
        specific_data={
            "aesBlockModeMask": HseAesBlockModeMask.BLOCK_MODE_CBC
            | HseAesBlockModeMask.BLOCK_MODE_GCM
        },
    )

    # Export to binary
    exported_data = key_info.export()

    # Import from binary
    imported_key_info = KeyInfo.parse(exported_data, family)

    # Verify imported data matches original
    assert imported_key_info.key_type == key_info.key_type
    assert imported_key_info.key_bit_len == key_info.key_bit_len
    assert imported_key_info.key_counter == key_info.key_counter
    assert imported_key_info.key_flags == key_info.key_flags
    assert imported_key_info.smr_flags == key_info.smr_flags
    assert "aesBlockModeMask" in imported_key_info.specific_data
    assert (
        imported_key_info.specific_data["aesBlockModeMask"]
        == key_info.specific_data["aesBlockModeMask"]
    )


def test_key_info_parse_invalid_data() -> None:
    """Test parsing invalid data."""
    # Test with empty data
    with pytest.raises(SPSDKParsingError, match="No data set for key info"):
        KeyInfo.parse(b"")

    # Test with too short data
    with pytest.raises(SPSDKParsingError, match="Invalid data length for key info"):
        KeyInfo.parse(b"1234")


def test_key_info_specific_data_ecc(family: FamilyRevision) -> None:
    """Test specific data for ECC keys."""
    key_info = KeyInfo(
        family=family,
        key_flags=HseKeyFlags.USAGE_SIGN | HseKeyFlags.USAGE_VERIFY,
        key_type=KeyType.ECC_PAIR,
        smr_flags=HseSmrFlags.SMR_0,
        key_bit_len=HseKeyBits.KEY256_BITS,
        specific_data={"eccCurveId": HseEccCurveId.SEC_SECP256R1},
    )

    # Check specific data encoding
    assert key_info.specific == bytes([HseEccCurveId.SEC_SECP256R1])

    # Export and parse
    exported_data = key_info.export()
    imported_key_info = KeyInfo.parse(exported_data, family)

    # Verify specific data was preserved
    assert "eccCurveId" in imported_key_info.specific_data
    assert imported_key_info.specific_data["eccCurveId"] == HseEccCurveId.SEC_SECP256R1


def test_key_info_specific_data_rsa(family: FamilyRevision) -> None:
    """Test specific data for RSA keys."""
    key_info = KeyInfo(
        family=family,
        key_flags=HseKeyFlags.USAGE_SIGN | HseKeyFlags.USAGE_VERIFY,
        key_type=KeyType.RSA_PAIR,
        smr_flags=HseSmrFlags.SMR_0,
        key_bit_len=HseKeyBits.KEY2048_BITS,
        specific_data={"pubExponentSize": 3},  # Common value for RSA exponent size (F4)
    )

    # Check specific data encoding
    assert key_info.specific == bytes([3])

    # Export and parse
    exported_data = key_info.export()
    imported_key_info = KeyInfo.parse(exported_data, family)

    # Verify specific data was preserved
    assert "pubExponentSize" in imported_key_info.specific_data
    assert imported_key_info.specific_data["pubExponentSize"] == 3


def test_key_info_flags_methods(family: FamilyRevision) -> None:
    """Test methods for getting flags."""
    key_info = KeyInfo(
        family=family,
        key_flags=(
            HseKeyFlags.USAGE_ENCRYPT | HseKeyFlags.USAGE_DECRYPT | HseKeyFlags.ACCESS_EXPORTABLE
        ),
        key_type=KeyType.AES,
        smr_flags=HseSmrFlags.SMR_0 | HseSmrFlags.SMR_1,
        key_bit_len=HseKeyBits.KEY256_BITS,
    )

    # Test usage flags
    usage_flags = key_info.get_key_usage_flags()
    assert HseKeyFlags.USAGE_ENCRYPT in usage_flags
    assert HseKeyFlags.USAGE_DECRYPT in usage_flags
    assert HseKeyFlags.USAGE_SIGN not in usage_flags

    # Test access flags
    access_flags = key_info.get_key_access_flags()
    assert HseKeyFlags.ACCESS_EXPORTABLE in access_flags
    assert HseKeyFlags.ACCESS_WRITE_PROT not in access_flags

    # Test SMR flags
    smr_flags = key_info.get_smr_flags()
    assert HseSmrFlags.SMR_0 in smr_flags
    assert HseSmrFlags.SMR_1 in smr_flags
    assert HseSmrFlags.SMR_2 not in smr_flags


def test_key_info_string_representation(family: FamilyRevision) -> None:
    """Test string representation of KeyInfo."""
    key_info = KeyInfo(
        family=family,
        key_flags=HseKeyFlags.USAGE_ENCRYPT | HseKeyFlags.USAGE_DECRYPT,
        key_type=KeyType.AES,
        smr_flags=HseSmrFlags.SMR_0 | HseSmrFlags.SMR_1,
        key_bit_len=HseKeyBits.KEY256_BITS,
        key_counter=1,
    )

    # Test __str__
    str_repr = str(key_info)
    assert "Key Information:" in str_repr
    assert "Key Flags:" in str_repr
    assert "USAGE_ENCRYPT" in str_repr
    assert "USAGE_DECRYPT" in str_repr
    assert "Key Bit Length:" in str_repr
    assert "Key Counter: 1" in str_repr
    assert "SMR Flags:" in str_repr
    assert "SMR_0" in str_repr
    assert "SMR_1" in str_repr
    assert "Key Type: AES" in str_repr

    # Test __repr__
    repr_str = repr(key_info)
    assert "AES" in repr_str
    assert "KEY256_BITS" in repr_str
    assert "2 flags" in repr_str
    assert "2 SMRs" in repr_str


def test_key_info_load_from_config(key_info_config: dict) -> None:
    """Test loading KeyInfo from configuration."""
    config = Config(key_info_config)
    key_info = KeyInfo.load_from_config(config)

    assert key_info.family.name == "mcxe31b"
    assert key_info.key_type == KeyType.AES
    assert key_info.key_bit_len == HseKeyBits.KEY256_BITS
    assert key_info.key_counter == 1
    assert key_info.key_flags & HseKeyFlags.USAGE_ENCRYPT
    assert key_info.key_flags & HseKeyFlags.USAGE_DECRYPT
    assert key_info.key_flags & HseKeyFlags.ACCESS_EXPORTABLE
    assert key_info.smr_flags & HseSmrFlags.SMR_0
    assert key_info.smr_flags & HseSmrFlags.SMR_1

    # Check specific data
    assert "aesBlockModeMask" in key_info.specific_data
    block_mode_mask = key_info.specific_data["aesBlockModeMask"]
    assert block_mode_mask & HseAesBlockModeMask.BLOCK_MODE_CBC
    assert block_mode_mask & HseAesBlockModeMask.BLOCK_MODE_GCM


def test_key_info_get_config(family: FamilyRevision) -> None:
    """Test getting configuration from KeyInfo."""
    key_info = KeyInfo(
        family=family,
        key_flags=HseKeyFlags.USAGE_ENCRYPT
        | HseKeyFlags.USAGE_DECRYPT
        | HseKeyFlags.ACCESS_EXPORTABLE,
        key_type=KeyType.AES,
        smr_flags=HseSmrFlags.SMR_0 | HseSmrFlags.SMR_1,
        key_bit_len=HseKeyBits.KEY256_BITS,
        key_counter=1,
        specific_data={
            "aesBlockModeMask": HseAesBlockModeMask.BLOCK_MODE_CBC
            | HseAesBlockModeMask.BLOCK_MODE_GCM
        },
    )

    config = key_info.get_config()

    assert config["keyType"] == "AES"
    assert config["keyBitLen"] == 256
    assert config["keyCounter"] == 1
    assert "USAGE_ENCRYPT" in config["keyFlags"]
    assert "USAGE_DECRYPT" in config["keyFlags"]
    assert "ACCESS_EXPORTABLE" in config["keyFlags"]
    assert 0 in config["smrFlags"]
    assert 1 in config["smrFlags"]
    assert "BLOCK_MODE_CBC" in config["specificData"]["aesBlockModeMask"]
    assert "BLOCK_MODE_GCM" in config["specificData"]["aesBlockModeMask"]


def test_key_info_config_roundtrip(family: FamilyRevision, tmp_path: str) -> None:
    """Test round-trip from KeyInfo to config and back."""
    # Create original key info
    original_key_info = KeyInfo(
        family=family,
        key_flags=HseKeyFlags.USAGE_ENCRYPT
        | HseKeyFlags.USAGE_DECRYPT
        | HseKeyFlags.ACCESS_EXPORTABLE,
        key_type=KeyType.AES,
        smr_flags=HseSmrFlags.SMR_0 | HseSmrFlags.SMR_1,
        key_bit_len=HseKeyBits.KEY256_BITS,
        key_counter=1,
        specific_data={
            "aesBlockModeMask": HseAesBlockModeMask.BLOCK_MODE_CBC
            | HseAesBlockModeMask.BLOCK_MODE_GCM
        },
    )

    # Get config
    config = original_key_info.get_config()

    # Create new key info from loaded config
    new_key_info = KeyInfo.load_from_config(config)

    # Verify new key info matches original
    assert new_key_info.key_type == original_key_info.key_type
    assert new_key_info.key_bit_len == original_key_info.key_bit_len
    assert new_key_info.key_counter == original_key_info.key_counter
    assert new_key_info.key_flags == original_key_info.key_flags
    assert new_key_info.smr_flags == original_key_info.smr_flags

    # Check specific data
    assert "aesBlockModeMask" in new_key_info.specific_data
    assert (
        new_key_info.specific_data["aesBlockModeMask"]
        == original_key_info.specific_data["aesBlockModeMask"]
    )


def test_key_info_template(family: FamilyRevision, tmp_path: str) -> None:
    """Test generating a template configuration."""
    template = KeyInfo.get_config_template(family)

    # Verify template is valid YAML
    template_dict = yaml.safe_load(template)

    # Check required fields are present
    assert "family" in template_dict
    assert "keyType" in template_dict
    assert "keyBitLen" in template_dict

    # Save template to file and verify it can be loaded
    template_file = os.path.join(tmp_path, "key_info_template.yaml")
    write_file(template, template_file)

    # Load template as config
    config = Config.create_from_file(template_file)
    # specificData would nto pass the validation, as oneOf condition applies
    del config["specificData"]

    # Verify schema validation
    schemas = KeyInfo.get_validation_schemas(family)
    config.check(schemas)


def test_key_handle_init() -> None:
    """Test initialization of KeyHandle."""
    key_handle = KeyHandle(KeyCatalogId.RAM, 1, 2)

    assert key_handle.catalog_id == KeyCatalogId.RAM
    assert key_handle.group_idx == 1
    assert key_handle.slot_idx == 2
    assert key_handle.handle == 0x00020102  # RAM(2) << 16 | 1 << 8 | 2


def test_key_handle_from_handle() -> None:
    """Test creating KeyHandle from raw handle value."""
    key_handle = KeyHandle.from_handle(0x00010203)  # NVM(1) << 16 | 2 << 8 | 3

    assert key_handle.catalog_id == KeyCatalogId.NVM
    assert key_handle.group_idx == 2
    assert key_handle.slot_idx == 3


def test_key_handle_parse() -> None:
    """Test parsing KeyHandle from bytes."""
    key_handle = KeyHandle.parse(b"\x04\x03\x02\x01")  # Little-endian: 0x01020304

    assert key_handle.catalog_id == KeyCatalogId.RAM
    assert key_handle.group_idx == 3
    assert key_handle.slot_idx == 4


def test_key_handle_parse_invalid() -> None:
    """Test parsing invalid KeyHandle data."""
    with pytest.raises(SPSDKParsingError, match="Invalid key handle data length"):
        KeyHandle.parse(b"\x01\x02\x03")  # Too short


def test_key_handle_export() -> None:
    """Test exporting KeyHandle to bytes."""
    key_handle = KeyHandle(KeyCatalogId.NVM, 5, 6)
    exported = key_handle.export()

    assert exported == b"\x06\x05\x01\x00"  # Little-endian: 0x00010506


def test_key_handle_is_valid() -> None:
    """Test is_valid method of KeyHandle."""
    # Valid key handle
    key_handle = KeyHandle(KeyCatalogId.RAM, 1, 2)
    assert key_handle.is_valid() is True

    # Invalid key handle (invalid group index)
    key_handle = KeyHandle(KeyCatalogId.RAM, KeyHandle.INVALID_GROUP_IDX, 2)
    assert key_handle.is_valid() is False

    # Invalid key handle (invalid slot index)
    key_handle = KeyHandle(KeyCatalogId.RAM, 1, KeyHandle.INVALID_SLOT_IDX)
    assert key_handle.is_valid() is False


def test_key_handle_is_rom_key() -> None:
    """Test is_rom_key property of KeyHandle."""
    # ROM key
    key_handle = KeyHandle(KeyCatalogId.ROM, 1, 2)
    assert key_handle.is_rom_key is True

    # Non-ROM key
    key_handle = KeyHandle(KeyCatalogId.RAM, 1, 2)
    assert key_handle.is_rom_key is False


def test_key_handle_string_representation() -> None:
    """Test string representation of KeyHandle."""
    key_handle = KeyHandle(KeyCatalogId.NVM, 3, 4)
    str_repr = str(key_handle)

    assert "Key Handle: 0x00010304" in str_repr
    assert "Catalog: NVM" in str_repr
    assert "Group: 3" in str_repr
    assert "Slot: 4" in str_repr


def test_key_handle_predefined_constants() -> None:
    """Test predefined key handle constants."""
    # ROM_KEY_AES256_KEY0
    key_handle = KeyHandle.from_handle(KeyHandle.ROM_KEY_AES256_KEY0)
    assert key_handle.catalog_id == KeyCatalogId.ROM
    assert key_handle.group_idx == 0
    assert key_handle.slot_idx == 0

    # ROM_KEY_RSA3072_PUB_KEY0
    key_handle = KeyHandle.from_handle(KeyHandle.ROM_KEY_RSA3072_PUB_KEY0)
    assert key_handle.catalog_id == KeyCatalogId.ROM
    assert key_handle.group_idx == 1
    assert key_handle.slot_idx == 0
