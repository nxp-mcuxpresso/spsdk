#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK SB3.1 functions testing module.

This module contains comprehensive test cases for SB3.1 (Secure Binary 3.1) format
functions and utilities, covering header validation, key derivation, command loading,
and data format validation.
"""

import os
from typing import Any

import pytest

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.signature_provider import PlainFileSP
from spsdk.exceptions import SPSDKError
from spsdk.image.cert_block.cert_blocks import CertBlockV21
from spsdk.sbfile.sb31.commands import BaseCmd, CmdErase, load_cmd_data_from_cfg
from spsdk.sbfile.sb31.functions import (
    KeyDerivationMode,
    KeyDerivator,
    _get_key_derivation_data,
    derive_block_key,
)
from spsdk.sbfile.sb31.images import SecureBinary31, SecureBinary31Commands, SecureBinary31Header
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary


def test_invalid_header_parse() -> None:
    """Test that BaseCmd.header_parse raises SPSDKError when given invalid tag data.

    This test verifies that the header_parse method properly validates input data
    and raises an appropriate exception when provided with invalid tag bytes instead
    of a valid command tag.

    :raises SPSDKError: Expected exception when invalid tag data is provided to header_parse.
    """
    # valid_tag = BaseCmd.TAG  # TAG = 0x55aaaa55
    invalid_tag = bytes(BaseCmd.SIZE)
    with pytest.raises(SPSDKError):
        BaseCmd.header_parse(data=invalid_tag)


def test_value_range() -> None:
    """Test value range for command attributes.

    Validates that CmdErase command address and length attributes accept values
    within the expected 32-bit unsigned integer range (0x00000000 to 0xFFFFFFFF).
    This test ensures proper bounds checking for command parameters.
    """
    cmd = CmdErase(address=1000, length=1000)
    cmd.address = 1000
    cmd.length = 1000

    assert 0x00000000 <= cmd.address <= 0xFFFFFFFF
    assert 0x00000000 <= cmd.length <= 0xFFFFFFFF


#
# def test_padding():
#     cmd = CmdLoadKeyBlob(
#         offset=100, key_wrap_id=CmdLoadKeyBlob.NXP_CUST_KEK_EXT_SK,
#         data=add_trailing_zeros(byte_data=bytes(5), return_size=16)
#     )
#
#     assert cmd.data == bytes(16)


@pytest.mark.parametrize(
    ["derivation_constant", "kdk_access_rights", "mode", "key_length", "iteration", "result"],
    [
        (15, 3, 2, 256, 1, "0F00000000000000000000000000000000000000c01000210000010000000001"),
        (15, 3, 2, 256, 2, "0F00000000000000000000000000000000000000c01000210000010000000002"),
        (
            0x27C0E97C,
            3,
            1,
            256,
            1,
            "7ce9c02700000000000000000000000000000000c00100210000010000000001",
        ),
    ],
)
def test_get_key_derivation_data(
    derivation_constant: int,
    kdk_access_rights: int,
    mode: int,
    key_length: int,
    iteration: int,
    result: str,
) -> None:
    """Test key derivation data generation.

    Validates that the _get_key_derivation_data function produces the expected
    derivation data bytes for given input parameters.

    :param derivation_constant: Constant value used in key derivation process.
    :param kdk_access_rights: Access rights for the Key Derivation Key (KDK).
    :param mode: Key derivation mode tag value.
    :param key_length: Length of the key to be derived in bytes.
    :param iteration: Iteration count for the derivation process.
    :param result: Expected result as hexadecimal string representation.
    """
    derivation_data = _get_key_derivation_data(
        derivation_constant,
        kdk_access_rights,
        KeyDerivationMode.from_tag(mode),
        key_length,
        iteration,
    )
    assert derivation_data == bytes.fromhex(result)


def test_key_derivator() -> None:
    """Test key derivation functionality for SB3.1 format.

    This test verifies that the KeyDerivator class correctly generates the Key Derivation Key (KDK)
    from the provided Part Common Key (PCK) and derives block-specific keys using
    the specified parameters including timestamp and access rights.

    :raises AssertionError: If any of the derived keys don't match expected values.
    """
    pck = bytes.fromhex("24e517d4ac417737235b6efc9afced8224e517d4ac417737235b6efc9afced82")
    derivator = KeyDerivator(pck=pck, timestamp=0x27C0E97C, kdk_access_rights=3, key_length=128)
    assert derivator.kdk == bytes.fromhex("751d0802bc9eb9adb42b68d40880aa6e")
    assert derivator.get_block_key(10) == bytearray.fromhex("40902f79dd0ec371307f7069590ad07a")
    assert derivator.get_block_key(13) == bytearray.fromhex("69362b5634b99b689a7c43df76f15b63")
    assert derivator.get_block_key(6) == bytearray.fromhex("4c28803b5de193c21f31e6fa10c76b03")


def test_key_derivator_invalid() -> None:
    """Test key derivator function with invalid input parameters.

    Validates that the derive_block_key function properly raises SPSDKError
    when called with invalid kdk_access_rights or key_length values.

    :raises SPSDKError: When kdk_access_rights is invalid (value 6).
    :raises SPSDKError: When key_length is invalid (value 5).
    """
    with pytest.raises(SPSDKError, match="Invalid kdk access rights"):
        derive_block_key(kdk=bytes(50), block_number=1, key_length=5, kdk_access_rights=6)
    with pytest.raises(SPSDKError, match="Invalid key length"):
        derive_block_key(kdk=bytes(50), block_number=1, key_length=5, kdk_access_rights=0)


def test_header_validate() -> None:
    """Test validation functionality of SecureBinary31Header class.

    Validates that the SecureBinary31Header properly rejects invalid configurations
    and accepts valid ones. Tests include validation of hash algorithms, header fields,
    and various edge cases with None values and invalid data types.

    :raises SPSDKError: When header validation fails with invalid parameters.
    """
    with pytest.raises(SPSDKError):
        SecureBinary31Header(hash_type=EnumHashAlgorithm.MD5, firmware_version=0)

    sb3h = SecureBinary31Header(hash_type=EnumHashAlgorithm.SHA256, firmware_version=0)
    sb3h.validate()

    with pytest.raises(SPSDKError, match="Invalid SB3.1 header flags."):
        sb3h.flags = None  # type: ignore
        sb3h.validate()
    sb3h.flags = 0
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header block count."):
        sb3h.block_count = None  # type: ignore
        sb3h.validate()
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header block count."):
        sb3h.block_count = -1  # type: ignore
        sb3h.validate()
    sb3h.block_count = 0
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header hash type."):
        sb3h.hash_type = None  # type: ignore
        sb3h.validate()
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header hash type."):
        sb3h.hash_type = "Invalid"  # type: ignore
        sb3h.validate()
    sb3h.hash_type = EnumHashAlgorithm.SHA256
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header image type."):
        sb3h.image_type = None  # type: ignore
        sb3h.validate()
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header image type."):
        sb3h.image_type = 1  # type: ignore
        sb3h.validate()
    sb3h.image_type = 6
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header firmware version."):
        sb3h.firmware_version = None  # type: ignore
        sb3h.validate()
    sb3h.firmware_version = 6
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header timestamp."):
        sb3h.timestamp = None  # type: ignore
        sb3h.validate()
    sb3h.timestamp = 1
    tl = sb3h.image_total_length
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header image total length."):
        sb3h.image_total_length = None  # type: ignore
        sb3h.validate()
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header image total length."):
        sb3h.image_total_length = 1  # type: ignore
        sb3h.validate()
    sb3h.image_total_length = tl
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header image description."):
        sb3h.description = None  # type: ignore
        sb3h.validate()
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header image description."):
        sb3h.description = "Short"  # type: ignore
        sb3h.validate()
    sb3h.description = b"                "
    sb3h.validate()


def test_load_command_validation(data_dir: str) -> None:
    """Test validation functionality for SecureBinary31 class.

    Validates that SecureBinary31 properly handles different signature provider
    configurations and raises appropriate errors for invalid configurations.

    :param data_dir: Directory path containing test data files including private keys.
    """

    family = FamilyRevision("lpc55s3x")
    rot = [load_binary(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem")) for x in range(4)]
    cert_blk = CertBlockV21(family, root_certs=rot, ca_flag=True)
    cert_blk.calculate()

    sb3_commands = SecureBinary31Commands(family=family, hash_type=EnumHashAlgorithm.SHA256)
    sb3 = SecureBinary31(
        family=family,
        cert_block=cert_blk,
        firmware_version=1,
        sb_commands=sb3_commands,
        signature_provider=PlainFileSP("ecc_secp256r1_priv_key.pem", search_paths=[data_dir]),
    )
    sb3.validate()
    with pytest.raises(SPSDKError):
        sb3.signature_provider = None
        sb3.validate()
    with pytest.raises(SPSDKError):
        sb3.signature_provider = "Invalid"  # type: ignore
        sb3.validate()
    sb3.signature_provider = PlainFileSP("ecc_secp256r1_priv_key.pem", search_paths=[data_dir])
    sb3.validate()


def test_secure_binary3_info(data_dir: str) -> None:
    """Test secure binary 3.1 info string representation functionality.

    This test verifies that the SecureBinary31 class properly generates
    a string representation containing "SB3.1" when the info function
    is called on an instance configured with certificate block, commands,
    and signature provider.

    :param data_dir: Directory path containing test data files including private keys
    :raises AssertionError: If the string representation is not valid or doesn't contain "SB3.1"
    """

    family = FamilyRevision("lpc55s3x")
    rot = [load_binary(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem")) for x in range(4)]
    cert_blk = CertBlockV21(family, root_certs=rot, ca_flag=True)
    cert_blk.calculate()

    sb3_commands = SecureBinary31Commands(family=family, hash_type=EnumHashAlgorithm.SHA256)

    sb3 = SecureBinary31(
        family=family,
        cert_block=cert_blk,
        firmware_version=1,
        sb_commands=sb3_commands,
        signature_provider=PlainFileSP("ecc_secp256r1_priv_key.pem", search_paths=[data_dir]),
    )
    info = str(sb3)
    assert isinstance(info, str)
    assert "SB3.1" in info


def test_cert_block_validate(data_dir: str) -> None:
    """Test certificate block validation functionality.

    Validates that CertBlockV21 properly validates its configuration and raises
    appropriate errors when invalid signature providers are used.

    :param data_dir: Directory path containing test data files including private keys and certificates.
    """

    family = FamilyRevision("lpc55s3x")
    rot = [load_binary(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem")) for x in range(4)]
    isk_cert = load_binary(os.path.join(data_dir, "ec_secp256r1_cert0.pem"))
    cert_blk = CertBlockV21(
        family=family,
        root_certs=rot,
        ca_flag=False,
        version="2.0",
        signature_provider=PlainFileSP("ecc_secp256r1_priv_key.pem", search_paths=[data_dir]),
        isk_cert=isk_cert,
    )
    cert_blk.calculate()
    cert_blk.validate()

    with pytest.raises(SPSDKError):
        cert_blk.isk_certificate.signature_provider = "invalid"  # type: ignore
        cert_blk.validate()


@pytest.mark.parametrize(
    "config_data,expected_bytes",
    [
        # Single integer value
        ({"data": 0x01020304}, b"\x04\x03\x02\x01"),
        # Using 'value' key instead of 'data'
        ({"value": 0x01020304}, b"\x04\x03\x02\x01"),
        # Single hex string value
        ({"data": "0x01020304"}, b"\x04\x03\x02\x01"),
        # List of integers
        (
            {"data": [0x01, 0x02, 0x03, 0x04]},
            b"\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00",
        ),
        # List of hex strings
        (
            {"data": ["0x01", "0x02", "0x03", "0x04"]},
            b"\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00",
        ),
        # Comma-separated integers
        (
            {"data": "1, 2, 3, 4"},
            b"\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00",
        ),
        # Comma-separated hex values
        (
            {"data": "0x01, 0x02, 0x03, 0x04"},
            b"\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00",
        ),
        # Decimal value
        ({"value": 16909060}, b"\x04\x03\x02\x01"),
        # Using 'values' key with a list
        (
            {"values": [0x01, 0x02, 0x03, 0x04]},
            b"\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00",
        ),
        # Binary notation
        (
            {"data": ["0b1", "0b10", "0b11", "0b100"]},
            b"\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00",
        ),
    ],
)
def test_load_cmd_data_from_cfg_formats(
    data_dir: str, config_data: dict[str, Any], expected_bytes: bytes
) -> None:
    """Test loading command data from configuration in various formats.

    This test function validates the load_cmd_data_from_cfg function by testing
    different data formats and ensuring the loaded data matches expected bytes.
    It handles file path resolution relative to the provided data directory.

    :param data_dir: Directory path containing test data files
    :param config_data: Configuration dictionary containing data format specifications
    :param expected_bytes: Expected byte sequence that should result from loading the configuration
    :raises AssertionError: When loaded data does not match expected bytes
    """
    if "file" in config_data:
        config_data["file"] = os.path.join(data_dir, config_data["file"])
    config = Config(config_data)
    result = load_cmd_data_from_cfg(config)
    assert result == expected_bytes


@pytest.fixture
def temp_binary_file(tmpdir: str) -> str:
    """Create a temporary binary file for testing.

    This function creates a binary file with sample data in the specified temporary
    directory for use in test scenarios.

    :param tmpdir: Path to the temporary directory where the file will be created.
    :return: Absolute path to the created temporary binary file.
    """
    sample_data = b"\x01\x02\x03\x04"
    file_path = os.path.join(tmpdir, "sample_data.bin")
    with open(file_path, "wb") as f:
        f.write(sample_data)
    return file_path


def test_load_cmd_data_from_cfg_file(  # pylint: disable=redefined-outer-name
    temp_binary_file: str,
) -> None:
    """Test loading command data from a configuration file.

    Verifies that the load_cmd_data_from_cfg function correctly loads binary data
    from a file specified in the configuration and returns the same result as
    directly loading the binary file.

    :param temp_binary_file: Path to the temporary binary file used for testing.
    """
    config = Config({"file": temp_binary_file})
    result = load_cmd_data_from_cfg(config)
    assert result == load_binary(temp_binary_file)


@pytest.mark.parametrize(
    "data_value,should_pass,description",
    [
        ("0xB38AA899", True, "Hex value with 0x prefix"),
        ("0b111000", True, "Binary value with 0b prefix"),
        ("12345", True, "Plain number as string"),
        ("0x1234, 0x5678, 0, 12345678", True, "Comma-separated list of values"),
        ("test_binary.bin", True, "Existing file path"),
        ("non_existing_file.bin", False, "Non-existing file path"),
        ([1, 2, 3, 4], True, "Array of integers"),
        (12345, True, "Single integer value"),
    ],
)
def test_sb31_data_format_validation(
    data_dir: str, data_value: Any, should_pass: bool, description: str
) -> None:
    """Test validation of different data formats in SB3.1 configuration.

    This test function validates various data formats used in SB3.1 secure binary
    configuration by creating a test configuration with the provided data value
    and checking if validation passes or fails as expected.

    :param data_dir: Directory path containing test data files.
    :param data_value: The data value to be tested in the configuration.
    :param should_pass: Expected validation result - True if validation should pass, False otherwise.
    :param description: Human-readable description of the test case for error reporting.
    :raises AssertionError: When validation result doesn't match the expected outcome.
    """
    config_data = {
        "family": "mimxrt798s",
        "containerOutputFile": "output.sb3",
        "signer": "type=my_sp",
        "certBlock": "cert_block.bin",
        "description": "Test SB3.1 file",
        "containerKeyBlobEncryptionKey": "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        "isNxpContainer": False,
        "kdkAccessRights": 0,
        "containerConfigurationWord": 0,
        "commands": [{"load": {"address": 0x1000, "data": data_value}}],
    }
    cfg = Config(config_data)
    cfg.search_paths = [data_dir]

    # Get validation schemas and validate
    try:
        schemas = SecureBinary31.get_validation_schemas_from_cfg(cfg)
        cfg.check(schemas, check_unknown_props=True)
        validation_passed = True
    except Exception:
        validation_passed = False

    # Assert the validation result matches expectations
    assert validation_passed == should_pass, (
        f"Validation {'passed' if validation_passed else 'failed'} "
        f"but {'should have failed' if not should_pass else 'should have passed'} "
        f"for {description}"
    )
