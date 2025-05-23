#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test of commands."""

import os
import pytest
from spsdk.utils.config import Config

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
from spsdk.sbfile.sb31.images import (
    SecureBinary31,
    SecureBinary31Commands,
    SecureBinary31Header,
)
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary


def test_invalid_header_parse():
    """Test invalid header parse function."""
    # valid_tag = BaseCmd.TAG  # TAG = 0x55aaaa55
    invalid_tag = bytes(BaseCmd.SIZE)
    with pytest.raises(SPSDKError):
        BaseCmd.header_parse(data=invalid_tag)


def test_value_range():
    """Test value range for command attributes."""
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
    derivation_constant, kdk_access_rights, mode, key_length, iteration, result
):
    """Test key derivation data generation."""
    derivation_data = _get_key_derivation_data(
        derivation_constant,
        kdk_access_rights,
        KeyDerivationMode.from_tag(mode),
        key_length,
        iteration,
    )
    assert derivation_data == bytes.fromhex(result)


def test_key_derivator():
    """Test key derivator functionality."""
    pck = bytes.fromhex("24e517d4ac417737235b6efc9afced8224e517d4ac417737235b6efc9afced82")
    derivator = KeyDerivator(pck=pck, timestamp=0x27C0E97C, kdk_access_rights=3, key_length=128)
    assert derivator.kdk == bytes.fromhex("751d0802bc9eb9adb42b68d40880aa6e")
    assert derivator.get_block_key(10) == bytearray.fromhex("40902f79dd0ec371307f7069590ad07a")
    assert derivator.get_block_key(13) == bytearray.fromhex("69362b5634b99b689a7c43df76f15b63")
    assert derivator.get_block_key(6) == bytearray.fromhex("4c28803b5de193c21f31e6fa10c76b03")


def test_key_derivator_invalid():
    """Test key derivator with invalid parameters."""
    with pytest.raises(SPSDKError, match="Invalid kdk access rights"):
        derive_block_key(kdk=bytes(50), block_number=1, key_length=5, kdk_access_rights=6)
    with pytest.raises(SPSDKError, match="Invalid key length"):
        derive_block_key(kdk=bytes(50), block_number=1, key_length=5, kdk_access_rights=0)


def test_header_validate():
    """Test of validation function for Secure Binary header class."""
    with pytest.raises(SPSDKError):
        SecureBinary31Header(hash_type=EnumHashAlgorithm.MD5, firmware_version=None)

    sb3h = SecureBinary31Header(hash_type=EnumHashAlgorithm.SHA256, firmware_version=0)
    sb3h.validate()

    with pytest.raises(SPSDKError, match="Invalid SB3.1 header flags."):
        sb3h.flags = None
        sb3h.validate()
    sb3h.flags = 0
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header block count."):
        sb3h.block_count = None
        sb3h.validate()
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header block count."):
        sb3h.block_count = -1
        sb3h.validate()
    sb3h.block_count = 0
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header hash type."):
        sb3h.hash_type = None
        sb3h.validate()
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header hash type."):
        sb3h.hash_type = "Invalid"
        sb3h.validate()
    sb3h.hash_type = EnumHashAlgorithm.SHA256
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header image type."):
        sb3h.image_type = None
        sb3h.validate()
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header image type."):
        sb3h.image_type = 1
        sb3h.validate()
    sb3h.image_type = 6
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header firmware version."):
        sb3h.firmware_version = None
        sb3h.validate()
    sb3h.firmware_version = 6
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header timestamp."):
        sb3h.timestamp = None
        sb3h.validate()
    sb3h.timestamp = 1
    tl = sb3h.image_total_length
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header image total length."):
        sb3h.image_total_length = None
        sb3h.validate()
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header image total length."):
        sb3h.image_total_length = 1
        sb3h.validate()
    sb3h.image_total_length = tl
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header image description."):
        sb3h.description = None
        sb3h.validate()
    with pytest.raises(SPSDKError, match="Invalid SB3.1 header image description."):
        sb3h.description = "Short"
        sb3h.validate()
    sb3h.description = "                "
    sb3h.validate()


def test_commands_validate():
    """Test of validation function for Secure Binary commands class."""
    family = FamilyRevision("lpc55s3x")
    with pytest.raises(SPSDKError):
        SecureBinary31Commands(family=family, hash_type=EnumHashAlgorithm.SHA256)

    SecureBinary31Commands(
        family=family, hash_type=EnumHashAlgorithm.SHA256, is_encrypted=False
    ).validate()

    sb3c = SecureBinary31Commands(
        family=family,
        hash_type=EnumHashAlgorithm.SHA256,
        pck=bytes(32),
        kdk_access_rights=1,
        timestamp=1,
    )
    sb3c.key_derivator = None  # something broke key derivator
    with pytest.raises(SPSDKError):
        sb3c.validate()


def test_secure_binary3_validate(data_dir):
    """Test of validation function for Secure Binary class."""

    family = FamilyRevision("lpc55s3x")
    rot = [load_binary(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem")) for x in range(4)]
    cert_blk = CertBlockV21(family, root_certs=rot, ca_flag=1)
    cert_blk.calculate()

    sb3_commands = SecureBinary31Commands(
        family=family, hash_type=EnumHashAlgorithm.SHA256, is_encrypted=False
    )
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
        sb3.signature_provider = "Invalid"
        sb3.validate()
    sb3.signature_provider = PlainFileSP("ecc_secp256r1_priv_key.pem", search_paths=[data_dir])
    sb3.validate()


def test_secure_binary3_info(data_dir):
    """Test of info function for Secure Binary class."""

    family = FamilyRevision("lpc55s3x")
    rot = [load_binary(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem")) for x in range(4)]
    cert_blk = CertBlockV21(family, root_certs=rot, ca_flag=1)
    cert_blk.calculate()

    sb3_commands = SecureBinary31Commands(
        family=family, hash_type=EnumHashAlgorithm.SHA256, is_encrypted=False
    )

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


def test_cert_block_validate(data_dir):
    """Test of validation function for Secure Binary class."""

    family = FamilyRevision("lpc55s3x")
    rot = [load_binary(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem")) for x in range(4)]
    isk_cert = load_binary(os.path.join(data_dir, "ec_secp256r1_cert0.pem"))
    cert_blk = CertBlockV21(
        family=family,
        root_certs=rot,
        ca_flag=0,
        version="2.0",
        signature_provider=PlainFileSP("ecc_secp256r1_priv_key.pem", search_paths=[data_dir]),
        isk_cert=isk_cert,
    )
    cert_blk.calculate()
    cert_blk.validate()

    with pytest.raises(SPSDKError):
        cert_blk.isk_certificate.signature_provider = "invalid"
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
def test_load_cmd_data_from_cfg_formats(data_dir, config_data, expected_bytes):
    """Test loading data in various formats."""
    if "file" in config_data:
        config_data["file"] = os.path.join(data_dir, config_data["file"])
    config = Config(config_data)
    result = load_cmd_data_from_cfg(config)
    assert result == expected_bytes


@pytest.fixture
def temp_binary_file(tmpdir):
    """Create a temporary binary file for testing."""
    sample_data = b"\x01\x02\x03\x04"
    file_path = os.path.join(tmpdir, "sample_data.bin")
    with open(file_path, "wb") as f:
        f.write(sample_data)
    return file_path


def test_load_cmd_data_from_cfg_file(temp_binary_file):
    """Test loading data from a file."""
    config = Config({"file": temp_binary_file})
    result = load_cmd_data_from_cfg(config)
    assert result == load_binary(temp_binary_file)
