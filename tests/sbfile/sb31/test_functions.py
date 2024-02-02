#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test of commands."""

import os

import pytest

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.sbfile.sb31.commands import BaseCmd, CmdErase
from spsdk.sbfile.sb31.constants import EnumCmdTag
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
    get_signature_provider,
)
from spsdk.utils.crypto.cert_blocks import CertBlockV21
from spsdk.utils.misc import load_binary


def test_invalid_header_parse():
    """Test invalid header parse function."""
    # valid_tag = BaseCmd.TAG  # TAG = 0x55aaaa55
    invalid_tag = bytes(BaseCmd.SIZE)
    with pytest.raises(SPSDKError):
        BaseCmd.header_parse(cmd_tag=EnumCmdTag.NONE, data=invalid_tag)


def test_value_range():
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
    derivation_data = _get_key_derivation_data(
        derivation_constant,
        kdk_access_rights,
        KeyDerivationMode.from_tag(mode),
        key_length,
        iteration,
    )
    assert derivation_data == bytes.fromhex(result)


def test_key_derivator():
    pck = bytes.fromhex("24e517d4ac417737235b6efc9afced8224e517d4ac417737235b6efc9afced82")
    derivator = KeyDerivator(pck=pck, timestamp=0x27C0E97C, kdk_access_rights=3, key_length=128)
    assert derivator.kdk == bytes.fromhex("751d0802bc9eb9adb42b68d40880aa6e")
    assert derivator.get_block_key(10) == bytearray.fromhex("40902f79dd0ec371307f7069590ad07a")
    assert derivator.get_block_key(13) == bytearray.fromhex("69362b5634b99b689a7c43df76f15b63")
    assert derivator.get_block_key(6) == bytearray.fromhex("4c28803b5de193c21f31e6fa10c76b03")


def test_key_derivator_invalid():
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
    with pytest.raises(SPSDKValueError):
        SecureBinary31Commands(family="lpc55s3x", hash_type=None)
    with pytest.raises(SPSDKValueError):
        SecureBinary31Commands(family="lpc55s3x", hash_type="Invalid")
    with pytest.raises(SPSDKError):
        SecureBinary31Commands(family="lpc55s3x", hash_type=EnumHashAlgorithm.SHA256)

    SecureBinary31Commands(
        family="lpc55s3x", hash_type=EnumHashAlgorithm.SHA256, is_encrypted=False
    ).validate()

    sb3c = SecureBinary31Commands(
        family="lpc55s3x",
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

    rot = [load_binary(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem")) for x in range(4)]
    cert_blk = CertBlockV21(root_certs=rot, ca_flag=1)
    cert_blk.calculate()

    sb3 = SecureBinary31(
        family="lpc55s3x",
        cert_block=cert_blk,
        firmware_version=1,
        signature_provider=get_signature_provider(
            sp_cfg=None, local_file_key="ecc_secp256r1_priv_key.pem", search_paths=[data_dir]
        ),
        is_encrypted=False,
    )
    sb3.validate()
    with pytest.raises(SPSDKError):
        sb3.signature_provider = None
        sb3.validate()
    with pytest.raises(SPSDKError):
        sb3.signature_provider = "Invalid"
        sb3.validate()
    sb3.signature_provider = get_signature_provider(
        sp_cfg=None, local_file_key="ecc_secp256r1_priv_key.pem", search_paths=[data_dir]
    )
    sb3.validate()


def test_secure_binary3_info(data_dir):
    """Test of info function for Secure Binary class."""

    rot = [load_binary(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem")) for x in range(4)]
    cert_blk = CertBlockV21(root_certs=rot, ca_flag=1)
    cert_blk.calculate()

    sb3 = SecureBinary31(
        family="lpc55s3x",
        cert_block=cert_blk,
        firmware_version=1,
        signature_provider=get_signature_provider(
            sp_cfg=None, local_file_key="ecc_secp256r1_priv_key.pem", search_paths=[data_dir]
        ),
        is_encrypted=False,
    )
    info = str(sb3)
    assert isinstance(info, str)
    assert "SB3.1" in info


def test_cert_block_validate(data_dir):
    """Test of validation function for Secure Binary class."""

    rot = [load_binary(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem")) for x in range(4)]
    isk_cert = load_binary(os.path.join(data_dir, "ec_secp256r1_cert0.pem"))
    cert_blk = CertBlockV21(
        root_certs=rot,
        ca_flag=0,
        version="2.0",
        signature_provider=get_signature_provider(
            sp_cfg=None, local_file_key="ecc_secp256r1_priv_key.pem", search_paths=[data_dir]
        ),
        isk_cert=isk_cert,
    )
    cert_blk.calculate()
    cert_blk.validate()

    with pytest.raises(SPSDKError):
        cert_blk.isk_certificate.signature_provider = "invalid"
        cert_blk.validate()
