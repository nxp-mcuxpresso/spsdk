#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test of commands."""

import pytest

from spsdk import SPSDKError
from spsdk.sbfile.sb31.commands import BaseCmd, CmdErase, MainCmd
from spsdk.sbfile.sb31.functions import KeyDerivator, _get_key_derivation_data, derive_block_key


def test_invalid_header_parse():
    """Test invalid header parse function."""
    valid_tag = BaseCmd.TAG  # TAG = 0x55aaaa55
    invalid_tag = bytes(BaseCmd.SIZE)
    with pytest.raises(SPSDKError):
        BaseCmd.header_parse(cmd_tag=0, data=invalid_tag)


def test_implementation_function_str():
    cmd = CmdErase(address=100, length=0)
    with pytest.raises(NotImplementedError):
        BaseCmd.info(cmd)
        MainCmd.__str__(cmd)


def test_implementation_function_info():
    cmd = CmdErase(address=100, length=0)
    with pytest.raises(NotImplementedError):
        MainCmd.info(cmd)


def test_implementation_function_export():
    cmd = CmdErase(address=100, length=0)
    with pytest.raises(NotImplementedError):
        MainCmd.export(cmd)


def test_implementation_function_parse():
    cmd = CmdErase(address=100, length=0)
    data = cmd.export()
    with pytest.raises(NotImplementedError):
        MainCmd.parse(data=data)


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
        derivation_constant, kdk_access_rights, mode, key_length, iteration
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
