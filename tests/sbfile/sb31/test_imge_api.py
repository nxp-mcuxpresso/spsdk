#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb31 import commands
from spsdk.sbfile.sb31.images import SecureBinary31Commands, SecureBinary31Header
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary
from spsdk.utils.spsdk_enum import SpsdkEnum

lpc_family = FamilyRevision("lpc55s3x")


def test_sb31_header_error():
    class TestEnumHashAlgorithm(SpsdkEnum):
        SHA256b = (0, "SHA256b", "SHA256b")

    # invalid MAGIC
    with pytest.raises(SPSDKError):
        SecureBinary31Header.parse(bytes(100))

    # invalid VERSION
    with pytest.raises(SPSDKError):
        SecureBinary31Header.parse(b"sbv3" + bytes(100))

    # invalid BLOCK_SIZE
    with pytest.raises(SPSDKError):
        SecureBinary31Header.parse(b"sbv3\x01\x00\x03\x00" + bytes(100))

    # invalid CURVE_NAME
    with pytest.raises(SPSDKError):
        SecureBinary31Header(firmware_version=1, hash_type=EnumHashAlgorithm.MD5)

    # invalid CURVE_NAME
    header = SecureBinary31Header(1, EnumHashAlgorithm.SHA256)
    header.hash_type = TestEnumHashAlgorithm.SHA256b
    with pytest.raises(SPSDKError):
        header.block_size
    with pytest.raises(SPSDKError):
        header.cert_block_offset


def test_sb31_header_description():
    header = SecureBinary31Header(1, EnumHashAlgorithm.SHA256)
    assert header.description == bytes(16)
    header = SecureBinary31Header(1, EnumHashAlgorithm.SHA256, description="desc")
    assert header.description == b"desc" + bytes(12)
    header = SecureBinary31Header(1, EnumHashAlgorithm.SHA256, description="very long description")
    assert header.description == b"very long descri"
    assert str(header)


def test_sb31_commands_errors():
    with pytest.raises(SPSDKError):
        SecureBinary31Commands.parse(bytes(100))


def test_sb31_commands_add():
    sc = SecureBinary31Commands(family=lpc_family, hash_type=EnumHashAlgorithm.SHA256)
    sc.add_command(commands.CmdCall(0x100))
    assert len(sc.commands) == 1
    info = str(sc)
    assert "CALL: Address=" in info


def test_sb31_commands_insert():
    sc = SecureBinary31Commands(family=lpc_family, hash_type=EnumHashAlgorithm.SHA256)
    sc.insert_command(0, commands.CmdCall(0x100))
    sc.insert_command(-1, commands.CmdExecute(0x100))
    assert len(sc.commands) == 2
    assert "CALL:" in str(sc.commands[0])
    assert "EXECUTE:" in str(sc.commands[1])


def test_sb31_parse(data_dir):
    data = load_binary(f"{data_dir}/sb3_384_384.sb3")
    header = SecureBinary31Header.parse(data)
    assert header.hash_type == EnumHashAlgorithm.SHA384
    assert header.image_total_length == 0x2C8
