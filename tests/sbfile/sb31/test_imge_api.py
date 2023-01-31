#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import pytest

from spsdk import SPSDKError
from spsdk.sbfile.sb31 import commands
from spsdk.sbfile.sb31.images import SecureBinary31Commands, SecureBinary31Header


def test_sb31_header_error():
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
        SecureBinary31Header(firmware_version=1, curve_name="totally-legit-curve")

    # invalid CURVE_NAME
    header = SecureBinary31Header(1, "secp256r1")
    header.curve_name = "wrong-name"
    with pytest.raises(SPSDKError):
        header.calculate_block_size()
    with pytest.raises(SPSDKError):
        header.calculate_cert_block_offset()


def test_sb31_header_description():
    header = SecureBinary31Header(1, "secp256r1")
    assert header.description == bytes(16)
    header = SecureBinary31Header(1, "secp256r1", description="desc")
    assert header.description == b"desc" + bytes(12)
    header = SecureBinary31Header(1, "secp256r1", description="very long description")
    assert header.description == b"very long descri"
    assert header.info()


def test_sb31_commands_errors():
    with pytest.raises(NotImplementedError):
        SecureBinary31Commands.parse(bytes(100))

    with pytest.raises(SPSDKError):
        SecureBinary31Commands(family="lpc55s3x", curve_name="secp384r1")


def test_sb31_commands_add():
    sc = SecureBinary31Commands(family="lpc55s3x", curve_name="secp256r1", is_encrypted=False)
    sc.add_command(commands.CmdCall(0x100))
    assert len(sc.commands) == 1
    info = sc.info()
    assert "CALL: Address=" in info


def test_sb31_commands_insert():
    sc = SecureBinary31Commands(family="lpc55s3x", curve_name="secp256r1", is_encrypted=False)
    sc.insert_command(0, commands.CmdCall(0x100))
    sc.insert_command(-1, commands.CmdExecute(0x100))
    assert len(sc.commands) == 2
    assert "CALL:" in sc.commands[0].info()
    assert "EXECUTE:" in sc.commands[1].info()


def test_sb31_commands_no_key_derivator():
    sc = SecureBinary31Commands(
        family="lpc55s3x",
        curve_name="secp256r1",
        is_encrypted=True,
        pck=bytes(16),
        timestamp=5,
        kdk_access_rights=3,
    )
    sc.add_command(commands.CmdCall(0x100))
    sc.key_derivator = None
    with pytest.raises(SPSDKError, match="No key derivator"):
        sc.export()


def test_sb31_parse(data_dir):
    with open(f"{data_dir}/sb3_384_384.sb3", "rb") as f:
        data = f.read()
    header = SecureBinary31Header.parse(data)
    assert header.curve_name == "secp384r1"
    assert header.image_total_length == 0x2C8
