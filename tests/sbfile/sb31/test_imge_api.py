#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import pytest

from spsdk import SPSDKError
from spsdk.sbfile.sb31 import commands
from spsdk.sbfile.sb31.images import SecureBinary31Commands, SecureBinary31Header


def test_sb31_header_error():
    with pytest.raises(NotImplementedError):
        SecureBinary31Header.parse(bytes(100))

    with pytest.raises(SPSDKError):
        SecureBinary31Header(firmware_version=1, curve_name="totally-legit-curve")

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
        SecureBinary31Commands(curve_name="secp384r1")


def test_sb31_commands_add():
    sc = SecureBinary31Commands(curve_name="secp256r1", is_encrypted=False)
    sc.add_command(commands.CmdCall(0x100))
    assert len(sc.commands) == 1
    info = sc.info()
    assert "CALL: Address=" in info


def test_sb31_commands_no_key_derivator():
    sc = SecureBinary31Commands(
        curve_name="secp256r1", is_encrypted=True, pck=bytes(16), timestamp=5, kdk_access_rights=3
    )
    sc.add_command(commands.CmdCall(0x100))
    sc.key_derivator = None
    with pytest.raises(SPSDKError, match="No key derivator"):
        sc.export()
