#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test of commands."""

import pytest

from spsdk.sbfile.sb31.commands import CmdErase, CmdLoadKeyBlob
from spsdk.sbfile.sb31.functions import BaseCmd, MainCmd, add_trailing_zeros, add_leading_zeros


def test_invalid_header_parse():
    """Test invalid header parse function."""
    valid_tag = BaseCmd.TAG  # TAG = 0x55aaaa55
    invalid_tag = bytes(BaseCmd.SIZE)
    with pytest.raises(ValueError):
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
