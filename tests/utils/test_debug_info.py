#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


import pytest

from spsdk import SPSDKError
from spsdk.utils.misc import DebugInfo


def _log_test_output(dbg_info: DebugInfo) -> None:
    """Uses all methods of DebugInfo class to append data in different format

    :param dbg_info: instance used for logging
    """
    dbg_info.append_section("SECTION")
    dbg_info.append("-test-line-")
    dbg_info.append_binary_section("bin", b"\x00\x11\x22\xFF")
    dbg_info.append_binary_data("data", b"\x00\x11\x22")
    dbg_info.append_hex_data(b"\x00\x11\x22\x00\x11\x22\x00\x11\x22\x00\x11\x22")


def test_debug_info() -> None:
    """Test basic DebugInfo methods"""
    dbg_info = DebugInfo()
    assert dbg_info.enabled
    _log_test_output(dbg_info)
    assert dbg_info.lines == [
        "[SECTION]",
        "-test-line-",
        "[bin]",
        "hex=001122ff",
        "len=4=0x4",
        "data=001122",
        "hex=001122001122001122001122",
        "len=12=0xc",
    ]


def test_debug_info_disabled() -> None:
    """Test disabled output"""
    dbg_info = DebugInfo.disabled()
    assert not dbg_info.enabled
    _log_test_output(dbg_info)
    assert dbg_info.lines == []
    assert dbg_info.info() == ""


def test_debug_info_invalid():
    dbg_info = DebugInfo()
    with pytest.raises(SPSDKError, match="Incorrect data length"):
        dbg_info.append_binary_data("data", bytes(20))
