#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.segments import FlexSPIConfBlockFCB, PaddingFCB, SegFCB, SegIVT3b
from spsdk.utils.misc import load_binary
from tests.misc import compare_bin_files


def test_FCB_base():
    segfcb = SegFCB()
    assert segfcb.version == 1
    assert segfcb.search_start_page == 0
    assert segfcb.search_stride == 0
    assert segfcb.search_count == 0
    assert segfcb.firmware_copies == 0
    assert segfcb.firmware_info_table == None
    assert segfcb.config_block == None


def test_FCB_eq():
    segfcb = SegFCB()
    ivt3b = SegIVT3b(0)
    assert segfcb != ivt3b
    assert segfcb == segfcb


def test_empty_FCB_export():
    segfcb = SegFCB()
    data = segfcb.export()
    assert isinstance(data, bytes)


def test_not_empty_FCB_export():
    segfcb = SegFCB()
    segfcb.firmware_info_table = b"\xb7"
    segfcb.config_block = b"\xb7"
    data = segfcb.export()
    assert isinstance(data, bytes)


def test_flexspi_conf_block_fcb(data_dir) -> None:
    # default object created
    fcb = FlexSPIConfBlockFCB()
    assert str(fcb)
    assert fcb.export()
    assert fcb == FlexSPIConfBlockFCB.parse(fcb.export())
    fcb.padding_len = 10
    assert len(fcb.export()) == fcb.space
    # FCB from RT105x EVK
    fcb_path = os.path.join(data_dir, "rt105x_flex_spi.fcb")
    fcb = FlexSPIConfBlockFCB.parse(load_binary(fcb_path))
    assert str(fcb)
    fcb.padding_len = 0
    compare_bin_files(fcb_path, fcb.export())
    fcb.enabled = False
    assert fcb.size == 0
    assert fcb.export() == b""
    # invalid tag
    with pytest.raises(SPSDKError):
        FlexSPIConfBlockFCB.parse(b"\x00" * 512)
    # invalid version
    with pytest.raises(SPSDKError):
        FlexSPIConfBlockFCB.parse(FlexSPIConfBlockFCB.TAG + b"\x00" * 512)
    # insufficient length
    with pytest.raises(SPSDKError):
        FlexSPIConfBlockFCB.parse(FlexSPIConfBlockFCB.TAG + FlexSPIConfBlockFCB.VERSION[::-1])


def test_padding_fcb() -> None:
    """See PaddingFCB class"""
    fcb = PaddingFCB(10, padding_value=0xA5)
    # enabled, no padding
    assert fcb.padding_len == 0
    assert fcb.size == 10
    assert fcb.space == 10
    assert fcb.export() == b"\xA5" * 10
    assert str(fcb)
    # not enabled
    fcb.enabled = False
    fcb.padding_len = 6
    assert fcb.size == 0
    assert fcb.space == 0
    assert fcb.export() == b""
    assert str(fcb)
    # enabled with padding
    fcb.enabled = True
    assert fcb.size == 10
    assert fcb.space == 16
    assert fcb.export() == b"\xA5" * 10 + b"\x00" * 6
    assert str(fcb)


def test_padding_fcb_invalid() -> None:
    with pytest.raises(SPSDKError, match="Invalid size of the exported padding"):
        PaddingFCB(size=-1, padding_value=0xA5)
    with pytest.raises(SPSDKError, match="Invalid padding"):
        PaddingFCB(size=10, padding_value=-1)
