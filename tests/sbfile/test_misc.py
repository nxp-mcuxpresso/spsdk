#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
from datetime import datetime, timezone

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.sbfile.misc import BcdVersion3, SecBootBlckSize, pack_timestamp, unpack_timestamp


def test_size_sbfile1x():
    """Test `SizeSB1` class"""
    assert SecBootBlckSize.BLOCK_SIZE == 16
    assert SecBootBlckSize.to_num_blocks(0) == 0
    assert SecBootBlckSize.to_num_blocks(16) == 1
    assert SecBootBlckSize.to_num_blocks(16 * 15) == 15
    assert SecBootBlckSize.to_num_blocks(16 * 65537) == 65537
    with pytest.raises(SPSDKError):
        SecBootBlckSize.to_num_blocks(1)
    assert len(SecBootBlckSize.align_block_fill_random(b"1")) == 16


def test_bcd_version3():
    """Test `BcdVersion3` class"""
    # default value
    version = BcdVersion3()
    assert str(version) == "1.0.0"
    assert version.nums == [1, 0, 0]
    # explicit value
    version = BcdVersion3(0x987, 0x654, 0x321)
    assert str(version) == "987.654.321"
    assert version.nums == [0x987, 0x654, 0x321]
    # invalid value
    with pytest.raises(SPSDKError):
        BcdVersion3(0x19999)
    with pytest.raises(SPSDKError):
        BcdVersion3(0xF)
    with pytest.raises(SPSDKError):
        BcdVersion3.to_version(0xF)
    with pytest.raises(SPSDKError):
        BcdVersion3(0xF1, 0, 0)
    # conversion from string
    fs_version = BcdVersion3.from_str("987.654.321")
    assert fs_version == version
    # conversion from string
    fs_version = BcdVersion3.to_version("987.654.321")
    assert fs_version == version
    # conversion from BcdVersion3
    fs_version = BcdVersion3.to_version(fs_version)
    assert fs_version == version


def test_bcd_invalid():
    with pytest.raises(SPSDKError, match="Invalid length"):
        BcdVersion3.from_str("")
    with pytest.raises(SPSDKError, match="Invalid text length"):
        BcdVersion3.from_str("bbbbbbbbb.vvvvvvvv.yyyyyyy")


def test_pack_timestamp_invalid():
    with pytest.raises(SPSDKError, match="Incorrect result of conversion"):
        pack_timestamp(value=datetime(1000, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc))


def test_unpack_timestamp_invalid():
    with pytest.raises(SPSDKError, match="Incorrect result of conversion"):
        unpack_timestamp(value=99999999999999999999999)
