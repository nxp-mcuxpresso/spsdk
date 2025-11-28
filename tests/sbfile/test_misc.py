#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB file miscellaneous utilities test suite.

This module contains unit tests for miscellaneous SB file utilities including
BCD version handling, secure boot block size calculations, and timestamp
operations.
"""

from datetime import datetime, timezone

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.sbfile.misc import BcdVersion3, SecBootBlckSize, pack_timestamp, unpack_timestamp


def test_size_sbfile1x() -> None:
    """Test SecBootBlckSize class functionality.

    Validates block size constants, block number calculations, alignment operations,
    and error handling for invalid inputs. Tests include boundary conditions
    and proper exception raising for non-aligned block sizes.

    :raises SPSDKError: When testing invalid block size alignment.
    """
    assert SecBootBlckSize.BLOCK_SIZE == 16
    assert SecBootBlckSize.to_num_blocks(0) == 0
    assert SecBootBlckSize.to_num_blocks(16) == 1
    assert SecBootBlckSize.to_num_blocks(16 * 15) == 15
    assert SecBootBlckSize.to_num_blocks(16 * 65537) == 65537
    with pytest.raises(SPSDKError):
        SecBootBlckSize.to_num_blocks(1)
    assert len(SecBootBlckSize.align_block_fill_random(b"1")) == 16


def test_bcd_version3() -> None:
    """Test BcdVersion3 class functionality and edge cases.

    Validates the BcdVersion3 class including default initialization, explicit value setting,
    string representation, number extraction, invalid value handling, and various conversion
    methods from strings and other BcdVersion3 instances.
    """
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
        BcdVersion3.to_version(0xF)  # type: ignore
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


def test_bcd_invalid() -> None:
    """Test BCD version parsing with invalid input strings.

    Validates that BcdVersion3.from_str() properly raises SPSDKError exceptions
    when provided with invalid input formats including empty strings and
    strings that exceed maximum allowed length.

    :raises SPSDKError: When empty string or overly long string is provided.
    """
    with pytest.raises(SPSDKError, match="Invalid length"):
        BcdVersion3.from_str("")
    with pytest.raises(SPSDKError, match="Invalid text length"):
        BcdVersion3.from_str("bbbbbbbbb.vvvvvvvv.yyyyyyy")


def test_pack_timestamp_invalid() -> None:
    """Test that pack_timestamp raises error for invalid timestamp values.

    Verifies that pack_timestamp function properly validates input timestamps
    and raises SPSDKError when given a timestamp that cannot be converted
    correctly, such as dates outside the valid range.

    :raises SPSDKError: When timestamp conversion fails for invalid input values.
    """
    with pytest.raises(SPSDKError, match="Incorrect result of conversion"):
        pack_timestamp(value=datetime(1000, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc))


def test_unpack_timestamp_invalid() -> None:
    """Test that unpack_timestamp raises SPSDKError for invalid timestamp values.

    This test verifies that the unpack_timestamp function properly handles
    extremely large timestamp values that cannot be converted correctly.

    :raises SPSDKError: When timestamp conversion fails due to invalid input value.
    """
    with pytest.raises(SPSDKError, match="Incorrect result of conversion"):
        unpack_timestamp(value=99999999999999999999999)
