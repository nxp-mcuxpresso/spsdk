#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK DK6 protocol unit tests.

This module contains comprehensive unit tests for the DK6 protocol implementation,
validating frame handling, CRC calculation, and protocol communication functionality.
"""

from typing import Optional

import pytest

from spsdk.dk6.commands import CommandTag
from spsdk.dk6.interface import Uart, to_int


@pytest.mark.parametrize(
    "data,frame_type,expected_frame",
    [
        (None, CommandTag.GET_CHIPID, b"\x00\x00\x08\x32\x21\x4a\x04\x94"),
        (b"\x00", CommandTag.UNLOCK_ISP, b"\x00\x00\x09\x4e\x00\xa7\x09\xae\x19"),
    ],
)
def test_frame(data: Optional[bytes], frame_type: CommandTag, expected_frame: bytes) -> None:
    """Test UART frame creation with given data and frame type.

    Verifies that the Uart.create_frame method correctly generates a frame
    with the specified data and command tag type.

    :param data: Optional byte data to be included in the frame.
    :param frame_type: Command tag specifying the type of frame to create.
    :param expected_frame: Expected byte sequence that should be generated.
    :raises AssertionError: When the created frame doesn't match expected frame.
    """
    frame = Uart.create_frame(data, frame_type)
    assert frame == expected_frame


def test_crc() -> None:
    """Test CRC calculation for UART frame.

    Verifies that the CRC calculation method produces the expected CRC value
    for a given data payload and frame type combination.

    :raises AssertionError: If calculated CRC doesn't match expected value.
    """
    data = b"\x00"
    frame_type = CommandTag.UNLOCK_ISP
    expected_crc = to_int(b"\xa7\x09\xae\x19")
    crc = Uart.calc_frame_crc(data, frame_type)
    assert expected_crc == crc
