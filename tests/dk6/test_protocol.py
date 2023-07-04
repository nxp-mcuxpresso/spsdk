#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
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
def test_frame(data, frame_type, expected_frame):
    frame = Uart.create_frame(data, frame_type)
    assert frame == expected_frame


def test_crc():
    data = b"\x00"
    frame_type = CommandTag.UNLOCK_ISP
    expected_crc = to_int(b"\xa7\x09\xae\x19")
    crc = Uart.calc_frame_crc(data, frame_type)
    assert expected_crc == crc
