#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""ELE message tests."""
from spsdk.ele.ele_message import EleMessageReadCommonFuse, EleMessageWriteFuse
from spsdk.utils.misc import value_to_bytes, value_to_int


def test_ele_write_fuse():
    msg = EleMessageWriteFuse(128 * 32, 32, False, 0x4E219CB1)
    assert msg.bit_length == 32
    assert msg.bit_position == 4096
    assert value_to_int(msg.export()) == 0x0603D61700102000B19C214E
    msg.decode_response(value_to_bytes(0x0603D6E1D600000080000000))
    assert msg.status == 0xD6
    assert msg.indication == 0
    assert msg.abort_code == 0
    assert msg.processed_idx == 128


def test_ele_read_fuse():
    msg = EleMessageReadCommonFuse(128)
    assert value_to_int(msg.export()) == 0x0602971780000000
    msg.decode_response(value_to_bytes(0x060397E1D6000000B19C214E))
    assert msg.indication == 0
    assert msg.status == 214
    assert msg.abort_code == 0
