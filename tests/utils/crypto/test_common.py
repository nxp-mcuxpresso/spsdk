#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.utils.crypto import Counter


def test_counter():
    # simple counter with nonce only
    cntr = Counter(bytes([0] * 16))
    assert cntr.value == bytes([0] * 16)

    # counter with nonce and counter encoded as little endian
    cntr = Counter(bytes([0] * 16), ctr_value=0x01234567, ctr_byteorder_encoding='little')
    assert cntr.value == bytes([0] * 12 + [0x67, 0x45, 0x23, 0x01])

    # counter with nonce and counter encoded as little endian
    cntr = Counter(bytes([0] * 16), ctr_value=0x01234567)
    assert cntr.value == bytes([0] * 12 + [0x67, 0x45, 0x23, 0x01])

    # counter with nonce and counter encoded as big endian
    cntr = Counter(bytes([0] * 16), ctr_value=1, ctr_byteorder_encoding='big')
    assert cntr.value == bytes([0] * 15 + [1])

    # increment
    cntr.increment()
    assert cntr.value == bytes([0] * 15 + [2])
    cntr.increment(2)
    assert cntr.value == bytes([0] * 15 + [4])
    cntr.increment(256)
    assert cntr.value == bytes([0] * 14 + [1, 4])
