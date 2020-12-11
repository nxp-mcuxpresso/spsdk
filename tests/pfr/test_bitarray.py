#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from bitstring import BitArray

def test_basic():
    ba = BitArray(f"uint:32={0x1111}")
    assert len(ba) == 32
    bl = ba[16:]
    assert len(bl) == 16
    assert bl.hex == '1111'

def test_invert():
    ba = BitArray(f"uint:32={0x1111}")
    bl = ba[16:]
    bl.invert()
    assert bl.hex == 'eeee'
    ba.overwrite(bl, 0)
    assert ba.hex == 'eeee1111'

def test_byteswap():
    ba = BitArray(f"uint:32={0x1234_5678}")
    ba.byteswap()
    assert ba.hex == '78563412'
