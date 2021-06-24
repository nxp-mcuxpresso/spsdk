#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.image import CmdCheckData, CmdNop
from spsdk.image import EnumCheckOps
from spsdk.image.segments import SegFCB, FlexSPIConfBlockFCB, SegDCD


def test_segDCD():
    dcd_seg = SegDCD()
    assert "DCD <Commands:" in repr(dcd_seg)


def test_segDCD_set_get_iter():
    dcd_seg = SegDCD(0x40)
    dcd_seg.append(CmdCheckData(ops=EnumCheckOps.ALL_CLEAR, address=0x307900C4, mask=0x00000001))
    dcd_seg.append(CmdNop())
    dcd_seg[1] = CmdCheckData(ops=EnumCheckOps.ALL_CLEAR, address=0x307900C4, mask=0x00000001)
    assert dcd_seg[1] == CmdCheckData(
        ops=EnumCheckOps.ALL_CLEAR, address=0x307900C4, mask=0x00000001
    )
    dcd_seg.append(CmdCheckData(ops=EnumCheckOps.ALL_CLEAR, address=0x307900C4, mask=0x00000001))
    my_iter = iter(dcd_seg)
    assert next(my_iter) == CmdCheckData(
        ops=EnumCheckOps.ALL_CLEAR, address=0x307900C4, mask=0x00000001
    )
    assert next(my_iter) == CmdCheckData(
        ops=EnumCheckOps.ALL_CLEAR, address=0x307900C4, mask=0x00000001
    )
    assert next(my_iter) == CmdCheckData(
        ops=EnumCheckOps.ALL_CLEAR, address=0x307900C4, mask=0x00000001
    )
    with pytest.raises(StopIteration):
        next(my_iter)


def test_segDCD_pop_append():
    dcd_seg = SegDCD(0x40)
    dcd_seg.append(CmdCheckData(ops=EnumCheckOps.ALL_CLEAR, address=0x307900C4, mask=0x00000001))
    dcd_seg.append(CmdNop())
    output = dcd_seg.pop(1)
    assert 'Command "No Operation' in output.info()
    output = dcd_seg.pop(0)
    assert 'Command "Check Data' in output.info()


def test_segDCD_clear():
    dcd_seg = SegDCD(0x40)
    dcd_seg.append(CmdCheckData(ops=EnumCheckOps.ALL_CLEAR, address=0x307900C4, mask=0x00000001))
    assert len(dcd_seg) == len(dcd_seg._commands)
    assert dcd_seg._header.length == 16
    assert dcd_seg._header.size == 4
    dcd_seg.clear()
    assert dcd_seg._header.length == 4
    assert dcd_seg._header.size == 4


def test_segDCD_eq():
    dcd_seg = SegDCD()
    segfcb = SegFCB()
    confFlexSpi = FlexSPIConfBlockFCB()
    assert dcd_seg != confFlexSpi
    assert dcd_seg != segfcb
    assert dcd_seg == dcd_seg
