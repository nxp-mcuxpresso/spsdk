#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.image import CmdCheckData, CmdWriteData, EnumWriteOps
from spsdk.image import SegCSF, EnumCheckOps
from spsdk.image.segments import SegDCD
from spsdk.utils.misc import extend_block


def test_SegCSF_eq():
    csf_seg = SegCSF()
    dcd_seg = SegDCD()
    assert csf_seg != dcd_seg


def test_SegCSF_repr_info():
    csf_seg = SegCSF()
    assert "CSF <Commands:" in repr(csf_seg)
    csf_seg.append_command(CmdWriteData(ops=EnumWriteOps.WRITE_VALUE, data=[(0x30340004, 0x4F400005)]))
    assert "Write Data Command" in csf_seg.info()


def test_SegCSF_append():
    csf_seg = SegCSF()
    csf_seg.append_command(CmdCheckData(ops=EnumCheckOps.ALL_CLEAR, address=0x307900C4, mask=0x00000001))
    assert len(csf_seg) == 1
    csf_seg.append_command(CmdCheckData(ops=EnumCheckOps.ANY_SET, address=0x307900C4, mask=0x00000001))
    assert len(csf_seg) == 2


def test_segCSF_clear():
    csf_seg = SegCSF(0x40)
    csf_seg.append_command(CmdCheckData(ops=EnumCheckOps.ALL_CLEAR, address=0x307900C4, mask=0x00000001))
    assert csf_seg._header.length == 16
    assert csf_seg._header.size == 4
    csf_seg.clear_commands()
    assert csf_seg._header.length == 4
    assert csf_seg._header.size == 4


def test_SegCSF_get_set_iter():
    csf_seg = SegCSF()
    csf_seg.append_command(CmdCheckData(ops=EnumCheckOps.ALL_CLEAR, address=0x307900C4, mask=0x00000001))
    csf_seg.append_command(CmdCheckData(ops=EnumCheckOps.ANY_SET, address=0x307900C4, mask=0x00000001))
    csf_seg[0] = CmdCheckData(ops=EnumCheckOps.ALL_SET, address=0x307900C4, mask=0x00000001)
    assert csf_seg[0] == CmdCheckData(ops=EnumCheckOps.ALL_SET, address=0x307900C4, mask=0x00000001)
    my_iter = iter(csf_seg)
    assert next(my_iter) == CmdCheckData(ops=EnumCheckOps.ALL_SET, address=0x307900C4, mask=0x00000001)
    assert next(my_iter) == CmdCheckData(ops=EnumCheckOps.ANY_SET, address=0x307900C4, mask=0x00000001)
    with pytest.raises(StopIteration):
        next(my_iter)


def test_SegCSF_export_parse():
    obj = SegCSF(enabled=True)
    obj.append_command(CmdWriteData(ops=EnumWriteOps.WRITE_VALUE, data=[(0x30340004, 0x4F400005)]))

    data = obj.export()
    csf_parsed = SegCSF.parse(data)
    assert data == csf_parsed.export()

    # with padding
    obj.padding_len = 0x10
    assert obj.export() == extend_block(data, obj.size + 0x10)
