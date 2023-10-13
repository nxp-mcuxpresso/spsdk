#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

import pytest

from spsdk.image.commands import CmdCheckData, CmdNop, CmdWriteData, EnumCheckOps, EnumWriteOps
from spsdk.image.segments import SegDCD


@pytest.fixture(scope="module")
def ref_dcd_obj():
    # Prepare reference DCD object
    obj = SegDCD(enabled=True)
    obj.append(
        CmdWriteData(
            ops=EnumWriteOps.WRITE_VALUE,
            data=[(0x400FC010, 0x4F400005), (0x400FC010, 0x4F463645), (0x400FC010, 0xA54EF14A)],
        )
    )
    obj.append(
        CmdWriteData(
            ops=EnumWriteOps.WRITE_CLEAR_BITS,
            data=[(0x402F0008, 0x00000001), (0x402F0008, 0x00000002), (0x402F0008, 0x00000003)],
        )
    )
    obj.append(
        CmdWriteData(
            ops=EnumWriteOps.SET_BITMASK,
            data=[(0x400D8158, 0x00000009), (0x400D8158, 0x0000000A), (0x400D8158, 0x000000B4)],
        )
    )
    obj.append(
        CmdCheckData(ops=EnumCheckOps.ALL_CLEAR, address=0x401F83F4, mask=0x000000AF, count=5)
    )
    obj.append(CmdCheckData(ops=EnumCheckOps.ALL_CLEAR, address=0x401F83F4, mask=0x000000A1))
    obj.append(
        CmdCheckData(ops=EnumCheckOps.ANY_CLEAR, address=0x400D8150, mask=0x000000FF, count=3)
    )
    obj.append(CmdCheckData(ops=EnumCheckOps.ANY_CLEAR, address=0x400D8150, mask=0x00000004))
    obj.append(CmdCheckData(ops=EnumCheckOps.ALL_SET, address=0x402F0008, mask=0x00000006))
    obj.append(CmdCheckData(ops=EnumCheckOps.ALL_SET, address=0x402F0008, mask=0x00000AF3, count=2))
    obj.append(CmdCheckData(ops=EnumCheckOps.ANY_SET, address=0x400D8158, mask=0x00000009))
    obj.append(CmdCheckData(ops=EnumCheckOps.ANY_SET, address=0x400D8158, mask=0xB00E60E1))
    obj.append(CmdCheckData(ops=EnumCheckOps.ANY_CLEAR, address=0x400D8158, mask=0x000F00A2))
    obj.append(CmdCheckData(ops=EnumCheckOps.ANY_CLEAR, address=0x400D8158, mask=0xA00F60C1))
    obj.append(CmdWriteData(ops=EnumWriteOps.WRITE_CLEAR_BITS, data=[(0x401F8400, 0x00000001)]))
    obj.append(CmdWriteData(ops=EnumWriteOps.SET_BITMASK, data=[(0x401F8400, 0x00000000)]))
    obj.append(CmdWriteData(ops=EnumWriteOps.WRITE_CLEAR_BITS, data=[(0x401F8400, 0x00000000)]))
    obj.append(CmdWriteData(ops=EnumWriteOps.SET_BITMASK, data=[(0x401F8400, 0x00000001)]))
    obj.append(CmdNop())
    return obj


def test_txt_parser_from_cfg_tools(data_dir, ref_dcd_obj):
    with open(os.path.join(data_dir, "dcd.txt"), "r") as f:
        dcd_data = f.read()
    dcd_obj = SegDCD.parse_txt(dcd_data)
    # compare with reference DCD
    assert dcd_obj == ref_dcd_obj


def test_txt_parser_for_empty_input():
    assert SegDCD.parse_txt("") == SegDCD(enabled=True)


def test_txt_parser_for_invalid_input():
    assert SegDCD.parse_txt("InvalidCmd\\\nNextLine") == SegDCD(
        enabled=True
    )  # test invalid commands are ignored


def test_txt_export_from_cfg_tools(data_dir, ref_dcd_obj):
    with open(os.path.join(data_dir, "dcd.txt"), "r") as f:
        dcd_obj = f.read()
    dcd_bin_exported = SegDCD.export_txt(ref_dcd_obj)
    # compare with reference DCD
    assert dcd_obj == dcd_bin_exported


def test_bin_parser_from_cfg_tools(data_dir, ref_dcd_obj):
    with open(os.path.join(data_dir, "dcd.bin"), "rb") as f:
        dcd_data = f.read()
    dcd_obj = SegDCD.parse(dcd_data)
    # compare with reference DCD
    assert dcd_obj == ref_dcd_obj


def test_bin_export_from_cfg_tools(data_dir, ref_dcd_obj):
    with open(os.path.join(data_dir, "dcd.bin"), "rb") as f:
        dcd_obj = f.read()
    dcd_bin_exported = SegDCD.export(ref_dcd_obj)
    # compare with reference DCD
    assert dcd_obj == dcd_bin_exported
