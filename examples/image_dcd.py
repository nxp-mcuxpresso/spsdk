#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This example shows various ways how to create/parse Device Configuration Data (DCD)."""

from os import mkdir, path
from spsdk.image import SegDCD, CmdWriteData, CmdCheckData, CmdNop, EnumWriteOps, EnumCheckOps

TEMP_DIR = path.join(path.dirname(path.abspath(__file__)), 'temp')


# Example-01: Create DCD object from TXT data
def dcd_from_txt() -> SegDCD:
    """Create DCD from a text (text file)."""
    data = """
        WriteValue    4 0x30340004 0x4F400005
        WriteValue    4 0x30340004 0x4F400005
        WriteValue    4 0x30340004 0x4F400005
        WriteValue    4 0x30340004 0x4F400005
        ClearBitMask  4 0x307900C4 0x00000001
        SetBitMask    4 0x307900C4 0x00000001
        CheckAllClear 4 0x307900C4 0x00000001
        CheckAllClear 4 0x307900C4 0x00000001 5
        CheckAnyClear 4 0x307900C4 0x00000001
        CheckAnyClear 4 0x307900C4 0x00000001 5
        CheckAllSet   4 0x307900C4 0x00000001
        CheckAllSet   4 0x307900C4 0x00000001 5
        CheckAnySet   4 0x307900C4 0x00000001
        CheckAnySet   4 0x307900C4 0x00000001 5
        Nop
    """
    return SegDCD.parse_txt(data)


# Example-02: Create DCD object from BIN data
def dcd_from_bin() -> SegDCD:
    """Create DCD from binary data (from binary file)."""
    data = bytes([
        0xd2, 0x00, 0xb4, 0x41, 0xcc, 0x00, 0x24, 0x04, 0x30, 0x34, 0x00, 0x04, 0x4f, 0x40, 0x00, 0x05,
        0x30, 0x34, 0x00, 0x04, 0x4f, 0x40, 0x00, 0x05, 0x30, 0x34, 0x00, 0x04, 0x4f, 0x40, 0x00, 0x05,
        0x30, 0x34, 0x00, 0x04, 0x4f, 0x40, 0x00, 0x05, 0xcc, 0x00, 0x0c, 0x14, 0x30, 0x79, 0x00, 0xc4,
        0x00, 0x00, 0x00, 0x01, 0xcc, 0x00, 0x0c, 0x1c, 0x30, 0x79, 0x00, 0xc4, 0x00, 0x00, 0x00, 0x01,
        0xcf, 0x00, 0x0c, 0x04, 0x30, 0x79, 0x00, 0xc4, 0x00, 0x00, 0x00, 0x01, 0xcf, 0x00, 0x10, 0x04,
        0x30, 0x79, 0x00, 0xc4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0xcf, 0x00, 0x0c, 0x14,
        0x30, 0x79, 0x00, 0xc4, 0x00, 0x00, 0x00, 0x01, 0xcf, 0x00, 0x10, 0x14, 0x30, 0x79, 0x00, 0xc4,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0xcf, 0x00, 0x0c, 0x0c, 0x30, 0x79, 0x00, 0xc4,
        0x00, 0x00, 0x00, 0x01, 0xcf, 0x00, 0x10, 0x0c, 0x30, 0x79, 0x00, 0xc4, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x05, 0xcf, 0x00, 0x0c, 0x1c, 0x30, 0x79, 0x00, 0xc4, 0x00, 0x00, 0x00, 0x01,
        0xcf, 0x00, 0x10, 0x1c, 0x30, 0x79, 0x00, 0xc4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05,
        0xc0, 0x00, 0x04, 0x00,
    ])
    return SegDCD.parse(data)


# Example-03: DCD object scripted in python
def dcd_in_python() -> SegDCD:
    """Create DCD in python code."""
    dcd = SegDCD(enabled=True)
    dcd.append(CmdWriteData(ops=EnumWriteOps.WRITE_VALUE, data=((0x30340004, 0x4F400005),
                                                                (0x30340004, 0x4F400005),
                                                                (0x30340004, 0x4F400005),
                                                                (0x30340004, 0x4F400005))))
    dcd.append(CmdWriteData(ops=EnumWriteOps.CLEAR_BITMASK, data=((0x307900C4, 0x00000001),)))
    dcd.append(CmdWriteData(ops=EnumWriteOps.SET_BITMASK, data=((0x307900C4, 0x00000001),)))
    dcd.append(CmdCheckData(ops=EnumCheckOps.ALL_CLEAR, address=0x307900C4, mask=0x00000001))
    dcd.append(CmdCheckData(ops=EnumCheckOps.ALL_CLEAR, address=0x307900C4, mask=0x00000001, count=5))
    dcd.append(CmdCheckData(ops=EnumCheckOps.ANY_CLEAR, address=0x307900C4, mask=0x00000001))
    dcd.append(CmdCheckData(ops=EnumCheckOps.ANY_CLEAR, address=0x307900C4, mask=0x00000001, count=5))
    dcd.append(CmdCheckData(ops=EnumCheckOps.ALL_SET, address=0x307900C4, mask=0x00000001))
    dcd.append(CmdCheckData(ops=EnumCheckOps.ALL_SET, address=0x307900C4, mask=0x00000001, count=5))
    dcd.append(CmdCheckData(ops=EnumCheckOps.ANY_SET, address=0x307900C4, mask=0x00000001))
    dcd.append(CmdCheckData(ops=EnumCheckOps.ANY_SET, address=0x307900C4, mask=0x00000001, count=5))
    dcd.append(CmdNop())
    return dcd


def main() -> None:
    """Main function."""
    dcd_01 = dcd_from_txt()
    dcd_02 = dcd_from_bin()
    dcd_03 = dcd_in_python()

    # All DCD objects contain same data, therefore must be same
    print(dcd_01 == dcd_02 == dcd_03)
    print(dcd_01.info())

    # Create temp directory if doesn't exist
    mkdir(TEMP_DIR)

    # Store DCD object into TXT file
    with open(f'{TEMP_DIR}/dcd.txt', 'w') as f_txt:
        f_txt.write(dcd_01.export_txt())

    # Store DCD object into BIN file
    with open(f'{TEMP_DIR}/dcd.bin', 'wb') as f_bin:
        f_bin.write(dcd_01.export())


if __name__ == "__main__":
    main()
