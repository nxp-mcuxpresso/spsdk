#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB DCD API test module.

This module contains unit tests for the Device Configuration Data (DCD) API
functionality in the High Assurance Boot (HAB) image processing components.
Tests cover text and binary parsing, export operations, and validation of
DCD configuration tools integration.
"""

import os

import pytest

from spsdk.image.hab.commands.cmd_check_data import CheckDataOpsEnum, CmdCheckData
from spsdk.image.hab.commands.cmd_nop import CmdNop
from spsdk.image.hab.commands.cmd_write_data import CmdWriteData, WriteDataOpsEnum
from spsdk.image.hab.segments.seg_dcd import SegDCD


@pytest.fixture(scope="module")
def ref_dcd_obj() -> SegDCD:
    """Create reference DCD segment object for testing.

    Creates a SegDCD object populated with various DCD commands including write data
    operations (write value, clear bits, set bitmask), check data operations with
    different conditions (all clear, any clear, all set, any set), and a NOP command.
    This reference object is used for testing DCD functionality across different
    scenarios.

    :return: Configured SegDCD object with sample commands for testing.
    """
    # Prepare reference DCD object
    obj = SegDCD(enabled=True)
    obj.append(
        CmdWriteData(
            ops=WriteDataOpsEnum.WRITE_VALUE,
            data=[(0x400FC010, 0x4F400005), (0x400FC010, 0x4F463645), (0x400FC010, 0xA54EF14A)],
        )
    )
    obj.append(
        CmdWriteData(
            ops=WriteDataOpsEnum.WRITE_CLEAR_BITS,
            data=[(0x402F0008, 0x00000001), (0x402F0008, 0x00000002), (0x402F0008, 0x00000003)],
        )
    )
    obj.append(
        CmdWriteData(
            ops=WriteDataOpsEnum.SET_BITMASK,
            data=[(0x400D8158, 0x00000009), (0x400D8158, 0x0000000A), (0x400D8158, 0x000000B4)],
        )
    )
    obj.append(
        CmdCheckData(ops=CheckDataOpsEnum.ALL_CLEAR, address=0x401F83F4, mask=0x000000AF, count=5)
    )
    obj.append(CmdCheckData(ops=CheckDataOpsEnum.ALL_CLEAR, address=0x401F83F4, mask=0x000000A1))
    obj.append(
        CmdCheckData(ops=CheckDataOpsEnum.ANY_CLEAR, address=0x400D8150, mask=0x000000FF, count=3)
    )
    obj.append(CmdCheckData(ops=CheckDataOpsEnum.ANY_CLEAR, address=0x400D8150, mask=0x00000004))
    obj.append(CmdCheckData(ops=CheckDataOpsEnum.ALL_SET, address=0x402F0008, mask=0x00000006))
    obj.append(
        CmdCheckData(ops=CheckDataOpsEnum.ALL_SET, address=0x402F0008, mask=0x00000AF3, count=2)
    )
    obj.append(CmdCheckData(ops=CheckDataOpsEnum.ANY_SET, address=0x400D8158, mask=0x00000009))
    obj.append(CmdCheckData(ops=CheckDataOpsEnum.ANY_SET, address=0x400D8158, mask=0xB00E60E1))
    obj.append(CmdCheckData(ops=CheckDataOpsEnum.ANY_CLEAR, address=0x400D8158, mask=0x000F00A2))
    obj.append(CmdCheckData(ops=CheckDataOpsEnum.ANY_CLEAR, address=0x400D8158, mask=0xA00F60C1))
    obj.append(CmdWriteData(ops=WriteDataOpsEnum.WRITE_CLEAR_BITS, data=[(0x401F8400, 0x00000001)]))
    obj.append(CmdWriteData(ops=WriteDataOpsEnum.SET_BITMASK, data=[(0x401F8400, 0x00000000)]))
    obj.append(CmdWriteData(ops=WriteDataOpsEnum.WRITE_CLEAR_BITS, data=[(0x401F8400, 0x00000000)]))
    obj.append(CmdWriteData(ops=WriteDataOpsEnum.SET_BITMASK, data=[(0x401F8400, 0x00000001)]))
    obj.append(CmdNop())
    return obj


def test_txt_parser_from_cfg_tools(data_dir: str, ref_dcd_obj: SegDCD) -> None:
    """Test TXT parser functionality using configuration tools format.

    This test verifies that the SegDCD.parse_txt method can correctly parse
    DCD data from a text file in the format used by configuration tools,
    and that the resulting object matches the expected reference DCD object.

    :param data_dir: Directory path containing the test data files
    :param ref_dcd_obj: Reference SegDCD object to compare against
    """
    with open(os.path.join(data_dir, "dcd.txt"), "r") as f:
        dcd_data = f.read()
    dcd_obj = SegDCD.parse_txt(dcd_data)
    # compare with reference DCD
    assert dcd_obj == ref_dcd_obj


def test_txt_parser_for_empty_input() -> None:
    """Test that DCD segment parser correctly handles empty string input.

    Verifies that parsing an empty string returns a DCD segment with default
    enabled state set to True.
    """
    assert SegDCD.parse_txt("") == SegDCD(enabled=True)


def test_txt_parser_for_invalid_input() -> None:
    """Test that invalid commands in text input are properly ignored.

    Verifies that the SegDCD.parse_txt method correctly handles invalid command
    syntax by ignoring unrecognized commands and returning a default SegDCD
    instance with enabled=True.
    """
    assert SegDCD.parse_txt("InvalidCmd\\\nNextLine") == SegDCD(
        enabled=True
    )  # test invalid commands are ignored


def test_txt_export_from_cfg_tools(data_dir: str, ref_dcd_obj: SegDCD) -> None:
    """Test TXT export functionality from configuration tools.

    Verifies that the TXT export from a reference DCD object matches
    the expected output by comparing it with a reference DCD text file
    from the configuration tools.

    :param data_dir: Directory path containing test data files
    :param ref_dcd_obj: Reference DCD segment object to export
    :raises AssertionError: When exported TXT doesn't match reference file
    :raises FileNotFoundError: When reference DCD text file is not found
    :raises OSError: When file operations fail
    """
    with open(os.path.join(data_dir, "dcd.txt"), "r") as f:
        dcd_obj = f.read()
    dcd_bin_exported = SegDCD.export_txt(ref_dcd_obj)
    # compare with reference DCD
    assert dcd_obj == dcd_bin_exported


def test_bin_parser_from_cfg_tools(data_dir: str, ref_dcd_obj: SegDCD) -> None:
    """Test binary parser functionality using configuration tools data.

    This test verifies that the SegDCD.parse() method correctly parses a binary DCD file
    and produces an object that matches the reference DCD object created from configuration.

    :param data_dir: Directory path containing test data files including dcd.bin
    :param ref_dcd_obj: Reference SegDCD object to compare against parsed result
    """
    with open(os.path.join(data_dir, "dcd.bin"), "rb") as f:
        dcd_data = f.read()
    dcd_obj = SegDCD.parse(dcd_data)
    # compare with reference DCD
    assert dcd_obj == ref_dcd_obj


def test_bin_export_from_cfg_tools(data_dir: str, ref_dcd_obj: SegDCD) -> None:
    """Test binary export functionality from configuration tools.

    This test verifies that the SegDCD.export() method produces binary output
    that matches the reference DCD binary file generated by configuration tools.

    :param data_dir: Directory path containing test data files including reference dcd.bin
    :param ref_dcd_obj: Reference SegDCD object to be exported and compared
    """
    with open(os.path.join(data_dir, "dcd.bin"), "rb") as f:
        dcd_obj = f.read()
    dcd_bin_exported = SegDCD.export(ref_dcd_obj)
    # compare with reference DCD
    assert dcd_obj == dcd_bin_exported
