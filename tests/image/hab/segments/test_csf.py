#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB CSF segment testing module.

This module contains comprehensive tests for the Command Sequence File (CSF) segment
functionality in SPSDK's High Assurance Boot (HAB) implementation. It validates
CSF segment operations including command management, serialization, and authentication.
"""

import os.path

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.hab.commands.cmd_auth_data import CmdAuthData
from spsdk.image.hab.commands.cmd_check_data import CheckDataOpsEnum, CmdCheckData
from spsdk.image.hab.commands.cmd_write_data import CmdWriteData, WriteDataOpsEnum
from spsdk.image.hab.hab_signature import Signature
from spsdk.image.hab.segments.seg_csf import SegCSF
from spsdk.image.hab.segments.seg_dcd import SegDCD
from spsdk.utils.misc import extend_block


@pytest.fixture(scope="module", name="ref_fast_auth_csf")
def ref_fast_auth_csf_obj(data_dir: str) -> SegCSF:
    """Create reference fast authentication CSF object from binary file.

    Loads and parses a fast authentication Command Sequence File (CSF) binary
    from the specified data directory to create a SegCSF object for testing purposes.

    :param data_dir: Directory path containing the fastauth.csf.bin file
    :raises FileNotFoundError: If the fastauth.csf.bin file is not found in the specified directory
    :raises SPSDKParsingError: If the CSF binary data cannot be parsed
    :return: Parsed CSF segment object containing fast authentication data
    """
    with open(os.path.join(data_dir, "fastauth.csf.bin"), "rb") as csf_bin:
        return SegCSF.parse(csf_bin.read())


def test_SegCSF_eq() -> None:
    """Test that SegCSF instance is not equal to SegDCD instance.

    This test verifies that the equality operator correctly distinguishes
    between different segment types (CSF and DCD segments).
    """
    csf_seg = SegCSF()
    dcd_seg = SegDCD()
    assert csf_seg != dcd_seg


def test_SegCSF_repr_info() -> None:
    """Test CSF segment string representation methods.

    Validates that the SegCSF class properly implements __repr__ and __str__ methods
    to provide meaningful string representations of CSF segments and their commands.
    """
    csf_seg = SegCSF()
    assert "CSF <Commands:" in repr(csf_seg)
    csf_seg.append_command(
        CmdWriteData(ops=WriteDataOpsEnum.WRITE_VALUE, data=[(0x30340004, 0x4F400005)])
    )
    assert "Write Data Command" in str(csf_seg)


def test_SegCSF_append() -> None:
    """Test CSF segment command appending functionality.

    Validates that commands can be successfully appended to a CSF segment
    and that the segment length is correctly updated after each append operation.
    Tests with two different CheckData commands using different operations.
    """
    csf_seg = SegCSF()
    csf_seg.append_command(
        CmdCheckData(ops=CheckDataOpsEnum.ALL_CLEAR, address=0x307900C4, mask=0x00000001)
    )
    assert len(csf_seg) == 1
    csf_seg.append_command(
        CmdCheckData(ops=CheckDataOpsEnum.ANY_SET, address=0x307900C4, mask=0x00000001)
    )
    assert len(csf_seg) == 2


def test_segCSF_clear() -> None:
    """Test CSF segment clear commands functionality.

    Verifies that clearing commands from a CSF segment properly updates the header
    length while maintaining the header size. Tests the append_command and
    clear_commands methods to ensure correct behavior.
    """
    csf_seg = SegCSF(0x40)
    csf_seg.append_command(
        CmdCheckData(ops=CheckDataOpsEnum.ALL_CLEAR, address=0x307900C4, mask=0x00000001)
    )
    assert csf_seg._header.length == 16
    assert csf_seg._header.size == 4
    csf_seg.clear_commands()
    assert csf_seg._header.length == 4
    assert csf_seg._header.size == 4


def test_SegCSF_get_set_iter() -> None:
    """Test SegCSF get, set, and iteration functionality.

    Validates that SegCSF segment supports list-like operations including
    appending commands, accessing items by index, setting items by index,
    and iterating through commands. Tests proper StopIteration behavior
    when iterator is exhausted.
    """
    csf_seg = SegCSF()
    csf_seg.append_command(
        CmdCheckData(ops=CheckDataOpsEnum.ALL_CLEAR, address=0x307900C4, mask=0x00000001)
    )
    csf_seg.append_command(
        CmdCheckData(ops=CheckDataOpsEnum.ANY_SET, address=0x307900C4, mask=0x00000001)
    )
    csf_seg[0] = CmdCheckData(ops=CheckDataOpsEnum.ALL_SET, address=0x307900C4, mask=0x00000001)
    assert csf_seg[0] == CmdCheckData(
        ops=CheckDataOpsEnum.ALL_SET, address=0x307900C4, mask=0x00000001
    )
    my_iter = iter(csf_seg)
    assert next(my_iter) == CmdCheckData(
        ops=CheckDataOpsEnum.ALL_SET, address=0x307900C4, mask=0x00000001
    )
    assert next(my_iter) == CmdCheckData(
        ops=CheckDataOpsEnum.ANY_SET, address=0x307900C4, mask=0x00000001
    )
    with pytest.raises(StopIteration):
        next(my_iter)


def test_SegCSF_fast_auth(ref_fast_auth_csf: SegCSF) -> None:
    "Load parsed Fast Authentication CSF"
    assert ref_fast_auth_csf
    assert len(ref_fast_auth_csf) == 5
    auth_data = ref_fast_auth_csf[4]
    assert isinstance(auth_data, CmdAuthData)
    assert auth_data.key_index == 0
    assert auth_data.engine == 0xFF
    assert auth_data.cmd_data_offset > 0
    assert isinstance(auth_data.cmd_data_reference, Signature)


def test_SegCSF_export_parse() -> None:
    """Test Fast Authentication CSF segment parsing and validation.

    Verifies that a parsed Fast Authentication CSF segment contains the expected
    structure with 5 elements, where the last element is a CmdAuthData command
    with proper authentication parameters and signature reference.

    :param ref_fast_auth_csf: Pre-loaded Fast Authentication CSF segment fixture
    :raises AssertionError: If CSF structure or authentication data validation fails
    """
    obj = SegCSF(enabled=True)
    obj.append_command(
        CmdWriteData(ops=WriteDataOpsEnum.WRITE_VALUE, data=[(0x30340004, 0x4F400005)])
    )

    data = obj.export()
    csf_parsed = SegCSF.parse(data)
    assert data == csf_parsed.export()

    # with padding
    obj.padding_len = 0x10
    assert obj.export() == extend_block(data, obj.size + 0x10)


def test_SegCSF_invalid_append_command() -> None:
    """Test that SegCSF raises an error when appending an invalid command.

    Verifies that the SegCSF segment properly validates command types and raises
    SPSDKError when an invalid command number is provided to append_command method.

    :raises SPSDKError: When invalid command number is provided.
    """
    obj = SegCSF(enabled=True)
    with pytest.raises(SPSDKError, match="Invalid command"):
        obj.append_command(cmd=6)  # type: ignore
