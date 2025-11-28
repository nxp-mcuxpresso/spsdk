#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB CSF API testing module.

This module contains unit tests for the HAB (High Assurance Boot) CSF (Command Sequence File)
API functionality, including parsing and validation of CSF segments and commands.
"""

import pytest

from spsdk.image.hab.commands.cmd_check_data import CheckDataOpsEnum, CmdCheckData
from spsdk.image.hab.commands.cmd_write_data import CmdWriteData, WriteDataOpsEnum
from spsdk.image.hab.segments.seg_csf import SegCSF


@pytest.fixture(scope="module")
def ref_csf_obj() -> SegCSF:
    """Create reference CSF segment object for testing.

    Creates a SegCSF object with predefined commands including WriteData and CheckData
    operations that can be used as a reference in test scenarios.

    :return: Configured CSF segment object with sample commands.
    """
    # Prepare reference CSF object
    obj = SegCSF(enabled=True)
    obj.append_command(
        CmdWriteData(ops=WriteDataOpsEnum.WRITE_VALUE, data=((0x30340004, 0x4F400005),))
    )
    obj.append_command(
        CmdCheckData(ops=CheckDataOpsEnum.ALL_CLEAR, address=0x307900C4, mask=0x00000001, count=10)
    )
    return obj


@pytest.mark.skip
def test_txt_parser() -> None:
    """Test the TXT parser functionality.

    This test verifies that the TXT parser correctly processes and parses
    text-based configuration files for CSF (Command Sequence File) operations.
    """
    pass


@pytest.mark.skip
def test_bin_parser() -> None:
    """Test binary parser functionality.

    This test method validates the binary parser implementation for CSF (Command Sequence File)
    processing in the HAB (High Assurance Boot) image segments.
    """
    pass
