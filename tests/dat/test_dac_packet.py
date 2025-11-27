#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Debug Authentication Challenge packet testing module.

This module contains unit tests for the Debug Authentication Challenge (DAC)
packet functionality, verifying packet creation, parsing, export operations,
and information retrieval across different NXP MCU families.
"""

import os

from spsdk.dat.dac_packet import DebugAuthenticationChallenge
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary


def test_dac_packet_export_parse(data_dir: str) -> None:
    """Test DAC packet export and parse functionality.

    Verifies that a Debug Authentication Challenge packet can be parsed from binary data
    and then exported back to the same binary format, ensuring round-trip consistency.

    :param data_dir: Directory path containing test data files including sample_dac.bin
    :raises AssertionError: When exported DAC packet doesn't match original binary data
    :raises SPSDKError: When DAC packet parsing or export fails
    """
    value = load_binary(os.path.join(data_dir, "sample_dac.bin"))
    family = FamilyRevision("lpc55s69")
    dac = DebugAuthenticationChallenge.parse(value, family)
    exported_dac = dac.export()
    assert exported_dac == value, "Export and parse of DAC packet do not work"


def test_dac_packet_info(data_dir: str) -> None:
    """Test DAC packet information extraction and validation.

    This test verifies that the DebugAuthenticationChallenge can correctly parse
    a sample DAC binary file and extract expected information including version
    and specific hex values.

    :param data_dir: Directory path containing test data files
    :raises AssertionError: If expected values are not found in DAC info string
    """
    data = load_binary(os.path.join(data_dir, "sample_dac.bin"))
    family = FamilyRevision("lpc55s69")
    dac = DebugAuthenticationChallenge.parse(data, family)
    dac_info = str(dac)
    assert "1.0" in dac_info
    assert "FF00FF00" in dac_info
    assert "AA55AA55" in dac_info


def test_dac_packet_export_parse_Lpc55s3x(data_dir: str) -> None:
    """Test DAC packet export and parse functionality for LPC55S3x family.

    Verifies that a Debug Authentication Challenge packet can be parsed from binary data
    and then exported back to the same binary format without data loss.

    :param data_dir: Directory path containing test data files
    :raises AssertionError: When exported DAC packet doesn't match original binary data
    :raises SPSDKError: When DAC packet parsing or export fails
    """
    value = load_binary(os.path.join(data_dir, "sample_dac_lpc55s3x.bin"))
    family = FamilyRevision("lpc55s36")
    dac = DebugAuthenticationChallenge.parse(value, family)
    exported_dac = dac.export()
    assert exported_dac == value, "Export and parse of DAC packet do not work"
