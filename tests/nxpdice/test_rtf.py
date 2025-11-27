#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK RTF calculator testing module.

This module contains unit tests for the RTF (Runtime Firmware) calculator
functionality in SPSDK DICE implementation. It validates the RTF calculation
process across different NXP MCU families and configurations.
"""

import pytest

from spsdk.dice.rtf import calculate_rtf
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary


@pytest.mark.parametrize(
    "file, family, expected_rtf",
    [
        (
            "mbi_4key_no-isk.bin",
            "mcxn9xx",
            "72c6371b2f827a986ca20789c708f2f11639342315f8fc93ae8150044bcdce01",
        )
    ],
)
def test_rtf(data_dir: str, file: str, family: str, expected_rtf: str) -> None:
    """Test RTF calculation for a given MBI file and family.

    This test function loads a binary MBI file, calculates the RTF (Root of Trust Fingerprint)
    for the specified family, and verifies it matches the expected RTF value.

    :param data_dir: Directory path containing the test data files.
    :param file: Name of the MBI binary file to test.
    :param family: Target MCU family identifier for RTF calculation.
    :param expected_rtf: Expected RTF value as hexadecimal string for comparison.
    """
    mbi_data = load_binary(f"{data_dir}/{file}")

    rtf = calculate_rtf(family=FamilyRevision(family), mbi_data=mbi_data)
    assert rtf == bytes.fromhex(expected_rtf)
