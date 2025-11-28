#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK HAB XMCD segment testing module.

This module contains unit tests for the HAB (High Assurance Boot) XMCD
(External Memory Configuration Data) segment functionality in SPSDK.
"""

from spsdk.image.hab.segments.seg_xmcd import HabSegmentXMCD
from spsdk.utils.family import FamilyRevision


def test_xmcd_header() -> None:
    """Test XMCD header parsing and export functionality.

    Verifies that HabSegmentXMCD can correctly parse XMCD data with initial padding
    and export it back to the original format. The test uses sample XMCD data for
    the MIMXRT1176 family and ensures round-trip consistency.
    """
    xmcd_data = b"\x08\x00\x00\xc0\x00\x07\x00\xc0"
    initial_padding = b"\x00" * HabSegmentXMCD.OFFSET
    xmcd = HabSegmentXMCD.parse(initial_padding + xmcd_data, family=FamilyRevision("mimxrt1176"))
    exported = xmcd.export()
    assert exported == xmcd_data
