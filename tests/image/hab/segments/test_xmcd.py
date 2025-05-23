#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.exceptions import SPSDKValueError
from spsdk.image.hab.segments.seg_xmcd import HabSegmentXMCD
from spsdk.utils.family import FamilyRevision


def test_xmcd_header():
    xmcd_data = b"\x08\x00\x00\xc0\x00\x07\x00\xc0"
    initial_padding = b"\x00" * HabSegmentXMCD.OFFSET
    xmcd = HabSegmentXMCD.parse(initial_padding + xmcd_data, family=FamilyRevision("mimxrt1176"))
    exported = xmcd.export()
    assert exported == xmcd_data
