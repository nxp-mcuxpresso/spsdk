#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import pytest
from spsdk.exceptions import SPSDKError
from spsdk.image.hab.segments.segment import PaddingSegment


def test_base():

    base = PaddingSegment()
    assert base.size == 0


def test_base_invalid_padding_length():
    base_seg = PaddingSegment()
    with pytest.raises(SPSDKError, match="Length of padding must be >= 0"):
        base_seg.padding_len = -1
