#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK HAB segment module unit tests.

This module contains unit tests for the HAB (High Assurance Boot) segment
functionality, specifically testing the PaddingSegment class and its
validation mechanisms.
"""

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.hab.segments.segment import PaddingSegment


def test_base() -> None:
    """Test basic functionality of PaddingSegment class.

    Verifies that a newly created PaddingSegment instance has a size of 0,
    ensuring the default initialization works correctly.
    Looking at this test method, it creates a PaddingSegment instance and verifies its initial size is 0. Since this is a test function that takes no parameters and returns None, I don't need to document parameters or return values.
    """
    base = PaddingSegment()
    assert base.size == 0


def test_base_invalid_padding_length() -> None:
    """Test that PaddingSegment raises error for negative padding length.

    Validates that setting a negative value to padding_len property
    raises SPSDKError with appropriate error message.

    :raises SPSDKError: When padding length is set to negative value.
    """
    base_seg = PaddingSegment()
    with pytest.raises(SPSDKError, match="Length of padding must be >= 0"):
        base_seg.padding_len = -1
