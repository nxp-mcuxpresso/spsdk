#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK test module for raw data reading functionality.

This module contains unit tests for the read_raw_data function from the
spsdk.image.misc module, verifying proper handling of binary data reading
and exception scenarios.
"""

import io

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.exceptions import SPSDKNotEnoughBytesException
from spsdk.image.misc import read_raw_data


def test_read_raw_segment() -> None:
    """Test reading raw data segment with invalid parameters.

    Validates that the read_raw_data function properly handles error conditions
    including negative index, negative length, and insufficient data in stream.

    :raises SPSDKError: When index or length parameters are invalid.
    :raises SPSDKNotEnoughBytesException: When stream doesn't contain enough bytes.
    """
    stream = io.BytesIO()
    with pytest.raises(SPSDKError):
        read_raw_data(stream, length=0, index=-1)
    with pytest.raises(SPSDKError):
        read_raw_data(stream, length=-1, index=1)
    with pytest.raises(SPSDKNotEnoughBytesException):
        read_raw_data(stream, length=1, index=1)
