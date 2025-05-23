#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import io

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.exceptions import SPSDKNotEnoughBytesException
from spsdk.image.misc import read_raw_data


def test_read_raw_segment():
    stream = io.BytesIO()
    with pytest.raises(SPSDKError):
        read_raw_data(stream, length=0, index=-1)
    with pytest.raises(SPSDKError):
        read_raw_data(stream, length=-1, index=1)
    with pytest.raises(SPSDKNotEnoughBytesException):
        read_raw_data(stream, length=1, index=1)
