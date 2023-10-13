#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import io

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.misc import NotEnoughBytesException, read_raw_data


def test_read_raw_segment():
    stream = io.BytesIO()
    with pytest.raises(SPSDKError):
        read_raw_data(stream, length=0, index=-1)
    with pytest.raises(SPSDKError):
        read_raw_data(stream, length=-1, index=1)
    with pytest.raises(NotEnoughBytesException):
        read_raw_data(stream, length=1, index=1)
