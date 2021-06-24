#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import io
import pytest
from spsdk.image.misc import read_raw_data, NotEnoughBytesException


def test_read_raw_segment():
    stream = io.BytesIO()
    with pytest.raises(ValueError):
        read_raw_data(stream, length=0, index=-1)
    with pytest.raises(ValueError):
        read_raw_data(stream, length=-1, index=1)
    with pytest.raises(NotEnoughBytesException):
        read_raw_data(stream, length=1, index=1)
