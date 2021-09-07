#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk import SPSDKError
from spsdk.image.segments import BaseSegment


def test_base_exceptions():
    from spsdk.image.segments import BaseSegment

    base = BaseSegment()
    with pytest.raises(NotImplementedError):
        base.info()
    with pytest.raises(NotImplementedError):
        base.export()
    with pytest.raises(NotImplementedError):
        base.parse(None)


def test_base():
    from spsdk.image.segments import BaseSegment

    base = BaseSegment()
    assert base.size == 0


def test_base_invalid_padding_length():
    base_seg = BaseSegment()
    with pytest.raises(SPSDKError, match="Length of padding must be >= 0"):
        base_seg.padding_len = -1
