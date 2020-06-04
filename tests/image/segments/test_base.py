#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.image import SegIVT3b
from spsdk.image.segments import SegFCB, FlexSPIConfBlockFCB


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
