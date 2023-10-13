#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.segments import SegBDT, SegIVT2


def test_bdt_export_parse():
    bdt = SegBDT()
    assert bdt.app_start == 0
    assert bdt.app_length == 0
    assert bdt.plugin == 0
    assert bdt.padding == 0

    # set nonzero values
    bdt.app_start = 0x8000000
    bdt.app_length = 1024
    bdt.plugin = 1

    data = bdt.export()
    bdt_parsed = SegBDT.parse(data)
    assert bdt == bdt_parsed


def test_bdt_eq_repr():
    bdt = SegBDT()
    bdt_other = SegBDT(0x555)
    ivt2 = SegIVT2(0x41)

    output = repr(bdt)
    repr_strings = ["BDT", "LEN", "Plugin:"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"

    assert bdt != bdt_other
    assert bdt != ivt2


def test_bdt_info():
    bdt = SegBDT()

    # set nonzero values
    bdt.app_start = 0x8000000
    bdt.app_length = 40
    bdt.plugin = 1

    output = str(bdt)
    info_strings = ["Start", "App Length", "Plugin"]
    for info_string in info_strings:
        assert info_string in output, f"string {info_string} is not in the output: {output}"

    bdt1 = SegBDT()
    # set nonzero values
    bdt1.app_start = 0x8000000
    bdt1.app_length = 40777777
    bdt1.plugin = 1

    output = str(bdt1)
    info_strings = ["Start", "App Length", "Plugin"]
    for info_string in info_strings:
        assert info_string in output, f"string {info_string} is not in the output: {output}"


def test_bdt_invalid_plugin():
    bdt = SegBDT()
    with pytest.raises(SPSDKError, match="Plugin value must be 0 .. 2"):
        bdt.plugin = 10
