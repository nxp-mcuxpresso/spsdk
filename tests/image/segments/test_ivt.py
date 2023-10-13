#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.segments import SegAPP, SegIVT2, SegIVT3a, SegIVT3b, _format_ivt_item


def test_ivt2_segment_api():
    ivt2 = SegIVT2(0x41)
    assert ivt2.version == 0x41
    assert ivt2.ivt_address == 0
    assert ivt2.bdt_address == 0
    assert ivt2.dcd_address == 0
    assert ivt2.app_address == 0
    assert ivt2.csf_address == 0

    with pytest.raises(SPSDKError):
        _ = ivt2.export()

    # set correct values
    ivt2.ivt_address = 0x877FF400
    ivt2.bdt_address = 0x877FF420
    ivt2.dcd_address = 0x877FF42C
    ivt2.app_address = 0x87800000
    ivt2.csf_address = 0

    ivt2.version = 0x44
    assert ivt2._header.param == 0x44


def test_ivt2_validate():
    ivt2 = SegIVT2(0x41)
    # set incorrect values
    ivt2.ivt_address = 0x877FF42C
    ivt2.dcd_address = 0x877FF400
    ivt2.bdt_address = 0x877FF42E
    with pytest.raises(SPSDKError):
        ivt2.validate()

    ivt2.csf_address = 0x877FF000
    ivt2.dcd_address = 0x877FF500
    with pytest.raises(SPSDKError):
        ivt2.validate()

    ivt2.padding = 1
    ivt2.csf_address = 0x877FF600
    with pytest.raises(SPSDKError):
        ivt2.validate()


def test_ivt2_export_parse():
    ivt2 = SegIVT2(0x41)
    ivt2.ivt_address = 0x877FF400
    ivt2.bdt_address = 0x877FF420
    ivt2.dcd_address = 0x877FF42C
    ivt2.app_address = 0x87800000
    ivt2.csf_address = 0

    data = ivt2.export()
    ivt2_parsed = SegIVT2.parse(data)
    assert ivt2 == ivt2_parsed

    # with padding
    data = ivt2.export()
    ivt2_parsed = SegIVT2.parse(data)
    assert ivt2 == ivt2_parsed


def test_ivt2_repr():
    ivt2 = SegIVT2(0x41)
    output = repr(ivt2)
    repr_strings = ["BDT", "IVT2", "DCD", "APP", "CSF"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_ivt2_equality():
    ivt2 = SegIVT2(0x41)
    ivt2_other = SegIVT2(0x40)
    ivt3a = SegIVT3a(0x41)
    assert ivt2 != ivt3a
    assert ivt2 != ivt2_other


def test_ivt2_invalid_version():
    ivt2 = SegIVT2(0x41)
    with pytest.raises(SPSDKError, match="Invalid version of IVT and image format"):
        ivt2.version = 0x39


def test_ivt3a_segment_api():
    ivt3a = SegIVT3a(0)
    assert ivt3a.version == 0
    assert ivt3a.ivt_address == 0
    assert ivt3a.bdt_address == 0
    assert ivt3a.dcd_address == 0
    assert ivt3a.csf_address == 0

    with pytest.raises(SPSDKError):
        _ = ivt3a.export()

    # set correct values
    ivt3a.ivt_address = 0x800400
    ivt3a.bdt_address = 0x800480
    ivt3a.dcd_address = 0x800660
    ivt3a.csf_address = 0


def test_ivt3a_validate():
    ivt3a = SegIVT3a(0)
    ivt3a.ivt_address = 0x800480
    ivt3a.dcd_address = 0x800400
    ivt3a.bdt_address = 0x800980
    with pytest.raises(SPSDKError):
        ivt3a.validate()
    ivt3a.dcd_address = 0x800500
    ivt3a.csf_address = 0x800200
    with pytest.raises(SPSDKError):
        ivt3a.validate()


def test_ivt3a_export_parse():
    ivt3a = SegIVT3a(0)
    # set correct values
    ivt3a.ivt_address = 0x800400
    ivt3a.bdt_address = 0x800480
    ivt3a.dcd_address = 0x800660
    ivt3a.csf_address = 0
    data = ivt3a.export()
    ivt3a_parsed = SegIVT3a.parse(data)
    assert ivt3a == ivt3a_parsed

    # with padding
    data = ivt3a.export()
    ivt3a_parsed = SegIVT3a.parse(data)
    assert ivt3a == ivt3a_parsed


def test_ivt3a_repr():
    ivt3a = SegIVT3a(0)
    output = repr(ivt3a)
    repr_strings = ["IVT3a", "BDT", "DCD", "CSF"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_ivt3a_eq():
    ivt3a = SegIVT3a(0)
    ivt3a_other = SegIVT3a(1)
    app = SegAPP()
    assert ivt3a != app
    assert ivt3a != ivt3a_other


def test_ivt3a_info():
    ivt3a = SegIVT3a(0)
    output = str(ivt3a)
    repr_strings = ["Format version", "IVT", "BDT", "DCD", "CSF", "NEXT"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_ivt3b_segment_api():
    ivt3b = SegIVT3b(0)
    assert ivt3b.ivt_address == 0
    assert ivt3b.bdt_address == 0
    assert ivt3b.dcd_address == 0
    assert ivt3b.scd_address == 0
    assert ivt3b.csf_address == 0

    with pytest.raises(SPSDKError):
        _ = ivt3b.export()

    # set correct values
    ivt3b.ivt_address = 0x2000E400
    ivt3b.bdt_address = 0x2000E480
    ivt3b.dcd_address = 0x2000E660
    ivt3b.scd_address = 0
    ivt3b.csf_address = 0


def test_ivt3b_validate():
    ivt3b = SegIVT3b(0)
    ivt3b.ivt_address = 0x2000E660
    ivt3b.dcd_address = 0x2000E000
    ivt3b.bdt_address = 0x2000E690
    ivt3b.dcd_address = 0x2000E659
    with pytest.raises(SPSDKError):
        ivt3b.validate()

    ivt3b.dcd_address = 0x2000E665
    ivt3b.csf_address = 0x2000E050
    with pytest.raises(SPSDKError):
        ivt3b.validate()

    ivt3b.csf_address = 0x2000E669
    ivt3b.scd_address = 0x2000E600
    with pytest.raises(SPSDKError):
        ivt3b.validate()


def test_ivt3b_export_parse():
    ivt3b = SegIVT3b(0)
    # set correct values
    ivt3b.ivt_address = 0x2000E400
    ivt3b.bdt_address = 0x2000E480
    ivt3b.dcd_address = 0x2000E660
    ivt3b.scd_address = 0
    ivt3b.csf_address = 0
    data = ivt3b.export()
    ivt3b_parsed = SegIVT3b.parse(data)
    assert ivt3b == ivt3b_parsed
    # with padding
    data = ivt3b.export()
    ivt3b_parsed = SegIVT3b.parse(data)
    assert ivt3b == ivt3b_parsed


def test_ivt3b_repr():
    ivt3b = SegIVT3b(0)
    output = repr(ivt3b)
    repr_strings = ["IVT3b", "BDT", "DCD", "CSF", "SCD"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_ivt3b_info():
    ivt3b = SegIVT3b(0)
    output = str(ivt3b)
    repr_strings = ["IVT", "BDT", "DCD", "CSF", "SCD"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_format_ivt_item():
    assert _format_ivt_item(0x123) == "0x00000123"
    assert _format_ivt_item(0xABCDEF) == "0x00abcdef"
    assert _format_ivt_item(0) == "none"
    assert _format_ivt_item(0x10, 2) == "0x10"
    assert _format_ivt_item(0x12, 3) == "0x012"
