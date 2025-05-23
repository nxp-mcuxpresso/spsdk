#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.exceptions import SPSDKError, SPSDKVerificationError
from spsdk.image.hab.segments.seg_ivt import SegIVT


def test_ivt_segment_api():
    ivt = SegIVT(0x41)
    assert ivt.version == 0x41
    assert ivt.ivt_address == 0
    assert ivt.bdt_address == 0
    assert ivt.dcd_address == 0
    assert ivt.app_address == 0
    assert ivt.csf_address == 0

    with pytest.raises(SPSDKError):
        _ = ivt.export()

    # set correct values
    ivt.ivt_address = 0x877FF400
    ivt.bdt_address = 0x877FF420
    ivt.dcd_address = 0x877FF42C
    ivt.app_address = 0x87800000
    ivt.csf_address = 0

    ivt.version = 0x44
    assert ivt._header.param == 0x44


def test_ivt_validate():
    ivt = SegIVT(0x41)
    # set incorrect values
    ivt.ivt_address = 0x877FF42C
    ivt.dcd_address = 0x877FF400
    ivt.bdt_address = 0x877FF42E
    with pytest.raises(SPSDKVerificationError):
        ivt.verify().validate()

    ivt.csf_address = 0x877FF000
    ivt.dcd_address = 0x877FF500
    with pytest.raises(SPSDKVerificationError):
        ivt.verify().validate()

    ivt.padding = 1
    ivt.csf_address = 0x877FF600
    with pytest.raises(SPSDKVerificationError):
        ivt.verify().validate()


def test_ivt_export_parse():
    ivt = SegIVT(0x41)
    ivt.ivt_address = 0x877FF400
    ivt.bdt_address = 0x877FF420
    ivt.dcd_address = 0x877FF42C
    ivt.app_address = 0x87800000
    ivt.csf_address = 0

    data = ivt.export()
    ivt_parsed = SegIVT.parse(data)
    assert ivt == ivt_parsed

    # with padding
    data = ivt.export()
    ivt_parsed = SegIVT.parse(data)
    assert ivt == ivt_parsed


def test_ivt_repr():
    ivt = SegIVT(0x41)
    output = repr(ivt)
    repr_strings = ["BDT", "IVT", "DCD", "APP", "CSF"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_ivt_invalid_version():
    ivt = SegIVT(0x41)
    with pytest.raises(SPSDKError, match="Invalid version of IVT and image format"):
        ivt.version = 0x39


def test_format_ivt_item():
    assert SegIVT._format_ivt_item(0x123) == "0x00000123"
    assert SegIVT._format_ivt_item(0xABCDEF) == "0x00abcdef"
    assert SegIVT._format_ivt_item(0) == "none"
    assert SegIVT._format_ivt_item(0x10, 2) == "0x10"
    assert SegIVT._format_ivt_item(0x12, 3) == "0x012"
