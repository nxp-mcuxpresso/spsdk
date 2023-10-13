#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.image.segments import SegBDS3a, SegBDS3b


def test_SegBDSa_repr():
    bds3a = SegBDS3a()
    output = repr(bds3a)
    repr_strings = ["BDS3a ", "IMAGES", "SIZE", "FLAG"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_SegBDSa_info():
    bds3a = SegBDS3a()
    bds3a.images_count = 2
    info_msg = str(bds3a)
    repr_strings = ["IMAGES", "DFLAGS", "IMAGE"]
    for req_string in repr_strings:
        assert req_string in info_msg, f"string {req_string} is not in the output: {info_msg}"


def test_SegBDSa_export_parse():
    bds3a = SegBDS3a()
    data = bds3a.export()
    bds3a_parsed = SegBDS3a.parse(data)
    assert bds3a == bds3a_parsed

    # with padding
    data = bds3a.export()
    bds3a_parsed = SegBDS3a.parse(data)
    assert bds3a == bds3a_parsed


def test_SegBDSb_repr():
    bds3b = SegBDS3b()
    output = repr(bds3b)
    repr_strings = ["BDS3b", "IMAGES", "SIZE", "FLAG"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_SegBDSb_info():
    bds3b = SegBDS3b()
    info_msg = str(bds3b)
    repr_strings = ["IMAGES", "DFLAGS", "IMAGE"]
    for req_string in repr_strings:
        assert req_string in info_msg, f"string {req_string} is not in the output: {info_msg}"

    bds3b.scd.image_source = 0x400FC010
    bds3b.csf.image_source = 0x400FC010
    info_msg = str(bds3b)
    repr_strings = ["SCD", "CSF"]
    for req_string in repr_strings:
        assert req_string in info_msg, f"string {req_string} is not in the output: {info_msg}"


def test_SegBDS3b_export_parse():
    bds3b = SegBDS3b()
    data = bds3b.export()
    bds3b_parsed = SegBDS3b.parse(data)
    assert bds3b == bds3b_parsed

    # with padding
    data = bds3b.export()
    bds3b_parsed = SegBDS3b.parse(data)
    assert bds3b == bds3b_parsed
