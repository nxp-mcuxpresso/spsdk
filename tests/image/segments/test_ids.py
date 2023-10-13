#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.image.segments import SegIDS3a, SegIDS3b


def test_SegIDS3a_repr():
    ids3a_seg = SegIDS3a()
    output = repr(ids3a_seg)
    repr_strings = ["IDS3a", "OUT", "ENTRY", "SIZE", "HAB", "SCFW", "ROM"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_SegIDS3a_info():
    ids3a_seg = SegIDS3a()
    info_msg = str(ids3a_seg)
    repr_strings = ["Source", "Dest", "Entry", "Size", "SCFW", "HAB", "ROM", "<Flags>"]
    for req_string in repr_strings:
        assert req_string in info_msg, f"string {req_string} is not in the output: {info_msg}"


def test_SegIDS3a_export_parse():
    ids3a_seg = SegIDS3a()
    data = ids3a_seg.export()
    ids3_parsed = SegIDS3a.parse(data)
    assert ids3a_seg == ids3_parsed

    # with padding
    data = ids3a_seg.export()
    ids3_parsed = SegIDS3a.parse(data)
    assert ids3a_seg == ids3_parsed


def test_SegIDS3b_repr():
    ids3b_seg = SegIDS3b()
    output = repr(ids3b_seg)
    repr_strings = ["IDS3b", "IN", "OUT", "ENTRY", "SIZE", "FLAGS"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_SegIDS3b_export_parse():
    ids3b_seg = SegIDS3b()
    data = ids3b_seg.export()
    ids3_parsed = SegIDS3b.parse(data)
    assert ids3b_seg == ids3_parsed

    # with padding
    data = ids3b_seg.export()
    ids3_parsed = SegIDS3b.parse(data)
    assert ids3b_seg == ids3_parsed
