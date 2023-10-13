#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.image.segments import SegAPP, SegBDT


def test_app_segment_api():
    app = SegAPP()
    assert app.size == 0
    assert app.padding == 0

    data = bytes([10] * 10)
    app.data = data
    assert app.size == len(data)

    data_exported = app.export()
    assert data == data_exported

    app.padding = 10
    data_exported = app.export()
    assert len(data_exported) == 20

    app.data = b"\x01\x02\x03\x04\x05"
    assert app._data == b"\x01\x02\x03\x04\x05"


def test_app_export():
    app = SegAPP()
    data = bytes([10] * 10)
    app.data = data

    data_exported = app.export()
    assert data == data_exported

    app.padding = 10
    data_exported = app.export()
    assert len(data_exported) == 20


def test_app_eq_info_repr():
    app = SegAPP()
    app_other = SegAPP(data=bytes([10] * 10))
    bdt = SegBDT()
    assert app != app_other
    assert app != bdt
    assert app == app

    assert "Size" in str(app_other)

    output = repr(app_other)
    repr_strings = ["Bytes", "LEN", "APP"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"
