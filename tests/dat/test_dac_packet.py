#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.dat.dac_packet import DebugAuthenticationChallenge
from spsdk.utils.misc import load_binary


def test_dac_packet_export_parse(data_dir):
    value = load_binary(data_dir, 'sample_dac.bin')
    dac = DebugAuthenticationChallenge.parse(value, offset=0)
    exported_dac = dac.export()
    assert exported_dac == value, "Export and parse of DAC packet do not work"


def test_dac_packet_info(data_dir):
    data = load_binary(data_dir, 'sample_dac.bin')
    dac = DebugAuthenticationChallenge.parse(data, offset=0)
    dac_info = dac.info()
    assert '1.0' in dac_info
    assert 'FF00FF00' in dac_info
    assert 'AA55AA55' in dac_info


def test_dac_packet_export_parse_N4A(data_dir):
    value = load_binary(data_dir, 'sample_dac_analog.bin')
    dac = DebugAuthenticationChallenge.parse(value, offset=0)
    exported_dac = dac.export()
    assert exported_dac == value, "Export and parse of DAC packet do not work"
