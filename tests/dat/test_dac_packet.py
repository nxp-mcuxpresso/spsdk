#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

from spsdk.dat.dac_packet import DebugAuthenticationChallenge
from spsdk.utils.misc import load_binary


def test_dac_packet_export_parse(data_dir):
    value = load_binary(os.path.join(data_dir, "sample_dac.bin"))
    dac = DebugAuthenticationChallenge.parse(value)
    exported_dac = dac.export()
    assert exported_dac == value, "Export and parse of DAC packet do not work"


def test_dac_packet_info(data_dir):
    data = load_binary(os.path.join(data_dir, "sample_dac.bin"))
    dac = DebugAuthenticationChallenge.parse(data)
    dac_info = str(dac)
    assert "1.0" in dac_info
    assert "FF00FF00" in dac_info
    assert "AA55AA55" in dac_info


def test_dac_packet_export_parse_Lpc55s3x(data_dir):
    value = load_binary(os.path.join(data_dir, "sample_dac_lpc55s3x.bin"))
    dac = DebugAuthenticationChallenge.parse(value)
    exported_dac = dac.export()
    assert exported_dac == value, "Export and parse of DAC packet do not work"
