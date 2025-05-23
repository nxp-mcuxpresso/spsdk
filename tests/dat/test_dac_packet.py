#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

from spsdk.dat.dac_packet import DebugAuthenticationChallenge
from spsdk.utils.misc import load_binary
from spsdk.utils.family import FamilyRevision


def test_dac_packet_export_parse(data_dir):
    value = load_binary(os.path.join(data_dir, "sample_dac.bin"))
    family = FamilyRevision("lpc55s69")
    dac = DebugAuthenticationChallenge.parse(value, family)
    exported_dac = dac.export()
    assert exported_dac == value, "Export and parse of DAC packet do not work"


def test_dac_packet_info(data_dir):
    data = load_binary(os.path.join(data_dir, "sample_dac.bin"))
    family = FamilyRevision("lpc55s69")
    dac = DebugAuthenticationChallenge.parse(data, family)
    dac_info = str(dac)
    assert "1.0" in dac_info
    assert "FF00FF00" in dac_info
    assert "AA55AA55" in dac_info


def test_dac_packet_export_parse_Lpc55s3x(data_dir):
    value = load_binary(os.path.join(data_dir, "sample_dac_lpc55s3x.bin"))
    family = FamilyRevision("lpc55s36")
    dac = DebugAuthenticationChallenge.parse(value, family)
    exported_dac = dac.export()
    assert exported_dac == value, "Export and parse of DAC packet do not work"
