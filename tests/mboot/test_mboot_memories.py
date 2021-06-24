#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest
from spsdk.image.misc import size_fmt
from spsdk.mboot.memories import FlashRegion, RamRegion, ExtMemRegion, MemoryRegion


def test_ram_region():
    ram_region = RamRegion(index=4, start=0, size=10)
    assert "Region 4: 0x00000000 - 0x00000009; Total Size: 10.0 B" == str(ram_region)


def test_flash_region():
    flash_region = FlashRegion(index=4, start=0, size=10, sector_size=5)
    assert "Region 4: 0x00000000 - 0x00000009; Total Size: 10.0 B Sector size: 5.0 B" == str(
        flash_region
    )


def test_ext_mem_region():
    ext_mem_region = ExtMemRegion(mem_id=4, raw_values=[1, 1, 1, 1, 10, 0])
    assert "Start Address = 0x00000001  Page Size = None  Sector Size = None  " == str(
        ext_mem_region
    )
    ext_mem_region = ExtMemRegion(mem_id=4)
    assert "Not Configured" == str(ext_mem_region)
    ext_mem_region = ExtMemRegion(mem_id=4, raw_values=[15, 134217728, 16384, 0, 0, 0])
    assert ext_mem_region.name == "IFR0"
    assert (
        "Start Address = 0x08000000  Total Size = 16.0 MiB  Page Size = 0  Sector Size = 0  "
        == str(ext_mem_region)
    )
