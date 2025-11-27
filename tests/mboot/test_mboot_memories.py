#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK MBoot memory regions unit tests.

This module contains comprehensive unit tests for the MBoot memory management
functionality, validating different memory region types and memory identifiers
used in the MBoot protocol implementation.
"""

from spsdk.mboot.memories import ExtMemRegion, FlashRegion, MemId, RamRegion


def test_ram_region() -> None:
    """Test RAM region string representation functionality.

    Verifies that a RamRegion object correctly formats its string representation
    to display the region index, memory range (start to end addresses), and total
    size in bytes with proper hexadecimal formatting.
    """
    ram_region = RamRegion(index=4, start=0, size=10)
    assert "Region 4: 0x00000000 - 0x00000009; Total Size: 10 B" == str(ram_region)


def test_flash_region() -> None:
    """Test FlashRegion string representation functionality.

    Verifies that a FlashRegion object with specified index, start address, size,
    and sector size produces the expected string format when converted to string.
    The test ensures proper formatting of memory region information including
    hexadecimal addresses, decimal sizes, and appropriate units.
    """
    flash_region = FlashRegion(index=4, start=0, size=10, sector_size=5)
    assert "Region 4: 0x00000000 - 0x00000009; Total Size: 10 B Sector size: 5 B" == str(
        flash_region
    )


def test_ext_mem_region() -> None:
    """Test external memory region functionality.

    Tests the ExtMemRegion class with different configurations including:
    - Region with basic raw values and string representation
    - Un-configured region behavior
    - Region with full configuration including name resolution and size formatting
    """
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


def test_legacy_mem_ids() -> None:
    """Test legacy memory ID conversion methods.

    Validates the MemId class methods for converting between legacy integer IDs,
    legacy string representations, and modern labels. Tests bidirectional conversion
    functionality and ensures proper handling of alternative naming conventions.
    """
    assert MemId.get_legacy_int(4) == "ifr"
    assert MemId.get_legacy_str("ifr") == 4
    assert MemId.get_legacy_str("fuse") == 4
    assert MemId.get_label(4) == "IFR0"
    assert MemId.from_label("IFR0") == 4
    assert MemId.from_label("FUSE") == 4
