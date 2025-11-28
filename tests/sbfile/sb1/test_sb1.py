#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB1 format testing module.

This module contains unit tests for the SB1 (Secure Binary version 1) file format
functionality in SPSDK. It validates the creation, parsing, and error handling
of SB1 secure boot files and their components.
"""

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb1 import BootSectionV1, SecureBootFlagsV1, SecureBootV1


def test_sb1x_basic() -> None:
    """Test basic functionality of SecureBootV1 class.

    This test verifies the core operations of SecureBootV1 including:
    - Object creation with different versions (1.0 and 1.2)
    - String representation functionality
    - Export validation (requires bootable section)
    - Section management (append and count operations)
    - Data export and parsing round-trip

    :raises SPSDKError: When attempting to export without a bootable section.
    """
    img = SecureBootV1(version="1.0")
    assert str(img)
    img = SecureBootV1(version="1.2")
    assert str(img)
    with pytest.raises(SPSDKError):
        img.export()  # missing bootable section
    assert len(img.sections) == 0
    img.append(BootSectionV1(0, SecureBootFlagsV1.ROM_SECTION_BOOTABLE))
    img.append(BootSectionV1(1))
    img.append(BootSectionV1(2, SecureBootFlagsV1.ROM_SECTION_BOOTABLE))
    assert len(img.sections) == 3
    data = img.export()
    assert data
    assert len(data) == img.size
    assert SecureBootV1.parse(data)


def test_sb1x_invalid_length_section() -> None:
    """Test invalid length section handling in SecureBootV1.

    Verifies that setting an invalid first_boot_section_id raises SPSDKError
    with appropriate error message, and that valid negative values are accepted.

    :raises SPSDKError: When first_boot_section_id is set to invalid value.
    """
    sb = SecureBootV1()
    with pytest.raises(SPSDKError, match="Invalid length of section"):
        sb.first_boot_section_id = 2222
    sb.first_boot_section_id = -1


def test_sb1x_invalid_export() -> None:
    """Test invalid export operation with incorrect padding length.

    This test verifies that the SecureBootV1 export method properly validates
    the auth_padding parameter and raises an appropriate error when an invalid
    padding length is provided.

    :raises SPSDKError: When invalid padding length is detected during export.
    """
    img = SecureBootV1(version="1.0")
    img.append(BootSectionV1(0, SecureBootFlagsV1.ROM_SECTION_BOOTABLE))
    img.append(BootSectionV1(1))
    img.append(BootSectionV1(2, SecureBootFlagsV1.ROM_SECTION_BOOTABLE))
    with pytest.raises(SPSDKError, match="Invalid padding length"):
        img.export(auth_padding=bytes(12365))


def test_sb1x_parse() -> None:
    """Test parsing of SB1 files with invalid inputs.

    Verifies that SecureBootV1.parse() properly handles error conditions
    including insufficient data size and invalid signature/tag values.

    :raises SPSDKError: When parsing fails due to invalid input data.
    """
    # insufficient size
    with pytest.raises(SPSDKError):
        SecureBootV1.parse(b"")
    # invalid signature/tag
    with pytest.raises(SPSDKError):
        SecureBootV1.parse(b"0" * 1024)
