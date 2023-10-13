#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb1 import BootSectionV1, SecureBootFlagsV1, SecureBootV1


def test_sb1x_basic():
    """Basic test of SB 1.x"""
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


def test_sb1x_invalid_length_section():
    sb = SecureBootV1()
    with pytest.raises(SPSDKError, match="Invalid length of section"):
        sb.first_boot_section_id = 2222
    sb.first_boot_section_id = -1


def test_sb1x_invalid_export():
    img = SecureBootV1(version="1.0")
    img.append(BootSectionV1(0, SecureBootFlagsV1.ROM_SECTION_BOOTABLE))
    img.append(BootSectionV1(1))
    img.append(BootSectionV1(2, SecureBootFlagsV1.ROM_SECTION_BOOTABLE))
    with pytest.raises(SPSDKError, match="Invalid padding length"):
        img.export(auth_padding=bytes(12365))


def test_sb1x_parse():
    # insufficient size
    with pytest.raises(SPSDKError):
        SecureBootV1.parse(b"")
    # invalid signature/tag
    with pytest.raises(SPSDKError):
        SecureBootV1.parse(b"0" * 1024)
