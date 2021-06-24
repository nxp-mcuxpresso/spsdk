#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.sbfile.sb1 import SecureBootV1, BootSectionV1, SecureBootFlagsV1


def test_sb1x_basic(data_dir):
    """Basic test of SB 1.x"""
    img = SecureBootV1(version="1.0")
    assert img.info()
    img = SecureBootV1(version="1.2")
    assert img.info()
    with pytest.raises(ValueError):
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


def test_sb1x_parse(data_dir):
    # insufficient size
    with pytest.raises(ValueError):
        SecureBootV1.parse(b"")
    # invalid signature/tag
    with pytest.raises(ValueError):
        SecureBootV1.parse(b"0" * 1024)
