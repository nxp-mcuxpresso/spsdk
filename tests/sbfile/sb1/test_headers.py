#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.sbfile.misc import BcdVersion3, SecBootBlckSize
from spsdk.sbfile.sb1.headers import (
    BootSectionHeaderV1,
    SectionHeaderItemV1,
    SecureBootFlagsV1,
    SecureBootHeaderV1,
)


def test_secure_boot_header_v1():
    # insufficient size
    with pytest.raises(SPSDKError):
        SecureBootHeaderV1.parse(b"\x00")
    # default params
    header = SecureBootHeaderV1()
    assert header.digest == bytes([0] * 20)
    assert header.version == "1.0"
    assert header.flags == 0
    assert header.image_blocks == 0
    assert header.first_boot_section_id == 0
    assert header.key_count == 0
    assert header.header_blocks == SecBootBlckSize.to_num_blocks(header.size)
    assert header.section_count == 0
    assert header.section_header_size == SecBootBlckSize.to_num_blocks(BootSectionHeaderV1.SIZE)
    assert str(header.product_version) == "999.999.999"
    assert str(header.component_version) == "999.999.999"
    assert header.drive_tag == 0
    header.version = "1.2"
    header.flags = 22
    header.image_blocks = 33
    header.first_boot_section_id = 44
    header.key_count = 55
    header.header_blocks = 66
    header.section_count = 77
    header.section_header_size = 88
    header.product_version = BcdVersion3.to_version("1.2.3")
    header.component_version = BcdVersion3.to_version("3.2.1")
    header.drive_tag = 99

    data = header.export()
    assert len(data) == header.size

    header_parsed = SecureBootHeaderV1.parse((b"\xFF" + data)[1:])
    s1 = str(header).split("\n")
    s2 = str(header_parsed).split("\n")
    assert len(s1) == len(s2)
    for index, line in enumerate(s1):
        assert line == s2[index]
    assert s1 == s2
    assert header == header_parsed


def test_section_header_item():
    header = SectionHeaderItemV1()
    assert header.identifier == 0
    assert header.offset == 0
    assert header.num_blocks == 0
    assert header.flags == SecureBootFlagsV1.NONE

    data = header.export()
    assert len(data) == header.size

    header_parsed = SectionHeaderItemV1.parse((b"\xFF" + data)[1:])
    assert header == header_parsed

    assert str(header)


def test_insufficient_size():
    with pytest.raises(SPSDKError):
        SectionHeaderItemV1.parse("\x00")


def test_secure_boot_header_v1_invalid():
    with pytest.raises(SPSDKError, match="Invalid header version"):
        SecureBootHeaderV1(version="2.0")
