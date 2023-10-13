#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.sbfile.sb1 import BootSectionV1, CmdNop, SecureBootFlagsV1


def test_boot_section_v1():
    """Test `BootSectionV1` class"""
    sect = BootSectionV1(0xA5, SecureBootFlagsV1.ROM_SECTION_BOOTABLE)
    assert sect.section_id == 0xA5
    assert sect.flags == SecureBootFlagsV1.ROM_SECTION_BOOTABLE
    assert sect.bootable
    assert not sect.rom_last_tag
    assert str(sect)
    assert sect.cmd_size == 0
    assert len(sect.commands) == 0
    sect.append(CmdNop())
    assert len(sect.commands) == 1
    sect.append(CmdNop())
    assert len(sect.commands) == 2
    assert str(sect)
    data = sect.export()
    assert len(data) == sect.size
    parsed_sect = BootSectionV1.parse(data)
    assert sect == parsed_sect
    assert str(sect)
