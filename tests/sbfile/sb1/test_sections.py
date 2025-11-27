#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for SB1 boot sections functionality.

This module contains unit tests for the SB1 (Secure Binary version 1) boot sections
implementation, validating the behavior of boot section creation, command handling,
and secure boot flags configuration.
"""

from spsdk.sbfile.sb1 import BootSectionV1, CmdNop, SecureBootFlagsV1


def test_boot_section_v1() -> None:
    """Test BootSectionV1 class functionality.

    This test verifies the creation, configuration, and serialization/deserialization
    of BootSectionV1 objects. It tests section properties, command management,
    data export, parsing, and equality comparison.
    """
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
