#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB Unlock command tests.

This module contains comprehensive test cases for HAB (High Assurance Boot) unlock
commands functionality, including SNVS, CAAM, and OCOTP unlock operations.
"""

from spsdk.image.hab.commands.cmd_nop import CmdNop
from spsdk.image.hab.commands.cmd_unlock import (
    CmdUnlockAny,
    CmdUnlockCAAM,
    CmdUnlockOCOTP,
    CmdUnlockSNVS,
    UnlockCAAMFeaturesEnum,
    UnlockOCOTPFeaturesEnum,
    UnlockSNVSFeaturesEnum,
)
from spsdk.image.hab.constants import EngineEnum
from spsdk.image.hab.hab_header import CmdHeader


def test_unlock_cmd_base() -> None:
    """Test basic functionality of CmdUnlockAny command class.

    Verifies that CmdUnlockAny command initializes correctly with default and
    specified engine parameters, validates size and string representation,
    and ensures proper header parameter assignment.
    """
    cmd = CmdUnlockAny()
    assert cmd.engine == EngineEnum.ANY
    assert cmd.size == 8
    assert "CmdUnlock" in str(cmd)
    assert cmd._header.param == 0

    cmd = CmdUnlockAny(EngineEnum.CSU)
    assert cmd._header.param == 10


def test_unlock_cmd_export_parse() -> None:
    """Test export and parse functionality of CmdUnlockAny command.

    Verifies that a CmdUnlockAny command can be exported to binary data
    and then parsed back to recreate the original command object.
    The test ensures data integrity and proper serialization/deserialization.

    :raises AssertionError: If exported data length is not 8 bytes or parsed command differs from original.
    """
    cmd = CmdUnlockAny()
    data = cmd.export()
    assert len(data) == 8
    assert cmd == CmdUnlockAny.parse(data)


def test_unlock_cmd_equality() -> None:
    """Test equality comparison for CmdUnlockAny command objects.

    Verifies that CmdUnlockAny objects correctly implement equality comparison
    by testing against different object types and configurations. Ensures that
    commands are equal to themselves, not equal to different command types,
    and not equal to commands with different configurations.
    """
    cmd = CmdUnlockAny()
    nop = CmdNop()
    cmd_other = CmdUnlockAny(engine=EngineEnum.DCP)

    assert cmd != nop
    assert cmd == cmd
    assert cmd != cmd_other


def test_unlock_cmd_info() -> None:
    """Test that CmdUnlockAny command string representation contains required information.

    Verifies that the string output of CmdUnlockAny command includes essential
    elements like command name, features section, and UID field to ensure
    proper command information display.

    :raises AssertionError: When required strings are missing from command output.
    """
    cmd = CmdUnlockAny()
    output = str(cmd)
    req_strings = ["Unlock Command", "Features:", "UID:"]
    for req_string in req_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_unlock_snvs() -> None:
    """Test Unlock SNVS command functionality.

    Validates the CmdUnlockSNVS command creation, properties, serialization,
    and deserialization. Tests both parameterized initialization with feature
    flags and default initialization. Verifies command properties like engine
    type, size, and feature flags, as well as export/parse roundtrip consistency.
    """
    cmd = CmdUnlockSNVS(UnlockSNVSFeaturesEnum.LP_SWR.tag | UnlockSNVSFeaturesEnum.ZMK_WRITE.tag)
    assert cmd.engine == EngineEnum.SNVS
    assert cmd.size == CmdHeader.SIZE + 4
    assert cmd.unlock_lp_swr
    assert cmd.unlock_zmk_write
    cmd = CmdUnlockSNVS()
    assert not cmd.unlock_lp_swr
    assert not cmd.unlock_zmk_write

    assert str(cmd)

    data = cmd.export()
    cmd2 = CmdUnlockAny.parse(data)
    assert data == cmd2.export()
    assert cmd == cmd2


def test_unlock_caam() -> None:
    """Test CmdUnlockCAAM command functionality.

    This test verifies the creation, configuration, and serialization/deserialization
    of CmdUnlockCAAM command with MID feature enabled. It checks that the command
    properly sets the unlock_mid flag while keeping other flags disabled, and
    ensures the command can be exported and parsed correctly.
    """
    cmd = CmdUnlockCAAM(features=UnlockCAAMFeaturesEnum.MID)
    assert cmd.features == 1
    assert cmd.unlock_mid
    assert not cmd.unlock_mfg
    assert not cmd.unlock_rng
    assert "CmdUnlockCAAM" in str(cmd)

    assert str(cmd)

    data = cmd.export()
    cmd2 = CmdUnlockAny.parse(data)
    assert data == cmd2.export()
    assert cmd == cmd2


def test_unlock_ocotp() -> None:
    """Test OCOTP unlock command functionality.

    Validates the creation and behavior of CmdUnlockOCOTP command with specific
    features and UID. Tests command properties, string representation, data
    export/import cycle, and command equality.
    """
    cmd = CmdUnlockOCOTP(
        features=UnlockOCOTPFeaturesEnum.FIELD_RETURN.tag
        | UnlockOCOTPFeaturesEnum.JTAG.tag
        | UnlockOCOTPFeaturesEnum.SCS.tag,
        uid=0x123456789,
    )

    assert cmd.unlock_fld_rtn
    assert not cmd.unlock_srk_rvk
    assert "CmdUnlockOCOTP" in str(cmd)

    assert "UID" in str(cmd)
    assert "UID" not in str(CmdUnlockOCOTP())

    data = cmd.export()
    cmd2 = CmdUnlockAny.parse(data)
    assert data == cmd2.export()
    assert cmd == cmd2


def test_unlock_parse_others() -> None:
    """Test parsing and serialization of CmdUnlockAny command with SRTC engine.

    Verifies that a CmdUnlockAny command can be properly exported to binary data
    and then parsed back to create an equivalent command object. Tests the
    round-trip serialization process and string representation.

    :raises AssertionError: If the parsed command doesn't match the original or string representation is incorrect.
    """
    cmd = CmdUnlockAny(engine=EngineEnum.SRTC)
    assert "CmdUnlock" in str(cmd)
    data = cmd.export()
    cmd2 = CmdUnlockAny.parse(data)
    assert cmd == cmd2


def test_need_uid() -> None:
    """Test UID requirement validation for unlock commands.

    Validates that CmdUnlockAny.need_uid() correctly identifies which engine and feature
    combinations require a UID parameter. Tests both positive cases (where UID is required)
    and negative cases (where UID is not required).

    :raises AssertionError: If UID requirement validation fails for any test case.
    """
    positive = [
        CmdUnlockAny.need_uid(EngineEnum.OCOTP, UnlockOCOTPFeaturesEnum.FIELD_RETURN.tag),
        CmdUnlockAny.need_uid(EngineEnum.OCOTP, UnlockOCOTPFeaturesEnum.JTAG.tag),
        CmdUnlockAny.need_uid(EngineEnum.OCOTP, UnlockOCOTPFeaturesEnum.SCS.tag),
    ]
    negative = [
        CmdUnlockAny.need_uid(EngineEnum.OCOTP, UnlockOCOTPFeaturesEnum.SRK_REVOKE.tag),
        CmdUnlockAny.need_uid(EngineEnum.CAAM, 0b001),
        CmdUnlockAny.need_uid(EngineEnum.CAAM, 0b010),
        CmdUnlockAny.need_uid(EngineEnum.CAAM, 0b100),
        CmdUnlockAny.need_uid(EngineEnum.ANY, 0b1111),
    ]
    assert all(positive)
    assert not all(negative)
