#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK registers utility test suite.

This module contains comprehensive tests for the SPSDK registers utility functionality,
including register management, bitfield operations, enumeration handling, and
register database operations across NXP MCU portfolio for secure provisioning
and configuration management.
"""

import os
from typing import Any, Optional
from unittest.mock import patch

import pytest
from ruamel.yaml import YAML

from spsdk.exceptions import SPSDKError
from spsdk.utils import database, family
from spsdk.utils.config import Config
from spsdk.utils.database import Database, QuickDatabase
from spsdk.utils.exceptions import (
    SPSDKRegsError,
    SPSDKRegsErrorBitfieldNotFound,
    SPSDKRegsErrorEnumNotFound,
    SPSDKRegsErrorRegisterGroupMishmash,
    SPSDKRegsErrorRegisterNotFound,
)
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import Endianness, use_working_directory, value_to_bytes, value_to_int
from spsdk.utils.registers import (
    Access,
    Register,
    Registers,
    RegistersPreValidationHook,
    RegsBitField,
    RegsEnum,
)

TEST_DEVICE_NAME = "TestDevice1"
TEST_REG_NAME = "TestReg"
TEST_REG_BC_NAME = "TestRegBc"
TEST_REG_OFFSET = 1024
TEST_REG_WIDTH = 32
TEST_REG_UID = "field400"
TEST_REG_UID2 = "UID_test_reg2"
TEST_REG_DESCR = "TestReg Description"
TEST_REG_REV = False
TEST_REG_ACCESS = Access.RW
TEST_REG_VALUE = 0xA5A5A5A5
TEST_REG_DEPRECATED_NAMES = ["OldReg1Name1", "AnotherOldReg1Name"]


TEST_BITFIELD_NAME = "TestBitfield"
TEST_BITFIELD_BC_NAME = "TestBitfieldBc"
TEST_BITFIELD_OFFSET = 0x0F
TEST_BITFIELD_WIDTH = 5
TEST_BITFIELD_UID = "UID_bitfield"
TEST_BITFIELD_UID2 = "UID_bitfield2"
TEST_BITFIELD_RESET_VAL = 30
TEST_BITFIELD_ACCESS = Access.RW
TEST_BITFIELD_DESCR = "Test Bitfield Description"
TEST_BITFIELD_SAVEVAL = 29
TEST_BITFIELD_OUTOFRANGEVAL = 70
TEST_BITFIELD_DEPRECATED_NAMES = ["OldBitfieldName1", "OldBitfieldName2"]

TEST_ENUM_NAME = "TestEnum"
TEST_ENUM_BC_NAME = "TestEnumBc"
TEST_ENUM_VALUE_BIN = "0b10001"
TEST_ENUM_VALUE_HEX = "0x11"
TEST_ENUM_VALUE_STRINT = "017"
TEST_ENUM_VALUE_INT = 17
TEST_ENUM_VALUE_BYTES = b"\x11"
TEST_ENUM_RES_VAL = "0b01_0001"
TEST_ENUM_DESCR = "Test Enum Description"
TEST_ENUM_MAXWIDTH = 6

TEST_JSON_FILE = "unit_test.json"


def create_simple_regs() -> Registers:
    """Create simple register structure with basic test cases.

    Creates a Registers object containing two test registers with predefined values,
    bitfields, and enums for testing purposes. The first register is basic, while
    the second register includes bitfields with enums for more complex testing scenarios.

    :return: Configured Registers object with test data including two registers,
             bitfields, and enums.
    """
    regs = Registers(
        family=FamilyRevision(TEST_DEVICE_NAME), feature="test", do_not_raise_exception=True
    )

    reg1 = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        TEST_REG_VALUE,
        TEST_REG_REV,
        TEST_REG_ACCESS,
        deprecated_names=TEST_REG_DEPRECATED_NAMES,
    )

    reg2 = Register(
        TEST_REG_NAME + "_2",
        TEST_REG_OFFSET + 4,
        TEST_REG_WIDTH,
        TEST_REG_UID2,
        TEST_REG_DESCR + "_2",
        0xF0000,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield1 = RegsBitField(
        reg2,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_UID,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_ACCESS,
        deprecated_names=TEST_BITFIELD_DEPRECATED_NAMES,
    )

    bitfield2 = RegsBitField(
        reg2,
        TEST_BITFIELD_NAME + "_2",
        TEST_BITFIELD_OFFSET + TEST_BITFIELD_WIDTH,
        1,
        TEST_BITFIELD_UID2,
        ".",
        TEST_BITFIELD_ACCESS,
    )
    enum1 = RegsEnum(TEST_ENUM_NAME, 0, TEST_ENUM_DESCR, 1)
    enum2 = RegsEnum(TEST_ENUM_NAME + "_2", 0, TEST_ENUM_DESCR + "_2", 1)
    bitfield2.add_enum(enum1)
    bitfield2.add_enum(enum2)
    reg2.add_bitfield(bitfield1)
    reg2.add_bitfield(bitfield2)
    regs.add_register(reg1)
    regs.add_register(reg2)

    return regs


def test_basic_regs(tmpdir: Any) -> None:
    """Test basic functionality of the Registers class.

    Validates register creation, addition, retrieval, and error handling.
    Tests include verifying family assignment, register operations like finding
    and setting values, and proper exception raising for invalid operations.

    :param tmpdir: Temporary directory fixture for test isolation.
    """
    regs = Registers(
        family=FamilyRevision(TEST_DEVICE_NAME), feature="test", do_not_raise_exception=True
    )

    assert regs.family.name == TEST_DEVICE_NAME

    reg1 = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        TEST_REG_VALUE,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    with pytest.raises(SPSDKRegsErrorRegisterNotFound):
        regs.find_reg("NonExisting")

    # The Registers MUST return empty array
    assert regs.get_reg_names() == []

    # Now we could do tests with a register added to list
    regs.add_register(reg1)

    assert TEST_REG_NAME in regs.get_reg_names()

    regt = regs.find_reg(TEST_REG_NAME)

    assert regt == reg1

    with pytest.raises(SPSDKError):
        regs.add_register("Invalid Parameter")  # type: ignore

    regt.set_value(TEST_REG_VALUE)
    assert reg1.get_value() == TEST_REG_VALUE


def test_register() -> None:
    """Test basic register functionality and string representation.

    This test verifies the creation and interaction of Register, RegsBitField, and RegsEnum
    objects. It validates that the string representation of a register contains all expected
    components including register properties, bitfield information, and enum details.
    """
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        TEST_REG_VALUE,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_UID,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_ACCESS,
    )

    enum = RegsEnum(TEST_ENUM_NAME, 0, TEST_ENUM_DESCR)
    bitfield.add_enum(enum)

    parent_reg.add_bitfield(bitfield)

    printed_str = str(parent_reg)

    assert "Name:" in printed_str
    assert TEST_REG_NAME in printed_str
    assert TEST_REG_DESCR in printed_str
    assert "Width:" in printed_str
    assert "Access:" in printed_str
    assert "Bitfield" in printed_str
    assert TEST_BITFIELD_NAME in printed_str
    assert TEST_BITFIELD_DESCR in printed_str
    assert TEST_ENUM_NAME in printed_str
    assert TEST_ENUM_DESCR in printed_str


def test_register_duplicate() -> None:
    """Test that adding a duplicate register raises an exception.

    This test verifies that when attempting to add a register with the same name
    but different UID to a Registers collection, an SPSDKRegsError is properly raised.

    :raises SPSDKRegsError: When attempting to add a duplicate register name.
    """
    reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        TEST_REG_VALUE,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )
    reg1 = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID2,
        TEST_REG_DESCR,
        TEST_REG_VALUE,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )
    regs = Registers(
        family=FamilyRevision(TEST_DEVICE_NAME), feature="test", do_not_raise_exception=True
    )
    regs.add_register(reg)

    with pytest.raises(SPSDKRegsError):
        regs.add_register(reg1)


def test_register_invalid_val() -> None:
    """Test register behavior with invalid value inputs.

    Verifies that the Register class properly handles and rejects invalid
    value types (string and list) by raising SPSDKError exceptions while
    preserving the original register value.

    :raises SPSDKError: When invalid value types are provided to set_value method.
    """
    reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        TEST_REG_VALUE,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    val = reg.get_value()
    with pytest.raises(SPSDKError):
        reg.set_value("Invalid")
    assert reg.get_value() == val

    with pytest.raises(SPSDKError):
        reg.set_value([1, 2])
    assert reg.get_value() == val


def test_enum() -> None:
    """Test basic functionality of RegsEnum class.

    Verifies that RegsEnum constructor properly initializes an enum object
    and that the string representation contains all expected components
    including name, value, and description fields.

    :raises AssertionError: If any of the expected string components are missing from the enum representation.
    """
    enum = RegsEnum(TEST_ENUM_NAME, 0, TEST_ENUM_DESCR)

    printed_str = str(enum)

    assert "Name:" in printed_str
    assert "Value:" in printed_str
    assert "Description:" in printed_str
    assert TEST_ENUM_NAME in printed_str
    assert "0x0" in printed_str
    assert TEST_ENUM_DESCR in printed_str


def test_enum_bin() -> None:
    """Test RegsEnum functionality with binary value input.

    Verifies that a RegsEnum instance can be created with binary value format
    and that its string representation contains the expected result value.

    :raises AssertionError: If the expected test result value is not found in the enum's string representation.
    """
    enum = RegsEnum(TEST_ENUM_NAME, TEST_ENUM_VALUE_BIN, TEST_ENUM_DESCR, TEST_ENUM_MAXWIDTH)
    printed_str = str(enum)
    assert TEST_ENUM_RES_VAL in printed_str


def test_enum_hex() -> None:
    """Test RegsEnum functionality with hexadecimal values.

    Verifies that a RegsEnum instance can be created with hexadecimal values
    and that the string representation contains the expected result value.
    This test ensures proper handling of hexadecimal input in enum creation
    and string formatting.
    """
    enum = RegsEnum(TEST_ENUM_NAME, TEST_ENUM_VALUE_HEX, TEST_ENUM_DESCR, TEST_ENUM_MAXWIDTH)
    printed_str = str(enum)
    assert TEST_ENUM_RES_VAL in printed_str


def test_enum_strint() -> None:
    """Test RegsEnum functionality with integer values provided as strings.

    Verifies that RegsEnum can properly handle enumeration values that are
    integers represented as string literals, and that the string representation
    of the enum contains the expected result value.

    :raises AssertionError: If the expected enum result value is not found in the string representation.
    """
    enum = RegsEnum(TEST_ENUM_NAME, TEST_ENUM_VALUE_STRINT, TEST_ENUM_DESCR, TEST_ENUM_MAXWIDTH)
    printed_str = str(enum)
    assert TEST_ENUM_RES_VAL in printed_str


def test_enum_int() -> None:
    """Test RegsEnum functionality with integer value input.

    Verifies that RegsEnum can be properly instantiated with an integer value
    and that the string representation contains the expected result value.

    :raises AssertionError: If the expected test enum result value is not found in the string representation.
    """
    enum = RegsEnum(TEST_ENUM_NAME, TEST_ENUM_VALUE_INT, TEST_ENUM_DESCR, TEST_ENUM_MAXWIDTH)
    printed_str = str(enum)
    assert TEST_ENUM_RES_VAL in printed_str


def test_enum_bytes() -> None:
    """Test RegsEnum functionality with bytes array as enum value.

    Verifies that a RegsEnum instance can be created with a bytes array value
    and that the string representation contains the expected result value.

    :raises AssertionError: If the expected test enum result value is not found in the string representation.
    """
    enum = RegsEnum(TEST_ENUM_NAME, TEST_ENUM_VALUE_BYTES, TEST_ENUM_DESCR, TEST_ENUM_MAXWIDTH)
    printed_str = str(enum)
    assert TEST_ENUM_RES_VAL in printed_str


def test_enum_invalidval() -> None:
    """Test that RegsEnum raises SPSDKRegsError when initialized with an invalid value.

    Verifies that the RegsEnum constructor properly validates input values and raises
    the appropriate exception when an invalid value is provided.

    :raises SPSDKRegsError: When RegsEnum is initialized with an invalid value.
    """
    with pytest.raises(SPSDKRegsError):
        RegsEnum(TEST_ENUM_NAME, "InvalidValue", TEST_ENUM_DESCR, TEST_ENUM_MAXWIDTH)


def test_bitfield() -> None:
    """Test bitfield functionality with register integration.

    This test verifies that a RegsBitField can be properly created, configured
    with enums, added to a parent register, and that its string representation
    contains all expected information fields including name, offset, width,
    access permissions, reset value, description, and enum details.

    :raises AssertionError: If the bitfield string representation is missing any required fields.
    """
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        TEST_REG_VALUE,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_UID,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_ACCESS,
    )

    enum = RegsEnum(TEST_ENUM_NAME, 0, TEST_ENUM_DESCR)
    bitfield.add_enum(enum)

    parent_reg.add_bitfield(bitfield)

    printed_str = str(bitfield)

    assert "Name:" in printed_str
    assert "Offset:" in printed_str
    assert "Width:" in printed_str
    assert "Access:" in printed_str
    assert "Reset val:" in printed_str
    assert "Description:" in printed_str
    assert "Enum" in printed_str


def test_bitfield_find() -> None:
    """Test the bitfield find functionality in registers.

    Verifies that a bitfield can be successfully found within its parent register
    by name, and that appropriate exceptions are raised when searching for
    non-existent bitfields.

    :raises SPSDKRegsErrorBitfieldNotFound: When searching for a bitfield that doesn't exist.
    """
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        TEST_REG_VALUE,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_UID,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_ACCESS,
    )

    enum = RegsEnum(TEST_ENUM_NAME, 0, TEST_ENUM_DESCR)
    bitfield.add_enum(enum)

    parent_reg.add_bitfield(bitfield)

    assert bitfield == parent_reg.find_bitfield(TEST_BITFIELD_NAME)

    with pytest.raises(SPSDKRegsErrorBitfieldNotFound):
        parent_reg.find_bitfield("Invalid Name")


def test_bitfields_names() -> None:
    """Test bitfield names retrieval functionality.

    Validates that the Register.get_bitfield_names() method correctly returns
    bitfield names and properly handles exclusion filtering. Tests include
    scenarios with no bitfields, multiple bitfields, and selective exclusion
    of specific bitfield names.
    """
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        TEST_REG_VALUE,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_UID,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_ACCESS,
    )

    bitfield1 = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME + "1",
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_UID2,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_ACCESS,
    )

    assert parent_reg.get_bitfield_names() == []

    parent_reg.add_bitfield(bitfield)
    parent_reg.add_bitfield(bitfield1)

    assert len(parent_reg.get_bitfield_names()) == 2

    names = parent_reg.get_bitfield_names()
    assert len(names) == 2
    assert TEST_BITFIELD_NAME in names
    assert TEST_BITFIELD_NAME + "1" in names

    ex_names = parent_reg.get_bitfield_names([TEST_BITFIELD_NAME + "1"])
    assert len(ex_names) == 1
    assert TEST_BITFIELD_NAME in ex_names

    ex_names1 = parent_reg.get_bitfield_names([TEST_BITFIELD_NAME])
    assert len(ex_names1) == 0


def test_bitfield_has_enums() -> None:
    """Test that bitfield correctly reports whether it contains enumeration values.

    This test verifies the has_enums() method functionality by creating a bitfield
    without enums (should return False), adding an enum, and then confirming it
    returns True. Also validates that the added enum is properly retrievable.
    """
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        TEST_REG_VALUE,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_UID,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_ACCESS,
    )

    parent_reg.add_bitfield(bitfield)

    assert bitfield.has_enums() is False
    enum = RegsEnum(TEST_ENUM_NAME, 0, TEST_ENUM_DESCR)
    bitfield.add_enum(enum)

    assert bitfield.has_enums() is True

    assert enum in bitfield.get_enums()


def test_bitfield_value() -> None:
    """Test bitfield functionality for value operations.

    Validates that RegsBitField correctly handles value getting and setting operations,
    including proper validation of out-of-range values.

    :raises SPSDKError: When attempting to set an out-of-range value to the bitfield.
    """
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        0,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_UID,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_ACCESS,
    )

    assert bitfield.get_value() == 0

    bitfield.set_value(TEST_BITFIELD_SAVEVAL)
    assert bitfield.get_value() == TEST_BITFIELD_SAVEVAL

    with pytest.raises(SPSDKError):
        bitfield.set_value(TEST_BITFIELD_OUTOFRANGEVAL)


def test_bitfield_enums() -> None:
    """Test bitfield enumeration functionality in register bitfields.

    Validates the complete enumeration workflow including creation of register
    with bitfield, adding enums to bitfield, retrieving enum names and constants,
    setting and getting enum values by name and index, and proper error handling
    for invalid enum names.

    :raises SPSDKRegsErrorEnumNotFound: When attempting to get constant for invalid enum name.
    """
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        TEST_REG_VALUE,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_UID,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_ACCESS,
    )

    parent_reg.add_bitfield(bitfield)

    enums = []
    for index in range((1 << TEST_BITFIELD_WIDTH) - 1):
        enum = RegsEnum(
            f"{TEST_ENUM_NAME}{index}", index, f"{TEST_ENUM_DESCR}{index}", TEST_BITFIELD_WIDTH
        )
        enums.append(enum)
        bitfield.add_enum(enum)

    enum_names = bitfield.get_enum_names()

    for index in range((1 << TEST_BITFIELD_WIDTH) - 1):
        assert index == bitfield.get_enum_constant(f"{TEST_ENUM_NAME}{index}")
        assert enums[index].name in enum_names

    for index in range((1 << TEST_BITFIELD_WIDTH)):
        bitfield.set_value(index)
        if index < (1 << TEST_BITFIELD_WIDTH) - 1:
            assert f"{TEST_ENUM_NAME}{index}" == bitfield.get_enum_value()
        else:
            assert index == value_to_int(bitfield.get_enum_value())

    for index in range((1 << TEST_BITFIELD_WIDTH) - 1):
        bitfield.set_enum_value(f"{TEST_ENUM_NAME}{index}")
        assert index == bitfield.get_value()

    for index in range((1 << TEST_BITFIELD_WIDTH) - 1):
        bitfield.set_enum_value(f"{index}")
        assert index == bitfield.get_value()

    with pytest.raises(SPSDKRegsErrorEnumNotFound):
        bitfield.get_enum_constant("Invalid name")


def test_bitfield_enums_invalid_name() -> None:
    """Test bitfield enums with invalid enum name.

    This test verifies that attempting to set an enum value using an invalid
    enum name raises the appropriate SPSDKError exception. It creates a register
    with a bitfield containing a valid enum, then tries to set a value using
    a non-existent enum name.

    :raises SPSDKError: When attempting to set enum value with invalid name.
    """
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        TEST_REG_VALUE,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_UID,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_ACCESS,
    )

    parent_reg.add_bitfield(bitfield)
    bitfield.add_enum(RegsEnum(f"{TEST_ENUM_NAME}", 0, f"{TEST_ENUM_DESCR}", TEST_BITFIELD_WIDTH))
    with pytest.raises(SPSDKError):
        bitfield.set_enum_value("Invalid Enum name")


def test_registers_json(data_dir: str, tmpdir: str) -> None:
    """Test registers JSON support.

    Validates that registers can be loaded from JSON specification, written back to JSON,
    and reloaded while maintaining consistency. This ensures proper serialization and
    deserialization of register configurations.

    :param data_dir: Directory containing the source registers.json file to load.
    :param tmpdir: Temporary directory where the registers.json will be written and reloaded from.
    """
    regs = Registers(
        family=FamilyRevision(TEST_DEVICE_NAME), feature="test", do_not_raise_exception=True
    )

    with use_working_directory(data_dir):
        regs._load_spec("registers.json")

    with use_working_directory(tmpdir):
        regs.write_spec("registers.json")

    regs2 = Registers(
        family=FamilyRevision(TEST_DEVICE_NAME), feature="test", do_not_raise_exception=True
    )

    with use_working_directory(tmpdir):
        regs2._load_spec("registers.json")

    assert str(regs) == str(regs2)


def test_registers_json_hidden(data_dir: str, tmpdir: str) -> None:
    """Test registers JSON support with hidden/reserved fields.

    This test verifies that registers can be properly loaded from and saved to JSON format,
    specifically testing the handling of reserved/hidden bitfields. It creates a Registers
    instance, loads a specification with reserved fields, validates the values, saves the
    specification to a new file, loads it again in a new instance, and verifies consistency.

    :param data_dir: Directory containing test data files with register specifications.
    :param tmpdir: Temporary directory for writing test output files.
    """
    regs = Registers(
        family=FamilyRevision(TEST_DEVICE_NAME), feature="test", do_not_raise_exception=True
    )

    with use_working_directory(data_dir):
        regs._load_spec("registers_reserved.json")

    assert len(regs.get_registers()[0].get_bitfields()) == 1
    assert regs.get_registers()[0].get_bitfields()[0].get_value() == 0xA
    assert regs.get_registers()[0].get_value() == 0x550A00

    with use_working_directory(tmpdir):
        regs.write_spec("registers_reserved.json")

    regs2 = Registers(
        family=FamilyRevision(TEST_DEVICE_NAME), feature="test", do_not_raise_exception=True
    )

    with use_working_directory(tmpdir):
        regs2._load_spec("registers_reserved.json")

    assert str(regs) == str(regs2)


def test_registers_json_bad_format(data_dir: str) -> None:
    """Test that registers JSON loading raises SPSDKError for malformed JSON files.

    This test verifies that the Registers class properly handles and raises
    SPSDKError when attempting to load a JSON specification file with
    invalid JSON format.

    :param data_dir: Directory path containing test data files including the malformed JSON file.
    :raises SPSDKError: Expected exception when loading malformed JSON file.
    """
    regs = Registers(
        family=FamilyRevision(TEST_DEVICE_NAME), feature="test", do_not_raise_exception=True
    )

    with pytest.raises(SPSDKError):
        regs._load_spec(data_dir + "/bad_format.json")


def test_registers_corrupted_json(data_dir: str) -> None:
    """Test registers JSON support with invalid data.

    Verifies that the Registers class properly handles and raises SPSDKError
    when attempting to load corrupted or malformed JSON specification files.

    :param data_dir: Directory path containing test data files with corrupted JSON.
    :raises SPSDKError: When loading corrupted JSON specification files.
    """
    regs = Registers(
        family=FamilyRevision(TEST_DEVICE_NAME), feature="test", do_not_raise_exception=True
    )

    with pytest.raises(SPSDKError):
        with use_working_directory(data_dir):
            regs._load_spec("registers_corr.json")

    with pytest.raises(SPSDKError):
        with use_working_directory(data_dir):
            regs._load_spec("registers_corr2.json")


def test_basic_grouped_register(data_dir: str) -> None:
    """Test basic functionality of register grouping functionality.

    This test verifies that grouped registers can be properly loaded, configured,
    and accessed. It tests the creation of a grouped register from multiple
    sub-registers, value setting across the group, and individual access to
    sub-registers within the group.

    :param data_dir: Directory path containing test data files including the grouped registers JSON specification.
    """
    regs = Registers(
        family=FamilyRevision(TEST_DEVICE_NAME), feature="test", do_not_raise_exception=True
    )

    group = [
        {
            "name": "TestRegA",
            "uid": "TestGroup",
            "sub_regs": ["field400", "field404", "field408", "field40C"],
        }
    ]

    regs._load_spec(data_dir + "/grp_regs.json", grouped_regs=group)

    reg = regs.find_reg("TestRegA")
    assert reg.offset == 0x400
    assert reg.width == 4 * 32

    reg.set_value("0x01020304_11121314_21222324_31323334")
    assert regs.find_reg("TestRegA0", include_group_regs=True).get_hex_value() == "0x31323334"
    assert regs.find_reg("TestRegA1", include_group_regs=True).get_hex_value() == "0x21222324"
    assert regs.find_reg("TestRegA2", include_group_regs=True).get_hex_value() == "0x11121314"
    assert regs.find_reg("TestRegA3", include_group_regs=True).get_hex_value() == "0x01020304"
    assert not regs.find_reg("TestRegA0", include_group_regs=True).reverse
    assert not regs.find_reg("TestRegA1", include_group_regs=True).reverse
    assert not regs.find_reg("TestRegA2", include_group_regs=True).reverse
    assert not regs.find_reg("TestRegA3", include_group_regs=True).reverse
    assert reg.get_hex_value() == "0x01020304111213142122232431323334"


def test_basic_grouped_register_reversed_value(data_dir: str) -> None:
    """Test basic functionality of register grouping with reversed byte order.

    This test verifies that grouped registers correctly handle reversed value processing,
    where the grouped register maintains logical byte order while individual sub-registers
    store values in reversed format. It validates proper value setting, retrieval in both
    hex and bytes format, and reverse flag behavior across grouped and individual registers.

    :param data_dir: Path to directory containing test data files including register specifications.
    """
    regs = Registers(
        family=FamilyRevision(TEST_DEVICE_NAME), feature="test", do_not_raise_exception=True
    )

    group = [
        {
            "name": "TestRegA",
            "reversed": "True",
            "uid": "TestGroup",
            "sub_regs": ["field400", "field404", "field408", "field40C"],
        }
    ]

    regs._load_spec(data_dir + "/grp_regs.json", grouped_regs=group)

    reg = regs.find_reg("TestRegA")
    assert reg.offset == 0x400
    assert reg.width == 4 * 32

    reg.set_value("0x01020304_11121314_21222324_31323334")
    assert regs.find_reg("TestRegA0", include_group_regs=True).get_hex_value() == "0x04030201"
    assert regs.find_reg("TestRegA1", include_group_regs=True).get_hex_value() == "0x14131211"
    assert regs.find_reg("TestRegA2", include_group_regs=True).get_hex_value() == "0x24232221"
    assert regs.find_reg("TestRegA3", include_group_regs=True).get_hex_value() == "0x34333231"
    assert regs.find_reg("TestRegA", include_group_regs=True).reverse
    assert not regs.find_reg("TestRegA0", include_group_regs=True).reverse
    assert not regs.find_reg("TestRegA1", include_group_regs=True).reverse
    assert not regs.find_reg("TestRegA2", include_group_regs=True).reverse
    assert not regs.find_reg("TestRegA3", include_group_regs=True).reverse

    assert reg.get_hex_value() == "0x01020304111213142122232431323334"
    assert (
        reg.get_bytes_value() == b"\x01\x02\x03\x04\x11\x12\x13\x14\x21\x22\x23\x24\x31\x32\x33\x34"
    )
    assert (
        reg.get_bytes_value(raw=True)
        == b"\x34\x33\x32\x31\x24\x23\x22\x21\x14\x13\x12\x11\x04\x03\x02\x01"
    )


@pytest.mark.parametrize(
    "group_reg",
    [
        [{"uid": "test_grp", "name": "TestCorrupted0Reg", "sub_regs": ["field500", "field508"]}],
        [
            {
                "uid": "test_grp",
                "name": "TestRegA",
                "sub_regs": ["field400", "field404", "field408", "field40C"],
                "width": 96,
            }
        ],
        [
            {
                "uid": "test_grp",
                "name": "TestRegA",
                "sub_regs": ["field400", "field404", "field408", "field40C"],
                "offset": 0x410,
            }
        ],
        [{"uid": "test_grp", "name": "TestCorrupted1Reg", "sub_regs": ["field500", "field508"]}],
    ],
)
def test_grouped_register_invalid_params(data_dir: str, group_reg: str) -> None:
    """Test register grouping with invalid parameters.

    Verifies that loading register specifications with invalid grouped register
    parameters raises the appropriate exception for register group mismatches.

    :param data_dir: Directory path containing test data files
    :param group_reg: Invalid grouped register parameter to test
    :raises SPSDKRegsErrorRegisterGroupMishmash: When register grouping parameters are invalid
    """
    regs = Registers(
        family=FamilyRevision(TEST_DEVICE_NAME), feature="test", do_not_raise_exception=True
    )

    with pytest.raises(SPSDKRegsErrorRegisterGroupMishmash):
        regs._load_spec(data_dir + "/grp_regs.json", grouped_regs=group_reg)  # type: ignore


def test_load_register_value_with_uid(data_dir: str) -> None:
    """Test loading register values using both register name and UID.

    Verifies that registers can be loaded from configuration data using either
    the register name or UID, and that values are properly set in both cases.
    The test creates a Registers instance, loads a specification file, and tests
    loading configuration data using both register name and UID identifiers.

    :param data_dir: Directory path containing test register specification files.
    """
    regs = Registers(
        family=FamilyRevision(TEST_DEVICE_NAME), feature="test", do_not_raise_exception=True
    )
    regs._load_spec(data_dir + "/registers.json")
    reg = regs.find_reg(TEST_REG_NAME)
    data = Config({TEST_REG_NAME: 0x12345678})
    regs.load_from_config(data)
    assert reg.get_value() == 0x12345678
    reg.set_value(0)
    data = Config({TEST_REG_UID: 0x87654321})
    regs.load_from_config(data)
    assert reg.get_value() == 0x87654321


def test_load_grouped_register_value(data_dir: str) -> None:
    """Test loading individual registers into grouped registers from YAML configuration.

    This test verifies that the Registers class can properly load individual register
    values from a YAML configuration file and correctly group them into a grouped
    register, ensuring all sub-registers maintain their expected values.

    :param data_dir: Path to directory containing test data files (grp_regs.json and group_reg.yml).
    """
    regs = Registers(
        family=FamilyRevision(TEST_DEVICE_NAME), feature="test", do_not_raise_exception=True
    )

    group = [
        {
            "name": "TestRegA",
            "uid": "TestGroup",
            "sub_regs": ["field400", "field404", "field408", "field40C"],
        }
    ]
    regs._load_spec(data_dir + "/grp_regs.json", grouped_regs=group)
    data = Config.create_from_file(data_dir + "/group_reg.yml")
    regs.load_from_config(data)
    reg = regs.find_reg("TestRegA")
    assert reg.get_hex_value() == "0x01020304111213142122232431323334"
    assert regs.find_reg("TestRegA0", include_group_regs=True).get_hex_value() == "0x31323334"
    assert regs.find_reg("field404", include_group_regs=True).get_hex_value() == "0x21222324"
    assert regs.find_reg("TestRegA2", include_group_regs=True).get_hex_value() == "0x11121314"
    assert regs.find_reg("field40C", include_group_regs=True).get_hex_value() == "0x01020304"


def test_load_grouped_register_value_compatibility(data_dir: str) -> None:
    """Test loading individual registers into grouped registers from YAML configuration.

    This test verifies the compatibility of loading individual register values
    from a YAML file into a grouped register structure. It creates a grouped
    register configuration, loads register specifications, and validates that
    both the grouped register and its individual sub-registers contain the
    expected hexadecimal values.

    :param data_dir: Path to the directory containing test data files including
                     register specifications and YAML configuration files.
    """
    regs = Registers(
        family=FamilyRevision(TEST_DEVICE_NAME), feature="test", do_not_raise_exception=True
    )

    group = [
        {
            "name": "TestRegA",
            "uid": "TestGroup",
            "sub_regs": ["field400", "field404", "field408", "field40C"],
        }
    ]
    regs._load_spec(data_dir + "/grp_regs.json", grouped_regs=group)
    yaml = YAML()
    with open(data_dir + "/group_none_reg.yml", "r", encoding="utf-8") as yml_file:
        data = yaml.load(yml_file)
    regs.load_from_config(data)
    reg = regs.find_reg("TestRegA")
    assert reg.get_hex_value() == "0x01020304111213142122232431323334"
    assert regs.find_reg("TestRegA0", include_group_regs=True).get_hex_value() == "0x31323334"
    assert regs.find_reg("TestRegA1", include_group_regs=True).get_hex_value() == "0x21222324"
    assert regs.find_reg("TestRegA2", include_group_regs=True).get_hex_value() == "0x11121314"
    assert regs.find_reg("TestRegA3", include_group_regs=True).get_hex_value() == "0x01020304"


def test_create_yml() -> None:
    """Test YAML configuration generation from register objects.

    Validates that register objects can be properly converted to YAML configuration
    format with correct structure and values. Tests both simple register values
    and complex bitfield configurations including enumerated values.
    """
    regs = create_simple_regs()
    yml = regs.get_config()

    assert TEST_REG_NAME in yml.keys()
    assert TEST_REG_NAME + "_2" in yml.keys()
    assert int(yml[TEST_REG_NAME], 16) == TEST_REG_VALUE
    assert TEST_BITFIELD_NAME in yml[TEST_REG_NAME + "_2"].keys()
    assert yml[TEST_REG_NAME + "_2"][TEST_BITFIELD_NAME] == "0x1E"
    assert TEST_BITFIELD_NAME + "_2" in yml[TEST_REG_NAME + "_2"].keys()
    assert yml[TEST_REG_NAME + "_2"][TEST_BITFIELD_NAME + "_2"] == TEST_ENUM_NAME


REG0 = 0x00112233  # ADDR 0
REG1 = 0x44556677  # ADDR 4
REG2 = 0x8899AABB  # ADDR 8
REG3 = 0xCCDDEEFF  # ADDR C

REG0_REVERSED = 0x33221100  # ADDR 0
REG1_REVERSED = 0x77665544  # ADDR 4
REG2_REVERSED = 0xBBAA9988  # ADDR 8
REG3_REVERSED = 0xFFEEDDCC  # ADDR C

REG = 0xCCDDEEFF8899AABB4455667700112233
REG_REV_ORDER = 0x00112233445566778899AABBCCDDEEFF
REG_REVERSED_REGS = 0x3322110077665544BBAA9988FFEEDDCC
REG_REV_ORDER_REVERSED_REGS = 0xFFEEDDCCBBAA99887766554433221100

REG_REVERSED = 0x3322110077665544BBAA9988FFEEDDCC
REG_REV_ORDER_REVERSED = 0xFFEEDDCCBBAA99887766554433221100
REG_REVERSED_REGS_REVERSED = 0x00112233445566778899AABBCCDDEEFF
REG_REV_ORDER_REVERSED_REGS_REVERSED = 0xCCDDEEFF8899AABB4455667700112233

REGS_GRP = {
    "name": "REG",
    "uid": "TestReg",
    "sub_regs": [
        "field000",
        "field004",
        "field008",
        "field00C",
        "field010",
        "field014",
        "field018",
        "field01C",
    ],
    "width": 256,
    "description": "Test REGS",
}

REGS_REV_ORDER_GRP = {
    "name": "REG",
    "uid": "TestReg",
    "sub_regs": [
        "field000",
        "field004",
        "field008",
        "field00C",
        "field010",
        "field014",
        "field018",
        "field01C",
    ],
    "width": 256,
    "reverse_subregs_order": True,
    "description": "Test REGS reversed order",
}
REGS_REVERSED_GRP = {
    "name": "REG",
    "uid": "TestReg",
    "sub_regs": [
        "field000",
        "field004",
        "field008",
        "field00C",
        "field010",
        "field014",
        "field018",
        "field01C",
    ],
    "width": 256,
    "reversed": True,
    "description": "Test REGS reversed bytes",
}

REGS_REV_ORDER_REVERSED_GRP = {
    "name": "REG",
    "uid": "TestReg",
    "sub_regs": [
        "field000",
        "field004",
        "field008",
        "field00C",
        "field010",
        "field014",
        "field018",
        "field01C",
    ],
    "width": 256,
    "reversed": True,
    "reverse_subregs_order": True,
    "description": "Test REGS reversed order, reversed bytes",
}


@pytest.mark.parametrize(
    "json,reg_list,reg_list_raw,group,reg_group_val",
    [
        (
            "test_regs.json",
            {"REG0": REG0, "REG1": REG1, "REG2": REG2, "REG3": REG3},
            {"REG0": REG0, "REG1": REG1, "REG2": REG2, "REG3": REG3},
            REGS_GRP,
            REG,
        ),
        (
            "test_regs.json",
            {"REG7": REG0, "REG6": REG1, "REG5": REG2, "REG4": REG3},
            {"REG7": REG0, "REG6": REG1, "REG5": REG2, "REG4": REG3},
            REGS_REV_ORDER_GRP,
            REG,
        ),
        (
            "test_regs.json",
            {
                "REG7": REG0_REVERSED,
                "REG6": REG1_REVERSED,
                "REG5": REG2_REVERSED,
                "REG4": REG3_REVERSED,
            },
            {"REG0": REG0, "REG1": REG1, "REG2": REG2, "REG3": REG3},
            REGS_REVERSED_GRP,
            REG,
        ),
        (
            "test_regs.json",
            {
                "REG0": REG0_REVERSED,
                "REG1": REG1_REVERSED,
                "REG2": REG2_REVERSED,
                "REG3": REG3_REVERSED,
            },
            {"REG7": REG0, "REG6": REG1, "REG5": REG2, "REG4": REG3},
            REGS_REV_ORDER_REVERSED_GRP,
            REG,
        ),
    ],
)
def test_regs(
    data_dir: str,
    json: str,
    reg_list: dict[str, int],
    reg_list_raw: dict[str, int],
    group: dict[str, Any],
    reg_group_val: int,
) -> None:
    """Test register group functionality with both raw and non-raw value operations.

    This test validates the Registers class by loading a specification file,
    setting values on grouped registers, and verifying that sub-registers
    contain expected values in both raw and processed modes.

    :param data_dir: Directory path containing test data files.
    :param json: JSON specification file name to load.
    :param reg_list: Dictionary mapping register names to expected non-raw values.
    :param reg_list_raw: Dictionary mapping register names to expected raw values.
    :param group: Dictionary containing register group configuration.
    :param reg_group_val: Value to set on the register group for testing.
    """
    regs = Registers(
        family=FamilyRevision("Test device"),
        feature="test",
        base_endianness=Endianness.LITTLE,
        do_not_raise_exception=True,
    )
    regs._load_spec(os.path.join(data_dir, json), grouped_regs=[group])

    grp_reg = regs.find_reg(group["name"], True)
    sub_regs = regs.find_reg(group["name"], True).sub_regs

    # None Raw test
    grp_reg.set_value(reg_group_val)
    assert reg_group_val == grp_reg.get_value()

    for reg in sub_regs:
        if reg.name in reg_list:
            reg_val = reg.get_bytes_value().hex()
            excepted_val = value_to_bytes(
                reg_list[reg.name], byte_cnt=4, endianness=regs.base_endianness
            ).hex()
            assert reg_val == excepted_val

    regs.reset_values()

    # Raw test
    grp_reg.set_value(reg_group_val, raw=True)
    assert reg_group_val == grp_reg.get_value(raw=True)

    for reg in sub_regs:
        if reg.name in reg_list_raw:
            reg_val = reg.get_bytes_value().hex()
            excepted_val = value_to_bytes(
                reg_list_raw[reg.name], byte_cnt=4, endianness=regs.base_endianness
            ).hex()
            assert reg_val == excepted_val

    regs.reset_values()


def test_registers_size() -> None:
    """Test the registers size property.

    Verifies that the Registers.size property correctly calculates the total size
    based on register offsets and widths. Tests empty registers, single register,
    multiple registers with different offsets, and registers starting at offset zero.
    """
    # Create empty registers
    regs = Registers(
        family=FamilyRevision(TEST_DEVICE_NAME), feature="test", do_not_raise_exception=True
    )
    assert regs.size == 0

    # Add a register and check the size
    reg1 = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        TEST_REG_VALUE,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )
    regs.add_register(reg1)
    assert regs.size == TEST_REG_OFFSET + TEST_REG_WIDTH // 8

    # Add another register with higher offset and check the size
    reg2 = Register(
        TEST_REG_NAME + "_2",
        TEST_REG_OFFSET + 100,
        TEST_REG_WIDTH,
        TEST_REG_UID2,
        TEST_REG_DESCR + "_2",
        TEST_REG_VALUE,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )
    regs.add_register(reg2)
    assert regs.size == (TEST_REG_OFFSET + 100) + TEST_REG_WIDTH // 8

    regs = Registers(
        family=FamilyRevision(TEST_DEVICE_NAME), feature="test", do_not_raise_exception=True
    )
    reg_at_zero = Register(
        "RegAtZero",
        0,
        64,
        "reg_zero",
        "Register at offset 0",
        0,
        False,
        TEST_REG_ACCESS,
    )
    regs.add_register(reg_at_zero)
    assert regs.size == 64 // 8


class SPSDK_TestDatabase:
    """Mock SPSDK database for testing purposes.

    This singleton class provides a test database implementation that mimics
    the behavior of the production SPSDK database system. It manages both
    full database operations and quick database access for register testing
    scenarios.

    :cvar _instance: Singleton instance of the test database.
    :cvar _db: Cached Database instance for register operations.
    :cvar _quick_info: Cached QuickDatabase instance for quick access operations.
    """

    _instance: Optional["SPSDK_TestDatabase"] = None
    _db: Optional[Database] = None
    _quick_info: Optional[QuickDatabase] = None

    @property
    def db(self) -> Database:
        """Get the database instance for register operations.

        This method retrieves the cached database instance and ensures it's properly
        initialized before returning it to the caller.

        :raises AssertionError: If the database instance is not properly initialized.
        :return: The database instance used for register operations.
        """
        db = type(self)._db
        assert isinstance(db, Database)
        return db

    @property
    def quick_info(self) -> QuickDatabase:
        """Get quick info Database.

        Retrieves the cached QuickDatabase instance containing quick access information
        for register operations and configurations.

        :return: QuickDatabase instance with quick access register information.
        """
        quick_info = type(self)._quick_info
        assert isinstance(quick_info, QuickDatabase)
        return quick_info


@pytest.fixture
def mock_test_database(monkeypatch: Any, data_dir: str) -> None:
    """Set up a mock database for testing.

    This function initializes a test database instance and patches the DatabaseManager
    in both database and family modules to use the mock implementation for testing purposes.

    :param monkeypatch: Pytest monkeypatch fixture for mocking objects during tests.
    :param data_dir: Directory path containing the test database files.
    """
    SPSDK_TestDatabase._db = Database(os.path.join(data_dir, "test_db"), complete_load=True)
    SPSDK_TestDatabase._quick_info = QuickDatabase.create(SPSDK_TestDatabase._db)
    SPSDK_TestDatabase._instance = SPSDK_TestDatabase()
    monkeypatch.setattr(database, "DatabaseManager", SPSDK_TestDatabase)
    monkeypatch.setattr(family, "DatabaseManager", SPSDK_TestDatabase)


def test_register_deprecated_names(
    mock_test_database: Any,  # pylint: disable=redefined-outer-name
) -> None:
    """Test register deprecated names functionality.

    Verifies that registers can be found using both their current names and their
    deprecated names. Creates a registers container and tests that the same register
    object is returned when searching by current name versus deprecated name.

    :param mock_test_database: Mock database fixture for testing register functionality.
    """
    # Create a register with deprecated names
    # Create registers container
    regs = Registers(
        family=FamilyRevision("dev1"),  # Use a device that exists in the mock database
        feature="feature4",
        do_not_raise_exception=True,
    )
    # Test finding register by current name
    found_reg = regs.find_reg("REG1")
    assert found_reg

    # Test finding register by deprecated names
    found_reg_old = regs.find_reg("REG1_OLD")
    assert found_reg == found_reg_old


def test_register_deprecated_bitfields(
    mock_test_database: Any,  # pylint: disable=redefined-outer-name
) -> None:
    """Test register deprecated bitfield names functionality.

    Validates that bitfields can be found using both their current names and
    deprecated aliases, ensuring backward compatibility in the register system.

    :param mock_test_database: Mock database fixture containing test register definitions.
    """
    # Create a register with deprecated names
    # Create registers container
    regs = Registers(
        family=FamilyRevision("dev1"),  # Use a device that exists in the mock database
        feature="feature4",
        do_not_raise_exception=True,
    )
    # Test finding register by current name
    found_reg = regs.find_reg("REG1")
    assert found_reg

    bf = found_reg.find_bitfield("REG1_BF2")
    assert bf
    bf_old = found_reg.find_bitfield("REG1_BF2_OLD")
    assert bf == bf_old
    bf_old = found_reg.find_bitfield("REG1_BF2_SUPER_OLD")
    assert bf == bf_old


@pytest.mark.parametrize(
    "config,result",
    [
        (Config({TEST_REG_NAME: 0x0}), TEST_REG_NAME),
        (Config({TEST_REG_NAME.lower(): 0x0}), TEST_REG_NAME.lower()),
        (Config({TEST_REG_NAME.upper(): 0x0}), TEST_REG_NAME.upper()),
        (Config({TEST_REG_DEPRECATED_NAMES[0]: 0x0}), TEST_REG_DEPRECATED_NAMES[0]),
        (Config({TEST_REG_DEPRECATED_NAMES[0].lower(): 0x0}), TEST_REG_DEPRECATED_NAMES[0].lower()),
        (Config({TEST_REG_DEPRECATED_NAMES[1].upper(): 0x0}), TEST_REG_DEPRECATED_NAMES[1].upper()),
        (Config({"Unknown": 0x0}), None),
    ],
)
def test_find_reg_in_cfg(config: Config, result: str) -> None:
    """Test register configuration key finding functionality.

    This test verifies that a Register instance can correctly find its configuration
    key within a given Config object and returns the expected result string.

    :param config: Configuration object to search within for the register key.
    :param result: Expected string result from the find_config_key operation.
    """
    reg_name = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        TEST_REG_VALUE,
        TEST_REG_REV,
        TEST_REG_ACCESS,
        deprecated_names=TEST_REG_DEPRECATED_NAMES,
    ).find_config_key(config)
    assert reg_name == result


@pytest.mark.parametrize(
    "config,result",
    [
        (Config({TEST_BITFIELD_NAME: 0x0}), TEST_BITFIELD_NAME),
        (Config({TEST_BITFIELD_NAME.lower(): 0x0}), TEST_BITFIELD_NAME.lower()),
        (Config({TEST_BITFIELD_NAME.upper(): 0x0}), TEST_BITFIELD_NAME.upper()),
        (Config({TEST_BITFIELD_DEPRECATED_NAMES[0]: 0x0}), TEST_BITFIELD_DEPRECATED_NAMES[0]),
        (
            Config({TEST_BITFIELD_DEPRECATED_NAMES[0].lower(): 0x0}),
            TEST_BITFIELD_DEPRECATED_NAMES[0].lower(),
        ),
        (
            Config({TEST_BITFIELD_DEPRECATED_NAMES[0].upper(): 0x0}),
            TEST_BITFIELD_DEPRECATED_NAMES[0].upper(),
        ),
        (Config({"Unknown": 0x0}), None),
    ],
)
def test_find_bitfield_in_cfg(config: Config, result: str) -> None:
    """Test bitfield's find_config_key method with various configurations.

    This test verifies that the RegsBitField.find_config_key method correctly
    identifies configuration keys across different configuration scenarios,
    including handling of deprecated names and various naming patterns.

    :param config: Configuration object containing bitfield settings to search through.
    :param result: Expected configuration key name that should be found by the method.
    """
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        TEST_REG_VALUE,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_UID,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_ACCESS,
        deprecated_names=TEST_BITFIELD_DEPRECATED_NAMES,
    )

    bf_name = bitfield.find_config_key(config)
    assert bf_name == result


@pytest.mark.parametrize(
    "reg_name, passed",
    [
        (TEST_REG_NAME, True),
        (TEST_REG_NAME.upper(), True),
        (TEST_REG_DEPRECATED_NAMES[0], True),
        (TEST_REG_DEPRECATED_NAMES[0].upper(), True),
        ("Unknown", False),
    ],
)
@patch("spsdk.utils.schema_validator.SPSDK_SCHEMA_STRICT", True)
def test_validation_schemas_registers(reg_name: str, passed: bool) -> None:
    """Test validation schemas for registers with different register names.

    This test verifies that the register validation schema correctly accepts or rejects
    configurations based on the provided register name and expected outcome.

    :param reg_name: Name of the register to test in the configuration.
    :param passed: Whether the validation is expected to pass (True) or fail (False).
    """
    config = Config({reg_name: {"value": 0x0}})
    regs = create_simple_regs()
    regs_sch = regs.get_validation_schema()
    schemas = [regs_sch]
    if passed:
        config.check(schemas, check_unknown_props=True)
    else:
        with pytest.raises(SPSDKError):
            config.check(schemas, check_unknown_props=True)


@pytest.mark.parametrize(
    "reg_name, bitfield_name, passed",
    [
        (TEST_REG_NAME + "_2", TEST_BITFIELD_NAME, True),
        (TEST_REG_NAME + "_2", TEST_BITFIELD_NAME.upper(), True),
        (TEST_REG_NAME + "_2", TEST_BITFIELD_DEPRECATED_NAMES[0], True),
        (TEST_REG_NAME + "_2", TEST_BITFIELD_DEPRECATED_NAMES[0].upper(), True),
        (TEST_REG_NAME + "_2", "Unknown", False),
        ("Unknown", TEST_BITFIELD_NAME, False),
    ],
)
@patch("spsdk.utils.schema_validator.SPSDK_SCHEMA_STRICT", True)
def test_validation_schemas_bitfields(reg_name: str, bitfield_name: str, passed: bool) -> None:
    """Test validation schemas for bitfields with different case variations.

    This test verifies that register validation schemas correctly handle bitfield
    configurations in both direct and nested formats, and properly validate
    based on the expected pass/fail behavior.

    :param reg_name: Name of the register to test validation for.
    :param bitfield_name: Name of the bitfield within the register.
    :param passed: Expected validation result - True if validation should pass, False if it should raise an exception.
    :raises SPSDKError: When validation is expected to fail (passed=False).
    """
    regs = create_simple_regs()

    # Create config with the bitfield name
    configs = [
        Config({reg_name: {bitfield_name: 0x0}}),
        Config({reg_name: {"bitfields": {bitfield_name: 0x0}}}),
    ]

    # Get validation schema
    regs_sch = regs.get_validation_schema()
    schemas = [regs_sch]

    for config in configs:
        if passed:
            config.check(schemas, check_unknown_props=True)
        else:
            with pytest.raises(SPSDKError):
                config.check(schemas, check_unknown_props=True)


@pytest.mark.parametrize(
    "reg_name, passed",
    [
        ("TestReg", True),
        ("testreg", True),
        ("TESTREG", True),
        ("TeStReG", True),
        ("Unknown", False),
    ],
)
@patch("spsdk.utils.schema_validator.SPSDK_SCHEMA_STRICT", True)
def test_registers_pre_validation_hook(reg_name: str, passed: bool) -> None:
    """Test registers pre-validation hook functionality.

    Tests the RegistersPreValidationHook by processing a configuration with a register
    and validating it against a schema. Verifies that validation passes or fails
    as expected based on the test parameters.

    :param reg_name: Name of the register to test in the configuration.
    :param passed: Whether the validation is expected to pass (True) or fail (False).
    :raises SPSDKError: When passed is False, expects this exception during validation.
    """
    config = Config({reg_name: {"value": 0x0}})
    RegistersPreValidationHook().process_registers(config)
    regs = create_simple_regs()
    regs_sch = regs.get_validation_schema()
    schemas = [regs_sch]
    if passed:
        config.check(schemas, check_unknown_props=True)
    else:
        with pytest.raises(SPSDKError):
            config.check(schemas, check_unknown_props=True)
