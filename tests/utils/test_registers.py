#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for registers utility."""

import os
from typing import Any

import pytest
from ruamel.yaml import YAML

from spsdk.exceptions import SPSDKError
from spsdk.utils.exceptions import (
    SPSDKRegsError,
    SPSDKRegsErrorBitfieldNotFound,
    SPSDKRegsErrorEnumNotFound,
    SPSDKRegsErrorRegisterGroupMishmash,
    SPSDKRegsErrorRegisterNotFound,
)
from spsdk.utils.misc import (
    Endianness,
    load_configuration,
    use_working_directory,
    value_to_bytes,
    value_to_int,
)
from spsdk.utils.registers import Access, Registers, RegsBitField, RegsEnum, Register

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


def create_simple_regs():
    """Create simple reg structure with basic cases."""
    regs = Registers(family=TEST_DEVICE_NAME, feature="test")

    reg1 = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    reg2 = Register(
        TEST_REG_NAME + "_2",
        TEST_REG_OFFSET + 4,
        TEST_REG_WIDTH,
        TEST_REG_UID2,
        TEST_REG_DESCR + "_2",
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
        TEST_BITFIELD_RESET_VAL,
        TEST_BITFIELD_ACCESS,
    )

    bitfield2 = RegsBitField(
        reg2,
        TEST_BITFIELD_NAME + "_2",
        TEST_BITFIELD_OFFSET + TEST_BITFIELD_WIDTH,
        1,
        TEST_BITFIELD_UID2,
        ".",
        0,
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


def test_basic_regs(tmpdir):
    """Basic test of registers class."""
    regs = Registers(family=TEST_DEVICE_NAME, feature="test")

    assert regs.family == TEST_DEVICE_NAME

    reg1 = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
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
        regs.add_register("Invalid Parameter")

    regt.set_value(TEST_REG_VALUE)
    assert reg1.get_value() == TEST_REG_VALUE


def test_register():
    """Basic registers test."""
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
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
        TEST_BITFIELD_RESET_VAL,
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


def test_register_duplicate():
    """Test registers add duplicate."""
    reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )
    reg1 = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID2,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )
    regs = Registers(family=TEST_DEVICE_NAME, feature="test")
    regs.add_register(reg)

    with pytest.raises(SPSDKRegsError):
        regs.add_register(reg1)


def test_register_invalid_val():
    """Invalid value register test."""
    reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
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


def test_enum():
    """Basic Enum test."""
    enum = RegsEnum(TEST_ENUM_NAME, 0, TEST_ENUM_DESCR)

    printed_str = str(enum)

    assert "Name:" in printed_str
    assert "Value:" in printed_str
    assert "Description:" in printed_str
    assert TEST_ENUM_NAME in printed_str
    assert "0x0" in printed_str
    assert TEST_ENUM_DESCR in printed_str


def test_enum_bin():
    """Enum test with binary value."""
    enum = RegsEnum(TEST_ENUM_NAME, TEST_ENUM_VALUE_BIN, TEST_ENUM_DESCR, TEST_ENUM_MAXWIDTH)
    printed_str = str(enum)
    assert TEST_ENUM_RES_VAL in printed_str


def test_enum_hex():
    """Enum test with hexadecimal value."""
    enum = RegsEnum(TEST_ENUM_NAME, TEST_ENUM_VALUE_HEX, TEST_ENUM_DESCR, TEST_ENUM_MAXWIDTH)
    printed_str = str(enum)
    assert TEST_ENUM_RES_VAL in printed_str


def test_enum_strint():
    """Enum test with integer in string value."""
    enum = RegsEnum(TEST_ENUM_NAME, TEST_ENUM_VALUE_STRINT, TEST_ENUM_DESCR, TEST_ENUM_MAXWIDTH)
    printed_str = str(enum)
    assert TEST_ENUM_RES_VAL in printed_str


def test_enum_int():
    """Enum test with integer value."""
    enum = RegsEnum(TEST_ENUM_NAME, TEST_ENUM_VALUE_INT, TEST_ENUM_DESCR, TEST_ENUM_MAXWIDTH)
    printed_str = str(enum)
    assert TEST_ENUM_RES_VAL in printed_str


def test_enum_bytes():
    """Enum test with bytes array value."""
    enum = RegsEnum(TEST_ENUM_NAME, TEST_ENUM_VALUE_BYTES, TEST_ENUM_DESCR, TEST_ENUM_MAXWIDTH)
    printed_str = str(enum)
    assert TEST_ENUM_RES_VAL in printed_str


def test_enum_invalidval():
    """Enum test with INVALID value."""
    with pytest.raises(SPSDKRegsError):
        RegsEnum(TEST_ENUM_NAME, "InvalidValue", TEST_ENUM_DESCR, TEST_ENUM_MAXWIDTH)


def test_bitfield():
    """Basic bitfield test."""
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
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
        TEST_BITFIELD_RESET_VAL,
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


def test_bitfield_find():
    """Test bitfield find function."""
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
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
        TEST_BITFIELD_RESET_VAL,
        TEST_BITFIELD_ACCESS,
    )

    enum = RegsEnum(TEST_ENUM_NAME, 0, TEST_ENUM_DESCR)
    bitfield.add_enum(enum)

    parent_reg.add_bitfield(bitfield)

    assert bitfield == parent_reg.find_bitfield(TEST_BITFIELD_NAME)

    with pytest.raises(SPSDKRegsErrorBitfieldNotFound):
        parent_reg.find_bitfield("Invalid Name")


def test_bitfields_names():
    """Test bitfield get names function."""
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
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
        TEST_BITFIELD_RESET_VAL,
        TEST_BITFIELD_ACCESS,
    )

    bitfield1 = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME + "1",
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_UID2,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_RESET_VAL,
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


def test_bitfield_has_enums():
    """Test bitfield has enums function."""
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
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
        TEST_BITFIELD_RESET_VAL,
        TEST_BITFIELD_ACCESS,
    )

    parent_reg.add_bitfield(bitfield)

    assert bitfield.has_enums() is False
    enum = RegsEnum(TEST_ENUM_NAME, 0, TEST_ENUM_DESCR)
    bitfield.add_enum(enum)

    assert bitfield.has_enums() is True

    assert enum in bitfield.get_enums()


def test_bitfield_value():
    """Test bitfield functionality about values."""
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
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
        None,
        TEST_BITFIELD_ACCESS,
    )

    assert bitfield.get_value() == 0

    bitfield.set_value(TEST_BITFIELD_SAVEVAL)
    assert bitfield.get_value() == TEST_BITFIELD_SAVEVAL

    with pytest.raises(SPSDKError):
        bitfield.set_value(TEST_BITFIELD_OUTOFRANGEVAL)


def test_bitfield_invalidvalue():
    """Test bitfield INVALID value."""
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    with pytest.raises(SPSDKError):
        RegsBitField(
            parent_reg,
            TEST_BITFIELD_NAME,
            TEST_BITFIELD_OFFSET,
            TEST_BITFIELD_WIDTH,
            TEST_BITFIELD_UID,
            TEST_BITFIELD_DESCR,
            "InvalidValue",
            TEST_BITFIELD_ACCESS,
        )


def test_bitfield_enums():
    """Test bitfield enums."""
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
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
        TEST_BITFIELD_RESET_VAL,
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


def test_bitfield_enums_invalid_name():
    """Test bitfield enums with invalid enum name."""
    parent_reg = Register(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_UID,
        TEST_REG_DESCR,
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
        TEST_BITFIELD_RESET_VAL,
        TEST_BITFIELD_ACCESS,
    )

    parent_reg.add_bitfield(bitfield)
    bitfield.add_enum(RegsEnum(f"{TEST_ENUM_NAME}", 0, f"{TEST_ENUM_DESCR}", TEST_BITFIELD_WIDTH))
    with pytest.raises(SPSDKError):
        bitfield.set_enum_value("Invalid Enum name")


def test_registers_json(data_dir, tmpdir):
    """Test registers JSON support."""
    regs = Registers(family=TEST_DEVICE_NAME, feature="test")

    with use_working_directory(data_dir):
        regs._load_spec("registers.json")

    with use_working_directory(tmpdir):
        regs.write_spec("registers.json")

    regs2 = Registers(family=TEST_DEVICE_NAME, feature="test")

    with use_working_directory(tmpdir):
        regs2._load_spec("registers.json")

    assert str(regs) == str(regs2)


def test_registers_json_hidden(data_dir, tmpdir):
    """Test registers JSON support."""
    regs = Registers(family=TEST_DEVICE_NAME, feature="test")

    with use_working_directory(data_dir):
        regs._load_spec("registers_reserved.json")

    assert len(regs.get_registers()[0].get_bitfields()) == 1
    assert regs.get_registers()[0].get_bitfields()[0].get_value() == 0xA
    assert regs.get_registers()[0].get_value() == 0x550A00

    with use_working_directory(tmpdir):
        regs.write_spec("registers_reserved.json")

    regs2 = Registers(family=TEST_DEVICE_NAME, feature="test")

    with use_working_directory(tmpdir):
        regs2._load_spec("registers_reserved.json")

    assert str(regs) == str(regs2)


def test_registers_json_bad_format(data_dir):
    """Test registers JSON support - BAd JSON format exception."""
    regs = Registers(family=TEST_DEVICE_NAME, feature="test")

    with pytest.raises(SPSDKError):
        regs._load_spec(data_dir + "/bad_format.json")


def test_registers_corrupted_json(data_dir):
    """Test registers JSON support with invalid data."""
    regs = Registers(family=TEST_DEVICE_NAME, feature="test")

    with pytest.raises(SPSDKError):
        with use_working_directory(data_dir):
            regs._load_spec("registers_corr.json")

    with pytest.raises(SPSDKError):
        with use_working_directory(data_dir):
            regs._load_spec("registers_corr2.json")


def test_basic_grouped_register(data_dir):
    """Test basic functionality of register grouping functionality"""
    regs = Registers(family=TEST_DEVICE_NAME, feature="test")

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
    assert regs.find_reg("TestRegA0", include_group_regs=True).reverse == False
    assert regs.find_reg("TestRegA1", include_group_regs=True).reverse == False
    assert regs.find_reg("TestRegA2", include_group_regs=True).reverse == False
    assert regs.find_reg("TestRegA3", include_group_regs=True).reverse == False
    assert reg.get_hex_value() == "0x01020304111213142122232431323334"


def test_basic_grouped_register_reversed_value(data_dir):
    """Test basic functionality of register grouping functionality with reversed value"""
    regs = Registers(family=TEST_DEVICE_NAME, feature="test")

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
    assert regs.find_reg("TestRegA", include_group_regs=True).reverse == True
    assert regs.find_reg("TestRegA0", include_group_regs=True).reverse == False
    assert regs.find_reg("TestRegA1", include_group_regs=True).reverse == False
    assert regs.find_reg("TestRegA2", include_group_regs=True).reverse == False
    assert regs.find_reg("TestRegA3", include_group_regs=True).reverse == False

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
def test_grouped_register_invalid_params(data_dir, group_reg):
    """Test of register grouping with invalid width"""
    regs = Registers(family=TEST_DEVICE_NAME, feature="test")

    with pytest.raises(SPSDKRegsErrorRegisterGroupMishmash):
        regs._load_spec(data_dir + "/grp_regs.json", grouped_regs=group_reg)


def test_load_register_value_with_uid(data_dir):
    """Simply test to handle load of individual registers into grouped from YML."""
    regs = Registers(family=TEST_DEVICE_NAME, feature="test")
    regs._load_spec(data_dir + "/registers.json")
    reg = regs.find_reg(TEST_REG_NAME)
    data = {TEST_REG_NAME: 0x12345678}
    regs.load_yml_config(data)
    assert reg.get_value() == 0x12345678
    reg.set_value(0)
    data = {TEST_REG_UID: 0x87654321}
    regs.load_yml_config(data)
    assert reg.get_value() == 0x87654321


def test_load_grouped_register_value(data_dir):
    """Simply test to handle load of individual registers into grouped from YML."""
    regs = Registers(family=TEST_DEVICE_NAME, feature="test")

    group = [
        {
            "name": "TestRegA",
            "uid": "TestGroup",
            "sub_regs": ["field400", "field404", "field408", "field40C"],
        }
    ]
    regs._load_spec(data_dir + "/grp_regs.json", grouped_regs=group)
    data = load_configuration(data_dir + "/group_reg.yml")
    regs.load_yml_config(data)
    reg = regs.find_reg("TestRegA")
    assert reg.get_hex_value() == "0x01020304111213142122232431323334"
    assert regs.find_reg("TestRegA0", include_group_regs=True).get_hex_value() == "0x31323334"
    assert regs.find_reg("field404", include_group_regs=True).get_hex_value() == "0x21222324"
    assert regs.find_reg("TestRegA2", include_group_regs=True).get_hex_value() == "0x11121314"
    assert regs.find_reg("field40C", include_group_regs=True).get_hex_value() == "0x01020304"


def test_load_grouped_register_value_compatibility(data_dir):
    """Simply test to handle load of individual registers into grouped from YML."""
    regs = Registers(family=TEST_DEVICE_NAME, feature="test")

    group = [
        {
            "name": "TestRegA",
            "uid": "TestGroup",
            "sub_regs": ["field400", "field404", "field408", "field40C"],
        }
    ]
    regs._load_spec(data_dir + "/grp_regs.json", grouped_regs=group)
    yaml = YAML()
    with open(data_dir + "/group_none_reg.yml", "r") as yml_file:
        data = yaml.load(yml_file)
    regs.load_yml_config(data)
    reg = regs.find_reg("TestRegA")
    assert reg.get_hex_value() == "0x01020304111213142122232431323334"
    assert regs.find_reg("TestRegA0", include_group_regs=True).get_hex_value() == "0x31323334"
    assert regs.find_reg("TestRegA1", include_group_regs=True).get_hex_value() == "0x21222324"
    assert regs.find_reg("TestRegA2", include_group_regs=True).get_hex_value() == "0x11121314"
    assert regs.find_reg("TestRegA3", include_group_regs=True).get_hex_value() == "0x01020304"


def test_create_yml():
    """Simple test to create YML record."""
    regs = create_simple_regs()
    yml = regs.get_config()

    assert TEST_REG_NAME in yml.keys()
    assert TEST_REG_NAME + "_2" in yml.keys()
    assert yml[TEST_REG_NAME] == "0x00000000"
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
):
    regs = Registers(family="Test device", feature="test", base_endianness=Endianness.LITTLE)
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
