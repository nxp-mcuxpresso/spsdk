#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for registers utility."""

import os
from typing import List

import pytest
from ruamel.yaml import YAML

from spsdk import SPSDKError
from spsdk.utils.exceptions import (
    SPSDKRegsError,
    SPSDKRegsErrorBitfieldNotFound,
    SPSDKRegsErrorEnumNotFound,
    SPSDKRegsErrorRegisterGroupMishmash,
    SPSDKRegsErrorRegisterNotFound,
)
from spsdk.utils.misc import use_working_directory
from spsdk.utils.registers import Registers, RegsBitField, RegsEnum, RegsRegister

TEST_DEVICE_NAME = "TestDevice1"
TEST_REG_NAME = "TestReg"
TEST_REG_BC_NAME = "TestRegBc"
TEST_REG_OFFSET = 1024
TEST_REG_WIDTH = 32
TEST_REG_DESCR = "TestReg Description"
TEST_REG_REV = False
TEST_REG_ACCESS = "RW"
TEST_REG_VALUE = 0xA5A5A5A5

TEST_BITFIELD_NAME = "TestBitfiled"
TEST_BITFIELD_BC_NAME = "TestBitfiledBc"
TEST_BITFIELD_OFFSET = 0x0F
TEST_BITFIELD_WIDTH = 5
TEST_BITFIELD_RESET_VAL = 30
TEST_BITFIELD_ACCESS = "RW"
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

TEST_XML_FILE = "unit_test.xml"


def create_simple_regs():
    """Create siple reg structure with basic cases."""
    regs = Registers(TEST_DEVICE_NAME)

    reg1 = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    reg2 = RegsRegister(
        TEST_REG_NAME + "_2",
        TEST_REG_OFFSET + 4,
        TEST_REG_WIDTH,
        TEST_REG_DESCR + "_2",
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield1 = RegsBitField(
        reg2,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_RESET_VAL,
        TEST_BITFIELD_ACCESS,
    )

    bitfield2 = RegsBitField(
        reg2,
        TEST_BITFIELD_NAME + "_2",
        TEST_BITFIELD_OFFSET + TEST_BITFIELD_WIDTH,
        1,
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
    regs = Registers(TEST_DEVICE_NAME)

    assert regs.dev_name == TEST_DEVICE_NAME

    reg1 = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    with pytest.raises(SPSDKRegsErrorRegisterNotFound):
        regs.find_reg("NonExisting")

    # The Registers MUST return empty array
    assert regs.get_reg_names() == []

    with pytest.raises(SPSDKError):
        regs.remove_register("String")

    with pytest.raises(ValueError):
        regs.remove_register(reg1)

    # Now we could do tests with a register added to list
    regs.add_register(reg1)

    regs.remove_register_by_name(["String"])

    assert TEST_REG_NAME in regs.get_reg_names()

    regt = regs.find_reg(TEST_REG_NAME)

    assert regt == reg1

    with pytest.raises(SPSDKError):
        regs.add_register("Invalid Parameter")

    regt.set_value(TEST_REG_VALUE)
    assert reg1.get_value() == TEST_REG_VALUE.to_bytes(4, "big")

    filename = os.path.join(tmpdir, TEST_XML_FILE)
    regs.write_xml(filename)
    assert os.path.isfile(filename)

    printed_str = str(regs)

    assert TEST_DEVICE_NAME in printed_str
    assert TEST_REG_NAME in printed_str

    regs.remove_register_by_name([TEST_REG_NAME])

    with pytest.raises(SPSDKRegsErrorRegisterNotFound):
        regs.find_reg(TEST_REG_NAME)
        assert False


def test_register():
    """Basic registers test."""
    parent_reg = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
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
    reg = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )
    reg1 = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )
    regs = Registers(TEST_DEVICE_NAME)
    regs.add_register(reg)

    with pytest.raises(SPSDKRegsError):
        regs.add_register(reg1)


def test_register_invalid_val():
    """Invalid value register test."""
    reg = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
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
    enum = RegsEnum(TEST_ENUM_NAME, "InvalidValue", TEST_ENUM_DESCR, TEST_ENUM_MAXWIDTH)
    printed_str = str(enum)
    assert "N/A" in printed_str


def test_bitfield():
    """Basic bitfield test."""
    parent_reg = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
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
    parent_reg = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
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
    parent_reg = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_RESET_VAL,
        TEST_BITFIELD_ACCESS,
    )

    bitfield1 = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME + "1",
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
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
    parent_reg = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
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
    parent_reg = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_RESET_VAL,
        TEST_BITFIELD_ACCESS,
    )

    bitfield.set_value(TEST_BITFIELD_SAVEVAL)
    assert bitfield.get_value() == TEST_BITFIELD_SAVEVAL

    with pytest.raises(SPSDKError):
        bitfield.set_value(TEST_BITFIELD_OUTOFRANGEVAL)


def test_bitfield_invalidvalue():
    """Test bitfield INVALID value."""
    parent_reg = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_DESCR,
        "InvalidValue",
        TEST_BITFIELD_ACCESS,
    )

    assert bitfield.get_value() == 0


def test_bitfield_enums():
    """Test bitfield enums."""
    parent_reg = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
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
            assert index == bitfield.get_enum_value()

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
    parent_reg = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        parent_reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_RESET_VAL,
        TEST_BITFIELD_ACCESS,
    )

    parent_reg.add_bitfield(bitfield)
    bitfield.add_enum(RegsEnum(f"{TEST_ENUM_NAME}", 0, f"{TEST_ENUM_DESCR}", TEST_BITFIELD_WIDTH))
    with pytest.raises(SPSDKError):
        bitfield.set_enum_value(f"Invalid Enum name")


def test_registers_xml(data_dir, tmpdir):
    """Test registers XML support."""
    regs = Registers(TEST_DEVICE_NAME)

    with use_working_directory(data_dir):
        regs.load_registers_from_xml("registers.xml")

    with use_working_directory(tmpdir):
        regs.write_xml("registers.xml")

    regs2 = Registers(TEST_DEVICE_NAME)

    with use_working_directory(tmpdir):
        regs2.load_registers_from_xml("registers.xml")

    assert str(regs) == str(regs2)


def test_registers_xml_bad_format(data_dir):
    """Test registers XML support - BAd XML format exception."""
    regs = Registers(TEST_DEVICE_NAME)

    with pytest.raises(SPSDKRegsError):
        regs.load_registers_from_xml(data_dir + "/bad_format.xml")


def test_registers_corrupted_xml(data_dir):
    """Test registers XML support with invalid data."""
    regs = Registers(TEST_DEVICE_NAME)

    with pytest.raises(SPSDKError):
        with use_working_directory(data_dir):
            regs.load_registers_from_xml("registers_corr.xml")

    with pytest.raises(SPSDKError):
        with use_working_directory(data_dir):
            regs.load_registers_from_xml("registers_corr2.xml")


def test_basic_grouped_register(data_dir):
    """Test basic functionality of register grouping functionality"""
    regs = Registers(TEST_DEVICE_NAME)

    group = [{"name": "TestRegA"}]

    regs.load_registers_from_xml(data_dir + "/grp_regs.xml", grouped_regs=group)

    reg = regs.find_reg("TestRegA")
    assert reg.offset == 0x400
    assert reg.width == 4 * 32

    reg.set_value("01020304_11121314_21222324_31323334")
    assert regs.find_reg("TestRegA0", include_group_regs=True).get_hex_value() == "0x01020304"
    assert regs.find_reg("TestRegA1", include_group_regs=True).get_hex_value() == "0x11121314"
    assert regs.find_reg("TestRegA2", include_group_regs=True).get_hex_value() == "0x21222324"
    assert regs.find_reg("TestRegA3", include_group_regs=True).get_hex_value() == "0x31323334"
    assert regs.find_reg("TestRegA0", include_group_regs=True).reverse == False
    assert regs.find_reg("TestRegA1", include_group_regs=True).reverse == False
    assert regs.find_reg("TestRegA2", include_group_regs=True).reverse == False
    assert regs.find_reg("TestRegA3", include_group_regs=True).reverse == False
    assert reg.get_hex_value() == "01020304111213142122232431323334"


def test_basic_grouped_register_reversed_value(data_dir):
    """Test basic functionality of register grouping functionality with reversed value"""
    regs = Registers(TEST_DEVICE_NAME)

    group = [{"name": "TestRegA", "reverse": "True"}]

    regs.load_registers_from_xml(data_dir + "/grp_regs.xml", grouped_regs=group)

    reg = regs.find_reg("TestRegA")
    assert reg.offset == 0x400
    assert reg.width == 4 * 32

    reg.set_value("0x01020304_11121314_21222324_31323334")
    assert regs.find_reg("TestRegA0", include_group_regs=True).get_hex_value() == "0x01020304"
    assert regs.find_reg("TestRegA1", include_group_regs=True).get_hex_value() == "0x11121314"
    assert regs.find_reg("TestRegA2", include_group_regs=True).get_hex_value() == "0x21222324"
    assert regs.find_reg("TestRegA3", include_group_regs=True).get_hex_value() == "0x31323334"
    assert regs.find_reg("TestRegA0", include_group_regs=True).reverse == True
    assert regs.find_reg("TestRegA1", include_group_regs=True).reverse == True
    assert regs.find_reg("TestRegA2", include_group_regs=True).reverse == True
    assert regs.find_reg("TestRegA3", include_group_regs=True).reverse == True

    assert reg.get_hex_value() == "01020304111213142122232431323334"


@pytest.mark.parametrize(
    "group_reg",
    [
        [{"name": "TestCorrupted0Reg"}],
        [{"name": "TestRegA", "width": 96}],
        [{"name": "TestRegA", "offset": 0x410}],
        [{"name": "TestCorrupted1Reg"}],
        [{"name": "TestCorrupted1Reg", "width": 64}],
        [{"name": "TestRegA", "access": "R"}],
        [{"name": "TestCorrupted2Reg", "width": 32}],
    ],
)
def test_grouped_register_invalid_params(data_dir, group_reg):
    """Test of register grouping with invalid width"""
    regs = Registers(TEST_DEVICE_NAME)

    with pytest.raises(SPSDKRegsErrorRegisterGroupMishmash):
        regs.load_registers_from_xml(data_dir + "/grp_regs.xml", grouped_regs=group_reg)


def test_load_grouped_register_value(data_dir):
    """Simply test to handle load of individual registers into grouped from YML."""
    regs = Registers(TEST_DEVICE_NAME)

    group = [{"name": "TestRegA"}]
    regs.load_registers_from_xml(data_dir + "/grp_regs.xml", grouped_regs=group)
    yaml = YAML()
    with open(data_dir + "/group_reg.yml", "r") as yml_file:
        data = yaml.load(yml_file)
    regs.load_yml_config(data)
    reg = regs.find_reg("TestRegA")
    assert reg.get_hex_value() == "01020304111213142122232431323334"
    assert regs.find_reg("TestRegA0", include_group_regs=True).get_hex_value() == "0x01020304"
    assert regs.find_reg("TestRegA1", include_group_regs=True).get_hex_value() == "0x11121314"
    assert regs.find_reg("TestRegA2", include_group_regs=True).get_hex_value() == "0x21222324"
    assert regs.find_reg("TestRegA3", include_group_regs=True).get_hex_value() == "0x31323334"


def test_load_grouped_register_value_compatibility(data_dir):
    """Simply test to handle load of individual registers into grouped from YML."""
    regs = Registers(TEST_DEVICE_NAME)

    group = [{"name": "TestRegA"}]
    regs.load_registers_from_xml(data_dir + "/grp_regs.xml", grouped_regs=group)
    yaml = YAML()
    with open(data_dir + "/group_none_reg.yml", "r") as yml_file:
        data = yaml.load(yml_file)
    regs.load_yml_config(data)
    reg = regs.find_reg("TestRegA")
    assert reg.get_hex_value() == "01020304111213142122232431323334"
    assert regs.find_reg("TestRegA0", include_group_regs=True).get_hex_value() == "0x01020304"
    assert regs.find_reg("TestRegA1", include_group_regs=True).get_hex_value() == "0x11121314"
    assert regs.find_reg("TestRegA2", include_group_regs=True).get_hex_value() == "0x21222324"
    assert regs.find_reg("TestRegA3", include_group_regs=True).get_hex_value() == "0x31323334"


def test_backward_compatibility_regs():
    """Simple test for backward compatibility for registers names in configuration."""

    def bc_reg(reg: RegsRegister) -> List[str]:
        """Test translator for bc compatibility."""
        return [TEST_REG_BC_NAME]

    regs = Registers(TEST_DEVICE_NAME)
    reg = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )
    regs.add_register(reg)

    assert regs.get_bc_reg("Invalid") is None
    regs.enable_backward_compatibility(bc_reg)

    assert regs.get_bc_reg(TEST_REG_BC_NAME) == TEST_REG_NAME
    assert regs.get_bc_reg("Invalid") is None


def test_backward_compatibility_bitfields():
    """Simple test for backward compatibility for bitfields names in configuration."""

    def bc_bitfield(reg: RegsRegister, bitfield: RegsBitField) -> List[str]:
        """Test translator for bc compatibility."""
        return [TEST_BITFIELD_BC_NAME]

    reg = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_RESET_VAL,
        TEST_BITFIELD_ACCESS,
    )
    reg.add_bitfield(bitfield)

    assert reg.get_bc_bitfield("Invalid") is None
    reg.enable_backward_compatibility(bc_bitfield)

    assert reg.get_bc_bitfield(TEST_BITFIELD_BC_NAME) == TEST_BITFIELD_NAME
    assert reg.get_bc_bitfield("Invalid") is None


def test_backward_compatibility_enums():
    """Simple test for backward compatibility for enum names in configuration."""

    def bc_enum(reg: RegsRegister, bitfield: RegsBitField, enum: RegsEnum) -> List[str]:
        """Test translator for bc compatibility."""
        return [TEST_ENUM_BC_NAME]

    reg = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_RESET_VAL,
        TEST_BITFIELD_ACCESS,
    )

    enum = RegsEnum(TEST_ENUM_NAME, 0, TEST_ENUM_DESCR, TEST_BITFIELD_WIDTH)
    reg.add_bitfield(bitfield)
    bitfield.add_enum(enum)

    assert bitfield.get_bc_enum("Invalid") is None
    bitfield.enable_backward_compatibility(bc_enum)

    assert bitfield.get_bc_enum(TEST_ENUM_BC_NAME) == TEST_ENUM_NAME
    assert bitfield.get_bc_enum("Invalid") is None


def test_backward_compatibility_enums_global():
    """Simple test for backward compatibility for enum names in configuration."""

    def bc_enum(reg: RegsRegister, bitfield: RegsBitField, enum: RegsEnum) -> List[str]:
        """Test translator for bc compatibility."""
        return [TEST_ENUM_BC_NAME]

    regs = Registers(TEST_DEVICE_NAME)

    reg = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )

    bitfield = RegsBitField(
        reg,
        TEST_BITFIELD_NAME,
        TEST_BITFIELD_OFFSET,
        TEST_BITFIELD_WIDTH,
        TEST_BITFIELD_DESCR,
        TEST_BITFIELD_RESET_VAL,
        TEST_BITFIELD_ACCESS,
    )

    enum = RegsEnum(TEST_ENUM_NAME, 0, TEST_ENUM_DESCR, TEST_BITFIELD_WIDTH)
    reg.add_bitfield(bitfield)
    bitfield.add_enum(enum)

    regs.add_register(reg)

    assert bitfield.get_bc_enum("Invalid") is None
    regs.enable_backward_compatibility_enums(bc_enum)

    assert bitfield.get_bc_enum(TEST_ENUM_BC_NAME) == TEST_ENUM_NAME
    assert bitfield.get_bc_enum("Invalid") is None


def test_backward_compatibility_regs_yml():
    """Simple test for backward compatibility for registers names in configuration."""

    def bc_reg(reg: RegsRegister) -> List[str]:
        """Test translator for bc compatibility."""
        if reg.name == TEST_REG_NAME:
            return [TEST_REG_BC_NAME]

        return []

    yml = {TEST_REG_BC_NAME: {"value": 0x01}}

    regs = Registers(TEST_DEVICE_NAME)
    reg = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )
    regs.add_register(reg)

    assert regs.get_bc_reg(TEST_REG_BC_NAME) is None
    regs.enable_backward_compatibility(bc_reg)

    regs.load_yml_config(yml)
    assert reg.get_int_value() == 0x01


def test_backward_nodata_yml():
    """Simple test for backward compatibility for registers names in configuration."""

    yml = {TEST_REG_NAME: {"invalid_key": 0x01}}

    regs = Registers(TEST_DEVICE_NAME)
    reg = RegsRegister(
        TEST_REG_NAME,
        TEST_REG_OFFSET,
        TEST_REG_WIDTH,
        TEST_REG_DESCR,
        TEST_REG_REV,
        TEST_REG_ACCESS,
    )
    regs.add_register(reg)
    regs.load_yml_config(yml)
    assert reg.get_int_value() != 0x01


def test_create_yml():
    """Simple test to create YML record."""
    regs = create_simple_regs()
    yml = regs.create_yml_config()

    assert TEST_REG_NAME in yml.keys()
    assert TEST_REG_NAME + "_2" in yml.keys()
    assert "value" in yml[TEST_REG_NAME].keys()
    assert yml[TEST_REG_NAME]["value"] == "0x00000000"
    assert "bitfields" in yml[TEST_REG_NAME + "_2"].keys()
    assert TEST_BITFIELD_NAME in yml[TEST_REG_NAME + "_2"]["bitfields"].keys()
    assert yml[TEST_REG_NAME + "_2"]["bitfields"][TEST_BITFIELD_NAME] == 30
    assert TEST_BITFIELD_NAME + "_2" in yml[TEST_REG_NAME + "_2"]["bitfields"].keys()
    assert yml[TEST_REG_NAME + "_2"]["bitfields"][TEST_BITFIELD_NAME + "_2"] == TEST_ENUM_NAME


def test_create_yml_excluded_regs():
    """Simple test to create YML record."""
    regs = create_simple_regs()
    yml = regs.create_yml_config(exclude_regs=[TEST_REG_NAME + "_2"])

    assert TEST_REG_NAME in yml.keys()
    assert "value" in yml[TEST_REG_NAME].keys()
    assert yml[TEST_REG_NAME]["value"] == "0x00000000"
    assert TEST_REG_NAME + "_2" not in yml.keys()


def test_create_yml_excluded_fields():
    """Simple test to create YML record."""
    regs = create_simple_regs()
    yml = regs.create_yml_config(
        exclude_fields={TEST_REG_NAME + "_2": {TEST_BITFIELD_NAME + "_2": ""}}
    )

    assert TEST_REG_NAME in yml.keys()
    assert "value" in yml[TEST_REG_NAME].keys()
    assert yml[TEST_REG_NAME]["value"] == "0x00000000"
    assert TEST_REG_NAME + "_2" in yml.keys()
    assert TEST_BITFIELD_NAME in yml[TEST_REG_NAME + "_2"]["bitfields"].keys()
    assert yml[TEST_REG_NAME + "_2"]["bitfields"][TEST_BITFIELD_NAME] == 30
    assert TEST_BITFIELD_NAME + "_2" not in yml[TEST_REG_NAME + "_2"]["bitfields"].keys()


def test_create_yml_ignored_fields():
    """Simple test to create YML record."""
    regs = create_simple_regs()
    yml = regs.create_yml_config(ignored_fields=[TEST_BITFIELD_NAME + "_2"])

    assert TEST_REG_NAME in yml.keys()
    assert "value" in yml[TEST_REG_NAME].keys()
    assert yml[TEST_REG_NAME]["value"] == "0x00000000"
    assert TEST_REG_NAME + "_2" in yml.keys()
    assert TEST_BITFIELD_NAME in yml[TEST_REG_NAME + "_2"]["bitfields"].keys()
    assert yml[TEST_REG_NAME + "_2"]["bitfields"][TEST_BITFIELD_NAME] == 30
    assert TEST_BITFIELD_NAME + "_2" not in yml[TEST_REG_NAME + "_2"]["bitfields"].keys()
