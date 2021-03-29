#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for registers utility."""

import os
import filecmp
import pytest

from spsdk.utils.exceptions import (
    SPSDKRegsError, SPSDKRegsErrorRegisterGroupMishmash, SPSDKRegsErrorRegisterNotFound,
    SPSDKRegsErrorBitfieldNotFound,
    SPSDKRegsErrorEnumNotFound
)
from spsdk.utils.registers import (
    Registers,
    RegsRegister,
    RegsBitField,
    RegsEnum,
)

from spsdk.utils.reg_config import RegConfig

from spsdk.utils.misc import use_working_directory
from ruamel.yaml import YAML

TEST_DEVICE_NAME = "TestDevice1"
TEST_REG_NAME = "TestReg"
TEST_REG_OFFSET = 1024
TEST_REG_WIDTH = 32
TEST_REG_DESCR = "TestReg Description"
TEST_REG_REV = False
TEST_REG_ACCESS = "RW"
TEST_REG_VALUE = 0xA5A5A5A5

TEST_BITFIELD_NAME = "TestBitfiled"
TEST_BITFILED_OFFSET = 0x0F
TEST_BITFILED_WIDTH = 5
TEST_BITFIELD_RESET_VAL = 30
TEST_BITFIELD_ACCESS = "RW"
TEST_BITFIELD_DESCR = "Test Bitfield Description"
TEST_BITFIELD_SAVEVAL = 29
TEST_BITFIELD_OUTOFRANGEVAL = 70

TEST_ENUM_NAME = "TestEnum"
TEST_ENUM_VALUE_BIN = "0b10001"
TEST_ENUM_VALUE_HEX = "0x11"
TEST_ENUM_VALUE_STRINT = "017"
TEST_ENUM_VALUE_INT = 17
TEST_ENUM_VALUE_BYTES = b'\x11'
TEST_ENUM_RES_VAL = "0b01_0001"
TEST_ENUM_DESCR = "Test Enum Description"
TEST_ENUM_MAXWIDTH = 6

TEST_XML_FILE = "unit_test.xml"


def test_basic_regs(tmpdir):
    """Basic test of registers class."""
    regs = Registers(TEST_DEVICE_NAME)

    assert regs.dev_name == TEST_DEVICE_NAME

    reg1 = RegsRegister(TEST_REG_NAME, TEST_REG_OFFSET, TEST_REG_WIDTH, TEST_REG_DESCR, TEST_REG_REV, TEST_REG_ACCESS)

    with pytest.raises(SPSDKRegsErrorRegisterNotFound):
        regs.find_reg("NonExisting")

    # The Registers MUST return empty array
    assert regs.get_reg_names() == []

    with pytest.raises(TypeError):
        regs.remove_register("String")

    with pytest.raises(ValueError):
        regs.remove_register(reg1)

    # Now we could do tests with a register added to list
    regs.add_register(reg1)

    regs.remove_register_by_name(["String"])

    assert TEST_REG_NAME in regs.get_reg_names()

    regt = regs.find_reg(TEST_REG_NAME)

    assert regt == reg1

    with pytest.raises(TypeError):
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
    parent_reg = RegsRegister(TEST_REG_NAME,
                              TEST_REG_OFFSET,
                              TEST_REG_WIDTH,
                              TEST_REG_DESCR,
                              TEST_REG_REV,
                              TEST_REG_ACCESS)

    bitfield = RegsBitField(parent_reg,
                            TEST_BITFIELD_NAME,
                            TEST_BITFILED_OFFSET,
                            TEST_BITFILED_WIDTH,
                            TEST_BITFIELD_DESCR,
                            TEST_BITFIELD_RESET_VAL,
                            TEST_BITFIELD_ACCESS)

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


def test_register_invalid_val():
    """Invalid value register test."""
    reg = RegsRegister(TEST_REG_NAME,
                       TEST_REG_OFFSET,
                       TEST_REG_WIDTH,
                       TEST_REG_DESCR,
                       TEST_REG_REV,
                       TEST_REG_ACCESS)

    val = reg.get_value()
    reg.set_value("Invalid")
    assert reg.get_value() == val

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
    try:
        enum = RegsEnum(TEST_ENUM_NAME, "InvalidValue", TEST_ENUM_DESCR, TEST_ENUM_MAXWIDTH)
        printed_str = str(enum)
        assert "N/A" in printed_str
    except TypeError:
        assert 0


def test_bitfield():
    """Basic bitfield test."""
    parent_reg = RegsRegister(TEST_REG_NAME,
                              TEST_REG_OFFSET,
                              TEST_REG_WIDTH,
                              TEST_REG_DESCR,
                              TEST_REG_REV,
                              TEST_REG_ACCESS)

    bitfield = RegsBitField(parent_reg,
                            TEST_BITFIELD_NAME,
                            TEST_BITFILED_OFFSET,
                            TEST_BITFILED_WIDTH,
                            TEST_BITFIELD_DESCR,
                            TEST_BITFIELD_RESET_VAL,
                            TEST_BITFIELD_ACCESS)

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
    parent_reg = RegsRegister(TEST_REG_NAME,
                              TEST_REG_OFFSET,
                              TEST_REG_WIDTH,
                              TEST_REG_DESCR,
                              TEST_REG_REV,
                              TEST_REG_ACCESS)

    bitfield = RegsBitField(parent_reg,
                            TEST_BITFIELD_NAME,
                            TEST_BITFILED_OFFSET,
                            TEST_BITFILED_WIDTH,
                            TEST_BITFIELD_DESCR,
                            TEST_BITFIELD_RESET_VAL,
                            TEST_BITFIELD_ACCESS)

    enum = RegsEnum(TEST_ENUM_NAME, 0, TEST_ENUM_DESCR)
    bitfield.add_enum(enum)

    parent_reg.add_bitfield(bitfield)

    assert bitfield == parent_reg.find_bitfield(TEST_BITFIELD_NAME)

    with pytest.raises(SPSDKRegsErrorBitfieldNotFound):
        parent_reg.find_bitfield("Invalid Name")


def test_bitfields_names():
    """Test bitfield get names function."""
    parent_reg = RegsRegister(TEST_REG_NAME,
                              TEST_REG_OFFSET,
                              TEST_REG_WIDTH,
                              TEST_REG_DESCR,
                              TEST_REG_REV,
                              TEST_REG_ACCESS)

    bitfield = RegsBitField(parent_reg,
                            TEST_BITFIELD_NAME,
                            TEST_BITFILED_OFFSET,
                            TEST_BITFILED_WIDTH,
                            TEST_BITFIELD_DESCR,
                            TEST_BITFIELD_RESET_VAL,
                            TEST_BITFIELD_ACCESS)

    bitfield1 = RegsBitField(parent_reg,
                             TEST_BITFIELD_NAME+"1",
                             TEST_BITFILED_OFFSET,
                             TEST_BITFILED_WIDTH,
                             TEST_BITFIELD_DESCR,
                             TEST_BITFIELD_RESET_VAL,
                             TEST_BITFIELD_ACCESS)

    assert parent_reg.get_bitfield_names() == []

    parent_reg.add_bitfield(bitfield)
    parent_reg.add_bitfield(bitfield1)

    assert len(parent_reg.get_bitfield_names()) == 2

    names = parent_reg.get_bitfield_names()
    assert len(names) == 2
    assert TEST_BITFIELD_NAME in names
    assert TEST_BITFIELD_NAME+"1" in names

    ex_names = parent_reg.get_bitfield_names([TEST_BITFIELD_NAME+"1"])
    assert len(ex_names) == 1
    assert TEST_BITFIELD_NAME in ex_names

    ex_names1 = parent_reg.get_bitfield_names([TEST_BITFIELD_NAME])
    assert len(ex_names1) == 0


def test_bitfield_has_enums():
    """Test bitfield has enums function."""
    parent_reg = RegsRegister(TEST_REG_NAME,
                              TEST_REG_OFFSET,
                              TEST_REG_WIDTH,
                              TEST_REG_DESCR,
                              TEST_REG_REV,
                              TEST_REG_ACCESS)

    bitfield = RegsBitField(parent_reg,
                            TEST_BITFIELD_NAME,
                            TEST_BITFILED_OFFSET,
                            TEST_BITFILED_WIDTH,
                            TEST_BITFIELD_DESCR,
                            TEST_BITFIELD_RESET_VAL,
                            TEST_BITFIELD_ACCESS)

    parent_reg.add_bitfield(bitfield)

    assert bitfield.has_enums() is False
    enum = RegsEnum(TEST_ENUM_NAME, 0, TEST_ENUM_DESCR)
    bitfield.add_enum(enum)

    assert bitfield.has_enums() is True

    assert enum in bitfield.get_enums()


def test_bitfield_value():
    """Test bitfield functionality about values."""
    parent_reg = RegsRegister(TEST_REG_NAME,
                              TEST_REG_OFFSET,
                              TEST_REG_WIDTH,
                              TEST_REG_DESCR,
                              TEST_REG_REV,
                              TEST_REG_ACCESS)

    bitfield = RegsBitField(parent_reg,
                            TEST_BITFIELD_NAME,
                            TEST_BITFILED_OFFSET,
                            TEST_BITFILED_WIDTH,
                            TEST_BITFIELD_DESCR,
                            TEST_BITFIELD_RESET_VAL,
                            TEST_BITFIELD_ACCESS)

    bitfield.set_value(TEST_BITFIELD_SAVEVAL)
    assert bitfield.get_value() == TEST_BITFIELD_SAVEVAL

    with pytest.raises(ValueError):
        bitfield.set_value(TEST_BITFIELD_OUTOFRANGEVAL)


def test_bitfield_invalidvalue():
    """Test bitfield INVALID value."""
    parent_reg = RegsRegister(TEST_REG_NAME,
                              TEST_REG_OFFSET,
                              TEST_REG_WIDTH,
                              TEST_REG_DESCR,
                              TEST_REG_REV,
                              TEST_REG_ACCESS)

    bitfield = RegsBitField(parent_reg,
                            TEST_BITFIELD_NAME,
                            TEST_BITFILED_OFFSET,
                            TEST_BITFILED_WIDTH,
                            TEST_BITFIELD_DESCR,
                            "InvalidValue",
                            TEST_BITFIELD_ACCESS)

    assert bitfield.get_value() == 0


def test_bitfield_enums():
    """Test bitfield enums."""
    parent_reg = RegsRegister(TEST_REG_NAME,
                              TEST_REG_OFFSET,
                              TEST_REG_WIDTH,
                              TEST_REG_DESCR,
                              TEST_REG_REV,
                              TEST_REG_ACCESS)

    bitfield = RegsBitField(parent_reg,
                            TEST_BITFIELD_NAME,
                            TEST_BITFILED_OFFSET,
                            TEST_BITFILED_WIDTH,
                            TEST_BITFIELD_DESCR,
                            TEST_BITFIELD_RESET_VAL,
                            TEST_BITFIELD_ACCESS)

    parent_reg.add_bitfield(bitfield)

    enums = []
    for index in range((1 << TEST_BITFILED_WIDTH)-1):
        enum = RegsEnum(f"{TEST_ENUM_NAME}{index}", index, f"{TEST_ENUM_DESCR}{index}", TEST_BITFILED_WIDTH)
        enums.append(enum)
        bitfield.add_enum(enum)

    enum_names = bitfield.get_enum_names()

    for index in range((1 << TEST_BITFILED_WIDTH)-1):
        assert index == bitfield.get_enum_constant(f"{TEST_ENUM_NAME}{index}")
        assert enums[index].name in enum_names

    for index in range((1 << TEST_BITFILED_WIDTH)):
        bitfield.set_value(index)
        if index < (1 << TEST_BITFILED_WIDTH)-1:
            assert f"{TEST_ENUM_NAME}{index}" == bitfield.get_enum_value()
        else:
            assert index == bitfield.get_enum_value()

    for index in range((1 << TEST_BITFILED_WIDTH)-1):
        bitfield.set_enum_value(f"{TEST_ENUM_NAME}{index}")
        assert index == bitfield.get_value()

    with pytest.raises(SPSDKRegsErrorEnumNotFound):
        bitfield.get_enum_constant("Invalid name")


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
        regs.load_registers_from_xml(data_dir+"/bad_format.xml")


def test_registers_corrupted_xml(data_dir, tmpdir):
    """Test registers XML support with invalid data."""
    regs = Registers(TEST_DEVICE_NAME)

    with use_working_directory(data_dir):
        regs.load_registers_from_xml("registers_corr.xml")

    with use_working_directory(tmpdir):
        regs.write_xml("registers_corr.xml")

    assert not filecmp.cmp(os.path.join(data_dir, "registers_corr.xml"), os.path.join(tmpdir, "registers_corr.xml"))

    regs.clear()

    with use_working_directory(tmpdir):
        regs.load_registers_from_xml("registers_corr.xml")
        regs.write_xml("registers_corr1.xml")

    assert filecmp.cmp(os.path.join(tmpdir, "registers_corr.xml"), os.path.join(tmpdir, "registers_corr1.xml"))

    # Without clear - Cannot add register with same name as is already added
    with use_working_directory(tmpdir):
        regs.load_registers_from_xml("registers_corr.xml")
        regs.write_xml("registers_corr1.xml")

    assert filecmp.cmp(os.path.join(tmpdir, "registers_corr.xml"), os.path.join(tmpdir, "registers_corr1.xml"))


def test_reg_config_get_devices(data_dir):
    """Test Register Config - get_devices function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))
    devices = reg_config.get_devices()

    assert "test_device1" in devices
    assert "test_device2" in devices


def test_reg_config_get_devices_class(data_dir):
    """Test Register Config - get_devices class function."""
    devices = RegConfig.devices(os.path.join(data_dir, "reg_config.json"))

    assert "test_device1" in devices
    assert "test_device2" in devices


def test_reg_config_get_latest_revision(data_dir):
    """Test Register Config - get_latest_revision function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))

    rev = reg_config.get_latest_revision("test_device1")
    assert rev == "x1"

    rev = reg_config.get_latest_revision("test_device2")
    assert rev == "b0"


def test_reg_config_get_revisions(data_dir):
    """Test Register Config - get_revisions function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))

    revs = reg_config.get_revisions("test_device1")
    assert "x0" in revs
    assert "x1" in revs

    revs = reg_config.get_revisions("test_device2")
    assert "b0" in revs


def test_reg_config_get_address(data_dir):
    """Test Register Config - get_address function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))

    addr = reg_config.get_address("test_device1")
    assert addr == "0xA5A5_1234"

    addr = reg_config.get_address("test_device2", remove_underscore=True)
    assert addr == "0x40000000"


def test_reg_config_get_data_file(data_dir):
    """Test Register Config - get_data_file function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))

    data_file = reg_config.get_data_file("test_device1", "x0")
    assert os.path.join(data_dir, "test_device1_x0.xml") == data_file

    data_file = reg_config.get_data_file("test_device1", "x1")
    assert os.path.join(data_dir, "test_device1_x1.xml") == data_file

    data_file = reg_config.get_data_file("test_device2", "b0")
    assert os.path.join(data_dir, "test_device2_b0.xml") == data_file


def test_reg_config_get_antipole_regs(data_dir):
    """Test Register Config - get_antipole_regs function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))

    antipole = reg_config.get_antipole_regs("test_device1")
    assert antipole["INVERTED_REG"] == "INVERTED_REG_AP"

    antipole = reg_config.get_antipole_regs("test_device2")
    assert antipole["INVERTED_REG"] == "INVERTED_REG_AP"

    antipole = reg_config.get_antipole_regs()
    assert antipole["INVERTED_REG"] == "INVERTED_REG_AP"


def test_reg_config_get_computed_regs(data_dir):
    """Test Register Config - get_computed_registers function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))

    computed_regs = reg_config.get_computed_registers("test_device1")
    assert "COMPUTED_REG" in computed_regs

    computed_regs = reg_config.get_computed_registers("test_device2")
    assert "COMPUTED_REG_GENERAL" in computed_regs

    computed_regs = reg_config.get_computed_registers("invalid_device")
    assert "COMPUTED_REG_GENERAL" in computed_regs

    computed_regs = reg_config.get_computed_registers()
    assert "COMPUTED_REG_GENERAL" in computed_regs


def test_reg_config_get_seal_start_address(data_dir):
    """Test Register Config - get_seal_start_address function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))

    seal_address = reg_config.get_seal_start_address("test_device1")
    assert seal_address == "COMPUTED_REG"

    seal_address = reg_config.get_seal_start_address("test_device2")
    assert seal_address == "COMPUTED_REG2"

    seal_address = reg_config.get_seal_start_address("invalid_device")
    assert seal_address == "COMPUTED_REG2"

    seal_address = reg_config.get_seal_start_address()
    assert seal_address == "COMPUTED_REG2"


def test_reg_config_get_seal_count(data_dir):
    """Test Register Config - get_seal_count function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))

    seal_count = reg_config.get_seal_count("test_device1")
    assert seal_count == 4

    seal_count = reg_config.get_seal_count("test_device2")
    assert seal_count == 8

    seal_count = reg_config.get_seal_count("invalid_device")
    assert seal_count == 8

    seal_count = reg_config.get_seal_count()
    assert seal_count == 8


def test_reg_config_get_ignored_registers(data_dir):
    """Test Register Config - get_ignored_registers function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))

    ignored_registers = reg_config.get_ignored_registers("test_device1")
    assert "IGNORED_REG" in ignored_registers

    ignored_registers = reg_config.get_ignored_registers("test_device2")
    assert "IGNORED_REG_GENERAL" in ignored_registers

    ignored_registers = reg_config.get_ignored_registers("invalid_device")
    assert "IGNORED_REG_GENERAL" in ignored_registers

    ignored_registers = reg_config.get_ignored_registers()
    assert "IGNORED_REG_GENERAL" in ignored_registers


def test_reg_config_get_ignored_fields(data_dir):
    """Test Register Config - get_ignored_fields function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))

    ignored_fields = reg_config.get_ignored_fields("test_device1")
    assert "FIELD" in ignored_fields

    ignored_fields = reg_config.get_ignored_fields("test_device2")
    assert "FIELD_GENERAL" in ignored_fields

    ignored_fields = reg_config.get_ignored_fields("invalid_device")
    assert "FIELD_GENERAL" in ignored_fields

    ignored_fields = reg_config.get_ignored_fields()
    assert "FIELD_GENERAL" in ignored_fields


def test_reg_config_get_computed_fields(data_dir):
    """Test Register Config - get_computed_fields function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))

    computed_fields = reg_config.get_computed_fields("test_device1")
    assert computed_fields["COMPUTED_REG"]["TEST_FIELD1"] == "computed_reg_test_field1"
    assert computed_fields["COMPUTED_REG"]["TEST_FIELD2"] == "computed_reg_test_field2"
    assert computed_fields["COMPUTED_REG2"]["TEST_FIELD1"] == "computed_reg2_test_field1"
    assert computed_fields["COMPUTED_REG2"]["TEST_FIELD2"] == "computed_reg2_test_field2"


def test_reg_config_get_grouped_registers(data_dir):
    """Test Register Config - get_grouped_registers function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))

    grouped_registers = reg_config.get_grouped_registers("test_device1")
    assert grouped_registers[0]["name"] == "DeviceTest"
    grouped_registers = reg_config.get_grouped_registers("test_device2")
    assert grouped_registers[0]["name"] == "Test"


def test_basic_grouped_register(data_dir):
    """Test basic functionality of register grouping functionality"""
    regs = Registers(TEST_DEVICE_NAME)

    group = [
        {
            "name": "TestRegA"
        }
    ]

    regs.load_registers_from_xml(data_dir + "/grp_regs.xml", grouped_regs=group)

    reg = regs.find_reg("TestRegA")
    assert reg.offset == 0x400
    assert reg.width == 4*32

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

    group = [
        {
            "name": "TestRegA",
            "reverse": "True"
        }
    ]

    regs.load_registers_from_xml(data_dir + "/grp_regs.xml", grouped_regs=group)

    reg = regs.find_reg("TestRegA")
    assert reg.offset == 0x400
    assert reg.width == 4*32

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
        [{"name": "TestCorrupted2Reg", "width": 32}]
    ]
)
def test_grouped_register_invalid_params(data_dir, group_reg):
    """Test of register grouping with invalid width"""
    regs = Registers(TEST_DEVICE_NAME)

    with pytest.raises(SPSDKRegsErrorRegisterGroupMishmash):
        regs.load_registers_from_xml(data_dir + "/grp_regs.xml", grouped_regs=group_reg)


def test_load_grouped_register_value(data_dir):
    """Simply test to handle load of individual registers into grouped from YML."""
    regs = Registers(TEST_DEVICE_NAME)

    group = [
        {
            "name": "TestRegA"
        }
    ]
    regs.load_registers_from_xml(data_dir + "/grp_regs.xml", grouped_regs=group)
    yaml = YAML()
    with open(data_dir+"/group_reg.yml", "r") as yml_file:
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

    group = [
        {
            "name": "TestRegA"
        }
    ]
    regs.load_registers_from_xml(data_dir + "/grp_regs.xml", grouped_regs=group)
    yaml = YAML()
    with open(data_dir+"/group_none_reg.yml", "r") as yml_file:
        data = yaml.load(yml_file)
    regs.load_yml_config(data)
    reg = regs.find_reg("TestRegA")
    assert reg.get_hex_value() == "01020304111213142122232431323334"
    assert regs.find_reg("TestRegA0", include_group_regs=True).get_hex_value() == "0x01020304"
    assert regs.find_reg("TestRegA1", include_group_regs=True).get_hex_value() == "0x11121314"
    assert regs.find_reg("TestRegA2", include_group_regs=True).get_hex_value() == "0x21222324"
    assert regs.find_reg("TestRegA3", include_group_regs=True).get_hex_value() == "0x31323334"
