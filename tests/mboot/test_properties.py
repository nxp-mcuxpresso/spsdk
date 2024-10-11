#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.mboot.commands import CommandTag
from spsdk.mboot.exceptions import McuBootError
from spsdk.mboot.properties import (
    AvailablePeripheralsValue,
    BoolValue,
    DeviceUidValue,
    EnumValue,
    ExternalMemoryAttributesValue,
    FuseLockedStatus,
    IntListValue,
    IntValue,
    IrqNotifierPinValue,
    PropertyTag,
    Version,
    VersionValue,
    parse_property_value,
)


def test_version_class():
    version = Version("K0.1.2")
    assert version.mark == "K"
    assert version.major == 0
    assert version.minor == 1
    assert version.fixation == 2
    assert version.to_str() == "K0.1.2"
    assert version.to_str(no_mark=True) == "0.1.2"
    assert version.to_int() == 0x4B000102
    assert version.to_int(no_mark=True) == 0x00000102
    assert version > Version(major=0, minor=1, fixation=1)
    assert version >= Version("0.1.1")
    assert version < Version("0.2.1")
    assert version <= Version("0.2.1")
    assert version != Version(0x00000102)
    assert str(version)
    assert repr(version)
    with pytest.raises(McuBootError):
        _ = Version(0.5)


def test_none_value():
    value = parse_property_value(1000, [0])
    assert isinstance(value, IntListValue)


def test_bool_value():
    value = parse_property_value(PropertyTag.VERIFY_WRITES.tag, [0])
    assert isinstance(value, BoolValue)
    assert value.tag == PropertyTag.VERIFY_WRITES
    assert value.name == PropertyTag.VERIFY_WRITES.label
    assert value.desc == PropertyTag.VERIFY_WRITES.description
    assert not value
    assert value.to_int() == 0
    assert value.to_str() == "OFF"


def test_enum_value():
    value = parse_property_value(PropertyTag.FLASH_READ_MARGIN.tag, [0])
    assert isinstance(value, EnumValue)
    assert value.tag == PropertyTag.FLASH_READ_MARGIN
    assert value.name == PropertyTag.FLASH_READ_MARGIN.label
    assert value.desc == PropertyTag.FLASH_READ_MARGIN.description
    assert value.value == 0
    assert value.to_int() == 0
    assert value.to_str() == "NORMAL"


def test_int_value():
    value = parse_property_value(PropertyTag.FLASH_SIZE.tag, [1024])
    assert isinstance(value, IntValue)
    assert value.tag == PropertyTag.FLASH_SIZE
    assert value.name == PropertyTag.FLASH_SIZE.label
    assert value.desc == PropertyTag.FLASH_SIZE.description
    assert value.value == 1024
    assert value.to_str() == "1.0 kiB"
    assert value.to_int() == 1024


def test_int_value_fmt():
    value = IntValue(tag=3, raw_values=[2, 4, 5], str_format="hex")
    assert isinstance(value, IntValue)
    assert value.to_str() == "0x00000002"
    value = IntValue(tag=3, raw_values=[2, 4, 5])
    assert isinstance(value, IntValue)
    assert value.to_str() == "2"
    value = IntValue(tag=3, raw_values=[2, 4, 5], str_format="size")
    assert isinstance(value, IntValue)
    assert value.to_str() == "2 B"
    value = IntValue(tag=3, raw_values=[2, 4, 5], str_format="sth")
    assert isinstance(value, IntValue)
    assert value.to_str() == "sth"
    value = IntValue(tag=3, raw_values=[0], str_format="int32")
    assert isinstance(value, IntValue)
    assert value.to_str() == "0"
    value = IntValue(tag=3, raw_values=[0xFFFFFFFF], str_format="int32")
    assert isinstance(value, IntValue)
    assert value.to_str() == "-1"


def test_version_value():
    value = parse_property_value(PropertyTag.CURRENT_VERSION.tag, [0x4B000102])
    assert isinstance(value, VersionValue)
    assert value.tag == PropertyTag.CURRENT_VERSION
    assert value.name == PropertyTag.CURRENT_VERSION.label
    assert value.desc == PropertyTag.CURRENT_VERSION.description
    assert value.value == Version(0x4B000102)
    assert value.to_int() == 0x4B000102
    assert value.to_str() == "K0.1.2"


@pytest.mark.parametrize(
    "input_numbers, out_string , out_int",
    [
        (
            [0x5C000102, 0x45000222, 0x4B000333],
            "02 01 00 5C 22 02 00 45 33 03 00 4B",
            620180645013280992354566219,
        ),
        ([0, 0x426B0], "00 00 00 00 B0 26 04 00", 2955281408),
    ],
)
def test_device_uid_value(input_numbers, out_string, out_int):
    value = parse_property_value(PropertyTag.UNIQUE_DEVICE_IDENT.tag, input_numbers)
    assert isinstance(value, DeviceUidValue)
    assert value.tag == PropertyTag.UNIQUE_DEVICE_IDENT
    assert value.name == PropertyTag.UNIQUE_DEVICE_IDENT.label
    assert value.desc == PropertyTag.UNIQUE_DEVICE_IDENT.description
    assert value.to_int() == out_int
    assert value.to_str() == out_string


def test_available_commands():
    value = parse_property_value(PropertyTag.AVAILABLE_COMMANDS.tag, [0xF])
    assert value.tags == [1, 2, 3, 4]
    assert all(index in value for index in [1, 2, 3, 4])
    command_names = [CommandTag.get_label(i) for i in [1, 2, 3, 4]]
    assert all(name in value.to_str() for name in command_names)


def test_reserved_regions():
    value = parse_property_value(
        PropertyTag.RESERVED_REGIONS.tag,
        [
            0,
            0,
            805306368,
            805339135,
            536870912,
            536903679,
            67108864,
            67125247,
            335544320,
            335552511,
        ],
    )
    assert value.tag == 12
    expected_strings = [
        "0x30000000 - 0x30007FFF",
        "0x20000000 - 0x20007FFF",
        "0x04000000 - 0x04003FFF",
        "0x14000000 - 0x14001FFF",
    ]
    for expected_string in expected_strings:
        assert expected_string in str(value)


def test_available_peripherals_value():
    value = AvailablePeripheralsValue(tag=3, raw_values=[2, 3])
    assert value.to_int() == 2
    assert value.to_str() == "I2C-Slave"


def test_irq_notifier_pin_value():
    value = IrqNotifierPinValue(tag=4, raw_values=[2, 3])
    assert value.pin == 2
    assert value.port == 0
    assert value.enabled == False
    assert value.to_str() == "IRQ Port[0], Pin[2] is disabled"
    assert bool(value) == False


def test_external_memory_attributes():
    value = ExternalMemoryAttributesValue(tag=4, raw_values=[2, 3, 4, 5, 6, 7])
    assert value.to_str() == "Total Size:    4.0 kiB"
    value = ExternalMemoryAttributesValue(tag=4, raw_values=[1, 3, 4, 5, 6, 7])
    assert value.to_str() == "Start Address: 0x00000003"
    value = ExternalMemoryAttributesValue(tag=4, raw_values=[4, 3, 4, 5, 6, 7])
    assert value.to_str() == "Page Size:     5 B"
    value = ExternalMemoryAttributesValue(tag=4, raw_values=[8, 3, 4, 5, 6, 7])
    assert value.to_str() == "Sector Size:   6 B"
    value = ExternalMemoryAttributesValue(tag=4, raw_values=[16, 3, 4, 5, 6, 7])
    assert value.to_str() == "Block Size:    7 B"


def test_fuse_locked_status():
    value = FuseLockedStatus(tag=31, raw_values=[0x4, 0x1E17F00F, 0x30000, 65535, 0])
    assert "FUSE000: UNLOCKED" in value.to_str()
    assert "FUSE084: LOCKED" in value.to_str()
    assert "FUSE143: UNLOCKED" in value.to_str()

    fuses = value.get_fuses()
    assert not fuses[0].locked
    assert fuses[84].locked
