#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.mboot.commands import CommandTag
from spsdk.mboot.exceptions import McuBootError
from spsdk.mboot.properties import (
    BoolValue,
    DeviceUidValue,
    EnumValue,
    IntValue,
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


def test_mone_value():
    value = parse_property_value(1000, [0])
    assert value is None


def test_bool_value():
    value = parse_property_value(PropertyTag.VERIFY_WRITES, [0])
    assert isinstance(value, BoolValue)
    assert value.tag == PropertyTag.VERIFY_WRITES
    assert value.name == PropertyTag[PropertyTag.VERIFY_WRITES]
    assert value.desc == PropertyTag.desc(PropertyTag.VERIFY_WRITES)
    assert not value
    assert value.to_int() == 0
    assert value.to_str() == "OFF"


def test_enum_value():
    value = parse_property_value(PropertyTag.FLASH_READ_MARGIN, [0])
    assert isinstance(value, EnumValue)
    assert value.tag == PropertyTag.FLASH_READ_MARGIN
    assert value.name == PropertyTag[PropertyTag.FLASH_READ_MARGIN]
    assert value.desc == PropertyTag.desc(PropertyTag.FLASH_READ_MARGIN)
    assert value.value == 0
    assert value.to_int() == 0
    assert value.to_str() == "NORMAL"


def test_int_value():
    value = parse_property_value(PropertyTag.FLASH_SIZE, [1024])
    assert isinstance(value, IntValue)
    assert value.tag == PropertyTag.FLASH_SIZE
    assert value.name == PropertyTag[PropertyTag.FLASH_SIZE]
    assert value.desc == PropertyTag.desc(PropertyTag.FLASH_SIZE)
    assert value.value == 1024
    assert value.to_str() == "1.0 kiB"


def test_version_value():
    value = parse_property_value(PropertyTag.CURRENT_VERSION, [0x4B000102])
    assert isinstance(value, VersionValue)
    assert value.tag == PropertyTag.CURRENT_VERSION
    assert value.name == PropertyTag[PropertyTag.CURRENT_VERSION]
    assert value.desc == PropertyTag.desc(PropertyTag.CURRENT_VERSION)
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
    value = parse_property_value(PropertyTag.UNIQUE_DEVICE_IDENT, input_numbers)
    assert isinstance(value, DeviceUidValue)
    assert value.tag == PropertyTag.UNIQUE_DEVICE_IDENT
    assert value.name == PropertyTag[PropertyTag.UNIQUE_DEVICE_IDENT]
    assert value.desc == PropertyTag.desc(PropertyTag.UNIQUE_DEVICE_IDENT)
    assert value.to_int() == out_int
    assert value.to_str() == out_string


def test_available_commands():
    value = parse_property_value(PropertyTag.AVAILABLE_COMMANDS, [0xF])
    assert value.tags == [1, 2, 3, 4]
    assert all(index in value for index in [1, 2, 3, 4])
    command_names = [CommandTag.name(i) for i in [1, 2, 3, 4]]
    assert all(name in value.to_str() for name in command_names)


def test_reserved_regions():
    value = parse_property_value(
        PropertyTag.RESERVED_REGIONS,
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
        f"0x30000000 - 0x30007FFF",
        f"0x20000000 - 0x20007FFF",
        f"0x04000000 - 0x04003FFF",
        f"0x14000000 - 0x14001FFF",
    ]
    for expected_string in expected_strings:
        assert expected_string in str(value)
