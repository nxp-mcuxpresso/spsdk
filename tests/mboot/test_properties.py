#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK MBoot properties testing module.

This module contains comprehensive test cases for the MBoot properties functionality,
including property value parsing, formatting, and property management operations.
The tests verify proper handling of various property types used in MBoot
communication and ensure correct property value interpretation across
different MCU families.
"""

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.mboot.commands import CommandTag
from spsdk.mboot.exceptions import McuBootError
from spsdk.mboot.properties import (
    COMMON_PROPERTY_INDEXES,
    AvailableCommandsValue,
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
    get_properties,
    get_property_index,
    parse_property_value,
)
from spsdk.utils.family import FamilyRevision


def test_version_class() -> None:
    """Test Version class functionality and edge cases.

    This test verifies the Version class constructor, property access, string/integer
    conversions, comparison operators, and error handling for invalid input types.

    :raises McuBootError: When Version is initialized with invalid type (float).
    """
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
        _ = Version(0.5)  # type: ignore


def test_none_value() -> None:
    """Test parsing property value with zero value.

    This test verifies that parse_property_value correctly handles a property
    with ID 1000 and a single zero value, ensuring it returns an IntListValue
    instance.
    """
    value = parse_property_value(1000, [0])
    assert isinstance(value, IntListValue)


def test_bool_value() -> None:
    """Test parsing of boolean property values.

    Verifies that parse_property_value correctly handles boolean properties by testing
    the VERIFY_WRITES property with a false value. Validates the returned BoolValue
    object's attributes, boolean evaluation, integer conversion, and string representation.
    """
    value = parse_property_value(PropertyTag.VERIFY_WRITES, [0])
    assert isinstance(value, BoolValue)
    assert value.tag == get_property_index(PropertyTag.VERIFY_WRITES)
    assert value.name == PropertyTag.VERIFY_WRITES.label
    assert value.desc == PropertyTag.VERIFY_WRITES.description
    assert not value
    assert value.to_int() == 0
    assert value.to_str() == "OFF"


def test_enum_value() -> None:
    """Test enum value parsing and properties.

    Verifies that parse_property_value correctly handles PropertyTag.FLASH_READ_MARGIN
    and returns an EnumValue object with proper attributes including tag, name,
    description, value, and string representation.

    :raises AssertionError: If any of the expected property values don't match.
    """
    value = parse_property_value(PropertyTag.FLASH_READ_MARGIN, [0])
    assert isinstance(value, EnumValue)
    assert value.tag == get_property_index(PropertyTag.FLASH_READ_MARGIN)
    assert value.name == PropertyTag.FLASH_READ_MARGIN.label
    assert value.desc == PropertyTag.FLASH_READ_MARGIN.description
    assert value.value == 0
    assert value.to_int() == 0
    assert value.to_str() == "NORMAL"


def test_int_value() -> None:
    """Test parsing of integer property values.

    Validates that parse_property_value correctly handles integer property values
    by testing the IntValue object creation, attribute assignment, and value
    conversion methods for FLASH_SIZE property.

    :raises AssertionError: If any of the property value attributes or conversions don't match expected values.
    """
    value = parse_property_value(PropertyTag.FLASH_SIZE, [1024])
    assert isinstance(value, IntValue)
    assert value.tag == get_property_index(PropertyTag.FLASH_SIZE)
    assert value.name == PropertyTag.FLASH_SIZE.label
    assert value.desc == PropertyTag.FLASH_SIZE.description
    assert value.value == 1024
    assert value.to_str() == "1.0 kiB"
    assert value.to_int() == 1024


def test_int_value_fmt() -> None:
    """Test IntValue string formatting with different format options.

    Validates that IntValue objects correctly format their string representation
    based on the specified str_format parameter, including hex, decimal, size,
    int32, and custom format options.
    """
    value = IntValue(prop=PropertyTag.FLASH_START_ADDRESS, raw_values=[2, 4, 5], str_format="hex")
    assert isinstance(value, IntValue)
    assert value.to_str() == "0x00000002"
    value = IntValue(prop=PropertyTag.FLASH_START_ADDRESS, raw_values=[2, 4, 5])
    assert isinstance(value, IntValue)
    assert value.to_str() == "2"
    value = IntValue(prop=PropertyTag.FLASH_START_ADDRESS, raw_values=[2, 4, 5], str_format="size")
    assert isinstance(value, IntValue)
    assert value.to_str() == "2 B"
    value = IntValue(prop=PropertyTag.FLASH_START_ADDRESS, raw_values=[2, 4, 5], str_format="sth")
    assert isinstance(value, IntValue)
    assert value.to_str() == "sth"
    value = IntValue(prop=PropertyTag.FLASH_START_ADDRESS, raw_values=[0], str_format="int32")
    assert isinstance(value, IntValue)
    assert value.to_str() == "0"
    value = IntValue(
        prop=PropertyTag.FLASH_START_ADDRESS, raw_values=[0xFFFFFFFF], str_format="int32"
    )
    assert isinstance(value, IntValue)
    assert value.to_str() == "-1"


def test_version_value() -> None:
    """Test version value property parsing functionality.

    Validates that the parse_property_value function correctly parses a CURRENT_VERSION
    property tag with a version value, ensuring all attributes are properly set and
    the version formatting works as expected.
    """
    value = parse_property_value(PropertyTag.CURRENT_VERSION, [0x4B000102])
    assert isinstance(value, VersionValue)
    assert value.tag == get_property_index(PropertyTag.CURRENT_VERSION)
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
            "0201005c220200453303004b",
            620180645013280992354566219,
        ),
        ([0, 0x426B0], "00000000b0260400", 2955281408),
    ],
)
def test_device_uid_value(input_numbers: list[int], out_string: str, out_int: int) -> None:
    """Test device UID value parsing and validation.

    Validates that the parse_property_value function correctly parses device unique identifier
    property values and that the resulting DeviceUidValue object has the expected attributes
    and conversion methods.

    :param input_numbers: List of integers representing the raw device UID data
    :param out_string: Expected string representation of the device UID
    :param out_int: Expected integer representation of the device UID
    """
    value = parse_property_value(PropertyTag.UNIQUE_DEVICE_IDENT, input_numbers)
    assert isinstance(value, DeviceUidValue)
    assert value.tag == get_property_index(PropertyTag.UNIQUE_DEVICE_IDENT)
    assert value.name == PropertyTag.UNIQUE_DEVICE_IDENT.label
    assert value.desc == PropertyTag.UNIQUE_DEVICE_IDENT.description
    assert value.to_int() == out_int
    assert value.to_str() == out_string


def test_available_commands() -> None:
    """Test parsing of available commands property value.

    Verifies that the AVAILABLE_COMMANDS property tag can be properly parsed
    from raw data and that the resulting AvailableCommandsValue object
    contains the expected command tags and string representation.

    :raises AssertionError: If any of the test assertions fail.
    """
    value = parse_property_value(PropertyTag.AVAILABLE_COMMANDS, [0xF])
    assert value
    assert isinstance(value, AvailableCommandsValue)
    assert value.tags == [1, 2, 3, 4]
    assert all(index in value for index in [1, 2, 3, 4])
    assert value.to_str() is not None
    command_names = [CommandTag.get_label(i) for i in [1, 2, 3, 4]]
    assert all(name in value.to_str() for name in command_names)


def test_reserved_regions() -> None:
    """Test reserved regions property parsing functionality.

    Verifies that the parse_property_value function correctly processes
    RESERVED_REGIONS property data by parsing a list of memory region
    boundaries and validating the resulting property object contains
    the expected memory address ranges in proper hexadecimal format.

    :raises AssertionError: If property parsing fails or expected memory ranges are not found.
    """
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
    assert value is not None
    assert value.tag == 12
    expected_strings = [
        "0x30000000 - 0x30007FFF",
        "0x20000000 - 0x20007FFF",
        "0x04000000 - 0x04003FFF",
        "0x14000000 - 0x14001FFF",
    ]
    for expected_string in expected_strings:
        assert expected_string in str(value)


def test_available_peripherals_value() -> None:
    """Test the AvailablePeripheralsValue class functionality.

    This test verifies that the AvailablePeripheralsValue class correctly converts
    raw peripheral values to integer and string representations. It tests the
    conversion of peripheral tag value 2 to its corresponding string representation.
    """
    value = AvailablePeripheralsValue(prop=PropertyTag.AVAILABLE_PERIPHERALS, raw_values=[2, 3])
    assert value.to_int() == 2
    assert value.to_str() == "I2C-Slave"


def test_irq_notifier_pin_value() -> None:
    """Test IRQ notifier pin value functionality.

    Validates the IrqNotifierPinValue class initialization and property access
    including pin number, port number, enabled state, string representation,
    and boolean conversion.
    """
    value = IrqNotifierPinValue(prop=PropertyTag.IRQ_NOTIFIER_PIN, raw_values=[2, 3])
    assert value.pin == 2
    assert value.port == 0
    assert not value.enabled
    assert value.to_str() == "IRQ Port[0], Pin[2] is disabled"
    assert not bool(value)


def test_external_memory_attributes() -> None:
    """Test external memory attributes value formatting.

    Validates that ExternalMemoryAttributesValue correctly formats different
    external memory attribute types based on the first raw value parameter.
    Tests total size, start address, page size, sector size, and block size
    formatting with various raw value configurations.
    """
    value = ExternalMemoryAttributesValue(
        prop=PropertyTag.EXTERNAL_MEMORY_ATTRIBUTES, raw_values=[2, 3, 4, 5, 6, 7]
    )
    assert value.to_str() == "Total Size:    4.0 kiB"
    value = ExternalMemoryAttributesValue(
        prop=PropertyTag.EXTERNAL_MEMORY_ATTRIBUTES, raw_values=[1, 3, 4, 5, 6, 7]
    )
    assert value.to_str() == "Start Address: 0x00000003"
    value = ExternalMemoryAttributesValue(
        prop=PropertyTag.EXTERNAL_MEMORY_ATTRIBUTES, raw_values=[4, 3, 4, 5, 6, 7]
    )
    assert value.to_str() == "Page Size:     5 B"
    value = ExternalMemoryAttributesValue(
        prop=PropertyTag.EXTERNAL_MEMORY_ATTRIBUTES, raw_values=[8, 3, 4, 5, 6, 7]
    )
    assert value.to_str() == "Sector Size:   6 B"
    value = ExternalMemoryAttributesValue(
        prop=PropertyTag.EXTERNAL_MEMORY_ATTRIBUTES, raw_values=[16, 3, 4, 5, 6, 7]
    )
    assert value.to_str() == "Block Size:    7 B"


def test_fuse_locked_status() -> None:
    """Test fuse locked status property parsing and validation.

    Verifies that FuseLockedStatus correctly parses raw property values
    and provides accurate fuse lock status information through both
    string representation and fuse object access methods.
    """
    value = FuseLockedStatus(
        prop=PropertyTag.FUSE_LOCKED_STATUS, raw_values=[0x4, 0x1E17F00F, 0x30000, 65535, 0]
    )
    assert "FUSE000: UNLOCKED" in value.to_str()
    assert "FUSE084: LOCKED" in value.to_str()
    assert "FUSE143: UNLOCKED" in value.to_str()

    fuses = value.get_fuses()
    assert not fuses[0].locked
    assert fuses[84].locked


def test_get_properties_no_family() -> None:
    """Test get_properties function without specifying a family parameter.

    Verifies that when no family is specified, the function returns the common
    property indexes that are applicable across all device families.
    """
    properties = get_properties()
    assert properties == COMMON_PROPERTY_INDEXES


def test_get_properties_with_family_with_overrides() -> None:
    """Test get_properties with a family that has overridden properties.

    This test verifies that the get_properties function correctly returns both
    common properties and family-specific overridden properties for the kw45b41z8
    family. It validates that overridden properties take precedence over common
    ones while non-overridden properties retain their common values.
    The test uses the mock database from tests/utils/test_database.py.
    """

    family = FamilyRevision("kw45b41z8")
    properties = get_properties(family)
    overwritten = {
        0xA: PropertyTag.VERIFY_ERASE,
        0x14: PropertyTag.BOOT_STATUS_REGISTER,
        0x15: PropertyTag.FIRMWARE_VERSION,
        0x16: PropertyTag.FUSE_PROGRAM_VOLTAGE,
    }
    for idx, prop in overwritten.items():
        assert properties[idx] == prop
    for idx, prop in COMMON_PROPERTY_INDEXES.items():
        if idx in overwritten:
            continue
        assert properties[idx] == prop


def test_get_property_index() -> None:
    """Test the get_property_index function with various input types.

    This test verifies that the get_property_index function correctly handles:
    - Integer values (passed through unchanged)
    - PropertyTag enums (converted to their corresponding indices)
    - Family-specific property mappings
    - Error cases for unsupported properties

    :raises SPSDKError: When PropertyTag.VERIFY_ERASE is used without family context.
    """
    assert get_property_index(42) == 42
    assert get_property_index(0) == 0
    assert get_property_index(PropertyTag.CURRENT_VERSION) == 0x01
    assert get_property_index(PropertyTag.BOOT_STATUS_REGISTER) == 0x20
    with pytest.raises(SPSDKError):
        assert get_property_index(PropertyTag.VERIFY_ERASE)
    family = FamilyRevision("kw45b41z8")
    assert get_property_index(PropertyTag.CURRENT_VERSION, family) == 0x01
    assert get_property_index(PropertyTag.BOOT_STATUS_REGISTER, family) == 0x14
    assert get_property_index(PropertyTag.VERIFY_ERASE, family) == 0xA
