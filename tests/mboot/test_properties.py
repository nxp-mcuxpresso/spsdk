#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest
from spsdk.mboot.properties import Version, BoolValue, EnumValue, IntValue, VersionValue, ReservedRegionsValue, \
                                  AvailableCommandsValue, AvailablePeripheralsValue, ExternalMemoryAttributesValue, \
                                  DeviceUidValue, FlashReadMargin, IrqNotifierPinValue, PfrKeystoreUpdateOpt, \
                                  parse_property_value, PropertyTag


def test_version_class():
    version = Version('K0.1.2')
    assert version.mark == 'K'
    assert version.major == 0
    assert version.minor == 1
    assert version.fixation == 2
    assert version.to_str() == 'K0.1.2'
    assert version.to_str(no_mark=True) == '0.1.2'
    assert version.to_int() == 0x4B000102
    assert version.to_int(no_mark=True) == 0x00000102
    assert version > Version(major=0, minor=1, fixation=1)
    assert version >= Version('0.1.1')
    assert version < Version('0.2.1')
    assert version <= Version('0.2.1')
    assert version != Version(0x00000102)
    assert str(version)
    assert repr(version)
    with pytest.raises(TypeError):
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
    assert value.to_str() == 'OFF'


def test_enum_value():
    value = parse_property_value(PropertyTag.FLASH_READ_MARGIN, [0])
    assert isinstance(value, EnumValue)
    assert value.tag == PropertyTag.FLASH_READ_MARGIN
    assert value.name == PropertyTag[PropertyTag.FLASH_READ_MARGIN]
    assert value.desc == PropertyTag.desc(PropertyTag.FLASH_READ_MARGIN)
    assert value.value == 0
    assert value.to_int() == 0
    assert value.to_str() == 'NORMAL'


def test_int_value():
    value = parse_property_value(PropertyTag.FLASH_SIZE, [1024])
    assert isinstance(value, IntValue)
    assert value.tag == PropertyTag.FLASH_SIZE
    assert value.name == PropertyTag[PropertyTag.FLASH_SIZE]
    assert value.desc == PropertyTag.desc(PropertyTag.FLASH_SIZE)
    assert value.value == 1024
    assert value.to_str() == '1.0 kiB'


def test_version_value():
    value = parse_property_value(PropertyTag.CURRENT_VERSION, [0x4B000102])
    assert isinstance(value, VersionValue)
    assert value.tag == PropertyTag.CURRENT_VERSION
    assert value.name == PropertyTag[PropertyTag.CURRENT_VERSION]
    assert value.desc == PropertyTag.desc(PropertyTag.CURRENT_VERSION)
    assert value.value == Version(0x4B000102)
    assert value.to_int() == 0x4B000102
    assert value.to_str() == 'K0.1.2'


def test_device_uid_value():
    value = parse_property_value(PropertyTag.UNIQUE_DEVICE_IDENT, [0x4B000102, 0x4B000102])
    assert isinstance(value, DeviceUidValue)
    assert value.tag == PropertyTag.UNIQUE_DEVICE_IDENT
    assert value.name == PropertyTag[PropertyTag.UNIQUE_DEVICE_IDENT]
    assert value.desc == PropertyTag.desc(PropertyTag.UNIQUE_DEVICE_IDENT)
    assert value.value == 0x4B0001024B000102
    assert value.to_str() == '4B0001024B000102'
