#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for registers utility."""
import os

import pytest

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.reg_config import RegConfig


def test_reg_config_get_devices(data_dir):
    """Test Register Config - get_devices function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))
    devices = reg_config.devices.device_names

    assert "test_device1" in devices
    assert "test_device2" in devices


def test_reg_config_get_devices_class(data_dir):
    """Test Register Config - get_devices class function."""
    devices = RegConfig.get_devices(os.path.join(data_dir, "reg_config.json")).device_names

    assert "test_device1" in devices
    assert "test_device2" in devices


def test_reg_config_get_latest(data_dir):
    """Test Register Config - get_latest function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))

    rev = reg_config.devices.get_by_name("test_device1").revisions.get_latest().name
    assert rev == "x1"

    rev = reg_config.devices.get_by_name("test_device2").revisions.get_latest().name
    assert rev == "b0"


def test_reg_config_revisions(data_dir):
    """Test Register Config - revisions property."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))

    revs = reg_config.devices.get_by_name("test_device1").revisions.revision_names
    assert "x0" in revs
    assert "x1" in revs

    revs = reg_config.devices.get_by_name("test_device2").revisions.revision_names
    assert "b0" in revs


def test_reg_config_get_address(data_dir):
    """Test Register Config - get_address function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))

    addr = reg_config.get_address("test_device1")
    assert addr == 0xA5A51234

    addr = reg_config.get_address("test_device2")
    assert addr == 0x40000000


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


def test_reg_config_get_value(data_dir):
    """Test Register Config - get_value function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config.json"))

    ignored_fields = reg_config.get_value("ignored_fields", "test_device1")
    assert "FIELD" in ignored_fields

    ignored_fields = reg_config.get_value("ignored_fields", "test_device2")
    assert "FIELD_GENERAL" in ignored_fields

    ignored_fields = reg_config.get_value("ignored_fields", "invalid_device")
    assert "FIELD_GENERAL" in ignored_fields

    ignored_fields = reg_config.get_value("ignored_fields")
    assert "FIELD_GENERAL" in ignored_fields

    none_exist = reg_config.get_value("none_exist_key", default="Yuppie")
    assert "Yuppie" == none_exist

    none_exist = reg_config.get_value("none_exist_key")
    assert None is none_exist


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


def test_reg_invalid(data_dir):
    reg_config = RegConfig(os.path.join(data_dir, "reg_config_invalid.json"))
    with pytest.raises(SPSDKError, match="Invalid seal start address name"):
        reg_config.get_seal_start_address("test_device1")
    with pytest.raises(SPSDKError, match="Invalid seal count"):
        reg_config.get_seal_count("test_device1")


def test_reg_config_missing_data_file(data_dir):
    """Test Register Config - get_devices function."""
    reg_config = RegConfig(os.path.join(data_dir, "reg_config_missing_datafile.json"))
    with pytest.raises(SPSDKValueError):
        reg_config.get_data_file("test_device1", "x0")
