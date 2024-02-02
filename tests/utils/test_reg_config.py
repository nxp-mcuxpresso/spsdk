#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for registers utility."""
import os

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.utils import database
from spsdk.utils.database import Database
from spsdk.utils.reg_config import RegConfig


class SPSDK_TestDatabase:
    """Main SPSDK database."""

    db: Database = None

    """List all SPSDK supported features"""
    FEATURE1 = "feature1"
    FEATURE2 = "feature2"
    FEATURE3 = "feature3"
    REG_CONFIG = "reg_config"


@pytest.fixture
def mock_test_database(monkeypatch, data_dir):
    """Change the SPSDK Database"""
    SPSDK_TestDatabase.db = Database(os.path.join(data_dir, "test_db"))
    monkeypatch.setattr(database, "DatabaseManager", SPSDK_TestDatabase)


def test_reg_config_get_devices(mock_test_database):
    """Test Register Config - get_devices function."""

    devices = SPSDK_TestDatabase.db.get_devices_with_feature(SPSDK_TestDatabase.REG_CONFIG)
    assert "dev1" in devices
    assert "dev2" in devices


# reg_config = RegConfig("dev1", SPSDK_TestDatabase.REG_CONFIG, )


def test_reg_config_get_address(mock_test_database):
    """Test Register Config - get_address function."""
    addr = RegConfig("dev1", SPSDK_TestDatabase.REG_CONFIG).get_address()
    assert addr == 0xA5A51234

    addr = RegConfig("dev2", SPSDK_TestDatabase.REG_CONFIG).get_address()
    assert addr == 0x40000000


def test_reg_config_get_data_file(mock_test_database, data_dir):
    """Test Register Config - get_data_file function."""

    data_file = RegConfig("dev1", SPSDK_TestDatabase.REG_CONFIG, "rev1").get_data_file()
    assert os.path.join(data_dir, "test_db", "devices", "dev1", "test_device1_x0.xml") == data_file

    data_file = RegConfig("dev1", SPSDK_TestDatabase.REG_CONFIG, "rev2").get_data_file()
    assert os.path.join(data_dir, "test_db", "devices", "dev1", "test_device1_x1.xml") == data_file

    data_file = RegConfig("dev2", SPSDK_TestDatabase.REG_CONFIG, "rev1").get_data_file()
    assert os.path.join(data_dir, "test_db", "devices", "dev2", "test_device2_b0.xml") == data_file


def test_reg_config_get_antipole_regs(mock_test_database):
    """Test Register Config - get_antipole_regs function."""
    antipole = RegConfig("dev1", SPSDK_TestDatabase.REG_CONFIG).get_antipole_regs()
    assert antipole["INVERTED_REG"] == "INVERTED_REG_AP"

    antipole = RegConfig("dev2", SPSDK_TestDatabase.REG_CONFIG).get_antipole_regs()
    assert antipole["INVERTED_REG"] == "INVERTED_REG_AP"


def test_reg_config_get_computed_regs(mock_test_database):
    """Test Register Config - get_computed_registers function."""
    computed_regs = RegConfig("dev1", SPSDK_TestDatabase.REG_CONFIG).get_computed_registers()
    assert "COMPUTED_REG" in computed_regs

    computed_regs = RegConfig("dev2", SPSDK_TestDatabase.REG_CONFIG).get_computed_registers()
    assert "COMPUTED_REG_GENERAL" in computed_regs

    with pytest.raises(SPSDKError):
        RegConfig("invalid_device", SPSDK_TestDatabase.REG_CONFIG).get_computed_registers()


def test_reg_config_get_seal_start_address(mock_test_database):
    """Test Register Config - get_seal_start_address function."""
    seal_address = RegConfig("dev1", SPSDK_TestDatabase.REG_CONFIG).get_seal_start_address()
    assert seal_address == "COMPUTED_REG"

    seal_address = RegConfig("dev2", SPSDK_TestDatabase.REG_CONFIG).get_seal_start_address()
    assert seal_address == "COMPUTED_REG2"

    with pytest.raises(SPSDKError):
        RegConfig("invalid_device", SPSDK_TestDatabase.REG_CONFIG).get_seal_start_address()


def test_reg_config_get_seal_count(mock_test_database):
    """Test Register Config - get_seal_count function."""
    seal_count = RegConfig("dev1", SPSDK_TestDatabase.REG_CONFIG).get_seal_count()
    assert seal_count == 4

    seal_count = RegConfig("dev2", SPSDK_TestDatabase.REG_CONFIG).get_seal_count()
    assert seal_count == 8

    with pytest.raises(SPSDKError):
        RegConfig("invalid_device", SPSDK_TestDatabase.REG_CONFIG).get_seal_count()


def test_reg_config_get_computed_fields(mock_test_database):
    """Test Register Config - get_computed_fields function."""
    computed_fields = RegConfig("dev1", SPSDK_TestDatabase.REG_CONFIG).get_computed_fields()
    assert computed_fields["COMPUTED_REG"]["TEST_FIELD1"] == "computed_reg_test_field1"
    assert computed_fields["COMPUTED_REG"]["TEST_FIELD2"] == "computed_reg_test_field2"
    assert computed_fields["COMPUTED_REG2"]["TEST_FIELD1"] == "computed_reg2_test_field1"
    assert computed_fields["COMPUTED_REG2"]["TEST_FIELD2"] == "computed_reg2_test_field2"


def test_reg_config_get_grouped_registers(mock_test_database):
    """Test Register Config - get_grouped_registers function."""
    grouped_registers = RegConfig("dev1", SPSDK_TestDatabase.REG_CONFIG).get_grouped_registers()
    assert grouped_registers[0]["name"] == "DeviceTest"
    grouped_registers = RegConfig("dev2", SPSDK_TestDatabase.REG_CONFIG).get_grouped_registers()
    assert grouped_registers[0]["name"] == "Test"
