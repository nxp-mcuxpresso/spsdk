#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


import os
from typing import Optional

import pytest

from spsdk import SPSDK_RESTRICTED_DATA_FOLDER
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils import database
from spsdk.utils.database import (
    Database,
    DatabaseManager,
    DevicesQuickInfo,
    MemBlock,
    QuickDatabase,
    SPSDKErrorMissingDevice,
    UsbId,
)

from spsdk.utils.misc import Endianness, load_text
from spsdk.utils.registers import Registers


class SPSDK_TestDatabase:
    """Main SPSDK database."""

    _instance = None
    _db: Optional[Database] = None
    _quick_info: Optional[DevicesQuickInfo] = None

    @property
    def db(self) -> Database:
        """Get Database."""
        db = type(self)._db
        assert isinstance(db, Database)
        return db

    @property
    def quick_info(self) -> QuickDatabase:
        """Get quick info Database."""
        quick_info = type(self)._quick_info
        assert isinstance(quick_info, QuickDatabase)
        return quick_info

    """List all SPSDK supported features"""
    FEATURE1 = "feature1"
    FEATURE2 = "feature2"
    FEATURE3 = "feature3"


@pytest.fixture
def mock_test_database(monkeypatch, data_dir):
    """Change the SPSDK Database"""
    SPSDK_TestDatabase._db = Database(os.path.join(data_dir, "test_db"), complete_load=True)
    SPSDK_TestDatabase._quick_info = QuickDatabase.create(SPSDK_TestDatabase._db)
    # SPSDK_TestDatabase._instance = DatabaseManager()
    monkeypatch.setattr(database, "DatabaseManager", SPSDK_TestDatabase)


@pytest.fixture
def mock_test_database_restricted(monkeypatch, data_dir):
    """Change the SPSDK Database"""
    SPSDK_TestDatabase._db = Database(
        os.path.join(data_dir, "test_db"),
        restricted_data_path=os.path.join(data_dir, "test_restricted_db"),
    )
    SPSDK_TestDatabase._quick_info = QuickDatabase.create(SPSDK_TestDatabase._db)
    SPSDK_TestDatabase._instance = SPSDK_TestDatabase()
    monkeypatch.setattr(database, "DatabaseManager", SPSDK_TestDatabase)


@pytest.mark.parametrize(
    "device,revision,feature,key,value,default",
    [
        (
            "dev1",
            "rev1",
            "feature1",
            "attribute_int1",
            1,
            None,
        ),  # Standard loaded defaults; integer
        (
            "dev1",
            "rev1",
            "feature1",
            "attribute_str1",
            "Database text",
            None,
        ),  # Standard loaded defaults; String
        (
            "dev1",
            "rev1",
            "feature1",
            "attribute_boolT",
            True,
            None,
        ),  # Standard loaded defaults; Boolean True
        (
            "dev1",
            "rev1",
            "feature1",
            "attribute_boolF",
            False,
            None,
        ),  # Standard loaded defaults; Boolean False
        (
            "dev1",
            "rev1",
            "feature1",
            "attribute_dict",
            {"dict_attribute_int": 1, "dict_attribute_str": "Dict text"},
            None,
        ),  # Standard loaded defaults; dict
        (
            "dev1",
            "rev1",
            "feature1",
            "attribute_list",
            [1, 2, 3],
            None,
        ),  # Standard loaded defaults; list
        (
            "dev1",
            "rev1",
            "feature2",
            "attribute_int1",
            3,
            None,
        ),  # Overloaded device value test
        (
            "dev1",
            "rev2",
            "feature2",
            "attribute_int1",
            4,
            None,
        ),  # Overloaded device overloaded revision value test
        (
            "dev1",
            "rev1",
            "feature3",
            "attribute__int1",
            10,
            None,
        ),  # Non existing default
        (
            "dev1",
            "rev1",
            "feature3",
            "invalid",
            10,
            10,
        ),  # Non existing key with default value
        ("dev1_alias", "rev1", "feature1", "attribute_int1", 1, None),  # Alias device loaded
        (
            "dev1_alias",
            "new_rev",
            "feature1",
            "attribute_int1",
            1,
            None,
        ),  # Alias device new revision
    ],
)
def test_get_device_value(mock_test_database, device, revision, feature, key, value, default):
    db = database.get_db(device=device, revision=revision)
    val = db.get_value(feature=feature, key=key, default=default)
    assert val == value


@pytest.mark.parametrize(
    "feature,devices,sub_feature,invalid",
    [
        ("feature1", ["dev1", "dev1_alias", "dev2"], None, False),
        ("feature2", ["dev1", "dev1_alias", "dev2"], None, True),
        ("feature2", ["dev1", "dev1_alias"], None, False),
        ("feature3", ["dev1", "dev1_alias"], None, False),
        ("feature1", ["dev2"], "sub_feature1", False),
    ],
)
def test_supported_devices(mock_test_database, feature, devices: list[str], sub_feature, invalid):
    dev_list = database.get_families(feature, sub_feature)
    dev_list.sort()
    devices.sort()
    assert (dev_list == devices) != invalid


@pytest.mark.parametrize(
    "device,rom_protocol,rom_usbid,flashloader_protocol,flashloader_usbid",
    [
        ("dev1", "sdps", UsbId(0xDEAD, 0xBEEF), "mboot", UsbId(0x1234, 0x5678)),
        ("dev1_alias", "sdps", UsbId(0xDEAD, 0xBEEF), "mboot", UsbId(0x1234, 0x5678)),
        ("dev2", "mboot", UsbId(0xAAAA, 0xBBBB), "sdp", UsbId(0xFEDC, 0xBA98)),
    ],
)
def test_isp(
    mock_test_database, device, rom_protocol, rom_usbid, flashloader_protocol, flashloader_usbid
):
    dev_info = database.get_device(device).info
    assert dev_info.isp.rom.protocol == rom_protocol
    assert dev_info.isp.rom.usb_id == rom_usbid
    assert dev_info.isp.flashloader.protocol == flashloader_protocol
    assert dev_info.isp.flashloader.usb_id == flashloader_usbid


@pytest.mark.parametrize(
    "device,rom_protocol,rom_usbid,flashloader_protocol,flashloader_usbid",
    [
        ("dev1", "sdps", UsbId(0xDEAD, 0xBEEF), "mboot", UsbId(0x1234, 0x5678)),
        ("dev1_alias", "sdps", UsbId(0xDEAD, 0xBEEF), "mboot", UsbId(0x1234, 0x5678)),
        ("dev2", "mboot", UsbId(0xAAAA, 0xBBBB), "sdp", UsbId(0xFEDC, 0xBA98)),
    ],
)
def test_isp_get_usb_config(
    mock_test_database, device, rom_protocol, rom_usbid, flashloader_protocol, flashloader_usbid
):
    dev_info = database.get_device(device).info
    usb_list = dev_info.isp.get_usb_ids(rom_protocol)
    assert len(usb_list) == 1
    assert usb_list[0] == rom_usbid
    usb_list = dev_info.isp.get_usb_ids(flashloader_protocol)
    assert len(usb_list) == 1
    assert usb_list[0] == flashloader_usbid


@pytest.mark.parametrize(
    "device,supported_protocols",
    [
        ("dev1", ["sdps", "mboot"]),
        ("dev1_alias", ["sdps", "mboot"]),
        ("dev2", ["mboot", "sdp"]),
    ],
)
def test_isp_get_is_protocol_supported(mock_test_database, device, supported_protocols):
    dev_info = database.get_device(device).info
    for protocol in ["mboot", "sdp", "sdps"]:
        is_supported = dev_info.isp.is_protocol_supported(protocol)
        assert is_supported == (protocol in supported_protocols)


def test_invalid_device(mock_test_database):
    with pytest.raises(SPSDKErrorMissingDevice):
        database.DatabaseManager().db.devices.get("invalid")


def test_invalid_revision(mock_test_database):
    with pytest.raises(SPSDKValueError):
        database.DatabaseManager().db.devices.get("dev2").revisions.get("invalid")


def test_load_database():
    assert isinstance(DatabaseManager().db, Database)


def test_load_database_without_cache():
    database.SPSDK_CACHE_DISABLED = True
    assert isinstance(DatabaseManager().db, Database)


def test_restricted_data(data_dir, mock_test_database_restricted):
    simple_db = Database(os.path.join(data_dir, "test_db"))
    restr_db = Database(
        os.path.join(data_dir, "test_db"), os.path.join(data_dir, "test_restricted_db")
    )

    # The database won't be same
    assert simple_db != restr_db
    dev1 = simple_db.get_device_features("dev1")
    r_dev1 = restr_db.get_device_features("dev1")
    # Restricted database must contains the secret information
    with pytest.raises(SPSDKValueError):
        dev1.get_str("feature1", "secret_info") == "Super secret information"
    r_dev1.get_str("feature1", "secret_info") == "Super secret information"
    # restricted database contains a new device
    with pytest.raises(SPSDKErrorMissingDevice):
        simple_db.get_device_features("dev3")
    restr_db.get_device_features("dev3")
    # restricted device 2 contains a new register in shadow registers
    r_dev2_regs = Registers(family="dev2", feature="fuses")
    r_dev2_regs.find_reg("RESTRICTED_REG")


def test_load_yaml_cfg_registers_with_restricted_data(tmpdir, mock_test_database_restricted):
    std_regs = Registers(
        family="dev2",
        feature="fuses",
        base_endianness=Endianness.LITTLE,
        just_standard_library_data=True,
    )
    # change the value
    for x, reg in enumerate(std_regs.get_registers()):
        reg.set_value(0xA + x)
    std_regs_cfg = std_regs.get_config(True)
    rstr_regs = Registers(
        family="dev2",
        feature="fuses",
        base_endianness=Endianness.LITTLE,
        just_standard_library_data=False,
    )
    rstr_regs.load_yml_config(std_regs_cfg)
    std = std_regs.export()
    rstr = rstr_regs.export()
    assert std == rstr[: len(std)]


def test_addons_data(data_dir):
    simple_db = Database(os.path.join(data_dir, "test_db"))
    restr_db = Database(
        os.path.join(data_dir, "test_db"), os.path.join(data_dir, "test_restricted_db")
    )
    addons_db = Database(
        os.path.join(data_dir, "test_db"),
        os.path.join(data_dir, "test_restricted_db"),
        os.path.join(data_dir, "test_db_addons"),
    )

    # The database won't be same
    assert simple_db != restr_db
    assert restr_db != addons_db
    # The database won't be same
    assert simple_db != restr_db
    dev1 = simple_db.get_device_features("dev1")
    r_dev1 = restr_db.get_device_features("dev1")
    a_dev1 = addons_db.get_device_features("dev1")
    # Restricted database must contains the secret information
    with pytest.raises(SPSDKValueError):
        load_text(dev1.get_file_path("feature1", "addons_file"))
    with pytest.raises(SPSDKValueError):
        load_text(r_dev1.get_file_path("feature1", "addons_file"))
    load_text(a_dev1.get_file_path("feature1", "addons_file"))


@pytest.mark.parametrize(
    "full_name,name,core,instance,security",
    [
        ("flexspi", "flexspi", None, None, None),
        ("flexspi0", "flexspi", None, 0, None),
        ("flexspi_ns", "flexspi", None, None, False),
        ("flexspi1_s", "flexspi", None, 1, True),
        ("cm4_flexspi2_ns", "flexspi", "cm4", 2, False),
        ("a55_flexspi", "flexspi", "a55", None, None),
    ],
)
def test_mem_block_names(full_name, name, core, instance, security):
    """Simple test of memory block parsing."""
    p_core, p_name, p_instance, p_security = MemBlock.parse_name(full_name)
    assert p_core == core
    assert p_name == name
    assert p_instance == instance
    assert p_security == security

    # Do reverse test to make full name from the elements
    assert full_name == MemBlock.create_name(
        block_name=name, core=core, instance=instance, secure_access=security
    )


def test_check_correct_names_of_memories():
    """Test of all names of memories in whole database."""
    qd = DatabaseManager().quick_info
    for dev, qi in qd.devices.devices.items():
        for mem_name, mem_block in qi.info.memory_map._mem_map.items():
            try:
                mem_block.parse_name(mem_name)
            except SPSDKError:
                assert False, f"Test fails on family: {dev}, block name: {mem_name}"


@pytest.mark.skipif(
    SPSDK_RESTRICTED_DATA_FOLDER == None, reason="Requires to have restricted data setup"
)
def test_restricted_data_devices():
    db = DatabaseManager().get_db(True)
    restricted_data = DatabaseManager.get_restricted_data()
    assert restricted_data is not None
    assert os.path.normpath(restricted_data) == os.path.normpath(
        os.path.join(SPSDK_RESTRICTED_DATA_FOLDER, "data")
    )
    for device in os.listdir(os.path.join(restricted_data, "devices")):
        assert db.devices.get(device)
