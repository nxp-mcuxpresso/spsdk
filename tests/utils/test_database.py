#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK database functionality test suite.

This module contains comprehensive tests for the SPSDK database system,
validating device configuration management, revision handling, ISP protocol
support, and data access controls including restricted data validation.
"""

import os
from typing import Any, Optional

import pytest

from spsdk import SPSDK_RESTRICTED_DATA_FOLDER
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils import database, family
from spsdk.utils.database import (
    Database,
    DatabaseManager,
    MemBlock,
    QuickDatabase,
    SPSDKErrorMissingDevice,
    UsbId,
)
from spsdk.utils.family import FamilyRevision, get_db, get_device, get_families
from spsdk.utils.misc import Endianness, load_text
from spsdk.utils.registers import Registers


class SPSDK_TestDatabase:
    """SPSDK Test Database Manager.

    This class provides a singleton interface for managing test database instances
    used in SPSDK testing operations. It maintains cached references to both the
    main database and quick lookup database for efficient access to device
    information and supported features.

    :cvar FEATURE1: Test feature identifier for feature1.
    :cvar FEATURE2: Test feature identifier for feature2.
    :cvar FEATURE3: Test feature identifier for feature3.
    """

    _instance: Optional["SPSDK_TestDatabase"] = None
    _db: Optional[Database] = None
    _quick_info: Optional[QuickDatabase] = None

    @property
    def db(self) -> Database:
        """Get Database instance.

        Retrieves the cached Database instance from the class variable and validates
        that it is properly initialized.

        :raises AssertionError: If the database instance is not of type Database.
        :return: The Database instance.
        """
        db = type(self)._db
        assert isinstance(db, Database)
        return db

    @property
    def quick_info(self) -> QuickDatabase:
        """Get quick info Database.

        Retrieves the cached QuickDatabase instance containing essential device information
        for fast lookups and operations.

        :return: Quick database instance with device information.
        """
        quick_info = type(self)._quick_info
        assert isinstance(quick_info, QuickDatabase)
        return quick_info

    # List all SPSDK supported features
    FEATURE1 = "feature1"
    FEATURE2 = "feature2"
    FEATURE3 = "feature3"


@pytest.fixture
def mock_test_database(monkeypatch: Any, data_dir: str) -> None:
    """Mock the SPSDK Database for testing purposes.

    This function replaces the default SPSDK database with a test database
    by creating a new Database instance from the specified data directory
    and patching the DatabaseManager in relevant modules.

    :param monkeypatch: Pytest monkeypatch fixture for mocking objects.
    :param data_dir: Path to directory containing test database files.
    """
    SPSDK_TestDatabase._db = Database(os.path.join(data_dir, "test_db"), complete_load=True)
    SPSDK_TestDatabase._quick_info = QuickDatabase.create(SPSDK_TestDatabase._db)
    # SPSDK_TestDatabase._instance = DatabaseManager()
    monkeypatch.setattr(database, "DatabaseManager", SPSDK_TestDatabase)
    monkeypatch.setattr(family, "DatabaseManager", SPSDK_TestDatabase)


@pytest.fixture
def mock_test_database_restricted(monkeypatch: Any, data_dir: str) -> None:
    """Mock the SPSDK Database for testing purposes.

    This function sets up a test database instance with both regular and restricted
    data paths, then patches the DatabaseManager in relevant modules to use the
    test database instead of the production one.

    :param monkeypatch: Pytest monkeypatch fixture for mocking.
    :param data_dir: Directory path containing test database files.
    """
    SPSDK_TestDatabase._db = Database(
        os.path.join(data_dir, "test_db"),
        restricted_data_path=os.path.join(data_dir, "test_restricted_db"),
    )
    SPSDK_TestDatabase._quick_info = QuickDatabase.create(SPSDK_TestDatabase._db)
    SPSDK_TestDatabase._instance = SPSDK_TestDatabase()
    monkeypatch.setattr(database, "DatabaseManager", SPSDK_TestDatabase)
    monkeypatch.setattr(family, "DatabaseManager", SPSDK_TestDatabase)


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
            "attribute_int1",
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
def test_get_device_value(  # pylint: disable=redefined-outer-name
    mock_test_database: Any,
    device: str,
    revision: str,
    feature: str,
    key: str,
    value: Any,
    default: Any,
) -> None:
    """Test device value retrieval from database.

    Verifies that the database correctly retrieves a specific value for a given
    device, revision, feature, and key combination, comparing it against the
    expected value.

    :param mock_test_database: Mock database fixture for testing.
    :param device: Device name to query in the database.
    :param revision: Device revision to query in the database.
    :param feature: Feature name to look up in the database.
    :param key: Specific key within the feature to retrieve.
    :param value: Expected value that should be returned from the database.
    :param default: Default value to return if the key is not found.
    """
    db = get_db(FamilyRevision(device, revision))
    val = db.get_value(feature=feature, key=key, default=default)
    assert val == value


@pytest.mark.parametrize(
    "feature,devices,sub_feature,invalid",
    [
        (
            "feature1",
            [
                FamilyRevision("dev1", "rev1"),
                FamilyRevision("dev1", "rev2"),
                FamilyRevision("dev1_alias", "rev1"),
                FamilyRevision("dev1_alias", "rev2"),
                FamilyRevision("dev1_alias", "new_rev"),
                FamilyRevision("dev2", "rev1"),
                FamilyRevision("dev2", "rev_test_invalid_computed"),
                FamilyRevision("dev2", "rev_test_invalid_flush_func"),
            ],
            None,
            False,
        ),
        (
            "feature2",
            [
                FamilyRevision("dev1", "rev1"),
                FamilyRevision("dev1", "rev2"),
                FamilyRevision("dev1_alias", "rev1"),
                FamilyRevision("dev1_alias", "rev2"),
                FamilyRevision("dev1_alias", "new_rev"),
                FamilyRevision("dev2", "rev1"),
                FamilyRevision("dev2", "rev_test_invalid_computed"),
                FamilyRevision("dev2", "rev_test_invalid_flush_func"),
            ],
            None,
            True,
        ),
        (
            "feature2",
            [
                FamilyRevision("dev1", "rev1"),
                FamilyRevision("dev1", "rev2"),
                FamilyRevision("dev1_alias", "rev1"),
                FamilyRevision("dev1_alias", "rev2"),
                FamilyRevision("dev1_alias", "new_rev"),
            ],
            None,
            False,
        ),
        (
            "feature3",
            [
                FamilyRevision("dev1", "rev1"),
                FamilyRevision("dev1", "rev2"),
                FamilyRevision("dev1_alias", "rev1"),
                FamilyRevision("dev1_alias", "rev2"),
                FamilyRevision("dev1_alias", "new_rev"),
            ],
            None,
            False,
        ),
        (
            "feature1",
            [
                FamilyRevision("dev2", "rev1"),
                FamilyRevision("dev2", "rev_test_invalid_computed"),
                FamilyRevision("dev2", "rev_test_invalid_flush_func"),
            ],
            "sub_feature1",
            False,
        ),
    ],
)
def test_supported_devices(  # pylint: disable=redefined-outer-name
    mock_test_database: Any,
    feature: str,
    devices: list[FamilyRevision],
    sub_feature: Optional[str],
    invalid: bool,
) -> None:
    """Test that get_families function returns correct device list for given feature.

    Validates that the get_families function returns the expected list of devices
    for a specified feature and optional sub-feature. The test can verify both
    positive and negative cases based on the invalid parameter.

    :param mock_test_database: Mocked test database fixture for testing.
    :param feature: Feature name to query for supported devices.
    :param devices: Expected list of family revisions that should be returned.
    :param sub_feature: Optional sub-feature name for more specific filtering.
    :param invalid: Flag indicating whether the test expects invalid/mismatched results.
    """
    dev_list = get_families(feature, sub_feature)
    dev_list.sort()
    devices.sort()
    assert (dev_list == devices) != invalid


@pytest.mark.parametrize(
    "feature,devices,sub_feature",
    [
        (
            "feature1",
            [
                FamilyRevision("dev1", "rev2"),
                FamilyRevision("dev1_alias", "rev2"),
                FamilyRevision("dev2", "rev1"),
            ],
            None,
        ),
        ("feature2", [FamilyRevision("dev1", "rev2"), FamilyRevision("dev1_alias", "rev2")], None),
        (
            "feature1",
            [FamilyRevision("dev2", "rev1")],
            "sub_feature1",
        ),
    ],
)
def test_supported_devices_latest(  # pylint: disable=redefined-outer-name
    mock_test_database: Any, feature: str, devices: list[FamilyRevision], sub_feature: Optional[str]
) -> None:
    """Test that get_families returns the latest supported devices for a feature.

    Verifies that the get_families function with single_revision=True returns
    the expected list of devices for a given feature and optional sub-feature.
    The test compares sorted lists to ensure order independence.

    :param mock_test_database: Mocked test database fixture.
    :param feature: The feature name to query for supported devices.
    :param devices: Expected list of FamilyRevision objects for the feature.
    :param sub_feature: Optional sub-feature name to filter devices.
    """
    dev_list = get_families(feature, sub_feature, single_revision=True)
    dev_list.sort()
    devices.sort()
    assert dev_list == devices


@pytest.mark.parametrize(
    "device,rom_protocol,rom_usbid,flashloader_protocol,flashloader_usbid",
    [
        ("dev1", "sdps", UsbId(0xDEAD, 0xBEEF), "mboot", UsbId(0x1234, 0x5678)),
        ("dev1_alias", "sdps", UsbId(0xDEAD, 0xBEEF), "mboot", UsbId(0x1234, 0x5678)),
        ("dev2", "mboot", UsbId(0xAAAA, 0xBBBB), "sdp", UsbId(0xFEDC, 0xBA98)),
    ],
)
def test_isp(  # pylint: disable=redefined-outer-name
    mock_test_database: Any,
    device: str,
    rom_protocol: str,
    rom_usbid: UsbId,
    flashloader_protocol: str,
    flashloader_usbid: UsbId,
) -> None:
    """Test ISP configuration for device database entries.

    Validates that the device database contains correct ISP (In-System Programming)
    configuration including ROM and flashloader protocol settings and USB IDs.

    :param mock_test_database: Mocked test database fixture for testing.
    :param device: Device family and revision identifier string.
    :param rom_protocol: Expected ROM protocol name for the device.
    :param rom_usbid: Expected USB ID for ROM communication.
    :param flashloader_protocol: Expected flashloader protocol name for the device.
    :param flashloader_usbid: Expected USB ID for flashloader communication.
    """
    dev_info = get_device(FamilyRevision(device)).info
    assert dev_info.isp.rom.protocol == rom_protocol
    assert rom_usbid in dev_info.isp.rom.usb_ids
    assert dev_info.isp.flashloader.protocol == flashloader_protocol
    assert flashloader_usbid in dev_info.isp.flashloader.usb_ids


@pytest.mark.parametrize(
    "device,rom_protocol,rom_usbid,flashloader_protocol,flashloader_usbid",
    [
        ("dev1", "sdps", UsbId(0xDEAD, 0xBEEF), "mboot", UsbId(0x1234, 0x5678)),
        ("dev1_alias", "sdps", UsbId(0xDEAD, 0xBEEF), "mboot", UsbId(0x1234, 0x5678)),
        ("dev2", "mboot", UsbId(0xAAAA, 0xBBBB), "sdp", UsbId(0xFEDC, 0xBA98)),
    ],
)
def test_isp_get_usb_config(  # pylint: disable=redefined-outer-name
    mock_test_database: Any,
    device: str,
    rom_protocol: str,
    rom_usbid: UsbId,
    flashloader_protocol: str,
    flashloader_usbid: UsbId,
) -> None:
    """Test ISP USB configuration retrieval for device protocols.

    Validates that the ISP (In-System Programming) interface correctly returns
    USB IDs for both ROM and flashloader protocols for a specified device.

    :param mock_test_database: Mock database fixture for testing.
    :param device: Device family revision identifier.
    :param rom_protocol: ROM protocol name to test.
    :param rom_usbid: Expected USB ID for ROM protocol.
    :param flashloader_protocol: Flashloader protocol name to test.
    :param flashloader_usbid: Expected USB ID for flashloader protocol.
    """
    dev_info = get_device(FamilyRevision(device)).info
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
def test_isp_get_is_protocol_supported(  # pylint: disable=redefined-outer-name
    mock_test_database: Any, device: str, supported_protocols: list[str]
) -> None:
    """Test ISP protocol support validation for devices.

    Validates that the ISP (In-System Programming) protocol support detection
    works correctly for different devices by checking if each protocol
    (mboot, sdp, sdps) is properly identified as supported or not supported
    based on the expected supported protocols list.

    :param mock_test_database: Mock database fixture for testing.
    :param device: Device family revision string to test.
    :param supported_protocols: List of protocol names that should be supported by the device.
    """
    dev_info = get_device(FamilyRevision(device)).info
    for protocol in ["mboot", "sdp", "sdps"]:
        is_supported = dev_info.isp.is_protocol_supported(protocol)
        assert is_supported == (protocol in supported_protocols)


def test_invalid_device(mock_test_database: Any) -> None:  # pylint: disable=redefined-outer-name
    """Test that getting an invalid device raises SPSDKErrorMissingDevice.

    Verifies that the DatabaseManager correctly handles requests for non-existent
    devices by raising the appropriate exception.

    :param mock_test_database: Mocked test database fixture.
    :raises SPSDKErrorMissingDevice: When requesting a non-existent device.
    """
    with pytest.raises(SPSDKErrorMissingDevice):
        database.DatabaseManager().db.devices.get("invalid")


def test_invalid_revision(mock_test_database: Any) -> None:  # pylint: disable=redefined-outer-name
    """Test that accessing an invalid device revision raises SPSDKValueError.

    This test verifies that the DatabaseManager properly validates revision names
    and raises an appropriate exception when attempting to access a non-existent
    revision for a device.

    :param mock_test_database: Mocked test database fixture for testing database operations.
    """
    with pytest.raises(SPSDKValueError):
        database.DatabaseManager().db.devices.get("dev2").revisions.get("invalid")


def test_load_database() -> None:
    """Test that DatabaseManager returns a Database instance.

    Verifies that the DatabaseManager singleton properly initializes and returns
    a Database object when accessing the db property.

    :raises AssertionError: If the db property is not a Database instance.
    """
    assert isinstance(DatabaseManager().db, Database)


def test_load_database_without_cache() -> None:
    """Test database loading functionality with caching disabled.

    This test verifies that the DatabaseManager can properly instantiate and return
    a Database object when the SPSDK cache is explicitly disabled.
    """
    database.SPSDK_CACHE_DISABLED = True
    assert isinstance(DatabaseManager().db, Database)


def test_restricted_data(  # pylint: disable=redefined-outer-name
    data_dir: str, mock_test_database_restricted: Any
) -> None:
    """Test restricted database functionality and data access.

    Verifies that a database with restricted data source provides access to
    additional secret information and devices that are not available in the
    simple database. Tests include validation of secret information access,
    restricted device availability, and restricted register access.

    :param data_dir: Directory path containing test database files.
    :param mock_test_database_restricted: Mock object for restricted database testing.
    """
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
        assert dev1.get_str("feature1", "secret_info") == "Super secret information"
    assert r_dev1.get_str("feature1", "secret_info") == "Super secret information"
    # restricted database contains a new device
    with pytest.raises(SPSDKErrorMissingDevice):
        simple_db.get_device_features("dev3")
    restr_db.get_device_features("dev3")
    # restricted device 2 contains a new register in shadow registers
    r_dev2_regs = Registers(family=FamilyRevision("dev2"), feature="fuses")
    r_dev2_regs.find_reg("RESTRICTED_REG")


def test_load_yaml_cfg_registers_with_restricted_data(  # pylint: disable=redefined-outer-name
    tmpdir: str, mock_test_database_restricted: Any
) -> None:
    """Test loading YAML configuration for registers with restricted data access.

    This test verifies that registers can be properly loaded from a YAML configuration
    when restricted data sources are available. It creates two register instances - one
    with standard library data only and another with access to restricted data - then
    compares their exported values to ensure consistency.

    :param tmpdir: Temporary directory path for test files.
    :param mock_test_database_restricted: Mock object for restricted database testing.
    """
    std_regs = Registers(
        family=FamilyRevision("dev2"),
        feature="fuses",
        base_endianness=Endianness.LITTLE,
        just_standard_library_data=True,
    )
    # change the value
    for x, reg in enumerate(std_regs.get_registers()):
        reg.set_value(0xA + x)
    std_regs_cfg = std_regs.get_config(diff=True)
    rstr_regs = Registers(
        family=FamilyRevision("dev2"),
        feature="fuses",
        base_endianness=Endianness.LITTLE,
        just_standard_library_data=False,
    )
    rstr_regs.load_from_config(std_regs_cfg)
    std = std_regs.export()
    rstr = rstr_regs.export()
    assert std == rstr[: len(std)]


def test_addons_data(data_dir: str) -> None:
    """Test database functionality with addons data sources.

    Verifies that Database instances with different data source configurations
    (simple, restricted, and addons) behave correctly and maintain proper
    access control to addon files.

    :param data_dir: Directory path containing test database files
    :raises SPSDKValueError: When accessing non-existent addon files in databases without addon support
    """
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
def test_mem_block_names(
    full_name: str,
    name: str,
    core: Optional[str],
    instance: Optional[int],
    security: Optional[bool],
) -> None:
    """Test memory block name parsing and creation functionality.

    This test verifies that MemBlock.parse_name() correctly extracts components
    from a full memory block name and that MemBlock.create_name() can reconstruct
    the original name from those components.

    :param full_name: Complete memory block name to parse and reconstruct
    :param name: Expected base name of the memory block
    :param core: Expected core identifier, if any
    :param instance: Expected instance number, if any
    :param security: Expected security flag, if any
    """
    p_core, p_name, p_instance, p_security = MemBlock.parse_name(full_name)
    assert p_core == core
    assert p_name == name
    assert p_instance == instance
    assert p_security == security

    # Do reverse test to make full name from the elements
    assert full_name == MemBlock.create_name(
        block_name=name, core=core, instance=instance, secure_access=security
    )


def test_check_correct_names_of_memories() -> None:
    """Test of all names of memories in whole database.

    Validates that all memory block names in the device database can be properly
    parsed by their corresponding memory block parsers. This ensures consistency
    between memory block naming conventions and parsing logic across all supported
    devices.

    :raises SPSDKError: When a memory block name cannot be parsed by its parser.
    :raises AssertionError: When test fails due to invalid memory block name.
    """
    qd = DatabaseManager().quick_info
    for dev, qi in qd.devices.devices.items():
        for mem_name, mem_block in qi.info.memory_map._mem_map.items():
            try:
                mem_block.parse_name(mem_name)
            except SPSDKError:
                assert False, f"Test fails on family: {dev}, block name: {mem_name}"


@pytest.mark.skipif(
    SPSDK_RESTRICTED_DATA_FOLDER is None, reason="Requires to have restricted data setup"
)
def test_restricted_data_devices() -> None:
    """Test restricted data devices functionality.

    Verifies that the DatabaseManager can properly access and validate devices
    from the restricted data folder. The test ensures that the restricted data
    path is correctly configured and that all devices listed in the restricted
    data devices folder are accessible through the database.

    :raises AssertionError: If restricted data is None, folder path doesn't
        match expected location, or any device from restricted data folder
        is not found in database.
    """
    db = DatabaseManager().get_db(True)
    restricted_data = DatabaseManager.get_restricted_data()
    assert restricted_data is not None
    assert SPSDK_RESTRICTED_DATA_FOLDER
    assert os.path.normpath(restricted_data) == os.path.normpath(
        os.path.join(SPSDK_RESTRICTED_DATA_FOLDER, "data")
    )
    for device in os.listdir(os.path.join(restricted_data, "devices")):
        assert db.devices.get(device)


ALLOWED_PURPOSES = [
    "32-bit DSC Series",
    "LPC800 Series",
    "MCX Series",
    "Wireless Connectivity MCUs",
    "i.MX Application Processors",
    "Wireless Power",
    "LPC5500 Series",
    "i.MX RT Crossover MCUs",
]


def test_processor_purpose() -> None:
    """Test that all devices in the database have valid purposes.

    Validates that each device's purpose field contains only values from the
    predefined set of allowed purposes. This ensures data consistency across
    the device database.

    :raises AssertionError: When a device has a purpose not in ALLOWED_PURPOSES.
    """
    for dev, quick_info in DatabaseManager().quick_info.devices.devices.items():
        assert (
            quick_info.info.purpose in ALLOWED_PURPOSES
        ), f"Device '{dev}' purpose {quick_info.info.purpose} is not amongst allowed purposes: {ALLOWED_PURPOSES}"
