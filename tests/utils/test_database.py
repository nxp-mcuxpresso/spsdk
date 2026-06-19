#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK database functionality test suite.

This module contains comprehensive tests for the SPSDK database system,
validating device configuration management, revision handling, ISP protocol
support, and data access controls including restricted data validation.
"""

import os
from pathlib import Path
from typing import Any, Optional

import pytest

from spsdk import SPSDK_RESTRICTED_DATA_FOLDER
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils import database, family
from spsdk.utils.database import (
    Bootloader,
    Database,
    DatabaseManager,
    DeviceInfo,
    DevicesQuickInfo,
    Features,
    FeaturesQuickData,
    IspCfg,
    MemBlock,
    MemMap,
    QuickDatabase,
    Revisions,
    SPSDKErrorMissingDevice,
    UsbId,
    UsbIdArray,
    _collect_usb_ids_for_feature,
    _format_udev_rule,
    _generate_device_rules,
    _generate_udev_header,
    _get_device_usb_ids,
    generate_udev_rules,
    get_spsdk_cache_dirname,
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


# get_spsdk_cache_dirname


def test_get_spsdk_cache_dirname_default() -> None:
    """Test get_spsdk_cache_dirname returns a non-empty path by default."""
    path = get_spsdk_cache_dirname()
    assert path
    assert isinstance(path, str)


def test_get_spsdk_cache_dirname_env_valid(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Test get_spsdk_cache_dirname with valid absolute SPSDK_CACHE_FOLDER."""
    cache_dir = str(tmp_path / "spsdk_cache")
    monkeypatch.setenv("SPSDK_CACHE_FOLDER", cache_dir)
    monkeypatch.setattr(database, "SPSDK_CACHE_FOLDER", cache_dir)
    result = get_spsdk_cache_dirname()
    assert result is not None


def test_get_spsdk_cache_dirname_env_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test get_spsdk_cache_dirname with relative SPSDK_CACHE_FOLDER raises."""
    monkeypatch.setattr(database, "SPSDK_CACHE_FOLDER", "relative/path")
    with pytest.raises(SPSDKValueError, match="Invalid SPSDK_CACHE_FOLDER"):
        get_spsdk_cache_dirname()


# SPSDKErrorMissingDevice


def test_spsdk_error_missing_device() -> None:
    """Test SPSDKErrorMissingDevice constructor and attributes."""
    err = SPSDKErrorMissingDevice(desc="Device not found", missing_device_name="lpc55s69")
    assert err.description == "Device not found"
    assert err.dev_name == "lpc55s69"


def test_spsdk_error_missing_device_defaults() -> None:
    """Test SPSDKErrorMissingDevice with no arguments."""
    err = SPSDKErrorMissingDevice()
    assert err.description is None
    assert err.dev_name is None


# Features class
# pylint: disable=redefined-outer-name


@pytest.fixture
def lpc55_db() -> Features:
    """Get database Features for lpc55s69."""
    return get_db(FamilyRevision("lpc55s69"))


def test_features_str(lpc55_db: Features) -> None:
    """Test Features.__str__."""
    s = str(lpc55_db)
    assert "Features" in s
    assert "lpc55s69" in s


def test_features_repr(lpc55_db: Features) -> None:
    """Test Features.__repr__."""
    r = repr(lpc55_db)
    assert "lpc55s69" in r


def test_features_check_key_exists(lpc55_db: Features) -> None:
    """Test Features.check_key for existing key."""
    assert lpc55_db.check_key("dat", "socc") is True


def test_features_check_key_missing(lpc55_db: Features) -> None:
    """Test Features.check_key for missing key."""
    assert lpc55_db.check_key("dat", "nonexistent_key_xyz") is False


def test_features_check_key_unsupported_feature(lpc55_db: Features) -> None:
    """Test Features.check_key with unsupported feature raises SPSDKValueError."""
    with pytest.raises(SPSDKValueError, match="Unsupported feature"):
        lpc55_db.check_key("nonexistent_feature_xyz", "key")


def test_features_check_key_nested_path(lpc55_db: Features) -> None:
    """Test Features.check_key with nested key list."""
    # Nested path that exists
    result = lpc55_db.check_key("dat", ["socc"])
    assert result is True


def test_features_check_key_nested_missing(lpc55_db: Features) -> None:
    """Test Features.check_key with deep nested missing path."""
    result = lpc55_db.check_key("dat", ["nonexistent", "deep", "path"])
    assert result is False


def test_features_get_value_unsupported_feature(lpc55_db: Features) -> None:
    """Test get_value with unsupported feature raises SPSDKValueError."""
    with pytest.raises(SPSDKValueError, match="Unsupported feature"):
        lpc55_db.get_value("nonexistent_feature", "key")


def test_features_get_int(lpc55_db: Features) -> None:
    """Test Features.get_int returns integer."""
    socc = lpc55_db.get_int("dat", "socc")
    assert isinstance(socc, int)


def test_features_get_bool(lpc55_db: Features) -> None:
    """Test Features.get_bool returns bool."""
    # Some bool-convertible value
    val = lpc55_db.get_bool("dat", "socc", default=False)
    assert isinstance(val, bool)


def test_features_get_str(lpc55_db: Features) -> None:
    """Test Features.get_str returns string."""
    # Use a key that's a string in the database
    # First find a string key
    families = lpc55_db.features.get("mbi", {})
    for key, val in families.items():
        if isinstance(val, str):
            result = lpc55_db.get_str("mbi", key)
            assert isinstance(result, str)
            break


def test_features_get_list(lpc55_db: Features) -> None:
    """Test Features.get_list returns list."""
    # Find a list key in the database
    for feature, data in lpc55_db.features.items():
        for key, val in data.items():
            if isinstance(val, list):
                result = lpc55_db.get_list(feature, key)
                assert isinstance(result, list)
                return
    pytest.skip("No list value found in lpc55s69 database")


def test_features_get_dict(lpc55_db: Features) -> None:
    """Test Features.get_dict returns dict."""
    for feature, data in lpc55_db.features.items():
        for key, val in data.items():
            if isinstance(val, dict):
                result = lpc55_db.get_dict(feature, key)
                assert isinstance(result, dict)
                return
    pytest.skip("No dict value found in lpc55s69 database")


# UsbId


def test_usb_id_str() -> None:
    """Test UsbId.__str__."""
    usb = UsbId(vid=0x1FC9, pid=0x0021)
    s = str(usb)
    assert "1FC9" in s or "0021" in s


def test_usb_id_equality() -> None:
    """Test UsbId.__eq__ same values."""
    usb1 = UsbId(vid=0x1234, pid=0x5678)
    usb2 = UsbId(vid=0x1234, pid=0x5678)
    assert usb1 == usb2


def test_usb_id_inequality() -> None:
    """Test UsbId.__eq__ different values."""
    usb1 = UsbId(vid=0x1234, pid=0x5678)
    usb2 = UsbId(vid=0xAAAA, pid=0xBBBB)
    assert usb1 != usb2


def test_usb_id_inequality_non_usb() -> None:
    """Test UsbId.__eq__ with non-UsbId object."""
    usb = UsbId(vid=0x1234, pid=0x5678)
    assert usb != "not a usb id"
    assert usb != 12345
    assert usb is not None


def test_usb_id_update() -> None:
    """Test UsbId.update method."""
    usb = UsbId(vid=0x1234, pid=0x5678)
    usb.update({"vid": 0xAAAA, "pid": 0xBBBB})
    assert usb.vid == 0xAAAA
    assert usb.pid == 0xBBBB


def test_usb_id_update_partial() -> None:
    """Test UsbId.update with partial config."""
    usb = UsbId(vid=0x1234, pid=0x5678)
    usb.update({"vid": 0xAAAA})
    assert usb.vid == 0xAAAA
    assert usb.pid == 0x5678  # unchanged


def test_usb_id_load() -> None:
    """Test UsbId.load classmethod."""
    usb = UsbId.load({"vid": 0x1FC9, "pid": 0x0021})
    assert usb.vid == 0x1FC9
    assert usb.pid == 0x0021


# UsbIdArray


def test_usb_id_array_str() -> None:
    """Test UsbIdArray.__str__."""
    arr = UsbIdArray()
    arr.append(UsbId(vid=0x1234, pid=0x5678))
    s = str(arr)
    assert s  # non-empty


def test_usb_id_array_contains_usb_id() -> None:
    """Test UsbIdArray.__contains__ with UsbId."""
    arr = UsbIdArray()
    usb = UsbId(vid=0x1234, pid=0x5678)
    arr.append(usb)
    assert UsbId(vid=0x1234, pid=0x5678) in arr


def test_usb_id_array_contains_missing() -> None:
    """Test UsbIdArray.__contains__ when item not present."""
    arr = UsbIdArray()
    arr.append(UsbId(vid=0x1234, pid=0x5678))
    assert UsbId(vid=0xFFFF, pid=0xFFFF) not in arr


def test_usb_id_array_contains_non_usb_id() -> None:
    """Test UsbIdArray.__contains__ with non-UsbId returns False."""
    arr = UsbIdArray()
    arr.append(UsbId(vid=0x1234, pid=0x5678))
    assert "not-a-usb-id" not in arr


def test_usb_id_array_load() -> None:
    """Test UsbIdArray.load classmethod."""
    arr = UsbIdArray.load([{"vid": 0x1234, "pid": 0x5678}, {"vid": 0xAAAA, "pid": 0xBBBB}])
    assert len(arr) == 2


def test_usb_id_array_no_duplicates() -> None:
    """Test UsbIdArray.update prevents duplicates."""
    arr = UsbIdArray()
    arr.update([{"vid": 0x1234, "pid": 0x5678}])
    arr.update([{"vid": 0x1234, "pid": 0x5678}])  # duplicate
    assert len(arr) == 1


# Bootloader


def test_bootloader_str_with_usb() -> None:
    """Test Bootloader.__str__ with USB IDs"""
    usb_ids = UsbIdArray()
    usb_ids.append(UsbId(vid=0x1FC9, pid=0x0021))
    bl = Bootloader(protocol="mboot", interfaces=["USB"], usb_ids=usb_ids, protocol_params={})
    s = str(bl)
    assert "mboot" in s
    assert "USB" in s


def test_bootloader_str_no_usb() -> None:
    """Test Bootloader.__str__ without USB IDs."""
    bl = Bootloader(protocol="sdp", interfaces=["UART"], usb_ids=UsbIdArray(), protocol_params={})
    s = str(bl)
    assert "sdp" in s
    assert "USB ID" not in s


def test_bootloader_str_no_protocol() -> None:
    """Test Bootloader.__str__ with no protocol."""
    bl = Bootloader(protocol=None, interfaces=[], usb_ids=UsbIdArray(), protocol_params={})
    s = str(bl)
    assert "Not specified" in s


def test_bootloader_invalid_protocol() -> None:
    """Test Bootloader raises SPSDKValueError for invalid protocol."""
    with pytest.raises(SPSDKValueError, match="Invalid protocol"):
        Bootloader(
            protocol="invalid_proto", interfaces=[], usb_ids=UsbIdArray(), protocol_params={}
        )


def test_bootloader_load() -> None:
    """Test Bootloader.load classmethod."""
    config = {
        "protocol": "mboot",
        "interfaces": ["USB", "UART"],
        "usb": [{"vid": 0x1FC9, "pid": 0x0021}],
        "protocol_params": {},
    }
    bl = Bootloader.load(config)
    assert bl.protocol == "mboot"
    assert "USB" in bl.interfaces


# MemBlock


def test_mem_block_parse_name_simple() -> None:
    """Test MemBlock.parse_name with simple name."""
    core, name, instance, _security = MemBlock.parse_name("sram0")
    assert name == "sram"
    assert instance == 0
    assert core is None


def test_mem_block_str() -> None:
    """Test MemBlock.__str__."""
    block = MemBlock("sram0", {"start_int": 0, "size_int": 65536, "external": False})
    s = str(block)
    assert "sram0" in s or "0x" in s


def test_mem_block_repr() -> None:
    """Test MemBlock.__repr__."""
    block = MemBlock("sram0", {"start_int": 0, "size_int": 65536, "external": False})
    r = repr(block)
    assert "MemBlock" in r


def test_mem_block_properties() -> None:
    """Test MemBlock.base_address, size, external properties."""
    block = MemBlock("sram0", {"start_int": 0x20000000, "size_int": 65536, "external": True})
    assert block.base_address == 0x20000000
    assert block.size == 65536
    assert block.external is True


def test_mem_block_create_name() -> None:
    """Test MemBlock.create_name."""
    name = MemBlock.create_name("sram", instance=0)
    assert name == "sram0"


# Features.get_value – nested key missing


def test_features_get_value_nested_missing_no_default(lpc55_db: Features) -> None:
    """Line 177: Missing nested group without default raises SPSDKValueError."""
    with pytest.raises(SPSDKValueError, match="Non-existing nested group"):
        lpc55_db.get_value("dat", ["nonexistent_group_xyz", "key"])


def test_features_get_value_nested_missing_with_default(lpc55_db: Features) -> None:
    """Lines 175-176: Missing nested group with default returns default value."""
    result = lpc55_db.get_value("dat", ["nonexistent_group_xyz", "key"], default="fallback")
    assert result == "fallback"


def test_features_check_key_non_dict_intermediate(lpc55_db: Features) -> None:
    """Lines 147-148: check_key returns False when intermediate value is not a dict."""
    # 'socc' is an integer, not a dict, so traversing into it returns False
    result = lpc55_db.check_key("dat", ["socc", "subkey"])
    assert result is False


# MemBlock additional parse_name paths


def test_mem_block_parse_name_too_many_underscores() -> None:
    """Line 650: parse_name raises SPSDKError for 3+ underscores."""
    with pytest.raises(SPSDKError, match="parse name failed"):
        MemBlock.parse_name("a_b_c_d")


def test_mem_block_parse_name_invalid_security_flag() -> None:
    """Lines 647-648: parse_name raises for invalid security suffix in 3-part name."""
    with pytest.raises(SPSDKError, match="Invalid security flag"):
        MemBlock.parse_name("cm33_sram_xyz")


def test_mem_block_parse_name_unknown_block_type() -> None:
    """Line 657: parse_name raises for unknown block type."""
    with pytest.raises(SPSDKError, match="parse name failed"):
        MemBlock.parse_name("unknownblock123")


def test_mem_block_parse_name_regex_no_match() -> None:
    """Line 654: parse_name raises when regex fails to match raw_name."""
    with pytest.raises(SPSDKError):
        MemBlock.parse_name("123invalid")


# MemBlock properties


def test_mem_block_core_property() -> None:
    """Lines 672-673: core property extracts core from name."""
    block = MemBlock("cm33_sram0", {"start_int": 0, "size_int": 0x1000})
    assert block.core == "cm33"


def test_mem_block_block_name_property() -> None:
    """Lines 684-685: block_name property extracts base block type."""
    block = MemBlock("cm33_sram0", {"start_int": 0, "size_int": 0x1000})
    assert block.block_name == "sram"


def test_mem_block_instance_property() -> None:
    """Lines 693-694: instance property extracts numeric instance."""
    block = MemBlock("sram2", {"start_int": 0, "size_int": 0x1000})
    assert block.instance == 2


def test_mem_block_security_access_property() -> None:
    """Lines 705-706: security_access property extracts security flag."""
    block_s = MemBlock("sram_s", {"start_int": 0, "size_int": 0x1000})
    assert block_s.security_access is True
    block_ns = MemBlock("sram_ns", {"start_int": 0, "size_int": 0x1000})
    assert block_ns.security_access is False


def test_mem_block_create_name_unknown_core() -> None:
    """Line 732: create_name raises SPSDKError for unknown core."""
    with pytest.raises(SPSDKError, match="unknown core name"):
        MemBlock.create_name("sram", core="invalid_core_xyz")


def test_mem_block_create_name_with_security() -> None:
    """Line 740: create_name appends security suffix."""
    name_s = MemBlock.create_name("sram", secure_access=True)
    assert name_s.endswith("_s")
    name_ns = MemBlock.create_name("sram", secure_access=False)
    assert name_ns.endswith("_ns")


# MemMap


def test_mem_map_str() -> None:
    """Lines 767-770: MemMap.__str__ includes block names."""
    mem_map = MemMap.load(
        {
            "sram": {"start_int": 0x20000000, "size_int": 0x8000},
            "internal-flash": {"start_int": 0x0, "size_int": 0x40000},
        }
    )
    s = str(mem_map)
    assert "sram" in s


def test_mem_map_get_table() -> None:
    """Lines 780-792: MemMap.get_table returns a formatted table string."""
    mem_map = MemMap.load(
        {
            "sram": {"start_int": 0x20000000, "size_int": 0x8000},
        }
    )
    table = mem_map.get_table()
    assert "sram" in table.lower() or "Block" in table


# IspCfg


def _make_isp(rom_proto: Optional[str] = "mboot", fl_proto: Optional[str] = "sdp") -> IspCfg:
    """Build a simple IspCfg for testing."""
    rom_cfg: dict = {"interfaces": ["uart"]}
    if rom_proto:
        rom_cfg["protocol"] = rom_proto
    fl_cfg: dict = {"interfaces": ["usb"]}
    if fl_proto:
        fl_cfg["protocol"] = fl_proto
    return IspCfg(rom=Bootloader.load(rom_cfg), flashloader=Bootloader.load(fl_cfg))


def test_isp_cfg_str_basic() -> None:
    """Lines 874-899: IspCfg.__str__ with ROM and FlashLoader."""
    isp = _make_isp()
    s = str(isp)
    assert "ROM" in s


def test_isp_cfg_str_with_fastboot() -> None:
    """Lines 874-899: IspCfg.__str__ includes Fastboot section when present."""
    isp = _make_isp()
    isp.fastboot = Bootloader.load({"protocol": "lpc", "interfaces": []})
    s = str(isp)
    assert "Fastboot" in s


def test_isp_cfg_str_empty() -> None:
    """Lines 897-899: IspCfg.__str__ returns empty string when no protocols set."""
    isp = IspCfg(rom=Bootloader.load({}), flashloader=Bootloader.load({}))
    s = str(isp)
    assert s == ""


def test_isp_cfg_update_adds_fastboot() -> None:
    """Lines 944-957: update() creates fastboot bootloader when absent."""
    isp = _make_isp()
    assert isp.fastboot is None
    isp.update({"fastboot": {"protocol": "lpc", "interfaces": []}})
    assert isp.fastboot is not None
    assert isp.fastboot.protocol == "lpc"


def test_isp_cfg_update_existing_fastboot() -> None:
    """Lines 944-957: update() updates existing fastboot bootloader."""
    isp = _make_isp()
    isp.fastboot = Bootloader.load({"protocol": "lpc", "interfaces": []})
    isp.update({"fastboot": {"interfaces": ["uart"]}})
    assert "uart" in isp.fastboot.interfaces


def test_isp_cfg_update_adds_sdpv() -> None:
    """Lines 944-957: update() creates sdpv bootloader when absent."""
    isp = _make_isp()
    assert isp.sdpv is None
    isp.update({"sdpv": {"protocol": "sdpv", "interfaces": []}})
    assert isp.sdpv is not None


def test_isp_cfg_get_usb_ids() -> None:
    """Lines 993-997: get_usb_ids returns IDs for matching protocol."""
    rom = Bootloader.load(
        {
            "protocol": "mboot",
            "interfaces": ["usb"],
            "usb": [{"vid": 0x1234, "pid": 0x5678}],
        }
    )
    isp = IspCfg(rom=rom, flashloader=Bootloader.load({}))
    ids = isp.get_usb_ids("mboot")
    assert len(ids) == 1
    assert ids[0].vid == 0x1234


def test_isp_cfg_get_usb_ids_wrong_proto() -> None:
    """Lines 993-997: get_usb_ids returns [] for non-matching protocol."""
    assert _make_isp().get_usb_ids("sdps") == []


def test_isp_cfg_get_all_bootloaders() -> None:
    """Lines 1034-1039: get_all_bootloaders includes configured bootloaders."""
    isp = _make_isp()
    isp.fastboot = Bootloader.load({"protocol": "lpc", "interfaces": []})
    bootloaders = isp.get_all_bootloaders()
    assert "rom" in bootloaders
    assert "fastboot" in bootloaders


def test_isp_cfg_get_bootloader_invalid_type() -> None:
    """Lines 1048-1053: get_bootloader raises SPSDKValueError for bad type."""
    with pytest.raises(SPSDKValueError, match="Invalid bootloader type"):
        _make_isp().get_bootloader("invalid_type")


def test_isp_cfg_get_bootloader_valid() -> None:
    """Lines 1048-1053: get_bootloader returns bootloader for valid type."""
    bl = _make_isp().get_bootloader("rom")
    assert bl is not None


# DeviceInfo.__repr__


def test_device_info_repr() -> None:
    """Line 1095: DeviceInfo.__repr__ returns expected format."""
    config = {
        "purpose": "Test MCU",
        "web": "https://test.com",
        "memory_map": {},
        "isp": {"rom": {}, "flashloader": {}},
    }
    defaults = {
        "purpose": "Default",
        "web": "https://default.com",
        "memory_map": {},
        "isp": {"rom": {}, "flashloader": {}},
    }
    info = DeviceInfo.load(config, defaults)
    r = repr(info)
    assert "DeviceInfo" in r
    assert "Test MCU" in r


# Device and Devices (real DB)


def test_device_repr() -> None:
    """Line 1214: Device.__repr__ returns 'Device(<name>)'."""
    dev = DatabaseManager().db.devices.get("lpc55s69")
    assert "Device" in repr(dev)
    assert "lpc55s69" in repr(dev)


def test_device_lt() -> None:
    """Line 1222: Device.__lt__ compares names lexicographically."""
    db = DatabaseManager().db
    dev_a = db.devices.get("lpc55s69")
    dev_b = db.devices.get("mcxn947")
    assert (dev_a < dev_b) == ("lpc55s69" < "mcxn947")


def test_device_get_features() -> None:
    """Line 1230: Device.get_features returns feature list."""
    dev = DatabaseManager().db.devices.get("lpc55s69")
    features = dev.get_features()
    assert isinstance(features, list)
    assert len(features) > 0


def test_devices_get_empty_name() -> None:
    """Line 1415: Devices.get('') raises SPSDKErrorMissingDevice."""
    with pytest.raises(SPSDKErrorMissingDevice):
        DatabaseManager().db.devices.get("")


def test_devices_get_nonexistent_device() -> None:
    """Line 1423: Devices.get raises for totally unknown device."""
    with pytest.raises(Exception):
        DatabaseManager().db.devices.get("completely_nonexistent_device_xyz_123")


def test_devices_load_already_loaded() -> None:
    """Lines 1470-1471: _load_and_append_device skips already-loaded devices."""
    db = DatabaseManager().db
    db.devices.get("lpc55s69")  # ensure loaded
    count_before = len(db.devices.devices)
    db.devices._load_and_append_device("lpc55s69")
    assert len(db.devices.devices) == count_before


# DevicesQuickInfo


def test_devices_quick_info_get_feature_list_empty() -> None:
    """Lines 1626-1628: get_feature_list returns [] when devices dict is empty."""
    dqi = DevicesQuickInfo()
    assert dqi.get_feature_list("any_family") == []


def test_devices_quick_info_predecessor_lookup_populated() -> None:
    """Lines 1604-1605: real DB has predecessor lookup entries."""
    pl = DatabaseManager().quick_info.devices.predecessor_lookup
    assert len(pl) > 0
    for pred_name, current_name in pl.items():
        assert isinstance(pred_name, str) and isinstance(current_name, str)


def test_devices_quick_info_is_predecessor_name() -> None:
    """DevicesQuickInfo.is_predecessor_name correctly identifies predecessors."""
    dqi = DevicesQuickInfo()
    dqi.predecessor_lookup = {"oldname": "newname"}
    assert dqi.is_predecessor_name("oldname") is True
    assert dqi.is_predecessor_name("newname") is False


def test_devices_quick_info_get_correct_name() -> None:
    """DevicesQuickInfo.get_correct_name resolves predecessor names."""
    qdb = DatabaseManager().quick_info
    pl = qdb.devices.predecessor_lookup
    if not pl:
        pytest.skip("No predecessor entries in DB")
    pred, current = next(iter(pl.items()))
    assert qdb.devices.get_correct_name(pred) == current
    assert qdb.devices.get_correct_name(current) == current


# FeaturesQuickData


def test_features_quick_data_get_all_features() -> None:
    """Line 1758: get_all_features property returns feature names."""
    fqd = FeaturesQuickData()
    fqd.features = {"mbi": {"mem_types": ["flexspi"]}, "cert_block": {}}
    assert "mbi" in fqd.get_all_features
    assert "cert_block" in fqd.get_all_features


def test_features_quick_data_get_mem_types_missing_feature() -> None:
    """Line 1771: get_mem_types returns [] for non-existent feature."""
    assert FeaturesQuickData().get_mem_types("nonexistent_feature") == []


def test_features_quick_data_get_mem_types_no_key() -> None:
    """Line 1773: get_mem_types returns [] when feature has no mem_types."""
    fqd = FeaturesQuickData()
    fqd.features = {"some_feature": {"other_key": "val"}}
    assert fqd.get_mem_types("some_feature") == []


def test_features_quick_data_mem_types_real_db() -> None:
    """Lines 1742-1748: FeaturesQuickData from real DB has mem_types for bootable_image."""
    mem_types = DatabaseManager().quick_info.features_data.get_mem_types("bootable_image")
    assert isinstance(mem_types, list) and len(mem_types) > 0


def test_features_quick_data_get_all_features_real_db() -> None:
    """Line 1758: get_all_features on real DB returns non-empty list."""
    all_feats = DatabaseManager().quick_info.features_data.get_all_features
    assert isinstance(all_feats, list) and len(all_feats) > 0


# QuickDatabase.split_devices_to_groups


def test_quick_database_split_devices_to_groups() -> None:
    """Lines 1816-1825: split_devices_to_groups groups devices by purpose."""
    qdb = DatabaseManager().quick_info
    sample = qdb.devices.get_family_names()[:5]
    groups = qdb.split_devices_to_groups(sample)
    assert isinstance(groups, dict)
    all_in_groups = [d for devs in groups.values() for d in devs]
    for s in sample:
        assert s in all_in_groups


# Database.get_defaults with invalid feature


def test_database_get_defaults_invalid_feature() -> None:
    """Line 2089: get_defaults raises SPSDKValueError for unknown feature."""
    with pytest.raises(SPSDKValueError, match="Invalid feature"):
        DatabaseManager().db.get_defaults("totally_nonexistent_feature_xyz_abc")


def test_database_get_defaults_valid_feature() -> None:
    """get_defaults returns dict for known feature."""
    assert isinstance(DatabaseManager().db.get_defaults("mbi"), dict)


# Database.__hash__


def test_database_hash() -> None:
    """Lines 2197-2199: Database.__hash__ returns an integer."""
    assert isinstance(hash(DatabaseManager().db), int)


# Database.load_db_cfg_file with invalid config


def test_database_load_db_cfg_file_invalid(tmp_path: Path) -> None:
    """Lines 2180-2185: load_db_cfg_file raises SPSDKError for malformed YAML."""
    bad_file = str(tmp_path / "bad.yaml")
    with open(bad_file, "w", encoding="utf-8") as f:
        f.write("key: [unclosed bracket\n")
    with pytest.raises(SPSDKError):
        DatabaseManager().db.load_db_cfg_file(bad_file)


# DatabaseManager.clear_cache


def test_database_manager_clear_cache_nonexistent(monkeypatch: Any, caplog: Any) -> None:
    """Lines 2287-2289: clear_cache logs error for non-existent directory."""
    import logging

    monkeypatch.setattr(
        database, "get_spsdk_cache_dirname", lambda: "/nonexistent/path/xyz_no_dir_abc"
    )
    with caplog.at_level(logging.ERROR, logger="spsdk.utils.database"):
        DatabaseManager.clear_cache()
    assert any("does not exist" in r.message for r in caplog.records)


# DatabaseManager.get_restricted_data


def test_database_manager_get_restricted_data_none(monkeypatch: Any) -> None:
    """Lines 2304-2305: get_restricted_data returns None when not configured."""
    monkeypatch.setattr(database, "SPSDK_RESTRICTED_DATA_FOLDER", None)
    assert DatabaseManager.get_restricted_data() is None


def test_database_manager_get_restricted_data_invalid_folder(monkeypatch: Any) -> None:
    """Lines 2307-2313: get_restricted_data returns None for bad/missing path."""
    monkeypatch.setattr(database, "SPSDK_RESTRICTED_DATA_FOLDER", "/nonexistent/restricted/xyz")
    assert DatabaseManager.get_restricted_data() is None


# udev rules generation


def test_generate_udev_header() -> None:
    """Line 2611: _generate_udev_header returns list with rule name."""
    lines = _generate_udev_header("TESTFEATURE")
    assert isinstance(lines, list)
    assert any("TESTFEATURE" in line for line in lines)


def test_format_udev_rule_valid() -> None:
    """Lines 2705-2711: _format_udev_rule formats rule for valid UsbId."""
    rule = _format_udev_rule(UsbId(vid=0x1FC9, pid=0x0135))
    assert rule is not None
    assert "1fc9" in rule
    assert "0135" in rule


def test_format_udev_rule_none_vid() -> None:
    """Lines 2708-2709: _format_udev_rule returns None when vid is None."""
    assert _format_udev_rule(UsbId(vid=None, pid=0x0135)) is None


def test_format_udev_rule_none_pid() -> None:
    """Lines 2708-2709: _format_udev_rule returns None when pid is None."""
    assert _format_udev_rule(UsbId(vid=0x1FC9, pid=None)) is None


def test_generate_device_rules_empty() -> None:
    """Lines 2685-2686: _generate_device_rules returns [] for empty USB IDs."""
    assert _generate_device_rules("testdevice", []) == []


def test_generate_device_rules_with_ids() -> None:
    """Lines 2685-2696: _generate_device_rules produces rule lines for device."""
    result = _generate_device_rules("mydevice", [UsbId(vid=0x1234, pid=0x5678)])
    assert isinstance(result, list)
    assert any("MYDEVICE" in line for line in result)


def test_get_device_usb_ids_known() -> None:
    """Lines 2657-2675: _get_device_usb_ids returns list for real device."""
    assert isinstance(_get_device_usb_ids(DatabaseManager(), "mimx8qxp"), list)


def test_get_device_usb_ids_nonexistent() -> None:
    """Lines 2657-2675: _get_device_usb_ids returns [] for unknown device."""
    assert _get_device_usb_ids(DatabaseManager(), "nonexistent_device_xyz_123") == []


def test_collect_usb_ids_invalid_feature() -> None:
    """Lines 2637-2638: _collect_usb_ids_for_feature raises for unknown feature."""
    with pytest.raises(SPSDKError, match="No devices found"):
        _collect_usb_ids_for_feature("completely_nonexistent_feature_xyz")


def test_collect_usb_ids_nxpuuu() -> None:
    """Lines 2632-2647: _collect_usb_ids_for_feature returns dict for nxpuuu."""
    result = _collect_usb_ids_for_feature("nxpuuu")
    assert isinstance(result, dict) and len(result) > 0


def test_generate_udev_rules_nxpuuu() -> None:
    """Lines 2586-2602: generate_udev_rules produces valid udev content."""
    rules = generate_udev_rules("nxpuuu")
    assert "NXP" in rules and "SUBSYSTEM" in rules


def test_generate_udev_rules_invalid_feature() -> None:
    """Lines 2595-2596: generate_udev_rules raises SPSDKError for unsupported feature."""
    with pytest.raises(SPSDKError):
        generate_udev_rules("completely_nonexistent_feature_xyz")


def test_generate_udev_rules_custom_rule_name() -> None:
    """Lines 2586-2590: generate_udev_rules uses provided rule_name in header."""
    rules = generate_udev_rules("nxpuuu", rule_name="CUSTOM_NAME")
    assert "CUSTOM_NAME" in rules


# Revisions.get error path


def test_revisions_get_nonexistent() -> None:
    """Line 321: Revisions.get raises SPSDKValueError for unknown revision."""
    from unittest.mock import MagicMock

    revisions = Revisions()
    device = MagicMock()
    device.name = "testdev"
    revisions.append(Features(name="rev1", is_latest=True, device=device, features={}))
    with pytest.raises(SPSDKValueError, match="not supported"):
        revisions.get("nonexistent_rev")
