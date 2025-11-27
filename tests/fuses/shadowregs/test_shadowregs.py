#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK Shadow Registers test suite.

This module contains comprehensive tests for the SPSDK shadow registers functionality,
covering register operations, YAML configuration handling, CRC validation,
debug enablement, and probe communication features.
"""

import os
from copy import copy
from typing import Any, Optional

import pytest
import yaml

import spsdk.fuses.shadowregs as SR
from spsdk.apps.shadowregs import main
from spsdk.exceptions import SPSDKError
from spsdk.utils.config import Config
from spsdk.utils.database import Database, DevicesQuickInfo, QuickDatabase
from spsdk.utils.exceptions import SPSDKRegsErrorBitfieldNotFound, SPSDKRegsErrorRegisterNotFound
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import Endianness, use_working_directory
from tests.cli_runner import CliRunner
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual

TEST_DEV_NAME = "dev2"
TEST_DATABASE = "test_database.yaml"
TEST_DATABASE_BAD_COMPUTED_FUNC = "test_database_invalid_computed.yaml"
TEST_DATABASE_INVALID_FLUSH_FUNC = "test_database_invalid_flush_func.yaml"


def get_probe() -> DebugProbeVirtual:
    """Get a virtual debug probe for testing purposes.

    Creates, opens, and connects a virtual debug probe instance that can be used
    in test scenarios without requiring actual hardware.

    :return: Connected virtual debug probe instance ready for use.
    """
    probe = DebugProbeVirtual(DebugProbeVirtual.UNIQUE_SERIAL)
    probe.open()
    probe.connect()
    return probe


class TestDatabaseManager:
    """SPSDK Test Database Manager for shadow registers operations.

    This class provides centralized access to database instances used for shadow registers
    testing and validation. It manages both the main Database instance containing register
    definitions and the QuickDatabase instance for fast access operations.

    :cvar FEATURE1: Test feature identifier.
    :cvar FEATURE2: Test feature identifier.
    :cvar FEATURE3: Test feature identifier.
    :cvar SHADOW_REGS: Shadow registers feature identifier.
    """

    _instance = None
    _db: Optional[Database] = None
    _quick_info: Optional[DevicesQuickInfo] = None

    @property
    def db(self) -> Database:
        """Get the Database instance for shadow registers operations.

        This method retrieves the cached Database instance used for shadow registers
        configuration and validation. The database contains register definitions,
        field mappings, and validation rules.

        :return: Database instance containing shadow registers configuration.
        :raises AssertionError: If the database instance is not properly initialized.
        """
        db = type(self)._db
        assert isinstance(db, Database)
        return db

    @property
    def quick_info(self) -> QuickDatabase:
        """Get quick info Database.

        Retrieves the cached QuickDatabase instance containing quick access information
        for shadow registers configuration and validation.

        :raises AssertionError: If the quick info is not a valid QuickDatabase instance.
        :return: QuickDatabase instance with quick access information.
        """
        quick_info = type(self)._quick_info
        assert isinstance(quick_info, QuickDatabase)
        return quick_info

    # List all SPSDK supported features
    FEATURE1 = "feature1"
    FEATURE2 = "feature2"
    FEATURE3 = "feature3"
    SHADOW_REGS = "shadow_regs"


def test_shadowreg_basic(mock_test_database: Any, data_dir: str) -> None:
    """Test Shadow Registers basic functionality.

    Verifies that ShadowRegisters can be instantiated with a family revision
    and debug probe, and that the family name is correctly set.

    :param mock_test_database: Mocked test database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    probe = get_probe()

    shadowregs = SR.ShadowRegisters(family=FamilyRevision("dev2"), debug_probe=probe)
    assert shadowregs.family.name == TEST_DEV_NAME


def test_shadowreg_set_get_reg(mock_test_database: Any, data_dir: str) -> None:
    """Test Shadow Registers setting and getting register functionality.

    Validates that shadow registers can be properly set with various data types
    and sizes, and that the retrieved values match the original input data.
    Tests include 32-bit integers, 16-bit integers, inverted access point registers,
    and large byte arrays with different endianness configurations.

    :param mock_test_database: Mocked test database fixture for testing environment
    :param data_dir: Directory path containing test data files
    """
    probe = get_probe()
    shadowregs = SR.ShadowRegisters(family=FamilyRevision("dev2"), debug_probe=probe)

    test_val = bytearray(32)
    for i in range(32):
        test_val[i] = i

    shadowregs.set_register("REG1", 0x12345678)
    shadowregs.set_register("REG2", 0x4321)
    shadowregs.set_register("REG_INVERTED_AP", 0xA5A5A5A5)
    shadowregs.set_register("REG_BIG", test_val)
    shadowregs.set_register("REG_BIG_REV", test_val)

    assert shadowregs.get_register("REG1") == 0x12345678.to_bytes(4, Endianness.BIG.value)
    assert shadowregs.get_register("REG2") == 0x4321.to_bytes(2, Endianness.BIG.value)
    assert shadowregs.get_register("REG_INVERTED_AP") == 0xA5A5A5A5.to_bytes(
        4, Endianness.BIG.value
    )
    assert shadowregs.get_register("REG_BIG") == test_val
    assert shadowregs.get_register("REG_BIG_REV") == test_val


def test_shadowreg_set_reg_invalid(mock_test_database: Any, data_dir: str) -> None:
    """Test Shadow Registers invalid register operations.

    This test verifies that ShadowRegisters properly handles invalid scenarios
    when setting registers, including oversized values and non-existent register names.

    :param mock_test_database: Mock database fixture for testing
    :param data_dir: Directory path containing test data files
    """
    probe = get_probe()

    shadowregs = SR.ShadowRegisters(family=FamilyRevision("dev2"), debug_probe=probe)
    with pytest.raises(SPSDKError):
        shadowregs.set_register("REG1", 0x1234567800004321)

    with pytest.raises(SPSDKError):
        shadowregs.set_register("REG1_Invalid", 0x12345678)


def test_shadowreg_get_reg_invalid(mock_test_database: Any, data_dir: str) -> None:
    """Test Shadow Registers invalid get_register method calls.

    This test verifies that the ShadowRegisters.get_register() method properly
    raises SPSDKError when attempting to retrieve a non-existent register.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    :raises SPSDKError: Expected exception when accessing invalid register name.
    """
    probe = get_probe()

    shadowregs = SR.ShadowRegisters(family=FamilyRevision("dev2"), debug_probe=probe)
    with pytest.raises(SPSDKError):
        shadowregs.get_register("REG1_Invalid")


def test_shadowreg_invalid_probe(mock_test_database: Any, data_dir: str) -> None:
    """Test Shadow Registers with invalid probe used for constructor.

    Verifies that ShadowRegisters raises SPSDKError when attempting to perform
    operations with a None debug probe. Tests both set_register and get_register
    operations to ensure proper error handling.

    :param mock_test_database: Mocked test database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    probe = None

    shadowregs = SR.ShadowRegisters(family=FamilyRevision("dev2"), debug_probe=probe)

    with pytest.raises(SPSDKError):
        shadowregs.set_register("REG1", 0x12345678)

    with pytest.raises(SPSDKError):
        shadowregs.get_register("REG1")


# pylint: disable=protected-access
def test_shadowreg_verify_write(mock_test_database: Any, data_dir: str) -> None:
    """Test Shadow Registers write operation with verification.

    This test verifies the shadow register write functionality including verification
    mask behavior and error handling when verification fails. It tests both successful
    writes with different verification masks and failure scenarios.

    :param mock_test_database: Mock database fixture for testing environment.
    :param data_dir: Directory path containing test data files.
    :raises SPSDKVerificationError: When shadow register write verification fails.
    """
    probe = get_probe()

    shadowregs = SR.ShadowRegisters(family=FamilyRevision("dev2"), debug_probe=probe)

    shadowregs._write_shadow_reg(1, 0x12345678, verify_mask=0xFFFFFFFF)
    shadowregs._write_shadow_reg(1, 0x87654321, verify_mask=0)

    assert probe.mem_reg_read(1) == 0x87654321

    probe.set_virtual_memory_substitute_data({1: [0x12345678, 0x5555AAAA]})
    with pytest.raises(SR.SPSDKVerificationError):
        shadowregs._write_shadow_reg(1, 0x87654321, verify_mask=0xFFFFFFFF)

    assert probe.mem_reg_read(1) == 0x5555AAAA


def test_shadowreg_yml(mock_test_database: Any, data_dir: str, tmpdir: Any) -> None:
    """Test Shadow Registers YML configuration functionality.

    Comprehensive test that validates the Shadow Registers class ability to:
    - Set and get register values with different data types and sizes
    - Export configuration to YML format
    - Load configuration from YML and recreate Shadow Registers instance
    - Handle computed fields like CRC and test bits
    - Set only loaded registers from partial configurations

    :param mock_test_database: Mock database fixture for testing
    :param data_dir: Directory path containing test data files
    :param tmpdir: Temporary directory fixture for test file operations
    """
    probe = get_probe()

    shadowregs = SR.ShadowRegisters(family=FamilyRevision("dev2"), debug_probe=probe)

    test_val = bytearray(32)
    for i in range(32):
        test_val[i] = i

    test_val_rev = copy(test_val)
    test_val_rev.reverse()
    shadowregs.set_register("REG1", 0x12345678)
    shadowregs.set_register("REG2", 0x4321)
    shadowregs.set_register("REG_INVERTED_AP", 0xEDCBA987)
    shadowregs.set_register("REG_BIG", test_val)
    shadowregs.set_register("REG_BIG_REV", test_val)

    assert shadowregs.get_register("REG1") == 0x12345678.to_bytes(4, Endianness.BIG.value)
    assert shadowregs.get_register("REG2") == 0x4321.to_bytes(2, Endianness.BIG.value)
    assert shadowregs.get_register("REG_INVERTED_AP") == 0xEDCBA987.to_bytes(
        4, Endianness.BIG.value
    )
    assert shadowregs.get_register("REG_BIG") == test_val
    assert shadowregs.get_register("REG_BIG_REV") == test_val

    # Test of full configuration including computed fields
    cfg = shadowregs.get_config()

    probe.clear()

    shadowregs_load = SR.ShadowRegisters.load_from_config(cfg, debug_probe=probe)
    shadowregs_load.set_all_registers(verify=True)
    # Value with updated CRC RESERVED field and DEV TEST BIT
    assert shadowregs_load.get_register("REG1") == 0x92345678.to_bytes(4, Endianness.BIG.value)
    # Stored just usable part
    assert shadowregs_load.get_register("REG2") == 0x4321.to_bytes(2, Endianness.BIG.value)
    assert shadowregs_load.get_register("REG_INVERTED_AP") == 0xEDCBA987.to_bytes(
        4, Endianness.BIG.value
    )
    assert shadowregs_load.get_register("REG_BIG") == test_val
    assert shadowregs_load.get_register("REG_BIG_REV") == test_val

    # Test loaded registers only
    cfg["registers"] = {"REG1": 0xF0F0F0F0}
    shadowregs = SR.ShadowRegisters.load_from_config(cfg, debug_probe=probe)
    shadowregs.set_loaded_registers()
    assert shadowregs.get_register("REG1") == 0xF0F0F0F0.to_bytes(4, Endianness.BIG.value)
    assert shadowregs.get_register("REG2") == 0x4321.to_bytes(2, Endianness.BIG.value)
    cfg["registers"] = {"REG2": 0x0}
    shadowregs = SR.ShadowRegisters.load_from_config(cfg, debug_probe=probe)
    shadowregs.set_loaded_registers()
    assert shadowregs.get_register("REG1") == 0xF0F0F0F0.to_bytes(4, Endianness.BIG.value)
    assert shadowregs.get_register("REG2") == 0x0.to_bytes(2, Endianness.BIG.value)


def test_shadowreg_yml_compute_values(mock_test_database: Any, data_dir: str, tmpdir: Any) -> None:
    """Test Shadow Registers YML configuration loading and value computation.

    This test verifies that shadow registers can be properly configured, loaded from
    YML configuration, and that computed fields (like CRC) are correctly calculated
    when registers are set. It tests various register types including standard,
    inverted, and big-endian registers.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    :param tmpdir: Temporary directory fixture for test operations.
    """
    probe = get_probe()

    shadowregs = SR.ShadowRegisters(family=FamilyRevision("dev2"), debug_probe=probe)

    test_val = bytearray(32)
    for i in range(32):
        test_val[i] = i

    test_val_rev = copy(test_val)
    test_val_rev.reverse()
    shadowregs.set_register("REG1", 0x12345678)
    shadowregs.set_register("REG2", 0x4321)
    shadowregs.set_register("REG_INVERTED_AP", 0xEDCBA987)
    shadowregs.set_register("REG_BIG", test_val)
    shadowregs.set_register("REG_BIG_REV", test_val)

    assert shadowregs.get_register("REG1") == 0x12345678.to_bytes(4, Endianness.BIG.value)
    assert shadowregs.get_register("REG2") == 0x4321.to_bytes(2, Endianness.BIG.value)
    assert shadowregs.get_register("REG_INVERTED_AP") == 0xEDCBA987.to_bytes(
        4, Endianness.BIG.value
    )
    assert shadowregs.get_register("REG_BIG") == test_val
    assert shadowregs.get_register("REG_BIG_REV") == test_val

    # Test of configuration without computed fields
    cfg = shadowregs.get_config()
    cfg["registers"].pop("REG_INVERTED_AP")
    cfg["registers"]["REG1"].pop("CRC8")
    probe.clear()

    shadowregs_load = SR.ShadowRegisters.load_from_config(cfg, debug_probe=probe)
    shadowregs_load.set_all_registers(verify=True)
    # VAlue with updated CRC RESERVED field and DEV TEST BIT
    assert shadowregs_load.get_register("REG1") == 0x92345656.to_bytes(4, Endianness.BIG.value)
    # Stored just usable part
    assert shadowregs_load.get_register("REG2") == 0x4321.to_bytes(2, Endianness.BIG.value)
    assert shadowregs_load.get_register("REG_INVERTED_AP") == 0x6DCBA9A9.to_bytes(
        4, Endianness.BIG.value
    )
    assert shadowregs_load.get_register("REG_BIG") == test_val
    assert shadowregs_load.get_register("REG_BIG_REV") == test_val


def test_shadowreg_yml_corrupted(mock_test_database: Any, data_dir: str) -> None:
    """Test Shadow Registers with corrupted YML configuration.

    Verifies that ShadowRegisters.load_from_config properly handles and raises
    appropriate exceptions when provided with a corrupted YAML configuration file.
    The test ensures that either SPSDKRegsErrorBitfieldNotFound or
    SPSDKRegsErrorRegisterNotFound is raised when attempting to load invalid
    shadow register configuration.

    :param mock_test_database: Mocked test database fixture for testing environment
    :param data_dir: Directory path containing test data files including corrupted YAML
    """
    probe = get_probe()

    test_val = bytearray(32)
    for i in range(32):
        test_val[i] = i

    with pytest.raises((SPSDKRegsErrorBitfieldNotFound, SPSDKRegsErrorRegisterNotFound)):
        SR.ShadowRegisters.load_from_config(
            Config.create_from_file(os.path.join(data_dir, "sh_regs_corrupted.yml")),
            debug_probe=probe,
        )


def test_shadowreg_yml_invalid_computed(mock_test_database: Any, tmpdir: Any) -> None:
    """Test Shadow Registers with invalid computed configuration.

    This test verifies that ShadowRegisters properly handles and raises an error
    when attempting to load a configuration with invalid computed values. It sets
    up various register types, generates a configuration, and ensures that loading
    the configuration fails as expected.

    :param mock_test_database: Mock database fixture for testing.
    :param tmpdir: Temporary directory fixture for test files.
    :raises SPSDKError: Expected exception when loading invalid computed configuration.
    """
    probe = get_probe()
    shadowregs = SR.ShadowRegisters(
        family=FamilyRevision("dev2", "rev_test_invalid_computed"), debug_probe=probe
    )

    test_val = bytearray(32)
    for i in range(32):
        test_val[i] = i

    shadowregs.set_register("REG1", 0x12345678)
    shadowregs.set_register("REG2", 0x4321)
    shadowregs.set_register("REG_INVERTED_AP", 0xA5A5A5A5)
    shadowregs.set_register("REG_BIG", test_val)
    shadowregs.set_register("REG_BIG_REV", test_val)

    assert shadowregs.get_register("REG1") == 0x12345678.to_bytes(4, Endianness.BIG.value)
    assert shadowregs.get_register("REG2") == 0x4321.to_bytes(2, Endianness.BIG.value)
    assert shadowregs.get_register("REG_INVERTED_AP") == 0xA5A5A5A5.to_bytes(
        4, Endianness.BIG.value
    )
    assert shadowregs.get_register("REG_BIG") == test_val
    assert shadowregs.get_register("REG_BIG_REV") == test_val

    cfg = shadowregs.get_config()

    with pytest.raises(SPSDKError):
        SR.ShadowRegisters.load_from_config(cfg, debug_probe=probe)


def test_shadow_register_crc8() -> None:
    """Test the CRC8 algorithm implementation in Shadow Registers.

    Validates that the CRC8 calculation works correctly by performing a multi-step
    update operation with test data and verifying the expected result.

    :raises AssertionError: If the calculated CRC8 value does not match expected result.
    """
    crc = SR.ShadowRegisters.crc_update(b"\x12\x34", is_final=False)
    crc = SR.ShadowRegisters.crc_update(b"\x56", crc=crc)
    assert crc == 0x29


def test_shadow_register_crc8_hook(mock_test_database: Any) -> None:
    """Test Shadow Registers CRC8 algorithm hook functionality.

    Verifies that the CRC8 algorithm hook in ShadowRegisters correctly computes
    CRC8 values for given input data using the comalg_dcfg_cc_socu_crc8 method.

    :param mock_test_database: Mocked test database fixture for testing.
    """
    shadowregs = SR.ShadowRegisters(
        family=FamilyRevision("dev2", revision="rev_test_invalid_computed")
    )
    assert shadowregs.comalg_dcfg_cc_socu_crc8(0x03020100) == 0x0302011D
    assert shadowregs.comalg_dcfg_cc_socu_crc8(0x80FFFF00) == 0x80FFFF20


def test_shadow_register_invalid_flush_hook(mock_test_database: Any) -> None:
    """Test Shadow Registers with invalid flush hook functionality.

    Verifies that ShadowRegisters properly handles and raises an exception when
    attempting to set a register value with an invalid flush hook configuration.
    The test uses a family revision configured with an invalid flush function
    to trigger the error condition.

    :param mock_test_database: Mocked test database fixture for testing
    :raises SPSDKError: When attempting to set register with invalid flush hook
    """
    probe = get_probe()
    shadowregs1 = SR.ShadowRegisters(
        family=FamilyRevision("dev2", revision="rev_test_invalid_flush_func"), debug_probe=probe
    )

    with pytest.raises(SPSDKError):
        shadowregs1.set_register("REG1", 0x12345678)


def test_shadow_register_enable_debug_invalid_probe() -> None:
    """Test Shadow Registers enable debug with invalid probe.

    Verifies that the enable_debug method properly raises SPSDKError
    when called with a None probe parameter.

    :raises SPSDKError: When probe parameter is None.
    """
    probe = None
    with pytest.raises(SPSDKError):
        SR.enable_debug(probe, FamilyRevision("lpc55s6x"))  # type: ignore


def test_shadow_register_enable_debug_device_cannot_enable() -> None:
    """Test that shadow register debug enabling fails when target device is not connected.

    This test verifies the behavior of the enable_debug function when attempting
    to enable debug mode on a device that cannot be accessed. It simulates a
    scenario where memory read operations fail due to connection issues.
    """
    probe = get_probe()
    # invalid run
    # Setup the simulated data for reading of AP registers
    probe.mem_read_cause_exception(2)
    assert not SR.enable_debug(probe, FamilyRevision("lpc55s6x"))


def test_shadow_register_enable_debug() -> None:
    """Test Shadow Registers enable debug algorithm with valid target.

    This test verifies that the Shadow Registers enable_debug function works correctly
    when provided with a valid probe and target family. It sets up simulated AP register
    data and confirms the debug enabling process succeeds.

    :param: None
    :raises AssertionError: If the enable_debug function fails to return True.
    """
    probe = get_probe()
    # valid run, the right values are prepared

    # Setup the simulated data for reading of AP registers
    access_port = {12: ["Exception", 0x12345678], 0x02000000: [2, 0, 2, 0], 0x02000008: [0]}
    probe.set_coresight_ap_substitute_data(access_port)
    assert SR.enable_debug(probe, FamilyRevision("lpc55s6x"))


def test_shadow_register_enable_debug_already_enabled() -> None:
    """Test Shadow Registers enable debug functionality with pre-enabled target.

    Verifies that the enable_debug algorithm correctly handles cases where
    the debug functionality is already enabled on the target device.
    Sets up mock probe data and validates the expected behavior.

    :raises AssertionError: If enable_debug does not return the expected result.
    """
    probe = get_probe()
    # Setup the simulated data for reading of AP registers
    mem_ap = {12: [0x12345678]}
    probe.set_coresight_ap_substitute_data(mem_ap)
    assert SR.enable_debug(probe, FamilyRevision("lpc55s6x"))


def test_shadow_register_enable_debug_probe_exceptions() -> None:
    """Test Shadow Registers enable debug algorithm with probe exceptions.

    Verifies that the enable_debug function properly handles exceptions when
    the debug probe encounters communication errors. The test configures a
    virtual probe to throw exceptions during memory read and AP write operations,
    then confirms that enable_debug returns False under these error conditions.

    :raises SPSDKError: When debug probe operations fail as expected in test scenario.
    """
    probe = get_probe()
    with pytest.raises(SPSDKError):
        assert isinstance(probe, DebugProbeVirtual)
        probe.mem_read_cause_exception()  # To fail test connection function
        probe.ap_write_cause_exception()  # To fail write to debug mailbox
        assert not SR.enable_debug(probe, FamilyRevision("lpc55s6x"))


def test_generate_template(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test shadow registers template generation functionality.

    Verifies that the CLI can successfully generate YAML templates for shadow registers
    configuration. Tests both initial template creation and forced overwrite scenarios,
    ensuring the generated files are valid YAML format.

    :param cli_runner: Click CLI test runner for invoking command line interface.
    :param tmpdir: Temporary directory fixture for test file operations.
    """
    template = "template.yaml"
    family = "rt6xx"
    with use_working_directory(tmpdir):
        cli_runner.invoke(main, f"--family {family} get-template --output {template}")
        assert os.path.isfile(template)
        cli_runner.invoke(main, f"--family {family} get-template --output {template} --force")
        assert os.path.isfile(template)
        with open(template) as f:
            assert yaml.safe_load(f)


@pytest.mark.parametrize(
    "family,rkth0,rkth7",
    [
        ("rt5xx", "RKTH_255_224", "RKTH_31_0"),
        ("rt6xx", "RKTH_255_224", "RKTH_31_0"),
        ("rw61x", "RKTH[383:352]", "RKTH[159:128]"),
    ],
)
def test_rkth_order(family: str, rkth0: str, rkth7: str, data_dir: str) -> None:
    """Test RKTH register byte order in shadow registers.

    Validates that RKTH (Root Key Table Hash) registers maintain correct byte order
    when loaded from configuration and accessed through shadow register interface.
    The test verifies individual register values and combined RKTH byte sequence.

    :param family: Target MCU family name for shadow register configuration
    :param rkth0: Name of the first RKTH register to validate
    :param rkth7: Name of the seventh RKTH register to validate
    :param data_dir: Directory path containing test configuration files
    """
    probe = get_probe()
    # to simplify HW differences unify offsets
    cfg = Config.create_from_file(os.path.join(data_dir, "cfg_rkth.yaml"))
    cfg["family"] = family
    sr = SR.ShadowRegisters.load_from_config(cfg, debug_probe=probe)
    sr.offset_for_write = 0
    sr.set_all_registers()

    # validate expected results
    assert sr.get_register(rkth0) == b"\x13\x12\x11\x10"
    assert sr.get_register(rkth7) == b"\x2f\x2e\x2d\x2c"
    rkth = sr.registers.find_reg("RKTH").get_bytes_value()
    assert rkth[:4] == b"\x10\x11\x12\x13"
