#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK Fuses module unit tests.

This module contains comprehensive unit tests for the SPSDK fuses functionality,
covering fuse operations, configuration management, family support validation,
and error handling scenarios.
"""

import os
from typing import Any

import pytest
from yaml import safe_load

from spsdk.exceptions import SPSDKError, SPSDKKeyError
from spsdk.fuses.fuse_registers import FuseRegister
from spsdk.fuses.fuses import (
    BlhostFuseOperator,
    FuseOperator,
    Fuses,
    NxpeleFuseOperator,
    SPSDKFuseOperationFailure,
)
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_configuration
from tests.fuses.fuses.fuses_test_operator import TestFuseOperator
from tests.fuses.fuses.test_fuse_registers import get_reg_from_cfg


def test_get_operator_type() -> None:
    """Test getting operator type from string identifier.

    Verifies that FuseOperator.get_operator_type() correctly returns the appropriate
    operator class for valid identifiers and raises SPSDKKeyError for unknown ones.

    :raises SPSDKKeyError: When an unknown operator type identifier is provided.
    """
    assert FuseOperator.get_operator_type("blhost") == BlhostFuseOperator
    assert FuseOperator.get_operator_type("nxpele") == NxpeleFuseOperator
    with pytest.raises(SPSDKKeyError):
        FuseOperator.get_operator_type("unknown")


def test_get_fuse_script(data_dir: str) -> None:
    """Test fuse script generation for different operators.

    This test verifies that both BlhostFuseOperator and NxpeleFuseOperator
    can generate proper fuse programming scripts with correct commands
    and formatting for a given family revision and fuse configuration.

    :param data_dir: Directory path containing test data files including fuses.json configuration
    """
    full_config = load_configuration(os.path.join(data_dir, "fuses.json"))
    fuse_cfg = get_reg_from_cfg(full_config, "BOOT_CFG", "SDHC_CFGF1")
    fuse = FuseRegister.create_from_spec(fuse_cfg)
    fuse.set_value(0xA)
    script = BlhostFuseOperator.get_fuse_script(FamilyRevision("mimxrt798s"), fuses=[fuse])
    assert "BLHOST fuses programming script" in script
    assert "efuse-program-once 159 0xA --no-verify" in script
    script = NxpeleFuseOperator.get_fuse_script(FamilyRevision("mimxrt798s"), fuses=[fuse])
    assert "NXPELE fuses programming script" in script
    assert "write-fuse --index 159 --data 0xA" in script


def test_get_supported_families(mock_test_database: Any, data_dir: str) -> None:
    """Test that Fuses.get_supported_families() returns expected family revisions.

    Verifies that the method returns exactly 3 families with correct FamilyRevision
    objects including dev2 family with rev1, rev_test_invalid_computed, and
    rev_test_invalid_flush_func revisions.

    :param mock_test_database: Mocked test database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    families = Fuses.get_supported_families()
    assert len(families) == 3
    assert families[0] == FamilyRevision("dev2", "rev1")
    assert families[1] == FamilyRevision("dev2", "rev_test_invalid_computed")
    assert families[2] == FamilyRevision("dev2", "rev_test_invalid_flush_func")


def test_initialize_unsupported_family(mock_test_database: Any, data_dir: str) -> None:
    """Test that Fuses initialization raises SPSDKError for unsupported family.

    This test verifies that attempting to initialize the Fuses class with an
    unsupported family revision properly raises an SPSDKError exception.

    :param mock_test_database: Mocked test database fixture.
    :param data_dir: Directory path containing test data files.
    """
    with pytest.raises(SPSDKError):
        Fuses(family=FamilyRevision("dev1"))


def test_fuses_operator(mock_test_database: Any, data_dir: str) -> None:
    """Test fuses operator functionality and validation.

    Tests the fuses operator property getter/setter behavior, including error handling
    for missing operators, validation of operator types, and verification that the
    correct operator type is returned for a given family revision.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    :raises SPSDKError: When fuse operator is not set or invalid operator is assigned.
    """
    fuses = Fuses(family=FamilyRevision("dev2"))
    with pytest.raises(SPSDKError):
        fuses.fuse_operator
    with pytest.raises(SPSDKError):
        from spsdk.mboot.mcuboot import McuBoot

        mock_mcuboot = McuBoot(interface=None)  # type: ignore
        fuses.fuse_operator = BlhostFuseOperator(mock_mcuboot)
    fuses.fuse_operator = TestFuseOperator()
    assert fuses.fuse_operator_type == TestFuseOperator
    assert Fuses.get_fuse_operator_type(FamilyRevision("dev2")) == TestFuseOperator


def test_fuses_try_read_write_only_fuse(mock_test_database: Any, data_dir: str) -> None:
    """Test reading a write-only fuse raises appropriate exception.

    This test verifies that attempting to read a write-only fuse field
    raises SPSDKFuseOperationFailure and that no actions are recorded
    in the operator when the operation fails.

    :param mock_test_database: Mocked test database fixture.
    :param data_dir: Directory path containing test data files.
    :raises SPSDKFuseOperationFailure: When attempting to read write-only fuse.
    """
    operator = TestFuseOperator()
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator)
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.read_single("field200")
    assert operator.actions == []


def test_fuses_try_write_read_only_fuse(mock_test_database: Any, data_dir: str) -> None:
    """Test writing to a read-only fuse field.

    Verifies that attempting to write to a read-only fuse field raises the appropriate
    exception and that no actions are performed on the fuse operator.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    :raises SPSDKFuseOperationFailure: When attempting to write to read-only fuse field.
    """
    operator = TestFuseOperator()
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator)
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.write_single("field204")
    assert operator.actions == []


def test_fuses_read_single(mock_test_database: Any, data_dir: str) -> None:
    """Test reading a single fuse value and verifying register update.

    This test verifies that reading a single fuse field correctly retrieves the value
    from the fuse operator and updates the corresponding register's cached value.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    operator = TestFuseOperator(return_values={0x14: 3})
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator)
    register = fuses.fuse_regs.get_reg("field204")
    assert register.get_value() == 0
    assert fuses.read_single("field204") == 3
    assert register.get_value() == 3


def test_fuses_read_single_grouped(mock_test_database: Any, data_dir: str) -> None:
    """Test reading a single grouped fuse register.

    This test verifies that reading a single fuse register that spans multiple
    physical fuse addresses works correctly. It sets up a mock fuse operator
    with specific return values and tests that the grouped register value is
    properly assembled from individual fuse reads.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    operator = TestFuseOperator(return_values={0x3: 1, 0x4: 1})
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator)
    register = fuses.fuse_regs.find_reg("REG_BIG")
    assert register.get_value() == 0
    assert fuses.read_single("REG_BIG") == 0x100000001


def test_fuses_read_all(mock_test_database: Any, data_dir: str) -> None:
    """Test reading all fuses from a mock database.

    This test verifies that the Fuses.read_all() method correctly reads fuse values
    from the operator and populates the fuse registers. It also ensures that fuses
    without proper permissions are not included in the fuse context.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    operator = TestFuseOperator(return_values={0x14: 0x30, 0x400: 3})
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator)
    fuses.read_all()
    assert fuses.fuse_regs.find_reg("lock0").get_value() == 3
    assert fuses.fuse_regs.find_reg("READ_ONLY_REG").get_value() == 0x30
    # some of the fuses were not read due to permissions
    for fuse in fuses.fuse_context:
        assert fuse.name not in ["REG1", "WRITE_ONLY_REG"]


def test_fuses_try_read_locked_fuse(mock_test_database: Any, data_dir: str) -> None:
    """Test reading a locked fuse register and verify proper exception handling.

    This test verifies that attempting to read a locked fuse register raises the appropriate
    exception, while also testing the lock register properties and write operations.
    The test uses a mock fuse operator to simulate hardware behavior.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    :raises SPSDKFuseOperationFailure: When attempting to read a locked fuse register.
    """
    operator = TestFuseOperator(return_values={0x15: 5, 0x400: 2})
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator)
    register = fuses.fuse_regs.get_reg("field208")
    assert register.fuse_lock_register is not None
    assert register.fuse_lock_register.register_id == "lock0"
    assert register.fuse_lock_register.read_lock_mask == 0x2
    assert register.fuse_lock_register.write_lock_mask == 0x1
    assert register.fuse_lock_register.operation_lock_mask == 0x4
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.read_single("field208")
    register.set_value(10)
    fuses.write_single("field208")
    assert len(operator.actions) == 3
    assert operator.actions[0].action_type == "read"
    assert operator.actions[1].action_type == "read"
    assert operator.actions[2].action_type == "write"
    assert operator.actions[2].fuse_index == 0x15
    assert operator.actions[2].value == 10


def test_fuses_try_write_locked_fuse(mock_test_database: Any, data_dir: str) -> None:
    """Test writing to a locked fuse register and verify proper exception handling.

    This test verifies that the fuse system correctly prevents write operations
    to locked fuse registers and raises appropriate exceptions. It also tests
    that read operations are handled correctly based on lock status.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    :raises SPSDKFuseOperationFailure: When attempting to write to locked fuse or read locked fuse.
    """
    operator = TestFuseOperator(return_values={0x15: 5, 0x400: 1})
    fuses = Fuses(family=FamilyRevision("dev2"), fuse_operator=operator)
    register = fuses.fuse_regs.get_reg("field208")
    assert register.fuse_lock_register is not None
    assert register.fuse_lock_register.register_id == "lock0"
    assert register.fuse_lock_register.read_lock_mask == 0x2
    assert register.fuse_lock_register.write_lock_mask == 0x1
    assert register.fuse_lock_register.operation_lock_mask == 0x4
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.write_single("field208")
    fuses.read_single("field208")
    assert len(operator.actions) == 3  # due to reading the lock register
    assert operator.actions[0].action_type == "read"
    assert operator.actions[1].action_type == "read"
    assert operator.actions[2].action_type == "read"
    assert operator.actions[2].fuse_index == 0x15
    operator.return_values[0x400] = 3  # lock the read and write
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.write_single("field208")
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.read_single("field208")


def test_fuses_template(mock_test_database: Any, data_dir: str) -> None:
    """Test fuses configuration template generation functionality.

    This test verifies that the Fuses class can generate a proper configuration
    template for a given family revision and that the template contains the
    expected structure and values.

    :param mock_test_database: Mocked test database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    fuses = Fuses(family=FamilyRevision("dev2"))
    template = fuses.get_config_template(FamilyRevision("dev2"))
    template_dict = safe_load(template)
    assert template_dict["family"] == "dev2"
    assert template_dict["revision"] == "latest"
    assert template_dict["registers"]


def test_fuses_load_config(mock_test_database: Any, data_dir: str) -> None:
    """Test loading fuses configuration from YAML file.

    Validates that fuses can be properly loaded from a configuration file and that
    the loaded fuse registers contain the expected values. Tests the complete flow
    of configuration loading and fuse register initialization.

    :param mock_test_database: Mocked test database fixture for testing.
    :param data_dir: Directory path containing test configuration files.
    """
    cfg = Config.create_from_file(os.path.join(data_dir, "test_config_1.yaml"))
    fuses = Fuses.load_from_config(cfg)
    assert isinstance(fuses, Fuses)
    reg = fuses.fuse_regs.find_reg("REG1")
    assert reg.get_value() == 0x300
    reg = fuses.fuse_regs.find_reg("REG2")
    assert reg.get_value() == 0x85
    reg = fuses.fuse_regs.find_reg("LOCK0")
    assert reg.get_value() == 0x1
    assert len(fuses.fuse_context) == 3
