#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK Fuse Registers testing module.

This module contains comprehensive tests for the fuse registers functionality in SPSDK,
including fuse register creation, configuration, locking mechanisms, and register
management operations for NXP MCU fuse handling.
"""

import os
from typing import Any, Dict, List, Optional

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.fuses.fuse_registers import FuseLock, FuseLockRegister, FuseRegister, FuseRegisters
from spsdk.utils.config import Config
from spsdk.utils.exceptions import (
    SPSDKRegsErrorRegisterGroupMishmash,
    SPSDKRegsErrorRegisterNotFound,
)
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_configuration
from spsdk.utils.registers import Access


def get_reg_from_cfg(cfg: dict, group_name: str, fuse_name: str) -> Dict[str, Any]:
    """Get register configuration from configuration dictionary.

    Searches through the configuration groups to find a specific register
    by group name and fuse name, returning its configuration data.

    :param cfg: Configuration dictionary containing groups and registers.
    :param group_name: Name of the group to search in.
    :param fuse_name: Name of the fuse register to find.
    :raises SPSDKError: When the register with specified name does not exist.
    :return: Dictionary containing the register configuration data.
    """
    for group in cfg["groups"]:
        if group["group"]["name"] == group_name:
            for reg in group["registers"]:
                if reg["name"] == fuse_name:
                    return reg
    raise SPSDKError(f"The register with name {fuse_name} does not exist")


@pytest.mark.parametrize(
    "config,exception",
    [
        (
            {
                "register_id": "fuse3",
                "write_lock_int": "0x1",
                "read_lock_int": "0x4",
                "operation_lock_int": "0x2",
            },
            None,
        ),
        (
            {
                "register_id": "fuse3",
            },
            None,
        ),
        (
            {
                "write_lock_int": "0x1",
                "read_lock_int": "0x4",
                "operation_lock_int": "0x2",
            },
            SPSDKError,
        ),
    ],
)
def test_fuse_lock_register_load_config(config: Dict[str, str], exception: Optional[type]) -> None:
    """Test loading FuseLockRegister from configuration data.

    This test verifies that FuseLockRegister.load_from_config() properly handles
    both valid and invalid configuration data, raising appropriate exceptions
    when expected.

    :param config: Configuration dictionary containing fuse lock register settings.
    :param exception: Expected exception type to be raised, or None if no exception expected.
    """
    if exception:
        with pytest.raises(exception):
            FuseLockRegister.load_from_config(Config(config))
    else:
        lock_register = FuseLockRegister.load_from_config(Config(config))
        assert isinstance(lock_register, FuseLockRegister)


@pytest.mark.parametrize(
    "config",
    [
        {
            "register_id": "fuse3",
            "write_lock_int": "0x1",
            "read_lock_int": "0x4",
            "operation_lock_int": "0x2",
        },
        {
            "register_id": "fuse3",
            "write_lock_int": "0x1",
        },
    ],
)
def test_fuse_lock_register_create_config(config: Dict[str, str]) -> None:
    """Test fuse lock register configuration creation and validation.

    This test verifies that a FuseLockRegister can be created from a configuration
    dictionary and that the created register can generate the same configuration
    back, ensuring proper serialization and deserialization.

    :param config: Dictionary containing fuse lock register configuration data.
    """
    lock_register = FuseLockRegister.load_from_config(Config(config))
    created = lock_register.create_config()
    assert config == created


def test_fuse_lock_register_equal() -> None:
    """Test equality comparison of FuseLockRegister instances.

    Verifies that two FuseLockRegister objects with identical parameters are equal,
    and that objects with different parameters are not equal.
    """
    assert FuseLockRegister(
        register_id="fuse0", write_lock_mask=1, operation_lock_mask=2, read_lock_mask=4
    ) == FuseLockRegister(
        register_id="fuse0", write_lock_mask=1, operation_lock_mask=2, read_lock_mask=4
    )
    assert FuseLockRegister(
        register_id="fuse0", write_lock_mask=1, operation_lock_mask=2, read_lock_mask=4
    ) != FuseLockRegister(
        register_id="fuse0", write_lock_mask=1, operation_lock_mask=2, read_lock_mask=5
    )


@pytest.mark.parametrize(
    "group_name,fuse_name,otp_index,shadow_offset,fuse_lock_register",
    [
        (
            "BOOT_CFG",
            "SDHC_CFGF1",
            159,
            636,
            FuseLockRegister(
                register_id="fuse0", write_lock_mask=1, operation_lock_mask=2, read_lock_mask=4
            ),
        ),
        ("BOOT_CFG", "BOOT_CFG8", 160, 640, None),
    ],
)
def test_fuse_register_create_from_spec(
    data_dir: str,
    group_name: str,
    fuse_name: str,
    otp_index: int,
    shadow_offset: int,
    fuse_lock_register: Optional[FuseLockRegister],
) -> None:
    """Test creation of FuseRegister from specification configuration.

    Validates that a FuseRegister instance can be properly created from a JSON
    configuration specification and verifies all expected attributes are set correctly.

    :param data_dir: Directory path containing the fuses configuration file.
    :param group_name: Name of the fuse group in the configuration.
    :param fuse_name: Name of the specific fuse register to create.
    :param otp_index: Expected OTP index value for validation.
    :param shadow_offset: Expected shadow register offset for validation.
    :param fuse_lock_register: Expected fuse lock register instance for validation.
    """
    full_config = load_configuration(os.path.join(data_dir, "fuses.json"))
    fuse_cfg = get_reg_from_cfg(full_config, group_name, fuse_name)
    register = FuseRegister.create_from_spec(fuse_cfg)
    assert register.otp_index == otp_index
    assert register.shadow_register_offset == shadow_offset
    assert register.shadow_register_addr is None
    assert register.fuse_lock_register == fuse_lock_register


@pytest.mark.parametrize(
    "group_name,fuse_name",
    [
        ("BOOT_CFG", "SDHC_CFGF1"),
        ("BOOT_CFG", "BOOT_CFG8"),
    ],
)
def test_fuse_register_locking(data_dir: str, group_name: str, fuse_name: str) -> None:
    """Test fuse register locking and unlocking functionality.

    Validates that fuse register locking mechanisms work correctly by testing
    read and write lock operations, verifying lock states, and ensuring proper
    behavior when applying duplicate locks or unlocking non-existent locks.

    :param data_dir: Directory path containing test data files.
    :param group_name: Name of the fuse group to test.
    :param fuse_name: Name of the specific fuse register to test.
    """
    full_config = load_configuration(os.path.join(data_dir, "fuses.json"))
    fuse_cfg = get_reg_from_cfg(full_config, group_name, fuse_name)
    register = FuseRegister.create_from_spec(fuse_cfg)
    assert register.is_readable
    assert register.is_writable
    assert not register.get_active_locks()
    register.lock(FuseLock.READ_LOCK)
    assert not register.is_readable
    assert register.is_writable
    assert register.get_active_locks() == [FuseLock.READ_LOCK]
    register.lock(FuseLock.READ_LOCK)
    assert not register.is_readable
    assert register.is_writable
    assert register.get_active_locks() == [FuseLock.READ_LOCK]
    register.lock(FuseLock.WRITE_LOCK)
    assert not register.is_readable
    assert not register.is_writable
    assert register.get_active_locks() == [FuseLock.READ_LOCK, FuseLock.WRITE_LOCK]
    register.unlock(FuseLock.READ_LOCK)
    assert register.is_readable
    assert not register.is_writable
    assert register.get_active_locks() == [FuseLock.WRITE_LOCK]
    register.unlock(FuseLock.READ_LOCK)
    assert register.is_readable
    assert not register.is_writable
    assert register.get_active_locks() == [FuseLock.WRITE_LOCK]


def test_fuse_register_access(data_dir: str) -> None:
    """Test fuse register access permissions functionality.

    Verifies that FuseRegister correctly handles different access modes (WO, RO, RW, NONE)
    and properly reports readable/writable status through is_readable and is_writable properties.

    :param data_dir: Directory path containing test data files including fuses.json configuration
    """
    full_config = load_configuration(os.path.join(data_dir, "fuses.json"))
    fuse_cfg = get_reg_from_cfg(full_config, "BOOT_CFG", "SDHC_CFGF1")
    register = FuseRegister.create_from_spec(fuse_cfg)
    register.access = Access.WO
    assert not register.is_readable
    assert register.is_writable
    register.access = Access.RO
    assert register.is_readable
    assert not register.is_writable
    register.access = Access.RW
    assert register.is_readable
    assert register.is_writable
    register.access = Access.NONE
    assert not register.is_readable
    assert not register.is_writable


@pytest.mark.parametrize(
    "group_reg",
    [
        [
            {
                "uid": "test_grp",
                "name": "TestRegA",
                "sub_regs": ["field400", "field404", "field408", "field40C"],
                "access": "RO",
            }
        ],
    ],
)
def test_grouped_register_invalid_params(
    mock_test_database: Any, data_dir: str, group_reg: List[Dict[str, Any]]
) -> None:
    """Test grouped register loading with invalid parameters.

    This test verifies that the FuseRegisters._load_spec method properly raises
    SPSDKRegsErrorRegisterGroupMishmash exception when provided with invalid
    grouped register parameters.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    :param group_reg: List of dictionaries containing grouped register configurations.
    :raises SPSDKRegsErrorRegisterGroupMishmash: When grouped register parameters are invalid.
    """
    regs = FuseRegisters(family=FamilyRevision("dev2"))

    with pytest.raises(SPSDKRegsErrorRegisterGroupMishmash):
        regs._load_spec(data_dir + "/grp_regs.json", grouped_regs=group_reg)


def test_grouped_registers_shadow_registers_offset(mock_test_database: Any, data_dir: str) -> None:
    """Test grouped registers shadow registers offset calculation.

    Verifies that shadow register addresses are correctly calculated for grouped registers
    in the fuse registers system. Tests the base address configuration and sequential
    offset calculation for sub-registers within a register group.

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    regs = FuseRegisters(family=FamilyRevision("dev2"))
    assert regs.shadow_reg_base_addr == 0x4000_0000
    group = regs.find_reg("REG_BIG")
    assert len(group.sub_regs) == 8
    assert group.sub_regs[0].shadow_register_addr == 0x4000_0000 + 0xE0
    assert group.sub_regs[1].shadow_register_addr == 0x4000_0000 + 0xE4
    assert group.sub_regs[2].shadow_register_addr == 0x4000_0000 + 0xE8
    assert group.sub_regs[3].shadow_register_addr == 0x4000_0000 + 0xEC


def test_update_locks_via_lock_register(mock_test_database: Any, data_dir: str) -> None:
    """Test updating fuse register locks via lock register manipulation.

    This test verifies that fuse register locks are properly updated when lock register
    values are modified. It tests the progression from no locks to write lock, then to
    read and write locks, and finally to all three lock types (read, write, operation).

    :param mock_test_database: Mock database fixture for testing.
    :param data_dir: Directory path containing test data files.
    """
    regs = FuseRegisters(family=FamilyRevision("dev2"))
    lock_fuses = regs.get_lock_fuses()
    assert len(lock_fuses) == 1
    reg = regs.find_reg("field010")
    assert not reg.get_active_locks()
    lock_fuses[0].set_value(1)
    regs.update_locks()
    assert reg.get_active_locks() == [FuseLock.WRITE_LOCK]
    lock_fuses[0].set_value(3)
    regs.update_locks()
    assert reg.get_active_locks() == [FuseLock.READ_LOCK, FuseLock.WRITE_LOCK]
    lock_fuses[0].set_value(7)
    regs.update_locks()
    assert reg.get_active_locks() == [
        FuseLock.READ_LOCK,
        FuseLock.WRITE_LOCK,
        FuseLock.OPERATION_LOCK,
    ]


def test_get_by_otp_index(mock_test_database: Any, data_dir: str) -> None:
    """Test retrieval of fuse register by OTP index.

    Verifies that a fuse register can be successfully retrieved using its OTP index
    and that appropriate exceptions are raised for invalid indices.

    :param mock_test_database: Mocked test database fixture.
    :param data_dir: Directory path containing test data files.
    :raises SPSDKRegsErrorRegisterNotFound: When OTP index is not found in registers.
    """
    regs = FuseRegisters(family=FamilyRevision("dev2"))
    reg = regs.get_by_otp_index(0x15)
    assert isinstance(reg, FuseRegister)
    assert reg.uid == "field208"
    with pytest.raises(SPSDKRegsErrorRegisterNotFound):
        regs.get_by_otp_index(0x1000)


@pytest.mark.parametrize(
    "fuse_id,lock_fuse_name",
    [
        (
            "field010",
            "LOCK0",
        ),
        (
            "field014",
            None,
        ),
    ],
)
def test_get_lock_fuse(
    mock_test_database: Any, data_dir: str, fuse_id: str, lock_fuse_name: Optional[str]
) -> None:
    """Test the get_lock_fuse method functionality.

    This test verifies that the get_lock_fuse method correctly retrieves lock fuses
    for given fuse registers, both by passing the fuse register object directly
    and by passing the fuse name as a string. It validates that the method returns
    None when no lock fuse exists and returns the correct lock fuse when one exists.

    :param mock_test_database: Mock database for testing purposes.
    :param data_dir: Directory path containing test data files.
    :param fuse_id: Identifier of the fuse register to find and test.
    :param lock_fuse_name: Expected name of the lock fuse, None if no lock fuse expected.
    """
    regs = FuseRegisters(family=FamilyRevision("dev2"))
    fuse = regs.find_reg(fuse_id)
    # by reg itself
    lock = regs.get_lock_fuse(fuse)
    if not lock_fuse_name:
        assert lock is None
    else:
        assert lock is not None
        assert lock.name == lock_fuse_name
    # by name
    lock = regs.get_lock_fuse(fuse.name)
    if not lock_fuse_name:
        assert lock is None
    else:
        assert lock is not None
        assert lock.name == lock_fuse_name
