#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import os
import pytest
from spsdk.exceptions import SPSDKError, SPSDKKeyError
from spsdk.fuses.fuse_registers import FuseLock, FuseLockRegister, FuseRegister, FuseRegisters
from spsdk.utils.exceptions import (
    SPSDKRegsErrorRegisterGroupMishmash,
    SPSDKRegsErrorRegisterNotFound,
)
from spsdk.utils.misc import load_configuration
from spsdk.utils.registers import Access


def get_reg_from_cfg(cfg: dict, group_name: str, fuse_name: str):
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
            SPSDKKeyError,
        ),
    ],
)
def test_fuse_lock_register_load_config(config, exception):
    if exception:
        with pytest.raises(exception):
            FuseLockRegister.load_from_config(config)
    else:
        lock_register = FuseLockRegister.load_from_config(config)
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
def test_fuse_lock_register_create_config(config):
    lock_register = FuseLockRegister.load_from_config(config)
    created = lock_register.create_config()
    assert config == created


def test_fuse_lock_register_equal():
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
    data_dir, group_name, fuse_name, otp_index, shadow_offset, fuse_lock_register
):
    full_config = load_configuration(os.path.join(data_dir, "fuses.json"))
    fuse_cfg = get_reg_from_cfg(full_config, group_name, fuse_name)
    register = FuseRegister.create_from_spec(fuse_cfg)
    assert register.otp_index == otp_index
    assert register.shadow_register_offset == shadow_offset
    assert register.shadow_register_addr == None
    assert register.fuse_lock_register == fuse_lock_register


@pytest.mark.parametrize(
    "group_name,fuse_name",
    [
        ("BOOT_CFG", "SDHC_CFGF1"),
        ("BOOT_CFG", "BOOT_CFG8"),
    ],
)
def test_fuse_register_locking(data_dir, group_name, fuse_name):
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


def test_fuse_register_access(data_dir):
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
def test_grouped_register_invalid_params(mock_test_database, data_dir, group_reg):
    regs = FuseRegisters(family="dev2")

    with pytest.raises(SPSDKRegsErrorRegisterGroupMishmash):
        regs._load_spec(data_dir + "/grp_regs.json", grouped_regs=group_reg)


def test_grouped_registers_shadow_registers_offset(mock_test_database, data_dir):
    regs = FuseRegisters(family="dev2")
    assert regs.shadow_reg_base_addr == 0x4000_0000
    group = regs.find_reg("REG_BIG")
    assert len(group.sub_regs) == 8
    assert group.sub_regs[0].shadow_register_addr == 0x4000_0000 + 0xE0
    assert group.sub_regs[1].shadow_register_addr == 0x4000_0000 + 0xE4
    assert group.sub_regs[2].shadow_register_addr == 0x4000_0000 + 0xE8
    assert group.sub_regs[3].shadow_register_addr == 0x4000_0000 + 0xEC


def test_update_locks_via_lock_register(mock_test_database, data_dir):
    regs = FuseRegisters(family="dev2")
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


def test_get_by_otp_index(mock_test_database, data_dir):
    regs = FuseRegisters(family="dev2")
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
def test_get_lock_fuse(mock_test_database, data_dir, fuse_id, lock_fuse_name):
    regs = FuseRegisters(family="dev2")
    fuse = regs.find_reg(fuse_id)
    # by reg itself
    lock = regs.get_lock_fuse(fuse)
    if not lock_fuse_name:
        assert lock is None
    else:
        assert lock.name == lock_fuse_name
    # by name
    lock = regs.get_lock_fuse(fuse.name)
    if not lock_fuse_name:
        assert lock is None
    else:
        assert lock.name == lock_fuse_name
