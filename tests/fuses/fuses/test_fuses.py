#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import os
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
from spsdk.utils.misc import load_configuration
from tests.fuses.fuses.fuses_test_operator import TestFuseOperator
from tests.fuses.fuses.test_fuse_registers import get_reg_from_cfg


def test_get_operator_type():
    assert FuseOperator.get_operator_type("blhost") == BlhostFuseOperator
    assert FuseOperator.get_operator_type("nxpele") == NxpeleFuseOperator
    with pytest.raises(SPSDKKeyError):
        FuseOperator.get_operator_type("unknown")


def test_get_fuse_script(data_dir):
    full_config = load_configuration(os.path.join(data_dir, "fuses.json"))
    fuse_cfg = get_reg_from_cfg(full_config, "BOOT_CFG", "SDHC_CFGF1")
    fuse = FuseRegister.create_from_spec(fuse_cfg)
    fuse.set_value(0xA)
    script = BlhostFuseOperator.get_fuse_script("mimxrt798s", fuses=[fuse])
    assert "BLHOST fuses programming script" in script
    assert "efuse-program-once 159 0xA --no-verify" in script
    script = NxpeleFuseOperator.get_fuse_script("mimxrt798s", fuses=[fuse])
    assert "NXPELE fuses programming script" in script
    assert "write-fuse --index 159 --data 0xA" in script


def test_get_supported_families(mock_test_database, data_dir):
    families = Fuses.get_supported_families()
    assert len(families) == 1
    assert families[0] == "dev2"


def test_initialize_unsupported_family(mock_test_database, data_dir):
    with pytest.raises(SPSDKError):
        Fuses(family="dev1")


def test_fuses_operator(mock_test_database, data_dir):
    fuses = Fuses(family="dev2")
    with pytest.raises(SPSDKError):
        fuses.fuse_operator
    with pytest.raises(SPSDKError):
        fuses.fuse_operator = BlhostFuseOperator(None)
    fuses.fuse_operator = TestFuseOperator()
    assert fuses.fuse_operator_type == TestFuseOperator
    assert Fuses.get_fuse_operator_type("dev2") == TestFuseOperator


def test_fuses_try_read_write_only_fuse(mock_test_database, data_dir):
    operator = TestFuseOperator()
    fuses = Fuses(family="dev2", fuse_operator=operator)
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.read_single("field200")
    assert operator.actions == []


def test_fuses_try_write_read_only_fuse(mock_test_database, data_dir):
    operator = TestFuseOperator()
    fuses = Fuses(family="dev2", fuse_operator=operator)
    with pytest.raises(SPSDKFuseOperationFailure):
        fuses.write_single("field204")
    assert operator.actions == []


def test_fuses_read_single(mock_test_database, data_dir):
    operator = TestFuseOperator(return_values={0x14: 3})
    fuses = Fuses(family="dev2", fuse_operator=operator)
    register = fuses.fuse_regs.get_reg("field204")
    assert register.get_value() == 0
    assert fuses.read_single("field204") == 3
    assert register.get_value() == 3


def test_fuses_read_single_grouped(mock_test_database, data_dir):
    operator = TestFuseOperator(return_values={0x3: 1, 0x4: 1})
    fuses = Fuses(family="dev2", fuse_operator=operator)
    register = fuses.fuse_regs.find_reg("REG_BIG")
    assert register.get_value() == 0
    assert fuses.read_single("REG_BIG") == 0x100000001


def test_fuses_read_all(mock_test_database, data_dir):
    operator = TestFuseOperator(return_values={0x14: 0x30, 0x400: 3})
    fuses = Fuses(family="dev2", fuse_operator=operator)
    fuses.read_all()
    assert fuses.fuse_regs.find_reg("lock0").get_value() == 3
    assert fuses.fuse_regs.find_reg("READ_ONLY_REG").get_value() == 0x30
    # some of the fuses were not read due to permissions
    for fuse in fuses.fuse_context:
        assert fuse.name not in ["REG1", "WRITE_ONLY_REG"]


def test_fuses_try_read_locked_fuse(mock_test_database, data_dir):
    operator = TestFuseOperator(return_values={0x15: 5, 0x400: 2})
    fuses = Fuses(family="dev2", fuse_operator=operator)
    register = fuses.fuse_regs.get_reg("field208")
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


def test_fuses_try_write_locked_fuse(mock_test_database, data_dir):
    operator = TestFuseOperator(return_values={0x15: 5, 0x400: 1})
    fuses = Fuses(family="dev2", fuse_operator=operator)
    register = fuses.fuse_regs.get_reg("field208")
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


def test_fuses_template(mock_test_database, data_dir):
    fuses = Fuses(family="dev2")
    template = fuses.generate_config_template("dev2")
    template_dict = safe_load(template)
    assert template_dict["family"] == "dev2"
    assert template_dict["revision"] == "latest"
    assert template_dict["registers"]


def test_fuses_load_config(mock_test_database, data_dir):
    cfg = load_configuration(os.path.join(data_dir, "test_config_1.yaml"))
    fuses = Fuses.load_from_config(cfg)
    assert isinstance(fuses, Fuses)
    reg = fuses.fuse_regs.find_reg("REG1")
    assert reg.get_value() == 0x300
    reg = fuses.fuse_regs.find_reg("REG2")
    assert reg.get_value() == 0x85
    reg = fuses.fuse_regs.find_reg("LOCK0")
    assert reg.get_value() == 0x1
    assert len(fuses.fuse_context) == 3
