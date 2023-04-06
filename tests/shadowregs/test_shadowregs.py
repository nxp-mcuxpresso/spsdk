#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for shadow registers support API."""
import os

import pytest

import spsdk.shadowregs.shadowregs as SR
import spsdk.utils.registers as REGS
from spsdk.exceptions import SPSDKError
from spsdk.utils.exceptions import SPSDKRegsErrorBitfieldNotFound, SPSDKRegsErrorRegisterNotFound
from spsdk.utils.reg_config import RegConfig
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual

# from spsdk.utils.misc import use_working_directory

TEST_DEV_NAME = "sh_test_dev"
TEST_DATABASE = "test_database.yaml"
TEST_DATABASE_BAD_COMPUTED_FUNC = "test_database_invalid_computed.yaml"


def get_probe():
    """Help function to get Probe - used in tests."""
    probe = DebugProbeVirtual(DebugProbeVirtual.UNIQUE_SERIAL)
    probe.open()
    return probe


def get_registers(xml_filename, filter_reg=None):
    """Help function to get Registers - used in tests."""
    registers = REGS.Registers(TEST_DEV_NAME)
    registers.load_registers_from_xml(xml_filename, filter_reg=filter_reg)
    return registers


def get_config(database_filename):
    """Help function to get RegConfig - used in tests."""
    config = RegConfig(database_filename)
    return config


def test_shadowreg_basic(data_dir):
    """Test Shadow Registers - Basic test."""
    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)
    assert shadowregs.device == TEST_DEV_NAME


def test_shadowreg_set_get_reg(data_dir):
    """Test Shadow Registers - Setting and getting register."""
    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)

    test_val = bytearray(32)
    for i in range(32):
        test_val[i] = i

    shadowregs.set_register("REG1", 0x12345678)
    shadowregs.set_register("REG2", 0x4321)
    shadowregs.set_register("REG_INVERTED_AP", 0xA5A5A5A5)
    shadowregs.set_register("REG_BIG", test_val)
    shadowregs.set_register("REG_BIG_REV", test_val)

    assert shadowregs.get_register("REG1") == 0x12345678.to_bytes(4, "big")
    assert shadowregs.get_register("REG2") == 0x00004321.to_bytes(4, "big")
    assert shadowregs.get_register("REG_INVERTED_AP") == 0xA5A5A5A5.to_bytes(4, "big")
    assert shadowregs.get_register("REG_BIG") == test_val
    assert shadowregs.get_register("REG_BIG_REV") == test_val


def test_shadowreg_set_reg_invalid(data_dir):
    """Test Shadow Registers - INVALID cases of set and get registers."""
    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)
    with pytest.raises(SPSDKError):
        shadowregs.set_register("REG1", 0x1234567800004321)

    with pytest.raises(SPSDKError):
        shadowregs.set_register("REG1_Invalid", 0x12345678)


def test_shadowreg_get_reg_invalid(data_dir):
    """Test Shadow Registers - another INVALID cases of get registers."""
    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)
    with pytest.raises(SPSDKError):
        shadowregs.get_register("REG1_Invalid")


def test_shadowreg_invalid_probe(data_dir):
    """Test Shadow Registers - INVALID probe used for constructor."""
    probe = None
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)

    with pytest.raises(SPSDKError):
        shadowregs.set_register("REG1", 0x12345678)

    with pytest.raises(SPSDKError):
        shadowregs.get_register("REG1")


# pylint: disable=protected-access
def test_shadowreg_verify_write(data_dir):
    """Test Shadow Registers - Verify write to register test."""
    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)

    shadowregs._write_shadow_reg(1, 0x12345678, verify_mask=0xFFFFFFFF)
    shadowregs._write_shadow_reg(1, 0x87654321, verify_mask=0)

    assert probe.mem_reg_read(1) == 0x87654321

    probe.set_virtual_memory_substitute_data({1: [0x12345678, 0x5555AAAA]})
    with pytest.raises(SR.IoVerificationError):
        shadowregs._write_shadow_reg(1, 0x87654321, verify_mask=0xFFFFFFFF)

    assert probe.mem_reg_read(1) == 0x5555AAAA


def test_shadowreg_yml(data_dir, tmpdir):
    """Test Shadow Registers - Load YML configuration test."""
    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)

    test_val = bytearray(32)
    for i in range(32):
        test_val[i] = i

    shadowregs.set_register("REG1", 0x12345678)
    shadowregs.set_register("REG2", 0x4321)
    shadowregs.set_register("REG_INVERTED_AP", 0xA5A5A5A5)
    shadowregs.set_register("REG_BIG", test_val)
    shadowregs.set_register("REG_BIG_REV", test_val)

    assert shadowregs.get_register("REG1") == 0x12345678.to_bytes(4, "big")
    assert shadowregs.get_register("REG2") == 0x00004321.to_bytes(4, "big")
    assert shadowregs.get_register("REG_INVERTED_AP") == 0xA5A5A5A5.to_bytes(4, "big")
    assert shadowregs.get_register("REG_BIG") == test_val
    assert shadowregs.get_register("REG_BIG_REV") == test_val

    shadowregs.create_yaml_config(os.path.join(tmpdir, "sh_regs.yml"), raw=False)
    shadowregs.create_yaml_config(os.path.join(tmpdir, "sh_regs_raw.yml"), raw=True)

    probe.clear()

    shadowregs_load_raw = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)
    shadowregs_load_raw.load_yaml_config(os.path.join(tmpdir, "sh_regs_raw.yml"), raw=True)
    shadowregs_load_raw.sets_all_registers(verify=True)

    assert shadowregs_load_raw.get_register("REG1") == 0x12345678.to_bytes(4, "big")
    assert shadowregs_load_raw.get_register("REG2") == 0x00004321.to_bytes(4, "big")
    assert shadowregs_load_raw.get_register("REG_INVERTED_AP") == 0xA5A5A5A5.to_bytes(4, "big")
    assert shadowregs_load_raw.get_register("REG_BIG") == test_val
    assert shadowregs_load_raw.get_register("REG_BIG_REV") == test_val

    probe.clear()

    shadowregs_load = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)
    shadowregs_load.load_yaml_config(os.path.join(tmpdir, "sh_regs.yml"), raw=False)
    shadowregs_load.sets_all_registers(verify=True)

    assert shadowregs_load.get_register("REG1") == b"\x92\x34\x56\x56"
    assert shadowregs_load.get_register("REG2") == b"\x00\x00\x03!"
    assert shadowregs_load.get_register("REG_INVERTED_AP") == b"m\xcb\xa9\xa9"
    assert shadowregs_load.get_register("REG_BIG") == test_val
    assert shadowregs_load.get_register("REG_BIG_REV") == test_val

    probe.clear()

    shadowregs_load2 = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)
    shadowregs_load2.load_yaml_config(os.path.join(tmpdir, "sh_regs_raw.yml"), raw=False)
    shadowregs_load2.sets_all_registers(verify=True)

    assert shadowregs_load2.get_register("REG1") == b"\x92\x34\x56\x56"
    assert shadowregs_load2.get_register("REG2") == b"\x00\x00\x03!"
    assert shadowregs_load2.get_register("REG_INVERTED_AP") == b"m\xcb\xa9\xa9"
    assert shadowregs_load2.get_register("REG_BIG") == test_val
    assert shadowregs_load2.get_register("REG_BIG_REV") == test_val

    shadowregs_load2 = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)
    shadowregs_load2.load_yaml_config(os.path.join(tmpdir, "sh_regs_raw.yml"), raw=False)
    shadowregs_load2.sets_all_registers(verify=False)

    assert shadowregs_load2.get_register("REG1") == b"\x92\x34\x56\x56"
    assert shadowregs_load2.get_register("REG2") == b"\x00\x00\x03!"
    assert shadowregs_load2.get_register("REG_INVERTED_AP") == b"m\xcb\xa9\xa9"
    assert shadowregs_load2.get_register("REG_BIG") == test_val
    assert shadowregs_load2.get_register("REG_BIG_REV") == test_val


def test_shadowreg_yml_corrupted(data_dir):
    """Test Shadow Registers - Corrupted YML configuration."""
    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    test_val = bytearray(32)
    for i in range(32):
        test_val[i] = i

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)
    with pytest.raises((SPSDKRegsErrorBitfieldNotFound, SPSDKRegsErrorRegisterNotFound)):
        shadowregs.load_yaml_config(os.path.join(data_dir, "sh_regs_corrupted.yml"), raw=True)


def test_shadowreg_yml_invalid_computed(tmpdir, data_dir):
    """Test Shadow Registers - INVALID computed configuration."""
    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE_BAD_COMPUTED_FUNC))

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)

    test_val = bytearray(32)
    for i in range(32):
        test_val[i] = i

    shadowregs.set_register("REG1", 0x12345678)
    shadowregs.set_register("REG2", 0x4321)
    shadowregs.set_register("REG_INVERTED_AP", 0xA5A5A5A5)
    shadowregs.set_register("REG_BIG", test_val)
    shadowregs.set_register("REG_BIG_REV", test_val)

    assert shadowregs.get_register("REG1") == 0x12345678.to_bytes(4, "big")
    assert shadowregs.get_register("REG2") == 0x00004321.to_bytes(4, "big")
    assert shadowregs.get_register("REG_INVERTED_AP") == 0xA5A5A5A5.to_bytes(4, "big")
    assert shadowregs.get_register("REG_BIG") == test_val
    assert shadowregs.get_register("REG_BIG_REV") == test_val

    shadowregs.create_yaml_config(os.path.join(tmpdir, "sh_regs.yml"), raw=False)

    shadowregs1 = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)

    with pytest.raises(SPSDKError):
        shadowregs1.load_yaml_config(os.path.join(tmpdir, "sh_regs.yml"))


def test_shadowreg_yml_none_existing(data_dir):
    """Test Shadow Registers - None existing YML configuration."""
    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    test_val = bytearray(32)
    for i in range(32):
        test_val[i] = i

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)
    with pytest.raises(SPSDKError):
        shadowregs.load_yaml_config(os.path.join(data_dir, "sh_regs_none.yml"), raw=True)


def test_shadow_register_crc8():
    """Test Shadow Registers - CRC8 algorithm test."""
    crc = SR.ShadowRegisters.crc_update(b"\x12\x34", is_final=False)
    crc = SR.ShadowRegisters.crc_update(b"\x56", crc=crc)
    assert crc == 0x29


def test_shadow_register_crc8_hook(data_dir):
    """Test Shadow Registers - CRC8 algorithm hook test."""
    config = get_config(os.path.join(data_dir, TEST_DATABASE_BAD_COMPUTED_FUNC))

    shadowregs = SR.ShadowRegisters(None, config, TEST_DEV_NAME)
    assert shadowregs.comalg_dcfg_cc_socu_crc8(0x03020100) == 0x0302011D
    assert shadowregs.comalg_dcfg_cc_socu_crc8(0x80FFFF00) == 0x80FFFF20


def test_shadow_register_enable_debug_invalid_probe():
    """Test Shadow Registers - Enable debug algorithm check with invalid probe."""
    probe = None
    with pytest.raises(SPSDKError):
        SR.enable_debug(probe)


def test_shadow_register_enable_debug_device_cannot_enable():
    """Test Shadow Registers - Enable debug algorithm without connected target."""
    probe = get_probe()
    # invalid run
    # Setup the simulated data for reading of AP registers
    probe.mem_read_cause_exception(2)
    assert not SR.enable_debug(probe)


def test_shadow_register_enable_debug():
    """Test Shadow Registers - Enable debug algorithm check with valid target."""
    probe = get_probe()
    # valid run, the right values are prepared

    # Setup the simulated data for reading of AP registers
    access_port = {12: ["Exception", 0x12345678], 0x02000000: [2, 0, 2, 0], 0x02000008: [0]}
    probe.set_coresight_ap_substitute_data(access_port)
    assert SR.enable_debug(probe)


def test_shadow_register_enable_debug_already_enabled():
    """Test Shadow Registers - Enable debug algorithm check with already enabled target."""
    probe = get_probe()
    # Setup the simulated data for reading of AP registers
    mem_ap = {12: [0x12345678]}
    probe.set_coresight_ap_substitute_data(mem_ap)
    assert SR.enable_debug(probe)


def test_shadow_register_enable_debug_probe_exceptions():
    """Test Shadow Registers - Enable debug algorithm check with probe exception."""
    probe = get_probe()
    with pytest.raises(SPSDKError):
        assert isinstance(probe, DebugProbeVirtual)
        probe.mem_read_cause_exception()  # To fail test connection function
        probe.ap_write_cause_exception()  # To fail write to debug mailbox
        assert not SR.enable_debug(probe)
