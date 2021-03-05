#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for nxpkeygen utility."""
import os
import pytest
from spsdk.exceptions import SPSDKError

import spsdk.dat.shadow_regs as SR
import spsdk.utils.registers as REGS
import spsdk.debuggers.debug_probe as DP


from tests.debuggers.debug_probe_virtual import DebugProbeVirtual
# from spsdk.utils.misc import use_working_directory

TEST_DEV_NAME = "sh_test_dev"
TEST_DATABASE = "test_database.json"
TEST_DATABASE_BAD_COMPUTED_FUNC = "test_database_invalid_computed.json"

def get_probe():
    probe = DebugProbeVirtual(DebugProbeVirtual.UNIQUE_SERIAL)
    probe.open()
    probe.enable_memory_interface()
    return probe

def get_registers(xml_filename, filter_reg=None):
    registers = REGS.Registers(TEST_DEV_NAME)
    registers.load_registers_from_xml(xml_filename, filter_reg=filter_reg)
    return registers

def get_config(database_filename):
    config = SR.RegConfig(database_filename)
    return config

def test_shadowreg_basic(data_dir):
    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)
    assert shadowregs.device == TEST_DEV_NAME

def test_shadowreg_set_get_reg(data_dir):
    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)

    test_val = bytearray(32)
    for i, val in enumerate(test_val):
        test_val[i] = i

    shadowregs.set_register("REG1", 0x12345678)
    shadowregs.set_register("REG2", 0x4321)
    shadowregs.set_register("REG_INVERTED_AP", 0xA5A5A5A5)
    shadowregs.set_register("REG_BIG", test_val)
    shadowregs.set_register("REG_BIG_REV", test_val)

    assert shadowregs.get_register("REG1") == 0x12345678.to_bytes(4, 'big')
    assert shadowregs.get_register("REG2") == 0x00004321.to_bytes(4, 'big')
    assert shadowregs.get_register("REG_INVERTED_AP") == 0xA5A5A5A5.to_bytes(4, 'big')
    assert shadowregs.get_register("REG_BIG") == test_val
    assert shadowregs.get_register("REG_BIG_REV") == test_val

def test_shadowreg_set_reg_invalid(data_dir):
    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)
    with pytest.raises(SPSDKError):
        shadowregs.set_register("REG1", 0x1234567800004321)

    with pytest.raises(SPSDKError):
        shadowregs.set_register("REG1_Invalid", 0x12345678)

def test_shadowreg_get_reg_invalid(data_dir):
    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)
    with pytest.raises(SPSDKError):
        shadowregs.get_register("REG1_Invalid")

def test_shadowreg_invalid_probe(data_dir):
    probe = None
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)

    with pytest.raises(DP.DebugProbeError):
        shadowregs.set_register("REG1", 0x12345678)

    with pytest.raises(DP.DebugProbeError):
        shadowregs.get_register("REG1")

def test_shadowreg_verify_write(data_dir):
    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)

    shadowregs._write_shadow_reg(1, 0x12345678, verify=True)
    shadowregs._write_shadow_reg(1, 0x87654321, verify=False)

    assert probe.mem_reg_read(1) == 0x87654321

    probe.set_virtual_memory_substitute_data({1: [0x12345678, 0x5555AAAA]})
    
    with pytest.raises(SR.IoVerificationError):
        shadowregs._write_shadow_reg(1, 0x87654321, verify=True)

    assert probe.mem_reg_read(1) == 0x5555AAAA

def test_shadowreg_reverse():
    test_val = b'\x01\x02\x03\x04\x11\x12\x13\x14\x21\x22\x23\x24\x31\x32\x33\x34'
    test_val_ret = b'\x04\x03\x02\x01\x14\x13\x12\x11\x24\x23\x22\x21\x34\x33\x32\x31'

    assert SR.ShadowRegisters._reverse_bytes_in_longs(test_val) == test_val_ret
    assert SR.ShadowRegisters._reverse_bytes_in_longs(test_val_ret) == test_val

    test_val1 = b'\x01\x02\x03\x04\x11\x12'
    with pytest.raises(ValueError):
        SR.ShadowRegisters._reverse_bytes_in_longs(test_val1)

def test_shadowreg_yml(data_dir, tmpdir):
    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)

    test_val = bytearray(32)
    for i, val in enumerate(test_val):
        test_val[i] = i

    shadowregs.set_register("REG1", 0x12345678)
    shadowregs.set_register("REG2", 0x4321)
    shadowregs.set_register("REG_INVERTED_AP", 0xA5A5A5A5)
    shadowregs.set_register("REG_BIG", test_val)
    shadowregs.set_register("REG_BIG_REV", test_val)

    assert shadowregs.get_register("REG1") == 0x12345678.to_bytes(4, 'big')
    assert shadowregs.get_register("REG2") == 0x00004321.to_bytes(4, 'big')
    assert shadowregs.get_register("REG_INVERTED_AP") == 0xA5A5A5A5.to_bytes(4, 'big')
    assert shadowregs.get_register("REG_BIG") == test_val
    assert shadowregs.get_register("REG_BIG_REV") == test_val

    shadowregs.create_yml_config(os.path.join(tmpdir, "sh_regs.yml"), raw=False)
    shadowregs.create_yml_config(os.path.join(tmpdir, "sh_regs_raw.yml"), raw=True)

    probe.clear()

    shadowregs_load_raw = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)
    shadowregs_load_raw.load_yml_config(os.path.join(tmpdir, "sh_regs_raw.yml"), raw=True)
    shadowregs_load_raw.sets_all_registers()

    assert shadowregs_load_raw.get_register("REG1") == 0x12345678.to_bytes(4, 'big')
    assert shadowregs_load_raw.get_register("REG2") == 0x00004321.to_bytes(4, 'big')
    assert shadowregs_load_raw.get_register("REG_INVERTED_AP") == 0xA5A5A5A5.to_bytes(4, 'big')
    assert shadowregs_load_raw.get_register("REG_BIG") == test_val
    assert shadowregs_load_raw.get_register("REG_BIG_REV") == test_val

    probe.clear()

    shadowregs_load = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)
    shadowregs_load.load_yml_config(os.path.join(tmpdir, "sh_regs.yml"), raw=False)
    shadowregs_load.sets_all_registers()

    assert shadowregs_load.get_register("REG1") == b'\x40\x34\x56\x66'
    assert shadowregs_load.get_register("REG2") == b'\x00\x00\x03!'
    assert shadowregs_load.get_register("REG_INVERTED_AP") == b'\xbf\xcb\xa9\x99'
    assert shadowregs_load.get_register("REG_BIG") == test_val
    assert shadowregs_load.get_register("REG_BIG_REV") == test_val

    probe.clear()

    shadowregs_load2 = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)
    shadowregs_load2.load_yml_config(os.path.join(tmpdir, "sh_regs_raw.yml"), raw=False)
    shadowregs_load2.sets_all_registers()

    assert shadowregs_load2.get_register("REG1") == b'\x40\x34\x56\x66'
    assert shadowregs_load2.get_register("REG2") == b'\x00\x00\x03!'
    assert shadowregs_load2.get_register("REG_INVERTED_AP") == b'\xbf\xcb\xa9\x99'
    assert shadowregs_load2.get_register("REG_BIG") == test_val
    assert shadowregs_load2.get_register("REG_BIG_REV") == test_val

def test_shadowreg_yml_corrupted(data_dir):
    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    test_val = bytearray(32)
    for i, val in enumerate(test_val):
        test_val[i] = i

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)
    shadowregs.load_yml_config(os.path.join(data_dir, "sh_regs_corrupted.yml"), raw=True)
    shadowregs.sets_all_registers()

    assert shadowregs.get_register("REG1") == 0x12345678.to_bytes(4, 'big')
    assert shadowregs.get_register("REG2") == 0x00004321.to_bytes(4, 'big')
    assert shadowregs.get_register("REG_INVERTED_AP") == 0xA5A5A5A5.to_bytes(4, 'big')
    assert shadowregs.get_register("REG_BIG_REV") == test_val

def test_shadowreg_yml_invalid_computed(tmpdir, data_dir):
    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE_BAD_COMPUTED_FUNC))

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)

    test_val = bytearray(32)
    for i, val in enumerate(test_val):
        test_val[i] = i

    shadowregs.set_register("REG1", 0x12345678)
    shadowregs.set_register("REG2", 0x4321)
    shadowregs.set_register("REG_INVERTED_AP", 0xA5A5A5A5)
    shadowregs.set_register("REG_BIG", test_val)
    shadowregs.set_register("REG_BIG_REV", test_val)

    assert shadowregs.get_register("REG1") == 0x12345678.to_bytes(4, 'big')
    assert shadowregs.get_register("REG2") == 0x00004321.to_bytes(4, 'big')
    assert shadowregs.get_register("REG_INVERTED_AP") == 0xA5A5A5A5.to_bytes(4, 'big')
    assert shadowregs.get_register("REG_BIG") == test_val
    assert shadowregs.get_register("REG_BIG_REV") == test_val

    shadowregs.create_yml_config(os.path.join(tmpdir, "sh_regs.yml"), raw=False)

    shadowregs1 = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)

    with pytest.raises(SPSDKError):
        shadowregs1.load_yml_config(os.path.join(tmpdir, "sh_regs.yml"))

def test_shadowreg_yml_none_existing(data_dir):

    probe = get_probe()
    config = get_config(os.path.join(data_dir, TEST_DATABASE))

    test_val = bytearray(32)
    for i, val in enumerate(test_val):
        test_val[i] = i

    shadowregs = SR.ShadowRegisters(probe, config, TEST_DEV_NAME)
    with pytest.raises(SPSDKError):
        shadowregs.load_yml_config(os.path.join(data_dir, "sh_regs_none.yml"), raw=True)

def test_shadow_register_crc8():
    crc = SR.ShadowRegisters.crc_update(b'\x12\x34', is_final=False)
    crc = SR.ShadowRegisters.crc_update(b'\x56', crc=crc)
    assert crc == 0x29

def test_shadow_register_crc8_hook():
    bval = SR.value_to_bytes(0x03020100)
    assert SR.ShadowRegisters.comalg_dcfg_cc_socu_crc8(SR.ShadowRegisters, bval) == b'\x03\x02\x01\x1d'    

    bval = SR.value_to_bytes(0x80FFFF00)
    assert SR.ShadowRegisters.comalg_dcfg_cc_socu_crc8(SR.ShadowRegisters, bval) == SR.value_to_bytes(0x80FFFF20)    

def test_shadow_register_enable_debug_invalid_probe():
    probe = None
    with pytest.raises(SPSDKError):
        SR.enable_debug(probe)

def test_shadow_register_enable_debug_device_cannot_enable():
    probe = get_probe()
    # invalid run (the mcu returns nonse values)
    assert not SR.enable_debug(probe)

def test_shadow_register_enable_debug():
    probe = get_probe()
    #valid run, the right values are prepared

    #Setup the simulated data for reading of AP registers
    ap = {12:["Exception", 0x12345678],0x02000000:[2, 0, 2, 0], 0x02000008:[0]}
    probe.set_coresight_ap_substitute_data(ap)
    assert SR.enable_debug(probe)


def test_shadow_register_enable_debug_already_enabled():
    probe = get_probe()
    #Setup the simulated data for reading of AP registers
    mem_ap = {12:[0x12345678]}
    probe.set_coresight_ap_substitute_data(mem_ap)
    assert SR.enable_debug(probe)


def test_shadow_register_enable_debug_probe_exceptions():
    probe = get_probe()
    with pytest.raises(SPSDKError):
        probe.dp_write_cause_exception()
        assert not SR.enable_debug(probe)
