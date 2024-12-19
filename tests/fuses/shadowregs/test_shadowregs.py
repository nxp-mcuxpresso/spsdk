#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for shadow registers support API."""
import os
from copy import copy

import pytest
import yaml

import spsdk.fuses.shadowregs
from spsdk.apps.shadowregs import main
from spsdk.exceptions import SPSDKError
from spsdk.utils.exceptions import SPSDKRegsErrorBitfieldNotFound, SPSDKRegsErrorRegisterNotFound
from spsdk.utils.misc import Endianness, load_configuration, use_working_directory
from tests.cli_runner import CliRunner
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual

TEST_DEV_NAME = "dev2"
TEST_DATABASE = "test_database.yaml"
TEST_DATABASE_BAD_COMPUTED_FUNC = "test_database_invalid_computed.yaml"
TEST_DATABASE_INVALID_FLUSH_FUNC = "test_database_invalid_flush_func.yaml"


def get_probe():
    """Help function to get Probe - used in tests."""
    probe = DebugProbeVirtual(DebugProbeVirtual.UNIQUE_SERIAL)
    probe.open()
    probe.connect()
    return probe


def test_shadowreg_basic(mock_test_database, data_dir):
    """Test Shadow Registers - Basic test."""
    probe = get_probe()

    shadowregs = spsdk.fuses.shadowregs.ShadowRegisters(family="dev2", debug_probe=probe)
    assert shadowregs.device == TEST_DEV_NAME


def test_shadowreg_set_get_reg(mock_test_database, data_dir):
    """Test Shadow Registers - Setting and getting register."""
    probe = get_probe()
    shadowregs = spsdk.fuses.shadowregs.ShadowRegisters(family="dev2", debug_probe=probe)

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


def test_shadowreg_set_reg_invalid(mock_test_database, data_dir):
    """Test Shadow Registers - INVALID cases of set and get registers."""
    probe = get_probe()

    shadowregs = spsdk.fuses.shadowregs.ShadowRegisters(family="dev2", debug_probe=probe)
    with pytest.raises(SPSDKError):
        shadowregs.set_register("REG1", 0x1234567800004321)

    with pytest.raises(SPSDKError):
        shadowregs.set_register("REG1_Invalid", 0x12345678)


def test_shadowreg_get_reg_invalid(mock_test_database, data_dir):
    """Test Shadow Registers - another INVALID cases of get registers."""
    probe = get_probe()

    shadowregs = spsdk.fuses.shadowregs.ShadowRegisters(family="dev2", debug_probe=probe)
    with pytest.raises(SPSDKError):
        shadowregs.get_register("REG1_Invalid")


def test_shadowreg_invalid_probe(mock_test_database, data_dir):
    """Test Shadow Registers - INVALID probe used for constructor."""
    probe = None

    shadowregs = spsdk.fuses.shadowregs.ShadowRegisters(family="dev2", debug_probe=probe)

    with pytest.raises(SPSDKError):
        shadowregs.set_register("REG1", 0x12345678)

    with pytest.raises(SPSDKError):
        shadowregs.get_register("REG1")


# pylint: disable=protected-access
def test_shadowreg_verify_write(mock_test_database, data_dir):
    """Test Shadow Registers - Verify write to register test."""
    probe = get_probe()

    shadowregs = spsdk.fuses.shadowregs.ShadowRegisters(family="dev2", debug_probe=probe)

    shadowregs._write_shadow_reg(1, 0x12345678, verify_mask=0xFFFFFFFF)
    shadowregs._write_shadow_reg(1, 0x87654321, verify_mask=0)

    assert probe.mem_reg_read(1) == 0x87654321

    probe.set_virtual_memory_substitute_data({1: [0x12345678, 0x5555AAAA]})
    with pytest.raises(spsdk.fuses.shadowregs.IoVerificationError):
        shadowregs._write_shadow_reg(1, 0x87654321, verify_mask=0xFFFFFFFF)

    assert probe.mem_reg_read(1) == 0x5555AAAA


def test_shadowreg_yml(mock_test_database, data_dir, tmpdir):
    """Test Shadow Registers - Load YML configuration test."""
    probe = get_probe()

    shadowregs = spsdk.fuses.shadowregs.ShadowRegisters(family="dev2", debug_probe=probe)

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

    shadowregs_load = spsdk.fuses.shadowregs.ShadowRegisters(family="dev2", debug_probe=probe)
    shadowregs_load.load_config(cfg)
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
    shadowregs = spsdk.fuses.shadowregs.ShadowRegisters(family="dev2", debug_probe=probe)
    cfg["registers"] = {"REG1": 0xF0F0F0F0}
    shadowregs.load_config(cfg)
    shadowregs.set_loaded_registers()
    assert shadowregs.get_register("REG1") == 0xF0F0F0F0.to_bytes(4, Endianness.BIG.value)
    assert shadowregs.get_register("REG2") == 0x4321.to_bytes(2, Endianness.BIG.value)
    cfg["registers"] = {"REG2": 0x0}
    shadowregs.load_config(cfg)
    shadowregs.set_loaded_registers()
    assert shadowregs.get_register("REG1") == 0xF0F0F0F0.to_bytes(4, Endianness.BIG.value)
    assert shadowregs.get_register("REG2") == 0x0.to_bytes(2, Endianness.BIG.value)


def test_shadowreg_yml_compute_values(mock_test_database, data_dir, tmpdir):
    """Test Shadow Registers - Load YML configuration test."""
    probe = get_probe()

    shadowregs = spsdk.fuses.shadowregs.ShadowRegisters(family="dev2", debug_probe=probe)

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

    shadowregs_load = spsdk.fuses.shadowregs.ShadowRegisters(family="dev2", debug_probe=probe)
    shadowregs_load.load_config(cfg)
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


def test_shadowreg_yml_corrupted(mock_test_database, data_dir):
    """Test Shadow Registers - Corrupted YML configuration."""
    probe = get_probe()

    test_val = bytearray(32)
    for i in range(32):
        test_val[i] = i

    shadowregs = spsdk.fuses.shadowregs.ShadowRegisters(family="dev2", debug_probe=probe)
    with pytest.raises((SPSDKRegsErrorBitfieldNotFound, SPSDKRegsErrorRegisterNotFound)):
        shadowregs.load_config(load_configuration(os.path.join(data_dir, "sh_regs_corrupted.yml")))


def test_shadowreg_yml_invalid_computed(mock_test_database, tmpdir):
    """Test Shadow Registers - INVALID computed configuration."""
    probe = get_probe()
    shadowregs = spsdk.fuses.shadowregs.ShadowRegisters(
        family="dev2", revision="rev_test_invalid_computed", debug_probe=probe
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

    shadowregs1 = spsdk.fuses.shadowregs.ShadowRegisters(
        family="dev2", revision="rev_test_invalid_computed", debug_probe=probe
    )

    with pytest.raises(SPSDKError):
        shadowregs1.load_config(cfg)


def test_shadow_register_crc8():
    """Test Shadow Registers - CRC8 algorithm test."""
    crc = spsdk.fuses.shadowregs.ShadowRegisters.crc_update(b"\x12\x34", is_final=False)
    crc = spsdk.fuses.shadowregs.ShadowRegisters.crc_update(b"\x56", crc=crc)
    assert crc == 0x29


def test_shadow_register_crc8_hook(mock_test_database):
    """Test Shadow Registers - CRC8 algorithm hook test."""
    shadowregs = spsdk.fuses.shadowregs.ShadowRegisters(
        family="dev2", revision="rev_test_invalid_computed"
    )
    assert shadowregs.comalg_dcfg_cc_socu_crc8(0x03020100) == 0x0302011D
    assert shadowregs.comalg_dcfg_cc_socu_crc8(0x80FFFF00) == 0x80FFFF20


def test_shadow_register_invalid_flush_hook(mock_test_database):
    """Test Shadow Registers - invalid flush hook test."""
    probe = get_probe()
    shadowregs1 = spsdk.fuses.shadowregs.ShadowRegisters(
        family="dev2", revision="rev_test_invalid_flush_func", debug_probe=probe
    )

    with pytest.raises(SPSDKError):
        shadowregs1.set_register("REG1", 0x12345678)


def test_shadow_register_enable_debug_invalid_probe():
    """Test Shadow Registers - Enable debug algorithm check with invalid probe."""
    probe = None
    with pytest.raises(SPSDKError):
        spsdk.fuses.shadowregs.enable_debug(probe, "lpc55s6x")


def test_shadow_register_enable_debug_device_cannot_enable():
    """Test Shadow Registers - Enable debug algorithm without connected target."""
    probe = get_probe()
    # invalid run
    # Setup the simulated data for reading of AP registers
    probe.mem_read_cause_exception(2)
    assert not spsdk.fuses.shadowregs.enable_debug(probe, "lpc55s6x")


def test_shadow_register_enable_debug():
    """Test Shadow Registers - Enable debug algorithm check with valid target."""
    probe = get_probe()
    # valid run, the right values are prepared

    # Setup the simulated data for reading of AP registers
    access_port = {12: ["Exception", 0x12345678], 0x02000000: [2, 0, 2, 0], 0x02000008: [0]}
    probe.set_coresight_ap_substitute_data(access_port)
    assert spsdk.fuses.shadowregs.enable_debug(probe, "lpc55s6x")


def test_shadow_register_enable_debug_already_enabled():
    """Test Shadow Registers - Enable debug algorithm check with already enabled target."""
    probe = get_probe()
    # Setup the simulated data for reading of AP registers
    mem_ap = {12: [0x12345678]}
    probe.set_coresight_ap_substitute_data(mem_ap)
    assert spsdk.fuses.shadowregs.enable_debug(probe, "lpc55s6x")


def test_shadow_register_enable_debug_probe_exceptions():
    """Test Shadow Registers - Enable debug algorithm check with probe exception."""
    probe = get_probe()
    with pytest.raises(SPSDKError):
        assert isinstance(probe, DebugProbeVirtual)
        probe.mem_read_cause_exception()  # To fail test connection function
        probe.ap_write_cause_exception()  # To fail write to debug mailbox
        assert not spsdk.fuses.shadowregs.enable_debug(probe, "lpc55s6x")


def test_generate_template(cli_runner: CliRunner, tmpdir):
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
def test_rkth_order(family, rkth0, rkth7, data_dir):
    """Test for rkth right order in shadowregs."""
    probe = get_probe()
    sr = spsdk.fuses.shadowregs.ShadowRegisters(family=family, debug_probe=probe)
    # to simplify HW differences unify offsets
    sr.offset_for_write = 0
    sr.load_config(load_configuration(os.path.join(data_dir, "cfg_rkth.yaml")))
    sr.set_all_registers()

    # validate expected results
    assert sr.get_register(rkth0) == b"\x13\x12\x11\x10"
    assert sr.get_register(rkth7) == b"\x2f\x2e\x2d\x2c"
    rkth = sr.registers.find_reg("RKTH").get_bytes_value()
    assert rkth[:4] == b"\x10\x11\x12\x13"
