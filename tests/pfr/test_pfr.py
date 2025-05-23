#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test suite for Protected Flash Region (PFR) API.

This module provides comprehensive testing for PFR functionality, including:
- CMPA (Customer Manufacturing Programming Area) configuration and binary generation
- CFPA (Customer Field Programmable Area) configuration and binary generation
- Configuration handling for different device families (LPC55Sxx, MCXAxx)
- Key handling and validation for various cryptographic algorithms
- Validation of sealing mechanisms for both CMPA and CFPA areas
- Error handling for invalid configurations and keys

The tests ensure proper functionality across different NXP microcontroller families
and verify compatibility between JSON and YAML configuration formats.
"""

import os

import pytest
from ruamel.yaml import YAML

from spsdk.crypto.keys import PrivateKeyRsa
from spsdk.crypto.utils import extract_public_keys
from spsdk.exceptions import SPSDKError
from spsdk.pfr.pfr import CFPA, CMPA, BaseConfigArea, SPSDKPfrRotkhIsNotPresent
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.misc import load_configuration, load_file
from spsdk.utils.family import FamilyRevision


def test_generate_cmpa(data_dir: str) -> None:
    """Test CMPA binary generation functionality.

    Verifies that CMPA binary data can be correctly generated from both JSON and YAML
    configuration files, and that the output matches expected binary file.

    :param data_dir: Path to test data directory containing configuration files and reference binary
    """
    binary = load_file(os.path.join(data_dir, "CMPA_96MHz.bin"), mode="rb")
    key = PrivateKeyRsa.load(os.path.join(data_dir, "selfsign_privatekey_rsa2048.pem"))

    pfr_cfg_json = Config.create_from_file(os.path.join(data_dir, "cmpa_96mhz.json"))
    cmpa_json = CMPA.load_from_config(pfr_cfg_json)
    assert binary == cmpa_json.export(add_seal=False, keys=[key.get_public_key()])

    pfr_cfg_yml = Config.create_from_file(os.path.join(data_dir, "cmpa_96mhz.yml"))
    cmpa_yml = CMPA.load_from_config(pfr_cfg_yml)
    assert binary == cmpa_yml.export(add_seal=False, keys=[key.get_public_key()])


def test_generate_cfpa(data_dir: str) -> None:
    """Test CFPA binary generation functionality.

    Verifies that CFPA binary data can be correctly generated from both JSON and YAML
    configuration files, and that the output matches expected binary file.

    :param data_dir: Path to test data directory containing configuration files and reference binary
    """
    binary = load_file(os.path.join(data_dir, "CFPA_test.bin"), mode="rb")

    pfr_cfg_json = Config.create_from_file(os.path.join(data_dir, "cfpa_test.json"))
    cfpa_json = CFPA.load_from_config(pfr_cfg_json)
    assert cfpa_json.export(add_seal=True) == binary

    pfr_cfg_yml = Config.create_from_file(os.path.join(data_dir, "cfpa_test.yml"))
    cfpa_yml = CFPA.load_from_config(pfr_cfg_yml)
    assert cfpa_yml.export(add_seal=True) == binary


def test_supported_devices() -> None:
    """Verify PFR tool correctly reports supported device families.

    Checks that the list of supported device families returned by the PFR API
    matches the list of devices with PFR features in the database, and that
    all CFPA-supported devices are also supported for CMPA operations.

    """
    cfpa_devices = CFPA.get_supported_families()
    assert isinstance(cfpa_devices, list)
    cfpa_device_names = list(set(family.name for family in cfpa_devices))
    assert cfpa_device_names.sort() == list(DatabaseManager().quick_info.devices.get_devices_with_feature(
        "pfr", "cfpa"
    ).keys()).sort()

    cmpa_devices = CMPA.get_supported_families()

    for cfpa in cfpa_devices:
        if cfpa not in cmpa_devices:
            assert False


def test_seal_cfpa() -> None:
    """Verify CFPA sealing functionality.

    Tests that CFPA data exported with and without sealing has the expected
    structure and seal markers at the appropriate offsets.

    """
    cfpa = CFPA(FamilyRevision("lpc55s6x"))

    data = cfpa.export(add_seal=False)
    assert len(data) == 512
    assert data[0x1E0:] == bytes(32)

    data = cfpa.export(add_seal=True)
    assert len(data) == 512
    assert data[0x1E0:] == CFPA.MARK * 8


def test_seal_cmpa_lpc55s3x() -> None:
    """Verify CMPA sealing functionality for LPC55S3x family.

    Tests that CFPA data for LPC55S3x devices exported with and without
    sealing has the expected structure and seal markers at the appropriate offsets.

    """
    cfpa = CFPA(FamilyRevision("lpc55s3x"))

    data = cfpa.export(add_seal=False)
    assert len(data) == 512
    assert data[0x1E0:] == bytes(32)

    data = cfpa.export(add_seal=True)
    assert len(data) == 512
    assert data[0x1EC:0x1F0] == CFPA.MARK


def test_basic_cmpa() -> None:
    """Verify basic CMPA instantiation.

    Tests that a CMPA object can be created for a supported family without errors.

    """
    CMPA(FamilyRevision("lpc55s6x"))


def test_config_cfpa(data_dir: str) -> None:
    """Verify CFPA configuration handling.

    Tests that CFPA configuration can be retrieved consistently and that
    configurations remain consistent after parsing and reexporting.

    :param data_dir: Path to test data directory containing configuration files
    """
    family = FamilyRevision("lpc55s6x")
    cfpa = CFPA(family)
    config = cfpa.get_config()
    config2 = cfpa.get_config()

    assert config == config2

    cfpa2 = CFPA(family)
    cfpa2.parse(bytes(512), family)  # Parse 512-bytes of empty CFPA page content
    cfpa2_pfr_cfg = load_configuration(
        data_dir + "/cfpa_after_reset.yml"
    )  # Apply known CFPA fields after reset values
    cfpa2.set_config(cfpa2_pfr_cfg["settings"])
    out = cfpa2.get_config()

    assert config == out


def test_config_cmpa() -> None:
    """Verify CMPA configuration handling.

    Tests that CMPA configuration can be retrieved consistently and that
    configurations remain consistent after parsing and reexporting.

    """
    family = FamilyRevision("lpc55s3x")
    cmpa = CMPA(family)
    config = cmpa.get_config()
    config2 = cmpa.get_config()

    assert config == config2

    cmpa2 = CMPA.load_from_config(config2)
    out = cmpa2.parse(bytes(512), family).get_config()

    assert out == config2


def test_config_cmpa_yml(tmpdir: str) -> None:
    """Verify CMPA configuration handling from YAML files.

    Tests that CMPA configuration can be correctly exported to and imported
    from YAML files, and that the configuration remains consistent through
    the process with expected default values.

    :param tmpdir: Temporary directory for creating test files
    """
    yaml = YAML()
    yaml.indent(sequence=4, offset=2)
    cmpa = CMPA(FamilyRevision("lpc55s36", "a1"))
    config = cmpa.get_config()

    assert cmpa.get_config(diff=True) == {
        "family": "lpc55s36",
        "revision": "a1",
        "type": "CMPA",
        "settings": {},
    }

    with open(os.path.join(tmpdir, "config.yml"), "w", encoding="ascii") as yml_file:
        yaml.dump(dict(config), yml_file)

    cmpa2_pfr_cfg = Config.create_from_file(os.path.join(tmpdir, "config.yml"))
    cmpa2 = CMPA.load_from_config(cmpa2_pfr_cfg)
    out_config = cmpa2.get_config(diff=True)

    assert out_config == {
        "family": "lpc55s36",
        "revision": "a1",
        "type": "CMPA",
        "settings": {
            "DCFG_CC_SOCU_PIN": {"INVERSE_VALUE": "0xFFFF"},
            "DCFG_CC_SOCU_DFLT": {"INVERSE_VALUE": "0xFFFF"},
        },
    }


def test_set_config_rev_latest(data_dir: str) -> None:
    """Verify configuration handling with 'latest' revision specification.

    Tests that a CMPA object can be correctly created from a configuration
    that specifies 'latest' as the revision value.

    :param data_dir: Path to test data directory containing configuration files
    """
    pfr_cfg = Config.create_from_file(data_dir + "/latest_rev.yml")
    cmpa = CMPA.load_from_config(pfr_cfg)
    assert cmpa


def test_json_yml_configs(data_dir: str) -> None:
    """Verify configuration equivalence between JSON and YAML formats.

    Tests that configurations loaded from equivalent JSON and YAML files
    produce identical CMPA configuration objects.

    :param data_dir: Path to test data directory containing configuration files
    """
    cmpa_json = CMPA.load_from_config(Config.create_from_file(f"{data_dir}/cmpa_96mhz.json"))
    cmpa_yml = CMPA.load_from_config(Config.create_from_file(f"{data_dir}/cmpa_96mhz.yml"))

    assert cmpa_yml.get_config(False) == cmpa_json.get_config(False)
    assert cmpa_yml.get_config(True) == cmpa_json.get_config(True)


def test_missing_rotkh() -> None:
    """Verify proper error handling for missing Root of Trust Key Hash.

    Tests that an appropriate exception is raised when trying to export
    CFPA data with invalid or missing keys for ROTKH generation.

    """
    cfpa = CFPA(FamilyRevision("lpc55s6x"))
    with pytest.raises(SPSDKPfrRotkhIsNotPresent):
        cfpa.export(keys=["Invalid"])


def test_lpc55s3x_load_yml_without_change(data_dir: str) -> None:
    """Verify LPC55S3x CFPA loading without configuration changes.

    Tests that CFPA data for LPC55S3x can be loaded from YAML configuration
    without changes and correctly computes antipole values.

    :param data_dir: Path to test data directory containing configuration files
    """
    cfpa = CFPA.load_from_config(Config.create_from_file(f"{data_dir}/cfpa_no_change.yml"))
    data = cfpa.export()

    assert len(data) == 512
    with open(data_dir + "/lpc55s3x_CFPA_basic.bin", "rb") as binary:
        assert data == binary.read()


def test_lpc55s3x_binary_ec256(data_dir: str) -> None:
    """Verify CMPA binary generation with ECC256 keys for LPC55S3x.

    Tests CMPA binary generation and ROTKH computation for LPC55S3x using
    ECC256 keys, verifying the output matches expected binary data.

    :param data_dir: Path to test data directory containing key files and reference binary
    """
    cmpa = CMPA(FamilyRevision("lpc55s3x"))
    keys_path = [
        data_dir + "/ec_secp256r1_cert0.pem",
        data_dir + "/ec_secp256r1_cert1.pem",
        data_dir + "/ec_secp256r1_cert2.pem",
        data_dir + "/ec_secp256r1_cert3.pem",
    ]

    data = cmpa.export(keys=extract_public_keys(keys_path, password=None))

    assert len(data) == 512
    with open(data_dir + "/lpc55s3x_CMPA.bin", "rb") as binary:
        assert data == binary.read()


def test_lpc55s3x_binary_ec384(data_dir: str) -> None:
    """Verify CMPA binary generation with ECC384 keys for LPC55S3x.

    Tests CMPA binary generation and ROTKH computation for LPC55S3x using
    ECC384 keys, verifying the output matches expected binary data.

    :param data_dir: Path to test data directory containing key files and reference binary
    """
    cmpa = CMPA(FamilyRevision("lpc55s3x"))
    keys_path = [
        data_dir + "/ec_secp384r1_cert0.pem",
        data_dir + "/ec_secp384r1_cert1.pem",
        data_dir + "/ec_secp384r1_cert2.pem",
        data_dir + "/ec_secp384r1_cert3.pem",
    ]

    data = cmpa.export(keys=extract_public_keys(keys_path, password=None))

    assert len(data) == 512
    with open(data_dir + "/lpc55s3x_CMPA_384.bin", "rb") as binary:
        assert data == binary.read()


def test_invalid_key_size(data_dir: str) -> None:
    """Verify error handling for invalid key sizes.

    Tests that an appropriate exception is raised when trying to use
    keys with unsupported sizes for ROTKH computation.

    :param data_dir: Path to test data directory containing key files
    """
    cfpa = CMPA(FamilyRevision("lpc55s6x"))
    keys_path = [
        data_dir + "/ec_secp384r1_cert0.pem",
        data_dir + "/ec_secp384r1_cert1.pem",
        data_dir + "/ec_secp384r1_cert2.pem",
        data_dir + "/ec_secp384r1_cert3.pem",
    ]

    with pytest.raises(SPSDKError):
        cfpa.export(keys=extract_public_keys(keys_path, password=None))


def test_base_config_area_invalid_device_revision() -> None:
    """Verify error handling for invalid device family and revision.

    Tests that appropriate exceptions are raised when attempting to use
    non-existent device families or unsupported revisions.

    """
    with pytest.raises(
        SPSDKError, match="Cannot load the device 'bb' - Doesn't exists in database."
    ):
        BaseConfigArea(family=FamilyRevision("bb"))
    with pytest.raises(SPSDKError, match="Requested revision hh is not supported."):
        BaseConfigArea(FamilyRevision(name="lpc55s6x", revision="HH"))


def get_mcxa_families() -> list[str]:
    """Get list of supported MCXA family devices for CMPA.

    Identifies all supported device families that start with 'mcxa' from
    the complete list of supported CMPA families.

    :return: List of MCXA family device names supported for CMPA operations
    """
    all_families = CMPA.get_supported_families()
    mcxa_families = [family.name for family in all_families if family.name.startswith("mcxa")]
    return mcxa_families


@pytest.mark.parametrize("cpu_name", get_mcxa_families())
def test_rop_state_reset_value_mcxa1x(cpu_name: str, reset_value: int = 0xFFFF_FFFF) -> None:
    """Test reset values of ROP_STATE registers for MCXA1x series.

    Verifies that both ROP_STATE and ROP_STATE_DP register fields in CMPA
    have the expected reset value of 0xFFFFFFFF for all MCXA1x series devices.

    :param cpu_name: Name of the CPU/device to test
    :param reset_value: Expected reset value for the registers
    :return: None
    """
    cmpa = CMPA(FamilyRevision(cpu_name))
    assert cmpa.registers.find_reg("ROP_STATE").get_reset_value() == reset_value
    assert cmpa.registers.find_reg("ROP_STATE_DP").get_reset_value() == reset_value
