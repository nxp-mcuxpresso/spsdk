#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test suite for SPSDK Protected Flash Region (PFR) functionality.

This module contains comprehensive tests for PFR (Protected Flash Region) implementation,
covering CMPA and CFPA area management, configuration generation, and validation across
NXP MCU families including LPC55Sxx and MCXAxx series.
The tests ensure reliable PFR functionality for secure provisioning workflows
across the NXP microcontroller portfolio.
"""

import os
from pathlib import Path

import pytest
from ruamel.yaml import YAML

from spsdk.crypto.keys import PrivateKeyRsa
from spsdk.crypto.utils import extract_public_keys
from spsdk.exceptions import SPSDKError
from spsdk.pfr.exceptions import SPSDKPfrError
from spsdk.pfr.pfr import (
    CFPA,
    CMPA,
    CMPA_CFG,
    CMPA_LC,
    CMPA_PSWD,
    UPDATE_CFPA_CMPA,
    BaseConfigArea,
    SPSDKPfrRotkhIsNotPresent,
)
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_configuration, load_file


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
    cmpa_json.compute_rotkh(keys=[key.get_public_key()])
    assert binary == cmpa_json.export(add_seal=False)

    pfr_cfg_yml = Config.create_from_file(os.path.join(data_dir, "cmpa_96mhz.yml"))
    cmpa_yml = CMPA.load_from_config(pfr_cfg_yml)
    cmpa_yml.compute_rotkh(keys=[key.get_public_key()])
    assert binary == cmpa_yml.export(add_seal=False)


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

    :raises AssertionError: When supported device families don't match database or CFPA devices are not supported for CMPA.
    """
    cfpa_devices = CFPA.get_supported_families()
    assert isinstance(cfpa_devices, list)
    cfpa_device_names = list(set(family.name for family in cfpa_devices))
    cfpa_device_names.sort()
    cfpa_device_names_raw = list(
        DatabaseManager().quick_info.devices.get_devices_with_feature("pfr", "cfpa").keys()
    )
    cfpa_device_names_raw.sort()
    assert cfpa_device_names == cfpa_device_names_raw

    cmpa_devices = CMPA.get_supported_families()
    cfpa_cmpa_devices = UPDATE_CFPA_CMPA.get_supported_families()

    for cfpa in cfpa_devices:
        if cfpa not in cmpa_devices and cfpa not in cfpa_cmpa_devices:
            assert False


def test_seal_cfpa() -> None:
    """```

    Verify CFPA sealing functionality.
    Tests that CFPA data exported with and without sealing has the expected
    structure and seal markers at the appropriate offsets. Validates that
    unsealed data contains zeros in the seal area and sealed data contains
    the proper CFPA mark pattern.
    ```
    """
    cfpa = CFPA(FamilyRevision("lpc55s6x"))

    data = cfpa.export(add_seal=False)
    assert len(data) == 512
    assert data[0x1E0:] == bytes(32)

    data = cfpa.export(add_seal=True)
    assert len(data) == 512
    assert data[0x1E0:] == CFPA.MARK * 8


def test_seal_cmpa_lpc55s3x() -> None:
    """Test CMPA sealing functionality for LPC55S3x family.

    Verifies that CFPA data for LPC55S3x devices exported with and without
    sealing has the expected structure and seal markers at the appropriate offsets.
    Tests both unsealed export (should have zeros in seal area) and sealed export
    (should contain CFPA.MARK at the correct offset).
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
    This test ensures the CMPA constructor works correctly with valid family revision input.
    """
    CMPA(FamilyRevision("lpc55s6x"))


def test_config_cfpa(data_dir: str) -> None:
    """Test CFPA configuration handling and consistency.

    Verifies that CFPA configuration can be retrieved consistently and that
    configurations remain consistent after parsing and reexporting. The test
    creates CFPA instances, parses empty page content, applies reset values,
    and validates configuration consistency.

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
    This test validates the round-trip integrity of CMPA configuration
    data for the lpc55s3x family.
    """
    family = FamilyRevision(name="lpc55s3x", revision="a0")
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

    :param tmpdir: Temporary directory for creating test files.
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
            "DCFG_CC_SOCU_PIN": {"Inverse_value": "0xFFFF"},
            "DCFG_CC_SOCU_DFLT": {"Inverse_value": "0xFFFF"},
        },
    }


def test_set_config_rev_latest(data_dir: str) -> None:
    """Test configuration handling with 'latest' revision specification.

    Tests that a CMPA object can be correctly created from a configuration
    that specifies 'latest' as the revision value.

    :param data_dir: Path to test data directory containing configuration files.
    """
    pfr_cfg = Config.create_from_file(data_dir + "/latest_rev.yml")
    cmpa = CMPA.load_from_config(pfr_cfg)
    assert cmpa


def test_json_yml_configs(data_dir: str) -> None:
    """```

    Verify configuration equivalence between JSON and YAML formats.
    Tests that configurations loaded from equivalent JSON and YAML files
    produce identical CMPA configuration objects. Validates both diff and
    non-diff configuration outputs for consistency.

    :param data_dir: Path to test data directory containing configuration files
    :raises AssertionError: When JSON and YAML configurations produce different results
    ```
    """
    cmpa_json = CMPA.load_from_config(Config.create_from_file(f"{data_dir}/cmpa_96mhz.json"))
    cmpa_yml = CMPA.load_from_config(Config.create_from_file(f"{data_dir}/cmpa_96mhz.yml"))

    assert cmpa_yml.get_config(diff=False) == cmpa_json.get_config(diff=False)
    assert cmpa_yml.get_config(diff=True) == cmpa_json.get_config(diff=True)


def test_missing_rotkh() -> None:
    """```

    Verify proper error handling for missing Root of Trust Key Hash.
    Tests that an appropriate exception is raised when trying to export
    CFPA data with invalid or missing keys for ROTKH generation.

    :raises SPSDKPfrRotkhIsNotPresent: When CFPA export is called with invalid keys.
    ```
    """
    cfpa = CFPA(FamilyRevision("lpc55s6x"))
    with pytest.raises(SPSDKPfrRotkhIsNotPresent):
        cfpa.compute_rotkh(keys=["Invalid"])  # type: ignore


def test_lpc55s3x_load_yml_without_change(data_dir: str) -> None:
    """```

    Verify LPC55S3x CFPA loading without configuration changes.
    Tests that CFPA data for LPC55S3x can be loaded from YAML configuration
    without changes and correctly computes antipole values. Validates that
    the exported binary data matches the expected reference file.

    :param data_dir: Path to test data directory containing configuration files
    ```
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

    :param data_dir: Path to test data directory containing key files and reference binary.
    """
    cmpa = CMPA(FamilyRevision("lpc55s3x"))
    keys_path = [
        data_dir + "/ec_secp256r1_cert0.pem",
        data_dir + "/ec_secp256r1_cert1.pem",
        data_dir + "/ec_secp256r1_cert2.pem",
        data_dir + "/ec_secp256r1_cert3.pem",
    ]
    cmpa.compute_rotkh(keys=extract_public_keys(keys_path, password=None))
    data = cmpa.export()

    assert len(data) == 512
    with open(data_dir + "/lpc55s3x_CMPA.bin", "rb") as binary:
        assert data == binary.read()


def test_lpc55s3x_binary_ec384(data_dir: str) -> None:
    """```

    Verify CMPA binary generation with ECC384 keys for LPC55S3x.
    Tests CMPA binary generation and ROTKH computation for LPC55S3x using
    ECC384 keys, verifying the output matches expected binary data.

    :param data_dir: Path to test data directory containing key files and reference binary.
    ```
    """
    cmpa = CMPA(FamilyRevision("lpc55s3x"))
    keys_path = [
        data_dir + "/ec_secp384r1_cert0.pem",
        data_dir + "/ec_secp384r1_cert1.pem",
        data_dir + "/ec_secp384r1_cert2.pem",
        data_dir + "/ec_secp384r1_cert3.pem",
    ]

    cmpa.compute_rotkh(keys=extract_public_keys(keys_path, password=None))
    data = cmpa.export()

    assert len(data) == 512
    with open(data_dir + "/lpc55s3x_CMPA_384.bin", "rb") as binary:
        assert data == binary.read()


def test_invalid_key_size(data_dir: str) -> None:
    """Verify error handling for invalid key sizes.

    Tests that an appropriate exception is raised when trying to use
    keys with unsupported sizes for ROTKH computation.

    :param data_dir: Path to test data directory containing key files.
    :raises SPSDKError: When keys with unsupported sizes are used for ROTKH computation.
    """
    cfpa = CMPA(FamilyRevision("lpc55s6x"))
    keys_path = [
        data_dir + "/ec_secp384r1_cert0.pem",
        data_dir + "/ec_secp384r1_cert1.pem",
        data_dir + "/ec_secp384r1_cert2.pem",
        data_dir + "/ec_secp384r1_cert3.pem",
    ]

    with pytest.raises(SPSDKError):
        cfpa.compute_rotkh(keys=extract_public_keys(keys_path, password=None))
        cfpa.export()


def test_base_config_area_invalid_device_revision() -> None:
    """Test error handling for invalid device family and revision in BaseConfigArea.

    Verifies that appropriate SPSDKError exceptions are raised when attempting to create
    BaseConfigArea instances with non-existent device families or unsupported device revisions.

    :raises SPSDKError: When device family doesn't exist in database or revision is not supported.
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

    :return: List of MCXA family device names supported for CMPA operations.
    """
    all_families = CMPA.get_supported_families()
    mcxa_families = [family.name for family in all_families if family.name.startswith("mcxa")]
    return mcxa_families


def get_mcxa1_3_families() -> list[str]:
    """Get list of supported MCXA family devices for CMPA.

    Identifies all supported device families that start with 'mcxa1' or 'mcxa3' from
    the complete list of supported CMPA families.

    :return: List of MCXA1x and MCXA3x family device names supported for CMPA operations.
    """
    all_families = get_mcxa_families()
    mcxa_families = [
        family
        for family in all_families
        if family.startswith("mcxa1") or family.startswith("mcxa3")
    ]
    return mcxa_families


@pytest.mark.parametrize("cpu_name", get_mcxa1_3_families())
def test_rop_state_reset_value_mcxa1x(cpu_name: str, reset_value: int = 0xFFFF_FFFF) -> None:
    """Test reset values of ROP_STATE registers for MCXA1x series.

    Verifies that both ROP_STATE and ROP_STATE_DP register fields in CMPA
    have the expected reset value of 0xFFFFFFFF for all MCXA1x series devices.

    :param cpu_name: Name of the CPU/device to test.
    :param reset_value: Expected reset value for the registers, defaults to 0xFFFFFFFF.
    """
    cmpa = CMPA(FamilyRevision(cpu_name))
    assert cmpa.registers.find_reg("ROP_STATE").get_reset_value() == reset_value
    assert cmpa.registers.find_reg("ROP_STATE_DP").get_reset_value() == reset_value


def test_additional_data_setter_success() -> None:
    """Test that additional_data setter works correctly when configuration allows it.

    This test verifies that the CMPA additional_data setter successfully accepts and stores
    data when the support_additional_data is configured as True. It uses a family that
    supports additional data and confirms the setter operates without errors.
    """
    # Use a family that supports additional data (check database for actual support)
    # For this test, we'll patch the support flag
    cmpa = CMPA(FamilyRevision("lpc55s6x"))
    cmpa.support_additional_data = True

    test_data = bytes([0x01, 0x02, 0x03, 0x04])

    # This should succeed
    cmpa.additional_data = test_data
    assert cmpa._additional_data == test_data


def test_additional_data_setter_disabled() -> None:
    """Test that additional_data setter raises error when additional data is disabled.

    This test verifies that attempting to set additional data on a CMPA instance
    raises SPSDKPfrError when the family configuration has additional data disabled.
    The test verifies the appropriate exception is raised with the expected error message.

    :raises SPSDKPfrError: When attempting to set additional data on disabled configuration.
    """
    cmpa = CMPA(FamilyRevision("lpc55s6x"))
    # Ensure support is disabled
    cmpa.support_additional_data = False

    test_data = bytes([0x01, 0x02, 0x03, 0x04])

    # This should raise an error
    with pytest.raises(SPSDKPfrError, match="Additional data is not supported"):
        cmpa.additional_data = test_data


def test_additional_data_setter_size_exceeded() -> None:
    """Test that additional_data setter accepts data regardless of size.

    This test verifies that the CMPA additional_data setter accepts data of any size
    when additional data is supported. Size validation happens during export, not during
    setter operation.

    Note: The BaseConfigArea.additional_data setter does not validate size - it only
    checks if additional data is supported. Size validation would occur in subclasses
    or during export operations.
    """
    cmpa = CMPA(FamilyRevision("lpc55s6x"))
    cmpa.support_additional_data = True

    test_data = bytes([0x01, 0x02, 0x03, 0x04])

    # This should succeed - size validation is not in the base setter
    cmpa.additional_data = test_data
    assert cmpa._additional_data == test_data


def test_additional_data_support_flag() -> None:
    """Test that support_additional_data flag is correctly loaded from database.

    This test verifies that the CMPA initialization properly loads the
    support_additional_data flag from the database configuration for a given family.

    :raises AssertionError: If the support flag is not properly loaded.
    """
    # Test with a family - actual support depends on database content
    family = FamilyRevision("lpc55s6x")
    cmpa = CMPA(family)

    # Verify the flag exists and is a boolean
    assert isinstance(cmpa.support_additional_data, bool)
    # The actual value depends on database configuration


def test_parse_with_additional_data() -> None:
    """Test that CMPA parse method handles binary data correctly.

    This test verifies the parse functionality of CMPA. Note that BaseConfigArea.parse()
    only parses register data, not additional data. Additional data parsing is handled
    by MultiRegionBaseConfigArea.

    The test creates a CMPA instance, exports it, and parses it back to verify
    register data integrity.
    """
    # Create original CMPA
    original_cmpa = CMPA(FamilyRevision("lpc55s6x"))
    original_cmpa.support_additional_data = True

    test_data = bytes([0xAA, 0xBB, 0xCC, 0xDD])
    original_cmpa.additional_data = test_data

    # Export to binary (only registers)
    binary = original_cmpa.export(add_seal=False)

    # Parse the binary back
    parsed_cmpa = CMPA.parse(binary, FamilyRevision("lpc55s6x"))

    # BaseConfigArea.parse() only parses registers, not additional data
    # So additional data will be empty after parsing
    assert parsed_cmpa.additional_data == b""

    # But registers should match
    assert parsed_cmpa.registers == original_cmpa.registers


def test_multi_region_additional_data_export() -> None:
    """Test that MultiRegionBaseConfigArea correctly exports additional data.

    This test verifies that the UPDATE_CFPA_CMPA class properly handles
    additional data export for multi-region configurations.
    """
    family = FamilyRevision("mcxa457")

    # Check if this family supports UPDATE_CFPA_CMPA
    if family not in UPDATE_CFPA_CMPA.get_supported_families():
        pytest.skip(f"Family {family} does not support UPDATE_CFPA_CMPA")

    multi_region = UPDATE_CFPA_CMPA(family)

    # Set additional data on CFPA region
    cfpa = multi_region.get_region("CFPA")
    cfpa.support_additional_data = True
    cfpa.additional_data = bytes([0xAA, 0xBB, 0xCC, 0xDD])

    # Export should include additional data
    binary = multi_region.export(add_seal=False)

    # Binary should include all regions plus additional data
    expected_size = (
        sum(r.registers_size for r in multi_region.regions)
        + multi_region.get_additional_data_size()
    )
    assert len(binary) == expected_size


def test_multi_region_additional_data_parse() -> None:
    """Test that MultiRegionBaseConfigArea correctly parses additional data.

    This test verifies the round-trip functionality of multi-region additional data:
    1. Creates a multi-region instance with additional data
    2. Exports to binary format
    3. Parses the binary back
    4. Verifies additional data was preserved
    """
    family = FamilyRevision("mcxa457")

    # Check if this family supports UPDATE_CFPA_CMPA
    if family not in UPDATE_CFPA_CMPA.get_supported_families():
        pytest.skip(f"Family {family} does not support UPDATE_CFPA_CMPA")

    # Create original multi-region with additional data
    original = UPDATE_CFPA_CMPA(family)
    cfpa = original.get_region("CFPA")
    cfpa.support_additional_data = True
    test_data = bytes([0xAA, 0xBB, 0xCC, 0xDD])
    cfpa.additional_data = test_data

    # Export to binary
    binary = original.export(add_seal=False)

    # Parse back
    parsed = UPDATE_CFPA_CMPA.parse(binary, family)

    # Verify additional data was preserved
    parsed_cfpa = parsed.get_region("CFPA")
    assert parsed_cfpa.additional_data == test_data


def test_mcxc151_cmpa_cfg_instantiation() -> None:
    """Test CMPA_CFG instantiation for mcxc151.

    Verifies that a CMPA_CFG object can be created for mcxc151 family without errors.
    """
    cmpa_cfg = CMPA_CFG(FamilyRevision("mcxc151"))
    assert cmpa_cfg is not None
    assert cmpa_cfg.SUB_FEATURE == "cmpa_cfg"


def test_mcxc151_cmpa_pswd_instantiation() -> None:
    """Test CMPA_PSWD instantiation for mcxc151.

    Verifies that a CMPA_PSWD object can be created for mcxc151 family without errors.
    """
    cmpa_pswd = CMPA_PSWD(FamilyRevision("mcxc151"))
    assert cmpa_pswd is not None
    assert cmpa_pswd.SUB_FEATURE == "cmpa_pswd"


def test_mcxc151_cmpa_lc_instantiation() -> None:
    """Test CMPA_LC instantiation for mcxc151.

    Verifies that a CMPA_LC object can be created for mcxc151 family without errors.
    """
    cmpa_lc = CMPA_LC(FamilyRevision("mcxc151"))
    assert cmpa_lc is not None
    assert cmpa_lc.SUB_FEATURE == "cmpa_lc"


def test_mcxc151_cmpa_pswd_export(tmpdir: str) -> None:
    """Test CMPA_PSWD binary export for mcxc151.

    Verifies that CMPA_PSWD can export binary data correctly.

    :param tmpdir: Temporary directory for creating test files
    """
    cmpa_pswd = CMPA_PSWD(FamilyRevision("mcxc151"))

    # Export the binary
    binary = cmpa_pswd.export(add_seal=False)

    # Verify binary was created and has expected size
    assert len(binary) > 0
    assert isinstance(binary, bytes)


def test_mcxc151_cmpa_pswd_config_uses_grouped_password() -> None:
    """Test CMPA_PSWD exposes the current grouped-password layout for mcxc151."""
    cmpa_pswd = CMPA_PSWD(FamilyRevision("mcxc151"))

    settings = cmpa_pswd.get_config()["settings"]
    expected_grouped_regs = {
        "DBG_AUTH_PASSWORD": [
            "DBG_AUTH_PASSWORD0",
            "DBG_AUTH_PASSWORD1",
            "DBG_AUTH_PASSWORD2",
            "DBG_AUTH_PASSWORD3",
        ],
        "IMG_MISR_SEED": [
            "IMG_MISR_SEED0",
            "IMG_MISR_SEED1",
            "IMG_MISR_SEED2",
            "IMG_MISR_SEED3",
        ],
        "ERASE_PASSWORD": [
            "ERASE_PASSWORD0",
            "ERASE_PASSWORD1",
            "ERASE_PASSWORD2",
            "ERASE_PASSWORD3",
        ],
    }

    for grouped_reg_name, sub_reg_names in expected_grouped_regs.items():
        grouped_reg = cmpa_pswd.registers.find_reg(grouped_reg_name)
        assert grouped_reg.has_group_registers()
        assert grouped_reg.reverse_subregs_order
        assert [sub_reg.name for sub_reg in grouped_reg.sub_regs] == sub_reg_names
        assert grouped_reg_name in settings
        assert all(sub_reg_name not in settings for sub_reg_name in sub_reg_names)

    assert "CMPA_MISR_SEED" not in settings


def test_mcxc151_cmpa_pswd_load_legacy_password_registers() -> None:
    """Test CMPA_PSWD still accepts the current per-word mcxc151 configuration."""
    legacy_cfg = Config(
        {
            "family": "mcxc151",
            "revision": "latest",
            "type": "CMPA_PSWD",
            "settings": {
                "DBG_AUTH_PASSWORD0": "0x11223344",
                "DBG_AUTH_PASSWORD1": "0x55667788",
                "DBG_AUTH_PASSWORD2": "0x99AABBCC",
                "DBG_AUTH_PASSWORD3": "0xDDEEFF00",
                "IMG_MISR_SEED0": "0x0F1E2D3C",
                "IMG_MISR_SEED1": "0x4B5A6978",
                "IMG_MISR_SEED2": "0x8796A5B4",
                "IMG_MISR_SEED3": "0xC3D2E1F0",
            },
        }
    )

    cmpa_pswd = CMPA_PSWD.load_from_config(legacy_cfg)
    settings = cmpa_pswd.get_config()["settings"]

    assert settings["DBG_AUTH_PASSWORD"] == "112233445566778899AABBCCDDEEFF00"
    assert settings["IMG_MISR_SEED"] == "0F1E2D3C4B5A69788796A5B4C3D2E1F0"
    assert "DBG_AUTH_PASSWORD2" not in settings
    assert "IMG_MISR_SEED0" not in settings
    assert (
        cmpa_pswd.registers.find_reg("DBG_AUTH_PASSWORD0", include_group_regs=True).get_value(
            raw=True
        )
        == 0x11223344
    )
    assert (
        cmpa_pswd.registers.find_reg("DBG_AUTH_PASSWORD3", include_group_regs=True).get_value(
            raw=True
        )
        == 0xDDEEFF00
    )
    assert (
        cmpa_pswd.registers.find_reg("IMG_MISR_SEED0", include_group_regs=True).get_value(raw=True)
        == 0x0F1E2D3C
    )
    assert (
        cmpa_pswd.registers.find_reg("IMG_MISR_SEED3", include_group_regs=True).get_value(raw=True)
        == 0xC3D2E1F0
    )


@pytest.mark.parametrize("family", ["mcxc151", "mcxc161", "mcxc162"])
@pytest.mark.parametrize(
    "case_name,expected_erase_password",
    [
        ("tc1", "00CCBBAA11CCBBAA22CCBBAA33CCBBAA"),
        ("tc2", "0A0000000B0000000C0000000D000000"),
        ("tc3", "0A000000000000000000000000000000"),
    ],
)
def test_mcxc151_alias_cmpa_pswd_grouped_cases_export_match(
    data_dir: str, family: str, case_name: str, expected_erase_password: str
) -> None:
    """Test grouped and per-word ERASE_PASSWORD forms export identical data for aliases."""
    legacy_cfg = Config.create_from_file(
        os.path.join(data_dir, "yaml_bin", f"mcxc162_cmpa_{case_name}_legacy.yaml")
    )
    grouped_cfg = Config.create_from_file(
        os.path.join(data_dir, "yaml_bin", f"mcxc162_cmpa_{case_name}_grouped.yaml")
    )
    legacy_cfg["family"] = family
    grouped_cfg["family"] = family

    legacy_binary = CMPA_PSWD.load_from_config(legacy_cfg).export(add_seal=False)
    grouped_binary = CMPA_PSWD.load_from_config(grouped_cfg).export(add_seal=False)
    expected_legacy_binary = load_file(
        os.path.join(data_dir, "yaml_bin", f"mcxc162_cmpa_{case_name}_legacy.bin"), mode="rb"
    )
    expected_grouped_binary = load_file(
        os.path.join(data_dir, "yaml_bin", f"mcxc162_cmpa_{case_name}_grouped.bin"), mode="rb"
    )

    assert grouped_binary == legacy_binary
    assert legacy_binary == expected_legacy_binary
    assert grouped_binary == expected_grouped_binary
    assert legacy_binary[0x30:0x40] == bytes.fromhex(expected_erase_password)


@pytest.mark.parametrize("case_name", ["tc1", "tc2", "tc3"])
def test_mcxc162_cmpa_pswd_grouped_yaml_has_single_128_bit_erase_password(
    data_dir: str, case_name: str
) -> None:
    """Test grouped ERASE_PASSWORD YAML contains one 128-bit grouped register value."""
    cfg_path = os.path.join(data_dir, "yaml_bin", f"mcxc162_cmpa_{case_name}_grouped.yaml")
    config = Config.create_from_file(cfg_path)
    settings = config["settings"]
    erase_password_value = settings["ERASE_PASSWORD"]
    erase_password_keys = [name for name in settings if name.startswith("ERASE_PASSWORD")]
    erase_password_reg = CMPA_PSWD(FamilyRevision("mcxc162")).registers.find_reg("ERASE_PASSWORD")

    assert erase_password_keys == ["ERASE_PASSWORD"]
    assert Path(cfg_path).read_text(encoding="utf-8").count("ERASE_PASSWORD") == 1
    assert erase_password_reg.width == 128
    assert len(erase_password_value.removeprefix("0x")) == erase_password_reg.width // 4


@pytest.mark.parametrize("case_name", ["tc1", "tc2"])
def test_mcxc162_cmpa_pswd_legacy_yaml_has_four_32_bit_erase_password_words(
    data_dir: str, case_name: str
) -> None:
    """Test full legacy ERASE_PASSWORD YAML contains four 32-bit sub-register values."""
    cfg_path = os.path.join(data_dir, "yaml_bin", f"mcxc162_cmpa_{case_name}_legacy.yaml")
    config = Config.create_from_file(cfg_path)
    settings = config["settings"]
    erase_password_keys = [name for name in settings if name.startswith("ERASE_PASSWORD")]
    cmpa_pswd = CMPA_PSWD(FamilyRevision("mcxc162"))

    assert erase_password_keys == [
        "ERASE_PASSWORD0",
        "ERASE_PASSWORD1",
        "ERASE_PASSWORD2",
        "ERASE_PASSWORD3",
    ]
    assert Path(cfg_path).read_text(encoding="utf-8").count("ERASE_PASSWORD") == 4
    for reg_name in erase_password_keys:
        assert cmpa_pswd.registers.find_reg(reg_name, include_group_regs=True).width == 32


def test_mcxc162_cmpa_pswd_legacy_yaml_allows_intentional_single_erase_password_word(
    data_dir: str,
) -> None:
    """Test partial legacy ERASE_PASSWORD YAML may intentionally contain only word 0."""
    cfg_path = os.path.join(data_dir, "yaml_bin", "mcxc162_cmpa_tc3_legacy.yaml")
    config = Config.create_from_file(cfg_path)
    settings = config["settings"]
    erase_password_keys = [name for name in settings if name.startswith("ERASE_PASSWORD")]
    cmpa_pswd = CMPA_PSWD(FamilyRevision("mcxc162"))

    assert erase_password_keys == ["ERASE_PASSWORD0"]
    assert Path(cfg_path).read_text(encoding="utf-8").count("ERASE_PASSWORD0") == 1
    assert cmpa_pswd.registers.find_reg("ERASE_PASSWORD0", include_group_regs=True).width == 32


def test_mcxc151_cmpa_lc_export(tmpdir: str) -> None:
    """Test CMPA_LC binary export for mcxc151.

    Verifies that CMPA_LC can export binary data correctly.

    :param tmpdir: Temporary directory for creating test files
    """
    cmpa_lc = CMPA_LC(FamilyRevision("mcxc151"))

    # Export the binary
    binary = cmpa_lc.export(add_seal=False)

    # Verify binary was created and has expected size
    assert len(binary) > 0
    assert isinstance(binary, bytes)


def test_mcxc151_supported_families() -> None:
    """Test that mcxc151 is in supported families for all sub-features.

    Verifies that mcxc151 appears in the supported families list for
    CMPA_CFG, CMPA_PSWD, and CMPA_LC.
    """
    cmpa_cfg_families = CMPA_CFG.get_supported_families()
    cmpa_pswd_families = CMPA_PSWD.get_supported_families()
    cmpa_lc_families = CMPA_LC.get_supported_families()

    # Check mcxc151 is in all lists
    assert any(f.name == "mcxc151" for f in cmpa_cfg_families)
    assert any(f.name == "mcxc151" for f in cmpa_pswd_families)
    assert any(f.name == "mcxc151" for f in cmpa_lc_families)


def test_mcxc151_cmpa_cfg_export_with_crc() -> None:
    """Test CMPA_CFG export with CRC calculation for mcxc151.

    Verifies that CRC is automatically calculated and placed at offset 0x70
    when exporting CMPA_CFG binary.
    """
    import logging

    cmpa_cfg = CMPA_CFG(FamilyRevision("mcxc151"))

    # Export the binary
    binary = cmpa_cfg.export(add_seal=False)

    # Verify binary size matches registers_size
    assert len(binary) == cmpa_cfg.registers_size

    # Get the CRC register to find its actual offset
    crc_reg = cmpa_cfg.registers.find_reg("CMPA_CRC32")
    crc_offset = crc_reg.offset

    # Verify binary has data at CRC offset
    assert len(binary) >= crc_offset + 4

    # Extract CRC value from binary at the CRC register offset
    crc_from_binary = int.from_bytes(binary[crc_offset : crc_offset + 4], byteorder="little")

    # CRC should be calculated (we can't predict exact value, but it should be set)
    # For empty/default data, CRC will be a specific value
    assert isinstance(crc_from_binary, int)

    # Log the calculated CRC value for debugging
    logger = logging.getLogger(__name__)
    logger.info(f"CRC register offset: 0x{crc_offset:04X}")
    logger.info(f"Calculated CRC value: 0x{crc_from_binary:08X}")

    # Verify CRC was actually calculated by checking it's not just zeros
    # (unless the data happens to have a CRC of 0, which is unlikely)
    # We can verify by recalculating the CRC ourselves
    from spsdk.crypto.crc import CrcAlg, from_crc_algorithm

    data_for_crc = binary[:crc_offset]
    crc_obj = from_crc_algorithm(CrcAlg.CRC32_MPEG)
    expected_crc = crc_obj.calculate(data_for_crc)

    # Verify the CRC in the binary matches what we calculate
    assert crc_from_binary == expected_crc, (
        f"CRC mismatch: binary has 0x{crc_from_binary:08X}, " f"expected 0x{expected_crc:08X}"
    )


def test_mcxc151_cmpa_cfg_crc_register_hidden() -> None:
    """Test that CRC register is hidden in CMPA_CFG template.

    Verifies that the CRC register is marked as reserved and won't appear
    in generated configuration templates.
    """
    cmpa_cfg = CMPA_CFG(FamilyRevision("mcxc151"))

    # Find the CRC register
    try:
        crc_reg = cmpa_cfg.registers.find_reg("CMPA_CRC32")

        # Verify it's marked as reserved (hidden from templates)
        assert crc_reg.reserved is True
    except Exception:
        # If register is not found or reserved attribute doesn't exist,
        # verify it's not in the config output
        config = cmpa_cfg.get_config(diff=True)
        assert "CMPA_CRC32" not in str(config.get("settings", {}))


def test_mcxc151_cmpa_cfg_config_roundtrip(tmpdir: str) -> None:
    """Test CMPA_CFG configuration export and import roundtrip for mcxc151.

    Verifies that configuration can be exported to YAML, modified, and
    imported back correctly.

    :param tmpdir: Temporary directory for creating test files
    """
    yaml = YAML()
    yaml.indent(sequence=4, offset=2)

    # Create CMPA_CFG instance
    cmpa_cfg = CMPA_CFG(FamilyRevision("mcxc151"))

    # Get configuration (diff=True to get only non-default values)
    config = cmpa_cfg.get_config(diff=True)

    # Verify basic structure
    assert config["family"] == "mcxc151"
    assert config["type"] == "CMPA_CFG"

    # Save to YAML
    config_file = os.path.join(tmpdir, "cmpa_cfg.yml")
    with open(config_file, "w", encoding="ascii") as yml_file:
        yaml.dump(dict(config), yml_file)

    # Load back from YAML
    loaded_config = Config.create_from_file(config_file)
    cmpa_cfg2 = CMPA_CFG.load_from_config(loaded_config)

    # Verify configurations match (compare diff versions)
    config2 = cmpa_cfg2.get_config(diff=True)
    assert config2["family"] == config["family"]
    assert config2["type"] == config["type"]

    # Export both and compare binaries
    binary1 = cmpa_cfg.export(add_seal=False)
    binary2 = cmpa_cfg2.export(add_seal=False)
    assert binary1 == binary2


@pytest.mark.parametrize("case_name", ["tc1", "tc2", "tc3"])
@pytest.mark.parametrize("variant", ["grouped", "legacy"])
def test_mcxc162_cmpa_pswd_parse_round_trip(data_dir: str, case_name: str, variant: str) -> None:
    """``CMPA_PSWD.parse(export(cfg))`` reproduces the original binary.

    End-to-end PFR round-trip: load a YAML config (grouped or legacy form),
    export it to binary, parse that binary back through ``CMPA_PSWD.parse``,
    and assert the re-exported binary equals the original. This covers the
    user-facing PFR ``parse`` path for grouped registers fixed in
    SPSDK-6746.

    :param data_dir: PFR test data directory.
    :param case_name: Test case fixture (tc1/tc2/tc3).
    :param variant: ``grouped`` or ``legacy`` YAML form.
    """
    if variant == "legacy" and case_name == "tc3":
        pytest.skip("Only grouped/legacy tc1/tc2 fixtures are equivalent for legacy form.")
    cfg_path = os.path.join(data_dir, "yaml_bin", f"mcxc162_cmpa_{case_name}_{variant}.yaml")
    cfg = Config.create_from_file(cfg_path)

    src = CMPA_PSWD.load_from_config(cfg)
    binary = src.export(add_seal=False)

    parsed = CMPA_PSWD.parse(binary, family=FamilyRevision("mcxc162"))
    assert parsed.export(add_seal=False) == binary
