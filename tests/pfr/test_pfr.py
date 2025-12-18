#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
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
from unittest.mock import patch

import pytest
from ruamel.yaml import YAML

from spsdk.crypto.keys import PrivateKeyRsa
from spsdk.crypto.utils import extract_public_keys
from spsdk.exceptions import SPSDKError
from spsdk.pfr.exceptions import SPSDKPfrError
from spsdk.pfr.pfr import (
    CFPA,
    CFPA_CMPA,
    CMPA,
    AdditionalDataCfg,
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

    :raises AssertionError: When supported device families don't match database or CFPA devices are not supported for CMPA.
    """
    cfpa_devices = CFPA.get_supported_families()
    assert isinstance(cfpa_devices, list)
    cfpa_device_names = list(set(family.name for family in cfpa_devices))
    assert (
        cfpa_device_names.sort()
        == list(
            DatabaseManager().quick_info.devices.get_devices_with_feature("pfr", "cfpa").keys()
        ).sort()
    )

    cmpa_devices = CMPA.get_supported_families()
    cfpa_cmpa_devices = CFPA_CMPA.get_supported_families()

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
        cfpa.export(keys=["Invalid"])  # type: ignore


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

    data = cmpa.export(keys=extract_public_keys(keys_path, password=None))

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

    data = cmpa.export(keys=extract_public_keys(keys_path, password=None))

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
        cfpa.export(keys=extract_public_keys(keys_path, password=None))


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


@pytest.mark.parametrize("cpu_name", get_mcxa_families())
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
    data when the additional_data_cfg is configured with enabled=True. It mocks the
    configuration to allow additional data and confirms the setter operates without errors.
    """
    # Use patch as a context manager instead of a fixture
    with patch.object(CMPA, "additional_data_cfg") as mock_cfg:
        # Mock the additional_data_cfg to return a configuration that allows additional data
        mock_cfg.return_value = AdditionalDataCfg(enabled=True, offset=512, max_size=128)

        cmpa = CMPA(FamilyRevision("lpc55s6x"))
        test_data = bytes([0x01, 0x02, 0x03, 0x04])

        # This should succeed
        cmpa.additional_data = test_data
        assert cmpa._additional_data == test_data


def test_additional_data_setter_disabled() -> None:
    """Test that additional_data setter raises error when additional data is disabled.

    This test verifies that attempting to set additional data on a CMPA instance
    raises SPSDKPfrError when the family configuration has additional data disabled.
    The test mocks the additional_data_cfg to return a configuration with enabled=False
    and verifies the appropriate exception is raised with the expected error message.

    :raises SPSDKPfrError: When attempting to set additional data on disabled configuration.
    """
    with patch.object(CMPA, "additional_data_cfg") as mock_cfg:
        # Mock the additional_data_cfg to return a configuration that disables additional data
        mock_cfg.return_value = AdditionalDataCfg(enabled=False, offset=-1, max_size=0)

        cmpa = CMPA(FamilyRevision("lpc55s6x"))
        test_data = bytes([0x01, 0x02, 0x03, 0x04])

        # This should raise an error
        with pytest.raises(SPSDKPfrError, match="Customer data is not allowed for family"):
            cmpa.additional_data = test_data


def test_additional_data_setter_size_exceeded() -> None:
    """Test that additional_data setter raises error when data size exceeds maximum.

    This test verifies that the CMPA additional_data setter properly validates
    the size of input data against the maximum allowed size and raises an
    appropriate SPSDKPfrError when the data exceeds the limit.

    :raises SPSDKPfrError: When additional data size exceeds the configured maximum size.
    """
    with patch.object(CMPA, "additional_data_cfg") as mock_cfg:
        # Mock the additional_data_cfg to return a configuration with small max size
        mock_cfg.return_value = AdditionalDataCfg(enabled=True, offset=512, max_size=2)

        cmpa = CMPA(FamilyRevision("lpc55s6x"))
        test_data = bytes([0x01, 0x02, 0x03, 0x04])  # 4 bytes, exceeds max of 2

        # This should raise an error
        with pytest.raises(SPSDKPfrError, match="Customer data size must be maximum 2 bytes"):
            cmpa.additional_data = test_data


def test_additional_data_cfg() -> None:
    """Test that additional_data_cfg returns correct configuration from database.

    This test verifies that the CMPA.additional_data_cfg method properly retrieves
    and returns the additional data configuration for a given family from the database.
    It checks that the returned object is of the correct type and contains the expected
    attributes.

    :raises AssertionError: If the configuration object is not of expected type or missing required attributes.
    """
    # Test with a family that has additional data configuration in the database
    family = FamilyRevision("lpc55s6x")
    cfg = CMPA.additional_data_cfg(family)

    # Verify the returned configuration matches expected values
    # Note: Actual values will depend on the database content
    assert isinstance(cfg, AdditionalDataCfg)
    assert hasattr(cfg, "enabled")
    assert hasattr(cfg, "offset")
    assert hasattr(cfg, "max_size")


def test_export_with_additional_data() -> None:
    """Test that export correctly includes additional data in the binary output.

    This test verifies that when a CMPA object has additional data configured,
    the export method properly includes that data in the generated binary output.
    The test mocks the additional data configuration and validates both the
    content placement and total binary size calculations.

    :raises AssertionError: If additional data is not properly included in binary output.
    """
    # This test requires mocking or using a family that supports additional data
    with patch.object(CMPA, "additional_data_cfg") as mock_cfg:
        mock_cfg.return_value = AdditionalDataCfg(enabled=True, offset=-1, max_size=16)

        cmpa = CMPA(FamilyRevision("lpc55s6x"))
        test_data = bytes([0xAA, 0xBB, 0xCC, 0xDD])
        cmpa.additional_data = test_data

        # Export the binary
        binary = cmpa.export(add_seal=False)

        # Verify the additional data is included in the binary
        # For offset=-1, additional data should be appended to the end
        assert binary[-len(test_data) :] == test_data

        # Verify total binary size includes additional data
        assert len(binary) == cmpa.registers_size + len(test_data)
        assert cmpa.binary_size == cmpa.registers_size + len(test_data)


def test_parse_with_additional_data() -> None:
    """Test that CMPA parse method correctly extracts additional data from binary.

    This test verifies the round-trip functionality of CMPA additional data handling:
    1. Creates a CMPA instance with mock additional data configuration
    2. Sets test data as additional data
    3. Exports the CMPA to binary format
    4. Parses the binary back to a new CMPA instance
    5. Verifies that the additional data was preserved correctly during the parse operation
    """
    # Create a binary with additional data
    with patch.object(CMPA, "additional_data_cfg") as mock_cfg:
        mock_cfg.return_value = AdditionalDataCfg(enabled=True, offset=-1, max_size=16)

        # Create original CMPA with additional data
        original_cmpa = CMPA(FamilyRevision("lpc55s6x"))
        test_data = bytes([0xAA, 0xBB, 0xCC, 0xDD])
        original_cmpa.additional_data = test_data

        # Export to binary
        binary = original_cmpa.export(add_seal=False)

        # Parse the binary back
        parsed_cmpa = CMPA.parse(binary, FamilyRevision("lpc55s6x"))

        # Verify the additional data was correctly parsed
        assert parsed_cmpa.additional_data == test_data


def test_get_config_with_additional_data() -> None:
    """Test that get_config method includes additional data in the configuration.

    This test verifies that when a CMPA object has additional data set,
    the get_config method properly includes this data in the returned
    configuration dictionary with the correct hexadecimal formatting.

    :raises AssertionError: If additional data is not properly included in config or formatting is incorrect.
    """
    with patch.object(CMPA, "additional_data_cfg") as mock_cfg:
        mock_cfg.return_value = AdditionalDataCfg(enabled=True, offset=-1, max_size=16)

        cmpa = CMPA(FamilyRevision("lpc55s6x"))
        test_data = bytes([0xAA, 0xBB, 0xCC, 0xDD])
        cmpa.additional_data = test_data

        # Get configuration
        config = cmpa.get_config()

        # Verify additional data is included in the configuration
        assert "additional_data" in config
        assert config["additional_data"] == test_data.hex()
