#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test HSE part of nxpimage app."""

import json
import os
from typing import Any

import pytest
import yaml

from spsdk.apps import nxpimage
from spsdk.exceptions import SPSDKError
from spsdk.image.hse.common import HseKeyBits, KeyType
from spsdk.image.hse.key_info import (
    HseAesBlockModeMask,
    HseEccCurveId,
    HseKeyFlags,
    HseSmrFlags,
    KeyInfo,
)
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary, load_configuration
from tests.cli_runner import CliRunner


@pytest.fixture
def key_info_config_data() -> dict:
    """Return a basic key info configuration for testing."""
    return {
        "family": "mcxe31b",
        "keyType": "AES",
        "keyBitLen": 256,
        "keyCounter": 1,
        "keyFlags": ["USAGE_ENCRYPT", "USAGE_DECRYPT", "ACCESS_EXPORTABLE"],
        "smrFlags": [0, 1],
        "specificData": {"aesBlockModeMask": ["BLOCK_MODE_CBC", "BLOCK_MODE_GCM"]},
        "output": "key_info.bin",
    }


@pytest.fixture
def key_info_config_file(tmpdir: str, key_info_config_data: dict) -> str:
    """Create a key info configuration file for testing."""
    config_file = os.path.join(tmpdir, "key_info_config.yaml")
    with open(config_file, "w") as f:
        yaml.dump(key_info_config_data, f)
    return config_file


def test_hse_key_info_get_template_command(cli_runner: CliRunner, tmpdir: str) -> None:
    """Test the 'hse key-info get-template' command."""
    output_file = os.path.join(tmpdir, "key_info_template.yaml")
    cmd = f"hse key-info get-template -f mcxe31b -o {output_file}"

    result = cli_runner.invoke(nxpimage.main, cmd.split())

    # Check command executed successfully
    assert result.exit_code == 0
    assert f"The template file {output_file} has been created" in result.output

    # Check template file exists and is valid YAML
    assert os.path.isfile(output_file)
    with open(output_file, "r") as f:
        template_data = yaml.safe_load(f)

    # Check basic template structure
    assert "family" in template_data
    assert template_data["family"] == "mcxe31b"
    assert "keyType" in template_data
    assert "keyBitLen" in template_data


def test_hse_key_info_get_template_command_unsupported_family(
    cli_runner: CliRunner, tmpdir: str
) -> None:
    """Test the 'hse key-info get-template' command with an unsupported family."""
    output_file = os.path.join(tmpdir, "key_info_template.yaml")
    cmd = f"hse key-info get-template -f unsupported_family -o {output_file}"

    # Command should fail with an error about unsupported family
    result = cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=2)
    assert "Invalid value for '-f'" in result.output


def test_hse_key_info_export_command(cli_runner: CliRunner, key_info_config_file: str) -> None:
    """Test the 'hse key-info export' command."""
    cmd = f"hse key-info export -c {key_info_config_file}"

    result = cli_runner.invoke(nxpimage.main, cmd.split())

    # Check command executed successfully
    assert result.exit_code == 0
    assert "Success. (Key Info:" in result.output

    # Load the config to get the output file path
    with open(key_info_config_file, "r") as f:
        config_data = yaml.safe_load(f)
    output_file = os.path.join(os.path.dirname(key_info_config_file), config_data["output"])

    # Check output file exists
    assert os.path.isfile(output_file)

    # Verify the binary content by parsing it back
    binary_data = load_binary(output_file)
    key_info = KeyInfo.parse(binary_data, FamilyRevision("mcxe31b"))

    # Check key info properties match the config
    assert key_info.key_type == KeyType.AES
    assert key_info.key_bit_len == HseKeyBits.KEY256_BITS
    assert key_info.key_counter == 1
    assert key_info.key_flags & HseKeyFlags.USAGE_ENCRYPT
    assert key_info.key_flags & HseKeyFlags.USAGE_DECRYPT
    assert key_info.key_flags & HseKeyFlags.ACCESS_EXPORTABLE
    assert key_info.smr_flags & HseSmrFlags.SMR_0
    assert key_info.smr_flags & HseSmrFlags.SMR_1

    # Check specific data
    assert "aesBlockModeMask" in key_info.specific_data
    block_mode_mask = key_info.specific_data["aesBlockModeMask"]
    assert block_mode_mask & HseAesBlockModeMask.BLOCK_MODE_CBC
    assert block_mode_mask & HseAesBlockModeMask.BLOCK_MODE_GCM


def test_hse_key_info_export_command_invalid_config(cli_runner: CliRunner, tmpdir: str) -> None:
    """Test the 'hse key-info export' command with an invalid configuration."""
    # Create an invalid config file (missing required fields)
    invalid_config = {
        "family": "mcxe31b",
        # Missing keyType and keyBitLen
        "output": "key_info.bin",
    }
    invalid_config_file = os.path.join(tmpdir, "invalid_config.yaml")
    with open(invalid_config_file, "w") as f:
        yaml.dump(invalid_config, f)

    cmd = f"hse key-info export -c {invalid_config_file}"

    # Command should fail with validation error
    result = cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=1)
    assert result.exc_info is not None
    assert isinstance(result.exc_info[1], SPSDKError)
    assert result.exc_info[1].description is not None
    assert "Configuration validation failed" in result.exc_info[1].description


def test_hse_key_info_export_different_key_types(cli_runner: CliRunner, tmpdir: str) -> None:
    """Test exporting key info for different key types."""
    # Test cases for different key types
    key_types: list[dict[str, Any]] = [
        {
            "keyType": "AES",
            "keyBitLen": 256,
            "specificData": {"aesBlockModeMask": ["BLOCK_MODE_CBC", "BLOCK_MODE_GCM"]},
        },
        {
            "keyType": "ECC_PAIR",
            "keyBitLen": 256,
            "specificData": {"eccCurveId": "SEC_SECP256R1"},
        },
        {
            "keyType": "RSA_PAIR",
            "keyBitLen": 2048,
            "specificData": {"pubExponentSize": 3},
        },
        {"keyType": "HMAC", "keyBitLen": 256},
    ]

    for i, key_type_data in enumerate(key_types):
        # Create config with this key type
        config_data: dict[str, Any] = {
            "family": "mcxe31b",
            "keyFlags": ["USAGE_ENCRYPT", "USAGE_DECRYPT"],
            "smrFlags": [0],
            "output": f"key_info_{i}.bin",
            **key_type_data,
        }

        config_file = os.path.join(tmpdir, f"key_info_config_{i}.yaml")
        with open(config_file, "w") as f:
            yaml.dump(config_data, f)

        cmd = f"hse key-info export -c {config_file}"
        result = cli_runner.invoke(nxpimage.main, cmd.split())

        # Check command executed successfully
        assert result.exit_code == 0
        assert "Success. (Key Info:" in result.output

        # Check output file exists
        assert isinstance(config_data["output"], str)
        output_file = os.path.join(tmpdir, config_data["output"])
        assert os.path.isfile(output_file)


def test_hse_key_info_export_with_json_config(
    cli_runner: CliRunner, tmpdir: str, key_info_config_data: dict
) -> None:
    """Test exporting key info using a JSON configuration file."""
    # Create JSON config file
    json_config_file = os.path.join(tmpdir, "key_info_config.json")
    with open(json_config_file, "w") as f:
        json.dump(key_info_config_data, f)

    cmd = f"hse key-info export -c {json_config_file}"
    result = cli_runner.invoke(nxpimage.main, cmd.split())

    # Check command executed successfully
    assert result.exit_code == 0
    assert "Success. (Key Info:" in result.output

    # Check output file exists
    output_file = os.path.join(tmpdir, key_info_config_data["output"])
    assert os.path.isfile(output_file)


def test_hse_key_info_export_idempotent(cli_runner: CliRunner, key_info_config_file: str) -> None:
    """Test that exporting key info is idempotent (same input produces same output)."""
    cmd = f"hse key-info export -c {key_info_config_file}"

    # Run the command twice
    cli_runner.invoke(nxpimage.main, cmd.split())

    # Get the output file path
    with open(key_info_config_file, "r") as f:
        config_data = yaml.safe_load(f)
    output_file = os.path.join(os.path.dirname(key_info_config_file), config_data["output"])

    # Save the first output
    first_output = load_binary(output_file)

    # Run the command again
    cli_runner.invoke(nxpimage.main, cmd.split())

    # Load the second output
    second_output = load_binary(output_file)

    # Verify both outputs are identical
    assert first_output == second_output


def test_hse_key_info_export_with_counter(cli_runner: CliRunner, tmpdir: str) -> None:
    """Test exporting key info with different counter values."""
    counter_values = [0, 1, 100, 0xFFFFFFFF - 1]  # MAX_KEY_COUNTER_VALUE

    for i, counter in enumerate(counter_values):
        # Create config with this counter value
        config_data = {
            "family": "mcxe31b",
            "keyType": "AES",
            "keyBitLen": 256,
            "keyCounter": counter,
            "keyFlags": ["USAGE_ENCRYPT"],
            "output": f"key_info_counter_{i}.bin",
        }

        config_file = os.path.join(tmpdir, f"key_info_counter_{i}.yaml")
        with open(config_file, "w") as f:
            yaml.dump(config_data, f)

        cmd = f"hse key-info export -c {config_file}"
        result = cli_runner.invoke(nxpimage.main, cmd.split())

        # Check command executed successfully
        assert result.exit_code == 0

        # Parse the output and verify counter
        assert isinstance(config_data["output"], str)
        output_file = os.path.join(tmpdir, config_data["output"])
        key_info = KeyInfo.parse(load_binary(output_file), FamilyRevision("mcxe31b"))
        assert key_info.key_counter == counter


def test_hse_key_info_export_with_ecc_curves(cli_runner: CliRunner, tmpdir: str) -> None:
    """Test exporting key info with different ECC curves."""
    # Test with different ECC curves
    ecc_curves = ["SEC_SECP256R1", "SEC_SECP384R1", "BRAINPOOL_P256R1", "ED25519"]

    for i, curve in enumerate(ecc_curves):
        # Create config with this ECC curve
        config_data = {
            "family": "mcxe31b",
            "keyType": "ECC_PAIR",
            "keyBitLen": 256,
            "keyFlags": ["USAGE_SIGN", "USAGE_VERIFY"],
            "specificData": {"eccCurveId": curve},
            "output": f"key_info_ecc_{i}.bin",
        }

        config_file = os.path.join(tmpdir, f"key_info_ecc_{i}.yaml")
        with open(config_file, "w") as f:
            yaml.dump(config_data, f)

        cmd = f"hse key-info export -c {config_file}"
        result = cli_runner.invoke(nxpimage.main, cmd.split())

        # Check command executed successfully
        assert result.exit_code == 0

        # Parse the output and verify ECC curve
        assert isinstance(config_data["output"], str)
        output_file = os.path.join(tmpdir, config_data["output"])
        key_info = KeyInfo.parse(load_binary(output_file), FamilyRevision("mcxe31b"))
        assert key_info.specific_data["eccCurveId"] == getattr(HseEccCurveId, curve).value


def test_hse_key_info_export_with_aes_block_modes(cli_runner: CliRunner, tmpdir: str) -> None:
    """Test exporting key info with different AES block modes."""
    # Test with different combinations of AES block modes
    block_mode_combinations = [
        ["BLOCK_MODE_CBC"],
        ["BLOCK_MODE_GCM"],
        ["BLOCK_MODE_CBC", "BLOCK_MODE_GCM"],
        ["BLOCK_MODE_XTS", "BLOCK_MODE_CTR", "BLOCK_MODE_CBC", "BLOCK_MODE_ECB"],
    ]

    for i, block_modes in enumerate(block_mode_combinations):
        # Create config with these block modes
        config_data = {
            "family": "mcxe31b",
            "keyType": "AES",
            "keyBitLen": 256,
            "keyFlags": ["USAGE_ENCRYPT", "USAGE_DECRYPT"],
            "specificData": {"aesBlockModeMask": block_modes},
            "output": f"key_info_aes_{i}.bin",
        }

        config_file = os.path.join(tmpdir, f"key_info_aes_{i}.yaml")
        with open(config_file, "w") as f:
            yaml.dump(config_data, f)

        cmd = f"hse key-info export -c {config_file}"
        result = cli_runner.invoke(nxpimage.main, cmd.split())

        # Check command executed successfully
        assert result.exit_code == 0

        # Parse the output and verify block modes
        assert isinstance(config_data["output"], str)
        output_file = os.path.join(tmpdir, config_data["output"])
        key_info = KeyInfo.parse(load_binary(output_file), FamilyRevision("mcxe31b"))

        block_mode_mask = key_info.specific_data["aesBlockModeMask"]
        for mode in block_modes:
            assert block_mode_mask & getattr(HseAesBlockModeMask, mode)


def test_hse_key_info_roundtrip(
    tmpdir: str, cli_runner: CliRunner, key_info_config_file: str
) -> None:
    """Test round-trip: export key info, parse it, and verify it matches the original config."""
    # Export key info
    export_cmd = f"hse key-info export -c {key_info_config_file}"
    cli_runner.invoke(nxpimage.main, export_cmd.split())

    # Get the output file path
    with open(key_info_config_file, "r") as f:
        config_data = yaml.safe_load(f)
    output_file = os.path.join(os.path.dirname(key_info_config_file), config_data["output"])

    parsed_config = os.path.join(tmpdir, "parsed_config.yaml")
    export_cmd = f"hse key-info parse -f mcxe31b -b {output_file} -o {parsed_config}"
    cli_runner.invoke(nxpimage.main, export_cmd.split())
    roundtrip_config = load_configuration(parsed_config)

    # Verify key properties match
    assert roundtrip_config["keyType"] == config_data["keyType"]
    assert roundtrip_config["keyBitLen"] == config_data["keyBitLen"]
    assert roundtrip_config["keyCounter"] == config_data["keyCounter"]

    # Verify flags match (order might be different)
    assert set(roundtrip_config["keyFlags"]) == set(config_data["keyFlags"])
    assert set(roundtrip_config["smrFlags"]) == set(config_data["smrFlags"])

    # Verify specific data matches
    if "specificData" in config_data:
        if "aesBlockModeMask" in config_data["specificData"]:
            assert set(roundtrip_config["specificData"]["aesBlockModeMask"]) == set(
                config_data["specificData"]["aesBlockModeMask"]
            )
