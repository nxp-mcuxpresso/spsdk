#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
from pathlib import Path

import pytest
from click.testing import CliRunner

from spsdk.apps.nxpimage_apps.nxpimage_signed_msg import signed_msg_group
from spsdk.utils.misc import load_binary, load_text


@pytest.fixture(scope="module")
def data_dir():
    """Get data directory for TLV tests."""
    return Path(__file__).parent / "data" / "ahab" / "tlv"


@pytest.fixture(scope="module")
def config_file_aes256(data_dir):
    """Get TLV AES256 configuration file."""
    return data_dir / "tlv_import_aes256.yaml"


@pytest.fixture(scope="module")
def config_file_ecc384(data_dir):
    """Get TLV ECC384 configuration file."""
    return data_dir / "tlv_import_ecc384.yaml"


@pytest.fixture(scope="module")
def binary_file_aes256(data_dir):
    """Get TLV AES256 binary reference file."""
    return data_dir / "tlv_import_aes256.bin"


@pytest.fixture(scope="module")
def binary_file_ecc384(data_dir):
    """Get TLV ECC384 binary reference file."""
    return data_dir / "tlv_import_ecc384.bin"


def test_tlv_get_template(tmp_path):
    """Test nxpimage signed-msg tlv get-template command."""
    runner = CliRunner()

    template_file = tmp_path / "tlv_template.yaml"

    # Test general template generation
    result = runner.invoke(
        signed_msg_group,
        [
            "tlv",
            "get-template",
            "--family",
            "mx95",
            "--output",
            str(template_file),
        ],
    )

    assert result.exit_code == 0, f"Command failed: {result.output}"
    assert template_file.exists(), "Template file was not created"

    # Verify template content
    template_content = load_text(str(template_file))
    assert "family:" in template_content
    assert "command:" in template_content
    assert "KEY_IMPORT:" in template_content

    print(f"General template generated successfully: {template_file}")


def test_tlv_get_template_specific_type(tmp_path):
    """Test nxpimage signed-msg tlv get-template command with specific TLV type."""
    runner = CliRunner()

    template_file = tmp_path / "tlv_key_import_template.yaml"

    # Test specific KEY_IMPORT template generation
    result = runner.invoke(
        signed_msg_group,
        [
            "tlv",
            "get-template",
            "--family",
            "mx93",
            "--tlv-type",
            "KEY_IMPORT",
            "--output",
            str(template_file),
        ],
    )

    assert result.exit_code == 0, f"Command failed: {result.output}"
    assert template_file.exists(), "Template file was not created"

    # Verify template content
    template_content = load_text(str(template_file))
    assert "family:" in template_content
    assert "command:" in template_content
    assert "KEY_IMPORT:" in template_content
    assert "key_id:" in template_content
    assert "permitted_algorithm:" in template_content
    assert "key_usage:" in template_content

    print(f"KEY_IMPORT template generated successfully: {template_file}")


@pytest.mark.parametrize(
    "config_type,config_fixture,binary_fixture",
    [
        ("aes256", "config_file_aes256", "binary_file_aes256"),
        ("ecc384", "config_file_ecc384", "binary_file_ecc384"),
    ],
)
def test_tlv_export(request, config_type, config_fixture, binary_fixture, tmp_path):
    """Test nxpimage signed-msg tlv export command."""
    runner = CliRunner()

    config_file = request.getfixturevalue(config_fixture)
    binary_file = request.getfixturevalue(binary_fixture)

    # Skip test if config file doesn't exist
    if not config_file.exists():
        pytest.skip(f"{config_type.upper()} config file not found: {config_file}")

    output_file = tmp_path / "tlv.bin"

    # Test TLV export with -oc to override config output path
    result = runner.invoke(
        signed_msg_group,
        [
            "tlv",
            "export",
            "--config",
            str(config_file),
            "-oc",
            f"output={output_file}",
        ],
    )

    assert result.exit_code == 0, f"{config_type.upper()} export failed: {result.output}"
    assert output_file.exists(), f"{config_type.upper()} output file not created: {output_file}"
    assert output_file.stat().st_size > 0, f"{config_type.upper()} output file is empty"

    print(f"TLV {config_type.upper()} exported successfully: {output_file}")

    # If reference binary exists, compare binaries exactly
    if binary_file.exists():
        output_data = load_binary(str(output_file))
        reference_data = load_binary(str(binary_file))

        assert output_data == reference_data, (
            f"{config_type.upper()} output binary differs from reference. "
            f"Output size: {len(output_data)}, Reference size: {len(reference_data)}"
        )

        print(f"{config_type.upper()} binary comparison passed: files are identical")


@pytest.mark.parametrize(
    "config_type,binary_fixture",
    [
        ("aes256", "binary_file_aes256"),
        ("ecc384", "binary_file_ecc384"),
    ],
)
def test_tlv_verify(request, config_type, binary_fixture):
    """Test nxpimage signed-msg tlv verify command."""
    runner = CliRunner()

    binary_file = request.getfixturevalue(binary_fixture)

    # Skip test if binary file doesn't exist
    if not binary_file.exists():
        pytest.skip(f"{config_type.upper()} binary file not found: {binary_file}")

    # Test TLV verify
    result = runner.invoke(
        signed_msg_group,
        [
            "tlv",
            "verify",
            "--family",
            "mx93",
            "--binary",
            str(binary_file),
            "--tlv-type",
            "KEY_IMPORT",
        ],
    )

    assert result.exit_code == 0, f"{config_type.upper()} verify failed: {result.output}"
    assert "TLV blob verification passed successfully" in result.output

    print(f"TLV {config_type.upper()} verification passed successfully")


@pytest.mark.parametrize(
    "config_type,binary_fixture",
    [
        ("aes256", "binary_file_aes256"),
        ("ecc384", "binary_file_ecc384"),
    ],
)
def test_tlv_verify_problems_only(request, config_type, binary_fixture):
    """Test nxpimage signed-msg tlv verify command with problems-only flag."""
    runner = CliRunner()

    binary_file = request.getfixturevalue(binary_fixture)

    # Skip test if binary file doesn't exist
    if not binary_file.exists():
        pytest.skip(f"{config_type.upper()} binary file not found: {binary_file}")

    # Test TLV verify with problems flag
    result = runner.invoke(
        signed_msg_group,
        [
            "tlv",
            "verify",
            "--family",
            "mx93",
            "--binary",
            str(binary_file),
            "--tlv-type",
            "KEY_IMPORT",
            "--problems",
        ],
    )

    assert (
        result.exit_code == 0
    ), f"{config_type.upper()} verify with problems flag failed: {result.output}"

    # With --problems flag, detailed TLV info should not be shown
    assert "TLV blob size:" not in result.output
    assert "TLV blob details:" not in result.output

    print(f"TLV {config_type.upper()} verification with problems-only flag passed")


@pytest.mark.parametrize(
    "config_type,binary_fixture",
    [
        ("aes256", "binary_file_aes256"),
        ("ecc384", "binary_file_ecc384"),
    ],
)
def test_tlv_parse(request, config_type, binary_fixture, tmp_path):
    """Test nxpimage signed-msg tlv parse command."""
    runner = CliRunner()

    binary_file = request.getfixturevalue(binary_fixture)

    # Skip test if binary file doesn't exist
    if not binary_file.exists():
        pytest.skip(f"{config_type.upper()} binary file not found: {binary_file}")

    # Test TLV parse
    result = runner.invoke(
        signed_msg_group,
        [
            "tlv",
            "parse",
            "--family",
            "mx93",
            "--binary",
            str(binary_file),
            "--tlv-type",
            "KEY_IMPORT",
            "--output",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, f"{config_type.upper()} parse failed: {result.output}"

    # Check if parsed config file was created
    parsed_config = tmp_path / "parsed_config.yaml"
    assert parsed_config.exists(), f"{config_type.upper()} parsed config file was not created"

    # Verify parsed config content
    config_content = load_text(str(parsed_config))
    assert "family:" in config_content
    assert "command:" in config_content
    assert "KEY_IMPORT:" in config_content

    print(f"TLV {config_type.upper()} parsed successfully: {parsed_config}")


@pytest.mark.parametrize(
    "config_type,config_fixture",
    [
        ("aes256", "config_file_aes256"),
        ("ecc384", "config_file_ecc384"),
    ],
)
def test_tlv_roundtrip(request, config_type, config_fixture, tmp_path):
    """Test TLV export -> parse roundtrip."""
    runner = CliRunner()

    config_file = request.getfixturevalue(config_fixture)

    # Skip test if config file doesn't exist
    if not config_file.exists():
        pytest.skip(f"{config_type.upper()} config file not found: {config_file}")

    # Step 1: Export TLV from config
    exported_tlv = tmp_path / "tlv.bin"

    # Export using -oc to override config output path
    result = runner.invoke(
        signed_msg_group,
        [
            "tlv",
            "export",
            "--config",
            str(config_file),
            "-oc",
            f"output={exported_tlv}",
        ],
    )

    assert result.exit_code == 0, f"{config_type.upper()} export failed: {result.output}"
    assert exported_tlv.exists(), f"{config_type.upper()} exported TLV file not found"

    # Step 2: Parse the exported TLV
    parse_output_dir = tmp_path / "parsed"
    parse_output_dir.mkdir()

    result = runner.invoke(
        signed_msg_group,
        [
            "tlv",
            "parse",
            "--family",
            "mx93",
            "--binary",
            str(exported_tlv),
            "--tlv-type",
            "KEY_IMPORT",
            "--output",
            str(parse_output_dir),
        ],
    )

    assert result.exit_code == 0, f"{config_type.upper()} parse failed: {result.output}"

    # Check parsed config
    parsed_config = parse_output_dir / "parsed_config.yaml"
    assert parsed_config.exists(), f"{config_type.upper()} parsed config not found"

    # Verify parsed config has expected structure
    parsed_content = load_text(str(parsed_config))
    assert "family:" in parsed_content
    assert "KEY_IMPORT:" in parsed_content

    print(f"TLV {config_type.upper()} roundtrip test passed successfully")
