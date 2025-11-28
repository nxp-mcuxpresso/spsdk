#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for SecureBinary 3.1 functionality in nxpimage application.

This module contains comprehensive tests for the SecureBinary 3.1 (SB3.1) format
handling within the nxpimage tool, covering image creation, parsing, encryption,
and key management scenarios.
"""

import json
import os
from typing import Any

import jsonschema
import pytest

from spsdk.apps import nxpimage
from spsdk.crypto.exceptions import SPSDKKeysNotMatchingError
from spsdk.crypto.keys import PrivateKeyEcc
from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb31.images import SecureBinary31, SecureBinary31Header
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary, load_configuration, use_working_directory
from tests.cli_runner import CliRunner
from tools.convert_cfg import DatabaseManager


def process_config_file(config_path: str, destination: str) -> tuple[str, str, str]:
    """Process configuration file and prepare it for destination directory.

    Loads the configuration file, normalizes path separators to forward slashes,
    extracts the container output file path, and creates a new configuration file
    in the destination directory with updated paths.

    :param config_path: Path to the source configuration file.
    :param destination: Destination directory where new config will be created.
    :raises ValueError: When containerOutputFile is not found in configuration.
    :return: Tuple containing reference binary path, new binary path, and new config path.
    """
    config_data = load_configuration(config_path)
    for key in config_data:
        if isinstance(config_data[key], str):
            config_data[key] = config_data[key].replace("\\", "/")
    ref_binary = config_data.get("containerOutputFile")
    if ref_binary is None:
        raise ValueError("containerOutputFile not found in config")
    new_binary = f"{destination}/{os.path.basename(ref_binary)}"
    new_config = f"{destination}/{os.path.basename(config_path)}"
    config_data["containerOutputFile"] = new_binary
    with open(new_config, "w") as f:
        json.dump(config_data, f, indent=2)
    return ref_binary, new_binary, new_config


def get_signing_key(config: Config) -> PrivateKeyEcc:
    """Get signing key from configuration.

    Extracts and loads the private key for signing operations from the provided
    configuration. First attempts to get the key file using the "signer" input
    file configuration, and if that fails, falls back to parsing the signer
    string directly to extract the file path.

    :param config: Configuration object containing signer information.
    :raises SPSDKError: When the private key file cannot be loaded or parsed.
    :return: Loaded ECC private key for signing operations.
    """
    try:
        private_key_file = config.get_input_file_name("signer")
    except SPSDKError:
        # let's assume plain file signature provider
        private_key_file = config.get_str("signer").split("=")[2]
    return PrivateKeyEcc.load(private_key_file)


@pytest.mark.parametrize(
    "config_file,device",
    [
        ("sb3_256_256.yaml", "lpc55s3x"),
        ("sb3_256_none.yaml", "lpc55s3x"),
        ("sb3_256_none_ernad.yaml", "lpc55s3x"),
        ("sb3_384_256.yaml", "lpc55s3x"),
        ("sb3_384_256_fixed_timestamp.yaml", "lpc55s3x"),
        ("sb3_384_256_unencrypted.yaml", "lpc55s3x"),
        ("sb3_384_384.yaml", "lpc55s3x"),
        ("sb3_384_none.yaml", "lpc55s3x"),
        ("sb3_test_384_384_unencrypted.yaml", "lpc55s3x"),
        ("sb3_256_256.yaml", "mcxn9xx"),
        ("sb3_256_none.yaml", "mcxn9xx"),
        ("sb3_384_256.yaml", "mcxn9xx"),
        ("sb3_384_256_fixed_timestamp.yaml", "mcxn9xx"),
        ("sb3_384_256_unencrypted.yaml", "mcxn9xx"),
        ("sb3_384_384.yaml", "mcxn9xx"),
        ("sb3_384_none.yaml", "mcxn9xx"),
        ("sb3_384_none_keyblob.yaml", "mcxn9xx"),
        ("sb3_test_384_384_unencrypted.yaml", "mcxn9xx"),
        ("sb3_test_384_384_unencrypted.yaml", "kw45xx"),
        ("sb3_384_384.yaml", "kw45xx"),
        ("sb3_384_none.yaml", "kw45xx"),
        ("sb3_test_384_384_unencrypted.yaml", "k32w1xx"),
        ("sb3_384_384.yaml", "k32w1xx"),
        ("sb3_384_none.yaml", "k32w1xx"),
    ],
)
def test_nxpimage_sb31(
    cli_runner: CliRunner, nxpimage_data_dir: str, tmpdir: str, config_file: str, device: str
) -> None:
    """Test SB31 secure binary generation and validation.

    This test validates the complete SB31 secure binary creation process including:
    - Exporting SB31 binary from configuration file using CLI
    - Loading and validating the secure binary structure
    - Comparing header and data block sections between reference and generated binaries
    - Verifying cryptographic signatures using the signing key

    :param cli_runner: CLI test runner for invoking nxpimage commands
    :param nxpimage_data_dir: Directory containing test data and configuration files
    :param tmpdir: Temporary directory for output files
    :param config_file: Name of the SB31 configuration file to test
    :param device: Target device name for configuration selection
    """
    with use_working_directory(nxpimage_data_dir):
        config_file = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)
        cmd = f"sb31 export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)

        sb31 = SecureBinary31.load_from_config(config=Config.create_from_file(config_file))

        assert sb31.sb_header.cert_block

        # Validate data part
        signature_offset = (
            SecureBinary31Header.HEADER_SIZE
            + len(sb31.sb_commands.final_hash)
            + sb31.sb_header.cert_block.expected_size
        )
        header_part_size = signature_offset
        signature_length = 0
        if sb31.signature_provider is not None:
            signature_length = sb31.signature_provider.signature_length
        data_blocks_offset = (
            SecureBinary31Header.HEADER_SIZE
            + len(sb31.sb_commands.final_hash)
            + sb31.sb_header.cert_block.expected_size
            + signature_length
        )
        if sb31.sb_header.cert_block.isk_certificate:
            header_part_size -= len(sb31.sb_header.cert_block.isk_certificate.signature)

        ref_data = load_binary(ref_binary)
        new_data = load_binary(new_binary)
        assert ref_data[:header_part_size], new_data[:header_part_size]
        assert ref_data[data_blocks_offset:], new_data[data_blocks_offset:]
        signing_key = get_signing_key(Config.create_from_file(config_file))

        # Validate signature
        assert signing_key.get_public_key().verify_signature(
            new_data[signature_offset:data_blocks_offset],
            new_data[:signature_offset],
        )
        assert signing_key.get_public_key().verify_signature(
            ref_data[signature_offset:data_blocks_offset],
            ref_data[:signature_offset],
        )

        # ISK signature won't be checked - is already checked in MBI tests


def test_nxpimage_sb31_notime(cli_runner: CliRunner, nxpimage_data_dir: str, tmpdir: str) -> None:
    """Test SB31 export command without timestamp validation.

    This test verifies that the nxpimage SB31 export functionality works correctly
    by comparing generated binary files while accounting for timestamp differences.
    The test uses a specific configuration file for LPC55S3X device and validates
    that the generated binary matches the reference binary in all sections except
    the timestamp portion.

    :param cli_runner: Click CLI test runner for invoking commands
    :param nxpimage_data_dir: Directory path containing test data files
    :param tmpdir: Temporary directory path for output files
    """
    config_file = "sb3_256_256.yaml"
    device = "lpc55s3x"
    with use_working_directory(nxpimage_data_dir):
        config_file = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)
        cmd = f"sb31 export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)

        # Since there's a new timestamp, compare only portions of files
        with open(ref_binary, "rb") as f:
            ref_data = f.read()
        with open(new_binary, "rb") as f:
            new_data = f.read()

        assert len(ref_data) == len(new_data)
        assert ref_data[:20] == new_data[:20]
        assert ref_data[0x1C:0x3C] == new_data[0x1C:0x3C]


def test_nxpimage_sb31_kaypair_not_matching(nxpimage_data_dir: str) -> None:
    """Test SB3.1 export with non-matching key pair configuration.

    This test verifies that the SecureBinary31.export() method properly raises
    an SPSDKKeysNotMatchingError when the configuration contains keys that don't
    match each other.

    :param nxpimage_data_dir: Path to the test data directory containing configuration files.
    :raises SPSDKKeysNotMatchingError: Expected exception when keys don't match.
    """
    with use_working_directory(nxpimage_data_dir):
        config_file = (
            f"{nxpimage_data_dir}/workspace/cfgs/lpc55s3x/sb3_256_256_keys_dont_match.yaml"
        )
        sb31 = SecureBinary31.load_from_config(config=Config.create_from_file(config_file))
        with pytest.raises(SPSDKKeysNotMatchingError):
            sb31.export()


@pytest.mark.parametrize(
    "config_file,device",
    [
        ("sb3_256_256.yaml", "lpc55s3x"),
        ("sb3_256_none.yaml", "lpc55s3x"),
        ("sb3_256_none_ernad.yaml", "lpc55s3x"),
        ("sb3_384_256.yaml", "lpc55s3x"),
        ("sb3_384_256_fixed_timestamp.yaml", "lpc55s3x"),
        ("sb3_384_256_unencrypted.yaml", "lpc55s3x"),
        ("sb3_384_384.yaml", "lpc55s3x"),
        ("sb3_384_none.yaml", "lpc55s3x"),
        ("sb3_test_384_384_unencrypted.yaml", "lpc55s3x"),
        ("sb3_256_256.yaml", "mcxn9xx"),
        ("sb3_256_none.yaml", "mcxn9xx"),
        ("sb3_384_256.yaml", "mcxn9xx"),
        ("sb3_384_256_fixed_timestamp.yaml", "mcxn9xx"),
        ("sb3_384_256_unencrypted.yaml", "mcxn9xx"),
        ("sb3_384_384.yaml", "mcxn9xx"),
        ("sb3_384_none.yaml", "mcxn9xx"),
        ("sb3_384_none_keyblob.yaml", "mcxn9xx"),
        ("sb3_test_384_384_unencrypted.yaml", "mcxn9xx"),
        ("sb3_test_384_384_unencrypted.yaml", "kw45xx"),
        ("sb3_384_384.yaml", "kw45xx"),
        ("sb3_384_none.yaml", "kw45xx"),
        ("sb3_test_384_384_unencrypted.yaml", "k32w1xx"),
        ("sb3_384_384.yaml", "k32w1xx"),
        ("sb3_384_none.yaml", "k32w1xx"),
    ],
)
def test_nxpimage_sb31_parse(
    cli_runner: CliRunner, nxpimage_data_dir: str, tmpdir: str, config_file: str, device: str
) -> None:
    """Test parsing of SB31 files using nxpimage CLI.

    This test verifies that SB31 files can be correctly parsed by:
    1. Loading the original configuration file
    2. Running the sb31 parse command with appropriate parameters
    3. Comparing the parsed configuration with the original to ensure accuracy
    The test handles both encrypted and non-encrypted SB31 files.

    :param cli_runner: Click CLI runner for executing nxpimage commands
    :param nxpimage_data_dir: Directory containing test data files
    :param tmpdir: Temporary directory for output files
    :param config_file: Name of the configuration file to test
    :param device: Target device name for the test
    """
    with use_working_directory(nxpimage_data_dir):
        # Load original config
        config_path = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{config_file}"
        orig_config = Config.create_from_file(config_path)
        family = FamilyRevision.load_from_config(orig_config)

        # Get the SB31 file path from the original config
        sb31_file = orig_config.get("containerOutputFile").replace("\\", "/")

        # Get PCK info and kdk_access_rights from config
        pck_info = orig_config.get("containerKeyBlobEncryptionKey")
        kdk_access_rights = orig_config.get("kdkAccessRights", 0)

        # Create output config path for parsed result
        parsed_config_dir = f"{tmpdir}/parsed_{os.path.basename(config_file)}"
        parsed_config = f"{parsed_config_dir}/sb31_{family.name}_config.yaml"
        # Run parse command
        cmd = f"sb31 parse -f {family.name} -b {sb31_file} -o {parsed_config_dir}"
        if bool(pck_info) and orig_config.get_bool("isEncrypted", True):
            cmd += f" -k {pck_info} -a {kdk_access_rights}"

        result = cli_runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0, f"Parse command failed: {result.output}"
        assert os.path.isfile(parsed_config), "Parsed config file was not created"

        # Load parsed config
        parsed_config_obj = Config.create_from_file(parsed_config)

        # Compare important values between original and parsed configs
        # Check commands (number and types should match)
        orig_cmds = orig_config.get("commands", [])
        parsed_cmds = parsed_config_obj.get("commands", [])

        # Check number of commands
        assert len(parsed_cmds) == len(orig_cmds), "Number of commands doesn't match"

        # Check each command has the same name in the same order
        for i, (parsed_cmd, orig_cmd) in enumerate(zip(parsed_cmds, orig_cmds)):
            # For dictionaries, check the 'type' key which typically identifies the command
            if isinstance(parsed_cmd, dict) and isinstance(orig_cmd, dict):
                assert parsed_cmd.get("type") == orig_cmd.get("type"), f"Command {i} type mismatch"
            # For other formats, compare the objects directly
            else:
                assert parsed_cmd.keys() == orig_cmd.keys(), f"Command {i} doesn't match"
                key = parsed_cmd.keys()[0]
                for k, v in parsed_cmd[key].items():
                    assert orig_cmd["key"][k] == v, f"Command {i} details don't match"

        # Check container version
        assert parsed_config_obj.get("containerVersion") == orig_config.get(
            "containerVersion"
        ), "Container version doesn't match"


@pytest.mark.parametrize(
    "config, passed",
    [
        ({"isEncrypted": True}, False),
        ({}, False),
        ({"isEncrypted": False}, True),
        ({"isEncrypted": True, "containerKeyBlobEncryptionKey": "path/to/key.txt"}, True),
        ({"containerKeyBlobEncryptionKey": "path/to/key.txt"}, True),
        ({"isEncrypted": False, "containerKeyBlobEncryptionKey": "path/to/key.txt"}, True),
    ],
)
def test_isEncrypted_requires_containerKeyBlobEncryptionKey(
    config: dict[str, Any], passed: bool
) -> None:
    """Test that when isEncrypted is true, containerKeyBlobEncryptionKey is required.

    This test validates the SB31 schema enforcement of the dependency between
    the isEncrypted flag and the containerKeyBlobEncryptionKey property.
    When isEncrypted is set to true, the schema should require the presence
    of containerKeyBlobEncryptionKey.

    :param config: Configuration dictionary to validate against SB31 schema.
    :param passed: Flag indicating whether validation should pass or fail.
    :raises ValidationError: When schema validation fails (expected for negative test cases).
    """
    sb31_schema = DatabaseManager.get_db().get_schema_file("sb31")["sb3"]
    if passed:
        # Should pass validation
        jsonschema.validate(instance=config, schema=sb31_schema)
    else:
        # Should fail validation with expected error
        with pytest.raises(jsonschema.exceptions.ValidationError) as excinfo:
            jsonschema.validate(instance=config, schema=sb31_schema)
        assert "containerKeyBlobEncryptionKey" in str(excinfo.value)
        assert "required property" in str(excinfo.value)
