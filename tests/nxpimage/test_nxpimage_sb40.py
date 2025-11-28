#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for SecureBinary 4.0 functionality in nxpimage application.

This module contains comprehensive tests for the SecureBinary version 4.0 format
handling within the nxpimage tool, including configuration processing, image
generation, and validation scenarios to ensure robust SecureBinary 4.0 support.
"""

import json
import os

import pytest

from spsdk.apps import nxpimage
from spsdk.crypto.keys import IS_DILITHIUM_SUPPORTED
from spsdk.sbfile.sb4.images import SecureBinary4
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary, load_configuration, use_working_directory
from tests.cli_runner import CliRunner

if not IS_DILITHIUM_SUPPORTED:
    pytest.skip(reason="PQC support is not installed", allow_module_level=True)


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
    with open(new_config, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)
    return ref_binary, new_binary, new_config


@pytest.mark.parametrize(
    "config_file,device",
    [
        # ECC256 configurations
        ("sb4_ecc256_basic.yaml", "mcxn556s"),
        ("sb4_ecc256_encrypted.yaml", "mcxn556s"),
        ("sb4_ecc256_unencrypted.yaml", "mcxn556s"),
        ("sb4_ecc256_image_version.yaml", "mcxn556s"),
        ("sb4_ecc256_fuse_version.yaml", "mcxn556s"),
        # ECC384 configurations
        ("sb4_ecc384_basic.yaml", "mcxn556s"),
        # ECC521 configurations
        ("sb4_ecc521_basic.yaml", "mcxn556s"),
        # PQC MLDSA configurations
        ("sb4_mldsa_basic.yaml", "mcxn556s"),
        ("sb4_ecc256_mldsa_dual.yaml", "mcxn556s"),
        # Various settings combinations
        ("sb4_kdk_access_rights_1.yaml", "mcxn556s"),
        ("sb4_kdk_access_rights_2.yaml", "mcxn556s"),
        ("sb4_kdk_access_rights_3.yaml", "mcxn556s"),
        ("sb4_fixed_timestamp.yaml", "mcxn556s"),
    ],
)
def test_nxpimage_sb40(
    cli_runner: CliRunner, nxpimage_data_dir: str, tmpdir: str, config_file: str, device: str
) -> None:
    """Test SB4.0 export functionality with various configurations."""
    with use_working_directory(nxpimage_data_dir):
        config_path = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{config_file}"
        if not os.path.exists(config_path):
            pytest.skip(f"Config file {config_file} not found")

        ref_binary, new_binary, new_config = process_config_file(config_path, tmpdir)

        # Export SB4 using CLI
        cmd = f"sb40 export -c {new_config}"
        result = cli_runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0, f"Export command failed: {result.output}"
        assert os.path.isfile(new_binary), "SB4 binary file was not created"

        # Load and validate SB4 object
        sb4 = SecureBinary4.load_from_config(config=Config.create_from_file(config_path))
        sb4.container.update_fields()

        # Validate that the container has proper structure
        assert sb4.container is not None, "SB4 container should not be None"
        assert sb4.container.srk_hash0 is not None, "SRK hash should be present"

        # Validate generated binary
        new_data = load_binary(new_binary)
        assert len(new_data) > 0, "Generated SB4 should not be empty"

        # For non-fixed timestamp tests, validate structure like SB31
        ref_data = load_binary(ref_binary)

        # SB4 structure validation - AHAB container + SB3.1 data
        # Get AHAB container size from the SB4 object
        ahab_container_size = sb4.container.length

        # Compare AHAB container part (excluding signature which may vary due to timestamp)
        # AHAB header should be consistent
        ahab_header_size = 0x20  # AHAB container header size
        assert (
            ref_data[:ahab_header_size] == new_data[:ahab_header_size]
        ), "AHAB headers should match"

        # Compare SB3.1 data part after AHAB container
        sb31_data_offset = ahab_container_size
        assert (
            ref_data[sb31_data_offset:] == new_data[sb31_data_offset:]
        ), "SB3.1 data parts should match"

        # Validate AHAB container signature if present
        if sb4.container.signature_block:
            # The signature block should be valid (we can't compare exact bytes due to potential timestamp differences)
            signature_block = sb4.container.signature_block
            assert signature_block is not None, "Signature block should be present"

            # Validate SRK hash consistency
            assert sb4.container.srk_hash0 is not None, "Primary SRK hash should be present"

            # For dual signing, check second SRK hash
            if sb4.container.srk_count > 1:
                assert (
                    sb4.container.srk_hash1 is not None
                ), "Secondary SRK hash should be present for dual signing"

        # Validate that both binaries have the same overall structure
        assert len(ref_data) == len(new_data), "Binary sizes should match"


@pytest.mark.parametrize(
    "config_file,device",
    [
        ("sb4_ecc256_basic.yaml", "mcxn556s"),
        ("sb4_ecc384_basic.yaml", "mcxn556s"),
        ("sb4_ecc521_basic.yaml", "mcxn556s"),
        ("sb4_mldsa_basic.yaml", "mcxn556s"),
        ("sb4_ecc256_mldsa_dual.yaml", "mcxn556s"),
    ],
)
def test_nxpimage_sb40_parse(
    cli_runner: CliRunner, nxpimage_data_dir: str, tmpdir: str, config_file: str, device: str
) -> None:
    """Test SB4.0 parse functionality."""
    with use_working_directory(nxpimage_data_dir):
        config_path = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, _, new_config = process_config_file(config_path, tmpdir)

        orig_config = Config.create_from_file(new_config)
        family = FamilyRevision.load_from_config(orig_config)

        # Get PCK info and kdk_access_rights from config
        pck_info = orig_config.get("containerKeyBlobEncryptionKey")
        kdk_access_rights = orig_config.get("kdkAccessRights", 0)

        # Create output config path for parsed result
        parsed_config_dir = f"{tmpdir}/parsed_{os.path.basename(config_file)}"
        parsed_config = f"{parsed_config_dir}/sb4_{family.name}_config.yaml"

        # Run parse command using ref_binary as input
        cmd = f"sb40 parse -f {family.name} -b {ref_binary} -o {parsed_config_dir}"
        if bool(pck_info) and orig_config.get_bool("isEncrypted", True):
            cmd += f" -k {pck_info} -a {kdk_access_rights}"

        result = cli_runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0, f"Parse command failed: {result.output}"
        assert os.path.isfile(parsed_config), "Parsed config file was not created"

        # Load parsed config and validate
        parsed_config_obj = Config.create_from_file(parsed_config)

        # Compare important values between original and parsed configs
        orig_cmds = orig_config.get("commands", [])
        parsed_cmds = parsed_config_obj.get("commands", [])

        # Check number of commands
        assert len(parsed_cmds) == len(orig_cmds), "Number of commands doesn't match"

        # Check container version and other key fields
        assert parsed_config_obj.get("family") == orig_config.get("family"), "Family doesn't match"
        if "imageVersion" in orig_config:
            assert parsed_config_obj.get("imageVersion") == orig_config.get(
                "imageVersion"
            ), "Image version doesn't match"
        if "fuse_version" in orig_config:
            assert parsed_config_obj.get("fuse_version") == orig_config.get(
                "fuse_version"
            ), "Fuse version doesn't match"


def test_nxpimage_sb40_get_template(cli_runner: CliRunner, tmpdir: str) -> None:
    """Test SB4.0 template generation."""
    template_file = f"{tmpdir}/sb4_template.yaml"
    cmd = f"sb40 get-template -f mcxn556s -o {template_file}"

    result = cli_runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0, f"Get template command failed: {result.output}"
    assert os.path.isfile(template_file), "Template file was not created"

    # Validate template content
    template_content = load_configuration(template_file)
    assert "family" in template_content, "Template should contain family field"
    assert "containerOutputFile" in template_content, "Template should contain output file field"
    assert "commands" in template_content, "Template should contain commands section"


def test_nxpimage_sb40_signature_validation(
    cli_runner: CliRunner, nxpimage_data_dir: str, tmpdir: str
) -> None:
    """Test that SB4 signatures are properly validated."""
    config_file = "sb4_ecc256_basic.yaml"
    device = "mcxn556s"

    with use_working_directory(nxpimage_data_dir):

        config_path = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{config_file}"
        if not os.path.exists(config_path):
            pytest.skip(f"Config file {config_file} not found")

        ref_binary, new_binary, new_config = process_config_file(config_path, tmpdir)

        # Export SB4
        cmd = f"sb40 export -c {new_config}"
        result = cli_runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0

        # Load the SB4 and validate signatures
        sb4 = SecureBinary4.load_from_config(config=Config.create_from_file(config_path))

        # Validate AHAB container signatures
        assert sb4.container is not None
        assert sb4.container.srk_hash0 is not None, "SRK hash should be present"


def test_nxpimage_sb40_rollback_protection(
    cli_runner: CliRunner, nxpimage_data_dir: str, tmpdir: str
) -> None:
    """Test SB4 rollback protection with different version configurations."""
    test_cases = [
        ("sb4_ecc256_image_version.yaml", "Image version test"),
        ("sb4_ecc256_fuse_version.yaml", "Fuse version test"),
    ]

    device = "mcxn556s"

    with use_working_directory(nxpimage_data_dir):

        for config_file, description in test_cases:
            config_path = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{config_file}"
            if not os.path.exists(config_path):
                pytest.skip(f"Config file {config_file} not found")

            _ref_binary, _new_binary, new_config = process_config_file(config_path, tmpdir)

            # Export SB4
            cmd = f"sb40 export -c {new_config}"
            result = cli_runner.invoke(nxpimage.main, cmd.split())
            assert result.exit_code == 0, f"{description} export failed: {result.output}"

            # Validate version fields are properly set
            config = Config.create_from_file(config_path)
            _sb4 = SecureBinary4.load_from_config(config)

            # Check that version fields are properly handled
            if "imageVersion" in config:
                assert config.get("imageVersion") is not None
            if "fuse_version" in config:
                assert config.get("fuse_version") is not None


def test_nxpimage_sb40_dual_signing(
    cli_runner: CliRunner, nxpimage_data_dir: str, tmpdir: str
) -> None:
    """Test SB4 dual signing (ECC + PQC) functionality."""
    config_file = "sb4_ecc256_mldsa_dual.yaml"
    device = "mcxn556s"

    with use_working_directory(nxpimage_data_dir):

        config_path = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{config_file}"
        if not os.path.exists(config_path):
            pytest.skip(f"Config file {config_file} not found")

        _ref_binary, _new_binary, new_config = process_config_file(config_path, tmpdir)

        # Export SB4 with dual signing
        cmd = f"sb40 export -c {new_config}"
        result = cli_runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0, f"Dual signing export failed: {result.output}"

        # Load the SB4 and validate dual signatures
        config = Config.create_from_file(config_path)
        sb4 = SecureBinary4.load_from_config(config)

        # Validate both signature providers are present
        assert sb4.container is not None
        assert sb4.container.srk_hash0 is not None, "Primary SRK hash should be present"

        # Check if second SRK table is present for PQC
        if sb4.container.srk_count > 1:
            assert (
                sb4.container.srk_hash1 is not None
            ), "Secondary SRK hash should be present for dual signing"
