#!/usr/bin/env python
#
# Copyright 2022-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK AHAB fuse script generation tests.

This module contains unit tests for validating the generation of fuse programming
scripts for AHAB (Advanced High Assurance Boot) enabled processors. It tests
both BLHOST and NXPELE tool script generation across all AHAB-supported families
and validates SRK hash fuse index functionality.
"""

import os
import re

import pytest

from spsdk.apps import nxpimage
from spsdk.crypto.dilithium import IS_DILITHIUM_SUPPORTED
from spsdk.utils.misc import load_text, use_working_directory
from tests.cli_runner import CliRunner
from tests.nxpimage.test_nxpimage_cert_block import process_config_file


@pytest.mark.parametrize(
    "family,revision,base_config_file,expected_tool,core",
    [
        ("mimxrt1189", "latest", "ahab_classic.yaml", "blhost", "cortex-m33"),
        # ("mimx8ulp", "latest", "ahab_classic.yaml", "nxpele", "cortex-a55"),
        ("mimx9131", "latest", "ahab_classic.yaml", "nxpele", "cortex-a55"),
        ("mimx9352", "latest", "ahab_classic.yaml", "nxpele", "cortex-a55"),
        ("mimxrt2662", "a0", "ahab_classic.yaml", "blhost", "cortex-m85"),
        pytest.param(
            "mimxrt2662",
            "a0",
            "ahab_pqc.yaml",
            "blhost",
            "cortex-m85",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "mimx943",
            "latest",
            "ahab_pqc.yaml",
            "nxpele",
            "cortex-a55",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "mimx9596",
            "a0",
            "ahab_classic.yaml",
            "nxpele",
            "cortex-a55",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "mimx9596",
            "b0",
            "ahab_pqc.yaml",
            "nxpele",
            "cortex-a55",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        # Add other family-config-tool mappings as needed
    ],
)
def test_nxpimage_ahab_fuse_generation(
    cli_runner: CliRunner,
    tmpdir: str,
    data_dir: str,
    family: str,
    revision: str,
    base_config_file: str,
    expected_tool: str,
    core: str,
) -> None:
    """Test AHAB fuse script generation for SRK hashes across all supported families.

    Verifies that correct fuse programming scripts are generated for both BLHOST and NXPELE tools
    with proper SRK hash values when exporting AHAB containers. The test validates the format of
    generated scripts, command syntax, and confirms that SRK hash values are properly calculated
    and not zero. For PQC configurations, validates both srk0 and srk1 hash generation.

    :param cli_runner: CLI runner instance for executing nxpimage commands.
    :param tmpdir: Temporary directory for test output files.
    :param data_dir: Directory containing test data files.
    :param family: Target processor family for which to generate fuses.
    :param revision: Silicon revision of the target processor.
    :param base_config_file: Base configuration file appropriate for the given family.
    :param expected_tool: Expected fuse programming tool (blhost or nxpele).
    :param core: Target processor core (e.g., cortex-m33, cortex-a55).
    """
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/fuses_scripts/{base_config_file}"
        _, new_binary, new_config = process_config_file(config_file, tmpdir, "output")

        # Export AHAB container to generate fuse files, overriding family with -oc option
        cmd = (
            f"ahab export -c {new_config} -oc family={family} -oc revision={revision}"
            f" -oc containers/0/container/images/0/core_id={core}"
        )
        result = cli_runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0, f"Export failed for family {family}: {result.stdout}"

        # Check for generated fuse files
        output_dir = os.path.dirname(new_binary)
        bcf_files = []

        # For PQC configurations, check for both srk0 and srk1
        srk_indices = ["srk0"]
        if "pqc" in base_config_file.lower():
            srk_indices.append("srk1")

        for srk_index in srk_indices:
            potential_bcf = os.path.join(
                output_dir, f"ahab_oem0_{srk_index}_hash_{expected_tool}.bcf"
            )
            assert os.path.isfile(
                potential_bcf
            ), f"No SRK hash BCF file{potential_bcf} found for family {family}"
            bcf_files.append(potential_bcf)

        # Process each BCF file found
        for bcf_file in bcf_files:
            srk_index = "srk0" if "srk0" in bcf_file else "srk1"

            # Load and verify the contents of the BCF file
            fuses_content = load_text(bcf_file)

            # Verify format of commands based on expected tool
            if expected_tool == "blhost":
                # Check for blhost format commands
                assert (
                    "efuse-program-once" in fuses_content
                ), f"Missing blhost fuse programming commands for {srk_index}"
                # Verify blhost command structure with regex
                fuse_cmd_pattern = r"efuse-program-once \d+ 0x[0-9A-F]+"
                assert re.search(
                    fuse_cmd_pattern, fuses_content
                ), f"Invalid blhost command format for {srk_index}"

                # Verify we have multiple fuse commands (typically 8 for SRK hash)
                fuse_commands = re.findall(r"efuse-program-once", fuses_content)
                assert (
                    len(fuse_commands) >= 8
                ), f"Not enough SRK hash fuse commands found for {srk_index}"
            else:
                # Check for nxpele format commands
                assert (
                    "write-fuse" in fuses_content
                ), f"Missing nxpele fuse programming commands for {srk_index}"
                # Verify nxpele command structure with regex
                fuse_cmd_pattern = r"write-fuse --index \d+ --data 0x[0-9A-F]+"
                assert re.search(
                    fuse_cmd_pattern, fuses_content
                ), f"Invalid nxpele command format for {srk_index}"

                # Verify we have multiple fuse commands (typically 8 for SRK hash)
                fuse_commands = re.findall(r"write-fuse", fuses_content)
                assert (
                    len(fuse_commands) >= 8
                ), f"Not enough SRK hash fuse commands found for {srk_index}"

            # Verify that the SRK hash values are non-zero
            # (At least one command should have non-zero value)
            hex_values = re.findall(r"0x([0-9A-F]+)", fuses_content)
            assert any(
                int(v, 16) > 0 for v in hex_values
            ), f"All SRK hash values are zero for {srk_index}"

            # Check for SRK hash text file
            hash_txt_file = bcf_file.replace(f"_{expected_tool}.bcf", ".txt")
            assert os.path.isfile(
                hash_txt_file
            ), f"SRK hash text file not found for {srk_index} ({family})"

            # Load and verify hash text file contains a valid hash
            hash_content = load_text(hash_txt_file)
            hash_pattern = r"[0-9A-F]{64}"  # 32 bytes = 64 hex chars
            assert re.search(
                hash_pattern, hash_content
            ), f"Valid SRK hash not found in text file for {srk_index}"


@pytest.mark.parametrize(
    "family,revision,base_config_file,expected_tool,core",
    [
        ("mimxrt1189", "latest", "ahab_classic.yaml", "blhost", "cortex-m33"),
        # ("mimx8ulp", "latest", "ahab_classic.yaml", "nxpele", "cortex-a55"),
        ("mimx9131", "latest", "ahab_classic.yaml", "nxpele", "cortex-a55"),
        ("mimx9352", "latest", "ahab_classic.yaml", "nxpele", "cortex-a55"),
        pytest.param(
            "mimx943",
            "latest",
            "ahab_pqc.yaml",
            "nxpele",
            "cortex-a55",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "mimx9596",
            "a0",
            "ahab_classic.yaml",
            "nxpele",
            "cortex-a55",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "mimx9596",
            "b0",
            "ahab_pqc.yaml",
            "nxpele",
            "cortex-a55",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        # Add other family-config-tool mappings as needed
    ],
)
def test_nxpimage_ahab_fuse_indexes(
    cli_runner: CliRunner,
    tmpdir: str,
    data_dir: str,
    family: str,
    revision: str,
    base_config_file: str,
    expected_tool: str,
    core: str,
) -> None:
    """Test correct fuse indexes used in AHAB SRK hash fuse scripts.

    Verifies that the correct fuse indexes are used for different processor families
    when generating SRK hash fuse programming scripts by comparing against reference test vectors.

    :param cli_runner: CLI runner instance for executing nxpimage commands
    :param tmpdir: Temporary directory for test output files
    :param data_dir: Directory containing test data files
    :param family: Target processor family for which to generate fuses
    :param revision: Silicon revision of the target processor
    :param base_config_file: Base configuration file appropriate for the given family
    :param expected_tool: Expected fuse programming tool (blhost or nxpele)
    :param core: Target processor core (e.g., cortex-m33, cortex-a55)
    :raises AssertionError: When export fails, files are missing, or fuse commands don't match expected values
    """
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/fuses_scripts/{base_config_file}"
        _, new_binary, new_config = process_config_file(config_file, tmpdir, "output")

        # Export AHAB container to generate fuse files, overriding family with -oc option
        cmd = (
            f"ahab export -c {new_config} -oc family={family} -oc revision={revision}"
            f" -oc containers/0/container/images/0/core_id={core}"
        )
        result = cli_runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0, f"Export failed for family {family}: {result.stdout}"

        # For PQC configurations, check for both srk0 and srk1
        srk_indices = ["srk0"]
        if "pqc" in base_config_file.lower():
            srk_indices.append("srk1")

        output_dir = os.path.dirname(new_binary)

        for srk_index in srk_indices:
            # Find SRK hash script file
            bcf_file = os.path.join(output_dir, f"ahab_oem0_{srk_index}_hash_{expected_tool}.bcf")
            assert os.path.isfile(
                bcf_file
            ), f"No SRK hash BCF file found for family {family} and {srk_index}"

            # Construct test vector filename based on naming convention
            if revision == "latest":
                test_vector_filename = f"{family}_ahab_oem0_{srk_index}_hash_{expected_tool}.bcf"
            else:
                test_vector_filename = (
                    f"{family}_{revision}_ahab_oem0_{srk_index}_hash_{expected_tool}.bcf"
                )

            test_vector_path = os.path.join(data_dir, "ahab", "fuses_scripts", test_vector_filename)
            assert os.path.isfile(
                test_vector_path
            ), f"Test vector file not found: {test_vector_path}"

            # Extract fuse indexes and values from generated file
            generated_content = load_text(bcf_file)
            if expected_tool == "blhost":
                # Extract index-value pairs for blhost format
                generated_commands = [
                    (int(idx), value)
                    for idx, value in re.findall(
                        r"efuse-program-once (\d+) (0x[0-9A-F]+)", generated_content
                    )
                ]
            else:
                # Extract index-value pairs for nxpele format
                generated_commands = [
                    (int(idx), value)
                    for idx, value in re.findall(
                        r"write-fuse --index (\d+) --data (0x[0-9A-F]+)", generated_content
                    )
                ]

            # Extract fuse indexes and values from test vector file
            test_vector_content = load_text(test_vector_path)
            if expected_tool == "blhost":
                # Extract index-value pairs for blhost format
                expected_commands = [
                    (int(idx), value)
                    for idx, value in re.findall(
                        r"efuse-program-once (\d+) (0x[0-9A-F]+)", test_vector_content
                    )
                ]
            else:
                # Extract index-value pairs for nxpele format
                expected_commands = [
                    (int(idx), value)
                    for idx, value in re.findall(
                        r"write-fuse --index (\d+) --data (0x[0-9A-F]+)", test_vector_content
                    )
                ]

            # Verify complete index-value pairs match between generated file and test vector
            assert generated_commands == expected_commands, (
                f"Generated fuse commands {generated_commands} do not match "
                f"expected commands {expected_commands} for {family} ({srk_index})"
            )


def test_nxpimage_ahab_fuse_generation_multi_container_same_srk(
    cli_runner: CliRunner, tmpdir: str, data_dir: str
) -> None:
    """Test that only one shared set of SRKH fuse files is generated for identical SRKs.

    When all AHAB containers in the image share the same SRK hash, only a single
    set of SRKH fuse files without a container index should be generated instead
    of one set per container (SPSDK-6159).

    :param cli_runner: CLI runner instance for executing nxpimage commands.
    :param tmpdir: Temporary directory for test output files.
    :param data_dir: Directory containing test data files.
    """
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/fuses_scripts/ahab_multi_container_same_srk.yaml"
        _, new_binary, new_config = process_config_file(config_file, tmpdir, "output")

        cmd = f"ahab export -c {new_config}"
        result = cli_runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0, f"Export failed: {result.stdout}"

        output_dir = os.path.dirname(new_binary)

        # Shared SRKH fuse files (without a container index) must be generated exactly once.
        shared_hash_txt = os.path.join(output_dir, "ahab_oem_srk0_hash.txt")
        shared_hash_bcf = os.path.join(output_dir, "ahab_oem_srk0_hash_blhost.bcf")
        assert os.path.isfile(shared_hash_txt), "Shared SRK hash text file was not generated"
        assert os.path.isfile(shared_hash_bcf), "Shared SRK hash fuse script was not generated"

        # No per-container indexed files should exist for either container.
        for cnt_ix in (0, 1):
            assert not os.path.isfile(
                os.path.join(output_dir, f"ahab_oem{cnt_ix}_srk0_hash.txt")
            ), f"Unexpected per-container SRK hash file generated for container {cnt_ix}"


def test_nxpimage_ahab_fuse_generation_multi_container_diff_srk(
    cli_runner: CliRunner, tmpdir: str, data_dir: str
) -> None:
    """Test that per-container SRKH fuse files are generated when SRKs differ.

    When AHAB containers in the image use different SRK hashes, the SRKH fuse
    files must still be generated individually per container (SPSDK-6159).

    :param cli_runner: CLI runner instance for executing nxpimage commands.
    :param tmpdir: Temporary directory for test output files.
    :param data_dir: Directory containing test data files.
    """
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/fuses_scripts/ahab_multi_container_diff_srk.yaml"
        _, new_binary, new_config = process_config_file(config_file, tmpdir, "output")

        cmd = f"ahab export -c {new_config}"
        result = cli_runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0, f"Export failed: {result.stdout}"

        output_dir = os.path.dirname(new_binary)

        # Per-container indexed files must exist for both containers.
        for cnt_ix in (0, 1):
            hash_txt = os.path.join(output_dir, f"ahab_oem{cnt_ix}_srk0_hash.txt")
            hash_bcf = os.path.join(output_dir, f"ahab_oem{cnt_ix}_srk0_hash_blhost.bcf")
            assert os.path.isfile(hash_txt), f"SRK hash text file missing for container {cnt_ix}"
            assert os.path.isfile(hash_bcf), f"SRK hash fuse script missing for container {cnt_ix}"

        # No shared file (without a container index) should exist.
        shared_hash_txt = os.path.join(output_dir, "ahab_oem_srk0_hash.txt")
        assert not os.path.isfile(shared_hash_txt), "Unexpected shared SRK hash file generated"


def test_nxpimage_ahab_fuse_generation_multi_container_nxp_first(
    cli_runner: CliRunner, tmpdir: str, data_dir: str
) -> None:
    """Test SRKH fuse generation when container 0 is skipped but shares SRK hash with others.

    Container 0 is signed by NXP keys (SRKH fuse generation is always skipped for
    NXP/DEVHSM containers) while container 1 is signed by OEM keys using the *same*
    SRK table. Even though the SRK hash of container 0 matches the SRK hash of the
    other containers, container 0 itself never produces SRKH fuse files. Since
    container 1 is the only container that actually produces fuse files, it is used
    as the shared representative and a single shared set of files without a
    container index is generated, instead of per-container indexed files
    (SPSDK-6159).

    :param cli_runner: CLI runner instance for executing nxpimage commands.
    :param tmpdir: Temporary directory for test output files.
    :param data_dir: Directory containing test data files.
    """
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/fuses_scripts/ahab_multi_container_nxp_first.yaml"
        _, new_binary, new_config = process_config_file(config_file, tmpdir, "output")

        cmd = f"ahab export -c {new_config}"
        result = cli_runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0, f"Export failed: {result.stdout}"

        output_dir = os.path.dirname(new_binary)

        # Only container 1 (OEM) produces fuse files; since it is the sole producer,
        # a shared set of files (without a container index) is generated instead
        # of an indexed one.
        shared_hash_txt = os.path.join(output_dir, "ahab_oem_srk0_hash.txt")
        shared_hash_bcf = os.path.join(output_dir, "ahab_oem_srk0_hash_blhost.bcf")
        assert os.path.isfile(shared_hash_txt), "Shared SRK hash text file was not generated"
        assert os.path.isfile(shared_hash_bcf), "Shared SRK hash fuse script was not generated"

        # No per-container indexed file should exist for the OEM container.
        assert not os.path.isfile(
            os.path.join(output_dir, "ahab_oem1_srk0_hash.txt")
        ), "Unexpected per-container SRK hash file generated for OEM container"

        # Container 0 (NXP) must never produce SRKH fuse files, indexed or shared.
        assert not os.path.isfile(
            os.path.join(output_dir, "ahab_nxp0_srk0_hash.txt")
        ), "Unexpected SRK hash file generated for NXP container"
        assert not os.path.isfile(
            os.path.join(output_dir, "ahab_nxp_srk0_hash.txt")
        ), "Unexpected SRK hash file generated for NXP container"


def test_nxpimage_ahab_fuse_generation_multi_container_nxp_plus_two_oem(
    cli_runner: CliRunner, tmpdir: str, data_dir: str
) -> None:
    """Test SRKH fuse generation for a common MPU layout: one NXP + several OEM containers.

    Container 0 is signed by NXP keys (always skipped for SRKH fuse generation),
    while containers 1 and 2 are signed by OEM keys using the *same* SRK table as
    each other and as the NXP container. This is the typical MPU container layout.
    Even though the SRK hash is identical across all three containers, only the
    two OEM containers actually produce fuse files, so a single shared set of
    files without a container index must be generated for them, not one set per
    OEM container (SPSDK-6159).

    :param cli_runner: CLI runner instance for executing nxpimage commands.
    :param tmpdir: Temporary directory for test output files.
    :param data_dir: Directory containing test data files.
    """
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/fuses_scripts/ahab_multi_container_nxp_plus_two_oem.yaml"
        _, new_binary, new_config = process_config_file(config_file, tmpdir, "output")

        cmd = f"ahab export -c {new_config}"
        result = cli_runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0, f"Export failed: {result.stdout}"

        output_dir = os.path.dirname(new_binary)

        # A single shared set of files (without a container index) must be
        # generated for the OEM containers, not one set per OEM container.
        shared_hash_txt = os.path.join(output_dir, "ahab_oem_srk0_hash.txt")
        shared_hash_bcf = os.path.join(output_dir, "ahab_oem_srk0_hash_nxpele.bcf")
        assert os.path.isfile(shared_hash_txt), "Shared SRK hash text file was not generated"
        assert os.path.isfile(shared_hash_bcf), "Shared SRK hash fuse script was not generated"

        # No per-container indexed files should exist for either OEM container.
        for cnt_ix in (1, 2):
            assert not os.path.isfile(
                os.path.join(output_dir, f"ahab_oem{cnt_ix}_srk0_hash.txt")
            ), f"Unexpected per-container SRK hash file generated for container {cnt_ix}"

        # Container 0 (NXP) must never produce SRKH fuse files, indexed or shared.
        assert not os.path.isfile(
            os.path.join(output_dir, "ahab_nxp0_srk0_hash.txt")
        ), "Unexpected SRK hash file generated for NXP container"
        assert not os.path.isfile(
            os.path.join(output_dir, "ahab_nxp_srk0_hash.txt")
        ), "Unexpected SRK hash file generated for NXP container"
