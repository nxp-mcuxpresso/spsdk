#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test AHAB part of nxpimage app.

This module contains tests for the Application Hold-off Authentication Block (AHAB)
functionality of the nxpimage application. Tests cover various AHAB operations including:

- Container export and parsing
- Image signing and encryption
- Certificate operations (export, parse, verify)
- Signed message handling
- Re-signing containers
- Keyblob updates
- Template generation
- Fuse generation

The tests verify both CLI functionality and internal API behavior across
different supported families and configurations.
"""

import filecmp
import os
import shutil
from typing import Optional

import pytest

from spsdk.apps import nxpimage
from spsdk.crypto.dilithium import IS_DILITHIUM_SUPPORTED
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.keys import IS_OSCCA_SUPPORTED
from spsdk.image.ahab.ahab_data import FlagsSrkSet
from spsdk.image.ahab.ahab_image import AHABImage
from spsdk.image.ahab.signed_msg import MessageCommands, SignedMessage
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import (
    load_binary,
    load_hex_string,
    load_text,
    reverse_bytes_in_longs,
    use_working_directory,
    value_to_bytes,
    value_to_int,
)
from tests.cli_runner import CliRunner
from tests.nxpimage.test_nxpimage_cert_block import process_config_file


@pytest.mark.parametrize(
    "config_file",
    [
        ("config_ctcm.yaml"),
        ("config_ctcm_gdet.yaml"),
    ],
)
def test_nxpimage_ahab_export(
    cli_runner: CliRunner, tmpdir: str, data_dir: str, config_file: str
) -> None:
    """Test AHAB container export functionality of the nxpimage tool.

    Tests the 'ahab export' command by processing a configuration file and comparing
    the generated binary with a reference binary to verify correct operation.

    :param cli_runner: CLI runner instance for invoking nxpimage commands
    :param tmpdir: Temporary directory path for test output
    :param data_dir: Directory containing test data files
    :param config_file: Name of the AHAB configuration file to test
    """
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir, "output")
        cmd = f"ahab export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)
        assert filecmp.cmp(os.path.join(data_dir, "ahab", ref_binary), new_binary, shallow=False)


@pytest.mark.parametrize(
    "config_file,tool_override",
    [
        # Standard configurations with default tool selection
        ("ctcm_cm33_signed_img.yaml", None),
        ("ctcm_cm33_signed.yaml", None),
        ("ctcm_cm33_signed_nx.yaml", None),
        ("ctcm_cm33_signed_sb.yaml", None),
        ("ctcm_cm33_signed_sb_mx93.yaml", None),
        ("ctcm_cm33_signed_nand.yaml", None),
        ("ctcm_cm33_encrypted_img.yaml", None),
        ("ctcm_cm33_signed_rsa4096.yaml", "nxpele"),
        pytest.param(
            "ahab_mx95_pqc.yaml",
            None,
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "ahab_mx943_pqc.yaml",
            None,
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "ahab_mx95_pqc_cert.yaml",
            None,
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
    ],
)
def test_nxpimage_ahab_export_signed_encrypted(
    cli_runner: CliRunner,
    tmpdir: str,
    data_dir: str,
    config_file: str,
    tool_override: Optional[str],
) -> None:
    """Test AHAB export functionality for signed and encrypted configurations.

    Executes the nxpimage CLI with 'ahab export' command to test generation of signed and
    encrypted image binaries. Verifies the output binary matches expected size and checks
    for proper generation of fuse files based on processor family and configuration.

    :param cli_runner: CLI runner instance for testing nxpimage commands
    :param tmpdir: Temporary directory for test output files
    :param data_dir: Directory containing test data and configuration files
    :param config_file: Name of the AHAB configuration YAML file to test
    :param tool_override: Optional override for the fuse programming tool selection
    """
    with use_working_directory(data_dir):
        config_file_path = f"{data_dir}/ahab/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file_path, tmpdir, "output")

        cmd = f"ahab export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())

        assert os.path.isfile(new_binary)
        assert os.path.getsize(ref_binary) == os.path.getsize(new_binary)

        # Check if fuse files were generated in post export step
        output_dir = os.path.dirname(new_binary)

        # Skip checking for encrypted
        if "encrypted" in config_file:
            return

        # Helper function to find files with either oem0 or oem1
        def find_oem_file(base_pattern: str) -> str:
            oem_options = ["oem0", "oem1"]
            for oem in oem_options:
                file_path = os.path.join(output_dir, base_pattern.replace("{oem}", oem))
                if os.path.isfile(file_path):
                    return file_path
            return None

        # Determine if this MCU uses nxpele or blhost
        config_filename = os.path.basename(config_file)

        # Allow explicit tool override for testing
        if tool_override:
            tool_suffix = tool_override
        else:
            uses_nxpele = "mx9" in config_filename  # i.MX 9x series use nxpele
            tool_suffix = "nxpele" if uses_nxpele else "blhost"

        # Check for base SRK hash file (should exist for all configurations)
        srk0_hash_txt = find_oem_file("ahab_{oem}_srk0_hash.txt")
        assert srk0_hash_txt, "SRK0 hash file not found"

        # Extract OEM identifier from the found file path
        oem_id = os.path.basename(srk0_hash_txt).split("_")[1]

        # Check for the appropriate fuse script file based on tool selection
        srk0_hash_script = os.path.join(output_dir, f"ahab_{oem_id}_srk0_hash_{tool_suffix}.bcf")
        assert os.path.isfile(
            srk0_hash_script
        ), f"SRK0 hash script file not found: {srk0_hash_script}"

        # For PQC configurations, check for second SRK hash files
        is_pqc = "pqc" in config_filename
        if is_pqc:
            srk1_hash_txt = os.path.join(output_dir, f"ahab_{oem_id}_srk1_hash.txt")
            assert os.path.isfile(srk1_hash_txt), "SRK1 hash file not found for PQC configuration"

            srk1_hash_script = os.path.join(
                output_dir, f"ahab_{oem_id}_srk1_hash_{tool_suffix}.bcf"
            )
            assert os.path.isfile(
                srk1_hash_script
            ), f"SRK1 hash script file not found for PQC configuration: {srk1_hash_script}"
        else:
            # For non-PQC configurations, check that second SRK hash doesn't exist
            # Try with both oem0 and oem1 to ensure neither exists
            srk1_hash_txt_exists = False
            for oem in ["oem0", "oem1"]:
                if os.path.isfile(os.path.join(output_dir, f"ahab_{oem}_srk1_hash.txt")):
                    srk1_hash_txt_exists = True
                    break

            assert not srk1_hash_txt_exists, "SRK1 hash file found for non-PQC configuration"


@pytest.mark.parametrize(
    "config_file",
    [
        ("ahab_certificate256.yaml"),
        ("ahab_certificate384.yaml"),
        ("ahab_certificate521.yaml"),
        pytest.param(
            ("ahab_certificate256_pqc.yaml"),
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            ("ahab_certificate384_pqc.yaml"),
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            ("ahab_certificate521_pqc.yaml"),
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
    ],
)
def test_nxpimage_ahab_cert_export(
    cli_runner: CliRunner, tmpdir: str, data_dir: str, config_file: str
) -> None:
    """Test AHAB certificate export functionality.

    Verifies that the 'ahab certificate export' command correctly generates certificate
    binary files from YAML configuration files. Tests include various certificate types:

    - Standard ECC certificates with different key sizes (256, 384, 521 bits)
    - Post-quantum cryptography (PQC) certificates with Dilithium when supported
    - Combined classical/PQC hybrid certificates

    The test ensures that output binaries are created with the expected file size
    matching reference binaries, validating the certificate generation process.

    :param cli_runner: CLI runner instance for executing nxpimage commands
    :param tmpdir: Temporary directory for storing generated certificate files
    :param data_dir: Directory containing test data and reference certificates
    :param config_file: Name of the certificate configuration YAML file
    """
    with use_working_directory(data_dir):
        ref_binary = os.path.join(data_dir, "ahab", os.path.splitext(config_file)[0] + ".bin")
        new_binary = os.path.join(tmpdir, os.path.splitext(config_file)[0] + ".bin")
        cmd = f"ahab certificate export -c ahab/{config_file} -o {new_binary}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)
        assert os.path.getsize(ref_binary) == os.path.getsize(new_binary)


@pytest.mark.parametrize(
    "config_file",
    [
        ("ahab_certificate256.bin"),
        ("ahab_certificate384.bin"),
        ("ahab_certificate521.bin"),
        pytest.param(
            "ahab_certificate256_pqc.bin",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "ahab_certificate384_pqc.bin",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "ahab_certificate521_pqc.bin",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
    ],
)
def test_nxpimage_ahab_cert_parse(
    cli_runner: CliRunner, tmpdir: str, data_dir: str, config_file: str
) -> None:
    """Test AHAB certificate parsing functionality.

    Verifies that the 'ahab certificate parse' command correctly extracts configuration
    information from binary certificate files. Tests with various certificate types
    including different key sizes and algorithms.

    :param cli_runner: CLI runner instance for executing nxpimage commands
    :param tmpdir: Temporary directory for storing parsed output files
    :param data_dir: Directory containing test data files
    :param config_file: Name of the certificate binary file to parse
    """
    with use_working_directory(tmpdir):
        input_binary = os.path.join(data_dir, "ahab", config_file)
        cmd = f"ahab certificate parse -f mx95 -b {input_binary} -o {tmpdir} -s oem"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile("certificate_config.yaml")


@pytest.mark.parametrize(
    "config_file",
    [
        ("ahab_certificate256.bin"),
        ("ahab_certificate384.bin"),
        ("ahab_certificate521.bin"),
        pytest.param(
            "ahab_certificate256_pqc.bin",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "ahab_certificate384_pqc.bin",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "ahab_certificate521_pqc.bin",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
    ],
)
def test_nxpimage_ahab_cert_verify(
    cli_runner: CliRunner, tmpdir: str, data_dir: str, config_file: str
) -> None:
    """Test AHAB certificate verification functionality.

    Verifies that the 'ahab certificate verify' command correctly validates
    certificate binary files for different key types and configurations.

    :param cli_runner: CLI runner instance for invoking nxpimage commands
    :param tmpdir: Temporary directory for test outputs
    :param data_dir: Directory containing test data files
    :param config_file: Certificate binary file to verify
    """
    with use_working_directory(tmpdir):
        input_binary = os.path.join(data_dir, "ahab", config_file)
        cmd = f"ahab certificate verify -f mx95 -b {input_binary}"
        cli_runner.invoke(nxpimage.main, cmd.split())


@pytest.mark.skipif(
    not IS_OSCCA_SUPPORTED, reason="Install OSCCA dependency with pip install spsdk[oscca]"
)
@pytest.mark.parametrize(
    "config_file",
    [
        ("ctcm_cm33_signed_img_sm2.yaml"),
    ],
)
def test_nxpimage_ahab_export_signed_encrypted_sm2(
    cli_runner: CliRunner, tmpdir: str, data_dir: str, config_file: str
) -> None:
    """Test AHAB command export with signed and encrypted SM2 option.

    Tests the generation of an AHAB container with SM2 signing and encryption.

    :param cli_runner: Runner for executing CLI commands in tests
    :param tmpdir: Temporary directory path for test outputs
    :param data_dir: Directory containing test data files
    :param config_file: Path to the configuration file to use for the test
    """
    test_nxpimage_ahab_export_signed_encrypted(cli_runner, tmpdir, data_dir, config_file, None)


def test_nxpimage_ahab_parse_cli(cli_runner: CliRunner, tmpdir: str, data_dir: str) -> None:
    """Test AHAB container parsing CLI functionality.

    Tests the 'ahab parse' command by parsing a binary container file and verifying that
    the extracted image components match the expected original binary files.

    :param cli_runner: Runner for executing CLI commands in tests
    :param tmpdir: Temporary directory path for storing parsed output files
    :param data_dir: Directory containing test data files
    """

    def is_subpart(new_file: str, orig_file: str) -> bool:
        """Check if the content of one file is contained within another file.

        :param new_file: Path to the file that should contain the original content
        :param orig_file: Path to the original file whose content should be found in new_file
        :return: True if orig_file's content is at the beginning of new_file, False otherwise
        """
        new = load_binary(new_file)
        orig = load_binary(orig_file)
        return new[: len(orig)] == orig

    with use_working_directory(data_dir):
        cmd = f"ahab parse -f mimxrt1189 -b ahab/test_parse_ahab.bin -o {tmpdir}/parsed"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(os.path.join(tmpdir, "parsed", "parsed_config.yaml"))
        assert is_subpart(
            os.path.join(tmpdir, "parsed", "container0_image0_executable_cortex-m33.bin"),
            os.path.join(data_dir, "ahab", "inc13.bin"),
        )
        assert is_subpart(
            os.path.join(tmpdir, "parsed", "container1_image0_executable_cortex-m33.bin"),
            os.path.join(data_dir, "ahab", "inc1024.bin"),
        )
        assert is_subpart(
            os.path.join(tmpdir, "parsed", "container1_image1_executable_cortex-m33.bin"),
            os.path.join(data_dir, "ahab", "inc1026.bin"),
        )
        assert is_subpart(
            os.path.join(tmpdir, "parsed", "container1_image2_executable_cortex-m33.bin"),
            os.path.join(data_dir, "ahab", "inc13.bin"),
        )


@pytest.mark.parametrize(
    "binary,family,target_memory",
    [
        ("cntr_signed_ctcm_cm33.bin", "mimxrt1189", "nor"),
        ("cntr_signed_ctcm_cm33_nx.bin", "mimxrt1189", "nor"),
        ("cntr_signed_ctcm_cm33_sb.bin", "mimxrt1189", "serial_downloader"),
        ("cntr_signed_ctcm_cm33_sb_mx93.bin", "mx93", "serial_downloader"),
        ("cntr_signed_ctcm_cm33_nand.bin", "mimxrt1189", "nand_2k"),
        ("cntr_encrypted_ctcm_cm33.bin", "mimxrt1189", "nor"),
        pytest.param(
            "ahab_mx95_dilithium3.bin",
            "mx95",
            "standard",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "ahab_mx95_dilithium3_cert.bin",
            "mx95",
            "standard",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
    ],
)
def test_nxpimage_ahab_parse(data_dir: str, binary: str, family: str, target_memory: str) -> None:
    """Test AHAB binary parsing functionality.

    Verifies that the AHABImage.parse method correctly processes various AHAB binary files
    for different processor families and target memory configurations. Tests the full
    parse-verify-export cycle to ensure data integrity is maintained.

    :param data_dir: Directory containing test data files
    :param binary: Name of the AHAB binary file to parse
    :param family: Processor family for the AHAB binary
    :param target_memory: Target memory configuration label
    """
    with use_working_directory(data_dir):
        original_file = load_binary(f"{data_dir}/ahab/{binary}")
        ahab = AHABImage.parse(original_file, FamilyRevision(family), target_memory)
        ahab.verify().validate()
        exported_ahab = ahab.export()
        # if original_file != exported_ahab:
        #     write_file(exported_ahab, f"{data_dir}/ahab/{binary}.created", mode="wb")
        assert original_file == exported_ahab
        assert ahab.chip_config.target_memory.label == target_memory


@pytest.mark.parametrize(
    "config_file,new_key,container_id,succeeded",
    [
        ("ctcm_cm33_signed.yaml", "../../_data/keys/ecc256/srk0_ecc256.pem", 1, True),
        ("ctcm_cm33_signed.yaml", "../../_data/keys/ecc256/srk0_ecc256.pem", 0, False),
        ("ctcm_cm33_signed.yaml", "../../_data/keys/ecc256/srk1_ecc256.pem", 1, False),
        ("ctcm_cm33_signed.yaml", "../../_data/keys/ecc384/srk0_ecc384.pem", 1, False),
        ("ctcm_cm33_signed.yaml", "srk0_ecc256.pem", 1, False),
    ],
)
def test_nxpimage_ahab_re_signs(
    cli_runner: CliRunner,
    tmpdir: str,
    data_dir: str,
    config_file: str,
    new_key: str,
    container_id: int,
    succeeded: bool,
) -> None:
    """Test the re-signing functionality of AHAB images.

    Tests the ability to re-sign an existing AHAB image with a different key.
    Verifies that the operation succeeds only with valid key and container combinations.

    :param cli_runner: CLI runner instance to invoke commands
    :param tmpdir: Temporary directory for test outputs
    :param data_dir: Directory with test data
    :param config_file: AHAB configuration file name
    :param new_key: Path to the new signing key
    :param container_id: ID of the container to re-sign
    :param succeeded: Whether the operation is expected to succeed
    """
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/{config_file}"
        ref_binary, new_binary, _ = process_config_file(config_file, tmpdir, "output")

        # we have now a reference binary - is not needed to run export
        shutil.copyfile(ref_binary, new_binary)
        cmd = f"ahab re-sign -f mimxrt1189 -b {new_binary} -k {new_key} -i {container_id}"
        if succeeded:
            cli_runner.invoke(nxpimage.main, cmd.split())
            assert os.path.isfile(new_binary)
            assert os.path.getsize(ref_binary) == os.path.getsize(new_binary)
            new_binary_data = load_binary(new_binary)
            ahab = AHABImage.parse(new_binary_data, FamilyRevision("mimxrt1189"))
            ahab.verify().validate()
            assert ahab.export() == new_binary_data
        else:
            cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=1)


@pytest.mark.parametrize(
    "binary,family",
    [
        ("cntr_signed_ctcm_cm33.bin", "mimxrt1189"),
        ("cntr_signed_ctcm_cm33_nx.bin", "mimxrt1189"),
        ("cntr_signed_ctcm_cm33_sb.bin", "mimxrt1189"),
        ("cntr_signed_ctcm_cm33_sb_mx93.bin", "mx93"),
        ("cntr_signed_ctcm_cm33_nand.bin", "mimxrt1189"),
        ("cntr_encrypted_ctcm_cm33.bin", "mimxrt1189"),
    ],
)
def test_nxpimage_ahab_parse_cli2(
    cli_runner: CliRunner, data_dir: str, binary: str, family: str, tmpdir: str
) -> None:
    """Test AHAB image parsing CLI command with different binary types.

    Verifies that the AHAB parse CLI command correctly processes various binary types
    and generates a parsed configuration file.

    :param cli_runner: CLI runner instance to invoke commands
    :param data_dir: Directory with test data
    :param binary: Binary file name to parse
    :param family: Target family/platform for the binary
    :param tmpdir: Temporary directory for test outputs
    """
    with use_working_directory(data_dir):
        cmd = f"ahab parse -f {family} -b ahab/{binary} -o {tmpdir}/parsed"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(os.path.join(tmpdir, "parsed", "parsed_config.yaml"))


@pytest.mark.parametrize(
    "binary,family,succeeded",
    [
        ("cntr_signed_ctcm_cm33.bin", "mimxrt1189", True),
        ("cntr_signed_ctcm_cm33_nx.bin", "mimxrt1189", True),
        ("cntr_signed_ctcm_cm33_sb.bin", "mimxrt1189", True),
        ("cntr_signed_ctcm_cm33_sb_mx93.bin", "mx93", True),
        ("cntr_signed_ctcm_cm33_nand.bin", "mimxrt1189", True),
        ("cntr_encrypted_ctcm_cm33.bin", "mimxrt1189", True),
        ("test_parse_ahab.bin", "mimxrt1189", True),
        ("test_parse_ahab_err.bin", "mimxrt1189", False),
        pytest.param(
            "ahab_mx95_dilithium3.bin",
            "mx95",
            True,
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "ahab_mx95_dilithium3_cert.bin",
            "mx95",
            True,
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
    ],
)
def test_nxpimage_ahab_verify(
    cli_runner: CliRunner, data_dir: str, binary: str, family: str, succeeded: bool
) -> None:
    """Test AHAB image verification functionality.

    Verifies that the AHAB verify command correctly validates different binary images,
    confirming success or failure as expected for each test case.

    :param cli_runner: CLI runner instance to invoke commands
    :param data_dir: Directory with test data
    :param binary: Binary file name to verify
    :param family: Target family/platform for the binary
    :param succeeded: Whether verification is expected to succeed
    """
    with use_working_directory(data_dir):
        cmd = f"ahab verify -f {family} -b ahab/{binary} -p"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=0 if succeeded else 1)


@pytest.mark.skipif(
    not IS_OSCCA_SUPPORTED, reason="Install OSCCA dependency with pip install spsdk[oscca]"
)
@pytest.mark.parametrize(
    "binary,family,target_memory",
    [
        ("cntr_signed_ctcm_cm33_img_sm2.bin", "mimxrt1189", "nor"),
    ],
)
def test_nxpimage_ahab_parse_sm2(
    data_dir: str, binary: str, family: str, target_memory: str
) -> None:
    """Test AHAB image parsing with SM2 Chinese algorithm support.

    Verifies that AHAB images signed with SM2 algorithm can be correctly parsed.
    This test is skipped if OSCCA support is not installed.

    :param data_dir: Directory with test data
    :param binary: Binary file name to parse
    :param family: Target family/platform for the binary
    :param target_memory: Target memory type
    """
    test_nxpimage_ahab_parse(data_dir, binary, family, target_memory)


@pytest.mark.parametrize(
    "config_file",
    [
        ("sm_return_lc.yaml"),
        ("sm_key_import.yaml"),
        ("sm_key_exchange.yaml"),
    ],
)
def test_nxpimage_signed_message_export(
    cli_runner: CliRunner, tmpdir: str, data_dir: str, config_file: str
) -> None:
    """Test the export of signed messages.

    Verifies that signed messages can be correctly exported from configuration files
    and validates the output binary size and content.

    :param cli_runner: CLI runner instance to invoke commands
    :param tmpdir: Temporary directory for test outputs
    :param data_dir: Directory with test data
    :param config_file: Configuration file name
    """
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/signed_msg/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir, "output")
        cmd = f"signed-msg export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)
        assert os.path.getsize(ref_binary) == os.path.getsize(new_binary)

        new_bin = load_binary(new_binary)
        ref_bin = load_binary(ref_binary)
        # Check content up to signature
        assert new_bin[:408] == ref_bin[:408]


def test_nxpimage_signed_message_parse_cli(
    cli_runner: CliRunner, tmpdir: str, data_dir: str
) -> None:
    """Test the signed message parsing CLI command.

    Verifies that the signed-msg parse command correctly processes a signed message
    binary and generates a parsed configuration file.

    :param cli_runner: CLI runner instance to invoke commands
    :param tmpdir: Temporary directory for test outputs
    :param data_dir: Directory with test data
    """
    with use_working_directory(data_dir):
        cmd = f"signed-msg parse -f mimxrt1189 -b ahab/signed_msg/signed_msg_oem_field_return.bin -o {tmpdir}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(os.path.join(tmpdir, "parsed_config.yaml"))


@pytest.mark.parametrize(
    "family",
    AHABImage.get_supported_families(),
)
@pytest.mark.parametrize(
    "message",
    MessageCommands.labels() + [None],
)
def test_nxpimage_signed_msg_template_cli(
    cli_runner: CliRunner, tmpdir: str, family: FamilyRevision, message: str
) -> None:
    """Test the signed message template generation CLI command.

    Verifies that the signed-msg get-template command generates a valid template
    for different families and message types.

    :param cli_runner: CLI runner instance to invoke commands
    :param tmpdir: Temporary directory for test outputs
    :param family: Target family/platform for the template
    :param message: Message type for the template (or None for default)
    """
    cmd = (
        f"signed-msg get-template -f {family.name} {f'-m {message}' if message else ''}"
        f" --output {tmpdir}/signed_msg.yml"
    )
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/signed_msg.yml")


def test_nxpimage_signed_message_parse(data_dir: str) -> None:
    """Test parsing of signed messages.

    Verifies that a signed message binary can be correctly parsed, validated, and
    re-exported to match the original.

    :param data_dir: Directory with test data
    """
    with use_working_directory(data_dir):
        original_file = load_binary(f"{data_dir}/ahab/signed_msg/signed_msg_oem_field_return.bin")
        signed_msg = SignedMessage.parse(original_file, family=FamilyRevision("mimxrt1189"))
        signed_msg.verify().validate()
        exported_signed_msg = signed_msg.export()
        assert original_file == exported_signed_msg


def test_nxpimage_signed_message_key_exchange(data_dir: str) -> None:
    """Test key exchange signed message functionality.

    Verifies that a key exchange signed message can be correctly loaded from config,
    fields updated, and then validated.

    :param data_dir: Directory with test data
    """
    with use_working_directory(data_dir):
        config = Config.create_from_file(
            os.path.join(data_dir, "ahab", "signed_msg", "sm_key_exchange.yaml")
        )
        signed_msg = SignedMessage.load_from_config(config)
        signed_msg.update_fields()
        signed_msg.verify().validate()


def test_nxpimage_ahab_update_keyblob(cli_runner: CliRunner, tmpdir: str, data_dir: str) -> None:
    """Test AHAB keyblob update functionality.

    Verifies that the 'ahab update-keyblob' command correctly updates the encryption keyblob
    in an existing encrypted AHAB container. Checks that the binary size remains unchanged
    while confirming that the content has been properly modified with the new keyblob.

    :param cli_runner: CLI runner instance for executing nxpimage commands
    :param tmpdir: Temporary directory for test output files
    :param data_dir: Directory containing test data files and keyblobs
    """
    with use_working_directory(data_dir):
        new_bin_path = f"{tmpdir}/cntr_encrypted_ctcm_cm33.bin"
        ref_bin_path = "ahab/cntr_encrypted_ctcm_cm33.bin"
        shutil.copyfile(ref_bin_path, new_bin_path)

        ref_bin = load_binary(ref_bin_path)

        cmd = f"ahab update-keyblob -f mimxrt1189 -b {new_bin_path} -i 1 -k ahab/keyblobs/container1_dek_keyblob.bin"
        result = cli_runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0

        new_bin = load_binary(new_bin_path)
        assert len(new_bin) == len(ref_bin)
        assert new_bin != ref_bin


def test_nxpimage_ahab_update_keyblob_bootable(
    cli_runner: CliRunner, tmpdir: str, data_dir: str
) -> None:
    """Test AHAB keyblob update functionality for bootable images.

    Verifies that the 'ahab update-keyblob' command correctly updates encryption keyblobs
    in bootable images with boot headers. Tests with a NAND flash bootable image and confirms
    that the binary size remains the same while the content is properly modified.

    :param cli_runner: CLI runner instance for executing nxpimage commands
    :param tmpdir: Temporary directory for test output files
    :param data_dir: Directory containing test data files
    """
    with use_working_directory(data_dir):
        new_bin_path = f"{tmpdir}/evkmimxrt1180_rgpio_led_output_cm33_int_RAM_bootable_NAND.bin"
        ref_bin_path = "ahab/evkmimxrt1180_rgpio_led_output_cm33_int_RAM_bootable_NAND.bin"
        shutil.copyfile(ref_bin_path, new_bin_path)

        ref_bin = load_binary(ref_bin_path)

        cmd = (
            f"ahab update-keyblob -f mimxrt1189 -m flexspi_nand -b {new_bin_path}"
            " -i 1 -k ahab/keyblobs/dek_keyblob.bin"
        )
        result = cli_runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0

        new_bin = load_binary(new_bin_path)
        assert len(new_bin) == len(ref_bin)
        assert new_bin != ref_bin


def test_nxpimage_ahab_update_keyblob_invalid(cli_runner: CliRunner, data_dir: str) -> None:
    """Test error handling in AHAB keyblob update functionality.

    Verifies that the 'ahab update-keyblob' command correctly rejects invalid parameters
    by attempting to update a non-existent container ID and checking that the command
    fails with the expected error code.

    :param cli_runner: CLI runner instance for executing nxpimage commands
    :param data_dir: Directory containing test data files
    """
    with use_working_directory(data_dir):
        cmd = (
            "ahab update-keyblob -f mimxrt1189 -b ahab/cntr_encrypted_ctcm_cm33.bin"
            " -i 2 -k ahab/keyblobs/container1_dek_keyblob.bin"
        )
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=1)


@pytest.mark.parametrize(
    "family",
    [
        "mx8ulp",
        "mx93",
        "mx95",
        "mimxrt1189",
    ],
)
def test_nxpimage_ahab_get_template(cli_runner: CliRunner, tmpdir: str, family: str) -> None:
    """Test AHAB template generation functionality.

    Verifies that the 'ahab get-template' command correctly generates standard AHAB
    configuration templates for different processor families. Ensures the template
    file is created at the specified location with the proper format.

    :param cli_runner: CLI runner instance for executing nxpimage commands
    :param tmpdir: Temporary directory for storing the generated template
    :param family: Target processor family for which to generate the template
    """
    cmd = f"ahab get-template -f {family} -o {tmpdir}/tmp.yaml"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/tmp.yaml")


@pytest.mark.parametrize(
    "family",
    [
        "mx8ulp",
        "mx93",
        "mx95",
        "mimxrt1189",
    ],
)
def test_nxpimage_ahab_sign_get_template(cli_runner: CliRunner, tmpdir: str, family: str) -> None:
    """Test AHAB signing template generation functionality.

    Verifies that the 'ahab get-template --sign' command correctly generates signing
    configuration templates for different processor families. Tests that the output
    template file is created with the expected format and content.

    :param cli_runner: CLI runner instance for executing nxpimage commands
    :param tmpdir: Temporary directory for storing the generated template
    :param family: Target processor family for which to generate the template
    """
    cmd = f"ahab get-template -f {family} -o {tmpdir}/tmp.yaml --sign"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/tmp.yaml")


def test_nxpimage_ahab__invalid_encrypt_flag(
    cli_runner: CliRunner, tmpdir: str, data_dir: str
) -> None:
    """Test handling of invalid encryption flag in AHAB configuration.

    Verifies that the nxpimage tool correctly rejects configurations with invalid
    encryption flags by checking that the export command fails with a non-zero exit
    code and that no output binary is generated.

    :param cli_runner: CLI runner instance for executing nxpimage commands
    :param tmpdir: Temporary directory for test output files
    :param data_dir: Directory containing test data files
    """
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/config_ctcm_invalid_encrypt_flag.yaml"
        _, new_binary, new_config = process_config_file(config_file, tmpdir, "output")
        cmd = f"ahab export -c {new_config}"
        res = cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=1)
        assert res.exit_code == 1
        assert not os.path.isfile(new_binary)


def test_nxpimage_ahab_fuses(cli_runner: CliRunner, tmpdir: str, data_dir: str) -> None:
    """Test AHAB fuse generation functionality.

    Verifies that the nxpimage tool correctly generates fuse configuration files (.bcf)
    with proper SRK hash values when exporting AHAB containers. Tests both blhost format
    for RT series and nxpele format for i.MX9 series processors.

    :param cli_runner: CLI runner instance for executing nxpimage commands
    :param tmpdir: Temporary directory for test output files
    :param data_dir: Directory containing test data files
    """
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/ctcm_cm33_signed_img.yaml"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir, "output")
        cmd = f"ahab export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)
        assert os.path.getsize(ref_binary) == os.path.getsize(new_binary)

        bcf_file = os.path.join(
            os.path.dirname(new_binary),
            "ahab_oem1_srk0_hash_blhost.bcf",
        )
        assert os.path.isfile(bcf_file)

        fuses = load_text(bcf_file)
        srk_hash = 0xCB2CC774B2DCEC92C840ECA0646B78F8D3661D3A43ED265A490A13ACA75E190A
        srk_rev = reverse_bytes_in_longs(value_to_bytes(srk_hash))

        fuse_start = 128

        for fuse_ix in range(8):
            value = srk_rev[fuse_ix * 4 : fuse_ix * 4 + 4]
            assert f"efuse-program-once {fuse_start+fuse_ix} 0x{value_to_int(value):X}" in fuses

        # Change family to mx93
        with open(new_config, "r", encoding="ascii") as f:
            config_mx93 = f.read().replace("mimxrt1189", "mx93")

        with open(new_config, "w", encoding="ascii") as f:
            f.write(config_mx93)
        cmd = f"ahab export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)

        bcf_file = os.path.join(
            os.path.dirname(new_binary),
            "ahab_oem1_srk0_hash_nxpele.bcf",
        )
        assert os.path.isfile(bcf_file)
        fuses = load_text(bcf_file)

        for fuse_ix in range(8):
            value = srk_rev[fuse_ix * 4 : fuse_ix * 4 + 4]
            assert (
                f"write-fuse --index {fuse_start+fuse_ix} --data 0x{value_to_int(value):X}" in fuses
            )


@pytest.mark.parametrize(
    "config_file,family,input_binary,hash",
    [
        ("container_sign_config.yaml", "mx93", "test_img_for_sign.bin", "default"),
        ("container_sign_encrypted_config.yaml", "mx93", "test_img_for_sign.bin", "default"),
        pytest.param(
            "container_sign_config_mx95b0_rsa4096.yaml",
            "mx95",
            "ahab_mx95_dilithium3.bin",
            "sha384",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "container_sign_config_mx95b0_rsa4096_mldsa65.yaml",
            "mx95",
            "ahab_mx95_dilithium3.bin",
            "sha3_256",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
    ],
)
def test_nxpimage_ahab_sign(
    cli_runner: CliRunner,
    tmpdir: str,
    data_dir: str,
    config_file: str,
    input_binary: str,
    family: str,
    hash: str,
) -> None:
    """Test AHAB image signing functionality.

    Tests the 'ahab sign' command by signing a binary file with the provided configuration
    and verifying that the signed output is valid. For encrypted configurations, also tests
    the decryption process with a test DEK key. Additionally verifies that the SRK hash
    (SRKH) is correctly computed.

    :param cli_runner: Runner for executing CLI commands in tests
    :param tmpdir: Temporary directory for test output files
    :param data_dir: Directory containing test data files
    :param config_file: Name of the signing configuration file to use
    :param input_binary: Name of the binary file to be signed
    :param family: Target family for the AHAB image (e.g., mx93, mx95)
    :param hash: Hash algorithm, default or hash specified in config
    """
    with use_working_directory(data_dir):
        config_file_path = f"{data_dir}/ahab/{config_file}"
        binary_for_sign = f"{data_dir}/ahab/{input_binary}"
        output_file = f"{tmpdir}/signed.bin"

        # Sign the binary
        cmd = f"ahab sign -c {config_file_path} -b {binary_for_sign} -o {output_file}"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=0)

        # Verify output file exists
        assert os.path.exists(output_file)

        # Parse the signed image
        signed_image = load_binary(output_file)
        family_revision = FamilyRevision(family)
        ahab = AHABImage.parse(signed_image, family_revision)

        # Handle decryption if needed
        dek = "000102030405060708090a0b0c0d0e0f"
        if "encrypted" in config_file:
            for container in ahab.ahab_containers:
                if container.flag_srk_set != FlagsSrkSet.NXP:
                    if container.signature_block and container.signature_block.blob:
                        container.signature_block.blob.dek = load_hex_string(
                            dek, container.signature_block.blob._size // 8
                        )
                        container.decrypt_data()

        # Verify the signed image
        ahab.verify().validate()

        # Verify SRK Hash (SRKH) is correctly computed
        for i, container in enumerate(ahab.ahab_containers):
            if container.signature_block and container.signature_block.srk_assets:
                # Get the computed SRK hash from the container
                computed_srkh = container.get_srk_hash(0)  # Get hash for SRK table 0

                # Verify the hash is not empty/zero
                assert computed_srkh != b"\x00" * len(
                    computed_srkh
                ), f"Container {i}: SRK hash is all zeros"
                assert len(computed_srkh) > 0, f"Container {i}: SRK hash is empty"

                # For SRKTableArray (V2), also check additional SRK tables if present
                if hasattr(container.signature_block.srk_assets, "srk_count"):
                    srk_count = container.signature_block.srk_assets.srk_count
                    for srk_id in range(srk_count):
                        srk_hash = container.get_srk_hash(srk_id)
                        assert srk_hash != b"\x00" * len(
                            srk_hash
                        ), f"Container {i}, SRK {srk_id}: SRK hash is all zeros"
                        assert len(srk_hash) > 0, f"Container {i}, SRK {srk_id}: SRK hash is empty"

                        # Verify hash length matches expected algorithm
                        if hasattr(container.signature_block.srk_assets, "_srk_tables"):
                            # verify the hash matches
                            if container.flag_srk_set != FlagsSrkSet.NXP and hash != "default":
                                hash_alg = EnumHashAlgorithm.from_label(hash)
                                assert (
                                    container.signature_block.srk_assets._srk_tables[srk_id]
                                    .srk_records[0]
                                    .hash_algorithm.name
                                    == hash_alg.name
                                )

                            # For SRKTableArray
                            expected_hash_len = (
                                64
                                if container.signature_block.srk_assets._srk_tables[
                                    srk_id
                                ].SRK_HASH_ALGORITHM
                                == EnumHashAlgorithm.SHA512
                                else 32
                            )
                        else:
                            # For SRKTable
                            expected_hash_len = (
                                32
                                if container.signature_block.srk_assets.SRK_HASH_ALGORITHM
                                == EnumHashAlgorithm.SHA256
                                else 64
                            )

                        assert (
                            len(srk_hash) == expected_hash_len
                        ), f"Container {i}, SRK {srk_id}: length {len(srk_hash)}, expected {expected_hash_len}"
