#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK NXP Image SB2.1 format testing module.

This module contains comprehensive tests for the SB2.1 (Secure Binary 2.1) image format
functionality in SPSDK's nxpimage tool. It validates image creation, parsing, conversion,
and CLI operations for SB2.1 secure boot images.
"""

import os
from binascii import unhexlify
from itertools import zip_longest
from typing import Any

import pytest
from test_nxpimage_sb31 import process_config_file

import spsdk.apps.nxpimage as nxpimage
from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb2.images import BootImageV21
from spsdk.utils.misc import load_configuration, use_working_directory
from tests.cli_runner import CliRunner

SB21_TEST_CONFIGURATIONS = [
    (
        "sb_sources/BD_files/real_example1.bd",
        "sb_sources/SB_files/legacy_real_example1.sb",
        [],
        "rt5xx",
    ),
    (
        "sb_sources/BD_files/real_example2.bd",
        "sb_sources/SB_files/legacy_real_example2.sb",
        [
            "sb_sources/output_images/tmdData.bin",
            "sb_sources/output_images/bootloaderImage.bin",
            "sb_sources/output_images/tmdImage.bin",
            "sb_sources/output_images/audioImage.bin",
        ],
        "rt6xx",
    ),
    (
        "sb_sources/BD_files/real_example3.bd",
        "sb_sources/SB_files/legacy_real_example3.sb",
        [],
        "rt5xx",
    ),
    (
        "sb_sources/BD_files/real_example3_test_options.bd",
        "sb_sources/SB_files/legacy_real_example3_test_options.sb",
        [],
        "rt5xx",
    ),
    (
        "sb_sources/BD_files/simpleExample_no_sha.bd",
        "sb_sources/SB_files/legacy_elftosb_no_sha.bin",
        [],
        "rt5xx",
    ),
    (
        "sb_sources/BD_files/simpleExample_sha.bd",
        "sb_sources/SB_files/legacy_elftosb_sha.bin",
        [],
        "rt5xx",
    ),
]


@pytest.mark.parametrize("use_signature_provider", [True, False])
@pytest.mark.parametrize("bd_file,legacy_sb,external,family", SB21_TEST_CONFIGURATIONS)
def test_nxpimage_sb21(
    cli_runner: CliRunner,
    use_signature_provider: bool,
    bd_file: str,
    legacy_sb: str,
    external: list[str],
    nxpimage_data_dir: str,
    family: str,
    tmpdir: Any,
) -> None:
    """Test SB2.1 image generation and compare with legacy implementation.

    This test validates that the new nxpimage SB2.1 export functionality produces
    equivalent secure boot images compared to legacy elftosb tool. It generates
    a new SB2.1 image using provided configuration and compares its structure
    with a reference legacy image, excluding timestamp and digest fields that
    naturally differ between generations.

    :param cli_runner: Click CLI test runner instance for command execution.
    :param use_signature_provider: Flag to determine signature provider usage format.
    :param bd_file: Relative path to the boot descriptor configuration file.
    :param legacy_sb: Relative path to the reference legacy SB2.1 image file.
    :param external: List of additional external command line arguments.
    :param nxpimage_data_dir: Absolute path to test data directory.
    :param family: Target MCU family identifier.
    :param tmpdir: Temporary directory for output files.
    """
    with use_working_directory(nxpimage_data_dir):
        bd_file_path = os.path.join(nxpimage_data_dir, bd_file)
        out_file_path_new = os.path.join(tmpdir, "new_elf2sb.bin")
        kek_key_path = os.path.join(nxpimage_data_dir, "sb_sources/keys/SBkek_PUF.txt")
        pkey = os.path.join(nxpimage_data_dir, "sb_sources/keys_and_certs/k0_cert0_2048.pem")
        if use_signature_provider:
            pkey = f"type=file;file_path={pkey}"
        certificate_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k0_signed_cert0_noca.der.cert"
        )
        root_key_certificate0_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k0_signed_cert0_noca.der.cert"
        )
        root_key_certificate1_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k1_signed_cert0_noca.der.cert"
        )
        root_key_certificate2_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k2_signed_cert0_noca.der.cert"
        )
        root_key_certificate3_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k3_signed_cert0_noca.der.cert"
        )
        hash_of_hashes_output_path = os.path.join(tmpdir, "hash.bin")

        out_file_path_legacy = os.path.join(nxpimage_data_dir, legacy_sb)

        cmd = [
            "sb21",
            "export",
            "-c",
            bd_file_path,
            "-o",
            out_file_path_new,
            "-k",
            kek_key_path,
            "-s",
            pkey,
            "-S",
            certificate_path,
            "-R",
            root_key_certificate0_path,
            "-R",
            root_key_certificate1_path,
            "-R",
            root_key_certificate2_path,
            "-R",
            root_key_certificate3_path,
            "-h",
            hash_of_hashes_output_path,
        ]
        for entry in external:
            cmd.append(entry)
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file_path_new)

        with open(kek_key_path) as f:
            # transform text-based KEK into bytes
            sb_kek = unhexlify(f.read())

        # read generated secure binary image (created with new elf2sb)
        with open(out_file_path_new, "rb") as f:
            sb_file_data_new = f.read()

        sb_new = BootImageV21.parse(data=sb_file_data_new, kek=sb_kek)

        # dump the info of the secure binary image generated with new elf2sb
        # Left for debugging purposes
        # with open(os.path.join(nxpimage_data_dir, "SB_files/new_elf2sb_sb21_file.txt"), 'w') as sb_file_content:
        #     sb_file_content.write(sb_new.__str__())

        # read SB file generated using legacy elftosb
        with open(out_file_path_legacy, "rb") as f:
            sb_file_data_old = f.read()

        # we assume that SB File version is 2.1
        sb_old = BootImageV21.parse(data=sb_file_data_old, kek=sb_kek)

        # dump the info of the secure binary image generated with legacy elftosb
        # Left for debugging purposes
        # with open(os.path.join(nxpimage_data_dir, "SB_files/old_elf2sb_sb21_file.txt"), 'w') as f:
        #     f.write(str(sb_old))

        sb_new_lines = str(sb_new).split("\n")
        sb_old_lines = str(sb_old).split("\n")

        DIGEST_LINE = 4
        TIMESTAMP_LINE = 14
        # Remove lines containing digest and timestamp, as these will always differ
        # -1 for indexing starting from 0
        del sb_new_lines[DIGEST_LINE - 1]
        # -1 for indexing starting from 0, -1 for previously removed line => -2
        del sb_new_lines[TIMESTAMP_LINE - 2]

        # -1 for indexing starting from 0
        del sb_old_lines[DIGEST_LINE - 1]
        # -1 for indexing starting from 0, -1 for previously removed line => -2
        del sb_old_lines[TIMESTAMP_LINE - 2]

        for i in zip_longest(sb_new_lines, sb_old_lines, fillvalue=None):
            assert i[0] == i[1]


def test_sb_21_invalid_parse() -> None:
    """Test parsing of SB 2.1 boot image with invalid empty KEK.

    Verifies that BootImageV21.parse() properly validates the KEK parameter
    and raises an appropriate error when an empty KEK is provided.

    :raises SPSDKError: When KEK parameter is empty bytes.
    """
    with pytest.raises(SPSDKError, match="kek cannot be empty"):
        BootImageV21.parse(data=bytes(232), kek=bytes())


def test_nxpimage_sbkek_cli(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test SB21 SBKEK CLI command functionality.

    This test verifies the 'sb21 get-sbkek' command works correctly in different scenarios:
    - Basic command execution without parameters
    - Command with output directory specification
    - Command with custom key and output directory
    Validates that the expected output files (sbkek.bin and sbkek.txt) are created.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test file operations.
    """
    cmd = "sb21 get-sbkek"
    cli_runner.invoke(nxpimage.main, cmd.split())

    cmd = f"sb21 get-sbkek -o {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(os.path.join(tmpdir, "sbkek.bin"))
    assert os.path.isfile(os.path.join(tmpdir, "sbkek.txt"))

    test_key = "858A4A83D07C78656165CDDD3B7AF4BB20E534392E7AF99EF7C296F95205E680"

    cmd = f"sb21 get-sbkek -k {test_key} -o {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(os.path.join(tmpdir, "sbkek.bin"))
    assert os.path.isfile(os.path.join(tmpdir, "sbkek.txt"))


@pytest.mark.parametrize("use_signature_provider", [True, False])
@pytest.mark.parametrize(
    "bd_file,legacy_sb,external",
    [
        (
            "sb_sources/BD_files/real_example1_relative.bd",
            "sb_sources/SB_files/legacy_real_example1.sb",
            [],
        ),
    ],
)
def test_nxpimage_relative_path_sb21(
    cli_runner: CliRunner,
    use_signature_provider: bool,
    bd_file: str,
    legacy_sb: str,
    external: list[str],
    nxpimage_data_dir: str,
    tmpdir: Any,
) -> None:
    """Test SB21 image generation with relative paths and compare against legacy output.

    This test validates that the new SPSDK SB21 export functionality produces
    equivalent secure boot images compared to legacy elftosb tool. It generates
    a new SB21 image using provided configuration and keys, then parses and
    compares the structure against a reference legacy image, excluding
    timestamp and digest fields that naturally differ between generations.

    :param cli_runner: Click CLI test runner instance for command execution.
    :param use_signature_provider: Flag to determine signature provider usage format.
    :param bd_file: Relative path to the boot descriptor configuration file.
    :param legacy_sb: Relative path to the legacy reference SB21 image file.
    :param external: List of additional external command line arguments.
    :param nxpimage_data_dir: Absolute path to test data directory containing input files.
    :param tmpdir: Temporary directory path for output file generation.
    """
    bd_file_path = os.path.join(nxpimage_data_dir, bd_file)
    out_file_path_new = os.path.join(tmpdir, "new_elf2sb.bin")
    kek_key_path = os.path.join(nxpimage_data_dir, "sb_sources/keys/SBkek_PUF.txt")
    pkey = os.path.join(nxpimage_data_dir, "sb_sources/keys_and_certs/k0_cert0_2048.pem")
    if use_signature_provider:
        pkey = f"type=file;file_path={pkey}"
    certificate_path = os.path.join(
        nxpimage_data_dir, "sb_sources/keys_and_certs/root_k0_signed_cert0_noca.der.cert"
    )
    root_key_certificate0_path = os.path.join(
        nxpimage_data_dir, "sb_sources/keys_and_certs/root_k0_signed_cert0_noca.der.cert"
    )
    root_key_certificate1_path = os.path.join(
        nxpimage_data_dir, "sb_sources/keys_and_certs/root_k1_signed_cert0_noca.der.cert"
    )
    root_key_certificate2_path = os.path.join(
        nxpimage_data_dir, "sb_sources/keys_and_certs/root_k2_signed_cert0_noca.der.cert"
    )
    root_key_certificate3_path = os.path.join(
        nxpimage_data_dir, "sb_sources/keys_and_certs/root_k3_signed_cert0_noca.der.cert"
    )
    hash_of_hashes_output_path = os.path.join(tmpdir, "hash.bin")

    out_file_path_legacy = os.path.join(nxpimage_data_dir, legacy_sb)

    cmd = [
        "sb21",
        "export",
        "-c",
        bd_file_path,
        "-o",
        out_file_path_new,
        "-k",
        kek_key_path,
        "-s",
        pkey,
        "-S",
        certificate_path,
        "-R",
        root_key_certificate0_path,
        "-R",
        root_key_certificate1_path,
        "-R",
        root_key_certificate2_path,
        "-R",
        root_key_certificate3_path,
        "-h",
        hash_of_hashes_output_path,
    ]
    for entry in external:
        cmd.append(entry)
    cli_runner.invoke(nxpimage.main, cmd)
    assert os.path.isfile(out_file_path_new)

    with open(kek_key_path) as f:
        # transform text-based KEK into bytes
        sb_kek = unhexlify(f.read())

    # read generated secure binary image (created with new elf2sb)
    with open(out_file_path_new, "rb") as f:
        sb_file_data_new = f.read()

    sb_new = BootImageV21.parse(data=sb_file_data_new, kek=sb_kek)

    # dump the info of the secure binary image generated with new elf2sb
    # Left for debugging purposes
    # with open(os.path.join(nxpimage_data_dir, "SB_files/new_elf2sb_sb21_file.txt"), 'w') as sb_file_content:
    #     sb_file_content.write(sb_new.__str__())

    # read SB file generated using legacy elftosb
    with open(out_file_path_legacy, "rb") as f:
        sb_file_data_old = f.read()

    # we assume that SB File version is 2.1
    sb_old = BootImageV21.parse(data=sb_file_data_old, kek=sb_kek)

    # dump the info of the secure binary image generated with legacy elftosb
    # Left for debugging purposes
    # with open(os.path.join(nxpimage_data_dir, "SB_files/old_elf2sb_sb21_file.txt"), 'w') as f:
    #     f.write(str(sb_old))

    sb_new_lines = str(sb_new).split("\n")
    sb_old_lines = str(sb_old).split("\n")

    DIGEST_LINE = 4
    TIMESTAMP_LINE = 14
    # Remove lines containing digest and timestamp, as these will always differ
    # -1 for indexing starting from 0
    del sb_new_lines[DIGEST_LINE - 1]
    # -1 for indexing starting from 0, -1 for previously removed line => -2
    del sb_new_lines[TIMESTAMP_LINE - 2]

    # -1 for indexing starting from 0
    del sb_old_lines[DIGEST_LINE - 1]
    # -1 for indexing starting from 0, -1 for previously removed line => -2
    del sb_old_lines[TIMESTAMP_LINE - 2]

    for i in zip_longest(sb_new_lines, sb_old_lines, fillvalue=None):
        assert i[0] == i[1]


@pytest.mark.parametrize(
    "family",
    [
        "lpc55s06",
        "lpc55s16",
        "lpc55s26",
        "lpc55s69",
        "mimxrt595s",
        "mimxrt685s",
    ],
)
def test_nxpimage_sb21_get_template(cli_runner: CliRunner, tmpdir: str, family: str) -> None:
    """Test SB21 get-template command functionality.

    Verifies that the nxpimage sb21 get-template command successfully generates
    a YAML configuration template file and validates its content structure.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory path for output file creation.
    :param family: Target MCU family name for template generation.
    """
    cmd = f"sb21 get-template -f {family} -o {tmpdir}/tmp.yaml"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/tmp.yaml")
    config = load_configuration(f"{tmpdir}/tmp.yaml")
    assert config["family"] == family


@pytest.mark.parametrize("bd_file,legacy_sb,external,family", SB21_TEST_CONFIGURATIONS)
def test_nxpimage_sb21_convert(
    cli_runner: CliRunner,
    bd_file: str,
    legacy_sb: str,
    external: list[str],
    nxpimage_data_dir: str,
    family: str,
    tmpdir: str,
) -> None:
    """Test SB21 convert functionality with CLI runner.

    This test verifies the complete SB21 conversion workflow by converting a BD file
    to YAML configuration, then exporting it to SB format, and comparing the result
    with a legacy SB file to ensure compatibility.

    :param cli_runner: CLI test runner instance for executing commands.
    :param bd_file: Relative path to the BD (Boot Data) file to convert.
    :param legacy_sb: Relative path to the legacy SB file for comparison.
    :param external: List of additional external command line arguments.
    :param nxpimage_data_dir: Absolute path to the test data directory.
    :param family: Target MCU family name for the conversion.
    :param tmpdir: Temporary directory path for output files.
    """
    with use_working_directory(nxpimage_data_dir):
        bd_file_path = os.path.join(nxpimage_data_dir, bd_file)
        out_file_path_new = os.path.join(tmpdir, "config.yaml")
        kek_key_path = os.path.join(nxpimage_data_dir, "sb_sources/keys/SBkek_PUF.txt")
        pkey = os.path.join(nxpimage_data_dir, "sb_sources/keys_and_certs/k0_cert0_2048.pem")

        certificate_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k0_signed_cert0_noca.der.cert"
        )
        root_key_certificate0_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k0_signed_cert0_noca.der.cert"
        )
        root_key_certificate1_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k1_signed_cert0_noca.der.cert"
        )
        root_key_certificate2_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k2_signed_cert0_noca.der.cert"
        )
        root_key_certificate3_path = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/root_k3_signed_cert0_noca.der.cert"
        )
        hash_of_hashes_output_path = os.path.join(tmpdir, "hash.bin")

        out_file_path_legacy = os.path.join(nxpimage_data_dir, legacy_sb)

        cmd = [
            "sb21",
            "convert",
            "-c",
            bd_file_path,
            "-o",
            out_file_path_new,
            "-k",
            kek_key_path,
            "-s",
            pkey,
            "-S",
            certificate_path,
            "-R",
            root_key_certificate0_path,
            "-R",
            root_key_certificate1_path,
            "-R",
            root_key_certificate2_path,
            "-R",
            root_key_certificate3_path,
            "-h",
            hash_of_hashes_output_path,
            "-f",
            family,
        ]
        for entry in external:
            cmd.append(entry)
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file_path_new)

        sb_file_path_new = os.path.join(tmpdir, "output.sb")

        cmd = ["sb21", "export", "-c", out_file_path_new, "-o", sb_file_path_new]

        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(sb_file_path_new)

        with open(kek_key_path) as f:
            # transform text-based KEK into bytes
            sb_kek = unhexlify(f.read())

        # read generated secure binary image (created with new elf2sb)
        with open(sb_file_path_new, "rb") as f:
            sb_file_data_new = f.read()

        sb_new = BootImageV21.parse(data=sb_file_data_new, kek=sb_kek)

        # dump the info of the secure binary image generated with new elf2sb
        # Left for debugging purposes
        # with open(os.path.join(nxpimage_data_dir, "SB_files/new_elf2sb_sb21_file.txt"), 'w') as sb_file_content:
        #     sb_file_content.write(sb_new.__str__())

        # read SB file generated using legacy elftosb
        with open(out_file_path_legacy, "rb") as f:
            sb_file_data_old = f.read()

        # we assume that SB File version is 2.1
        sb_old = BootImageV21.parse(data=sb_file_data_old, kek=sb_kek)

        # dump the info of the secure binary image generated with legacy elftosb
        # Left for debugging purposes
        # with open(os.path.join(nxpimage_data_dir, "SB_files/old_elf2sb_sb21_file.txt"), 'w') as f:
        #     f.write(str(sb_old))

        sb_new_lines = str(sb_new).split("\n")
        sb_old_lines = str(sb_old).split("\n")

        DIGEST_LINE = 4
        TIMESTAMP_LINE = 14
        # Remove lines containing digest and timestamp, as these will always differ
        # -1 for indexing starting from 0
        del sb_new_lines[DIGEST_LINE - 1]
        # -1 for indexing starting from 0, -1 for previously removed line => -2
        del sb_new_lines[TIMESTAMP_LINE - 2]

        # -1 for indexing starting from 0
        del sb_old_lines[DIGEST_LINE - 1]
        # -1 for indexing starting from 0, -1 for previously removed line => -2
        del sb_old_lines[TIMESTAMP_LINE - 2]

        for i in zip_longest(sb_new_lines, sb_old_lines, fillvalue=None):
            assert i[0] == i[1]


def test_sb_21_invalid_signature_provider(
    cli_runner: CliRunner, tmpdir: str, nxpimage_data_dir: str
) -> None:
    """Test SB21 export command with invalid signature provider.

    Verifies that the nxpimage CLI properly handles and rejects invalid signature
    provider types when exporting SB21 images. The test expects the command to fail
    with an SPSDKError when an invalid signature provider type is specified.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory path for output files.
    :param nxpimage_data_dir: Path to test data directory containing SB sources.
    """
    with use_working_directory(nxpimage_data_dir):
        cmd = [
            "sb21",
            "export",
            "-c",
            os.path.join(nxpimage_data_dir, "sb_sources", "BD_files", "real_example1.bd"),
            "-o",
            os.path.join(tmpdir, "new_elf2sb.bin"),
            "-k",
            os.path.join(nxpimage_data_dir, "sb_sources", "keys", "SBkek_PUF.txt"),
            "-s",
            "type=invalid_sp",
            "-S",
            os.path.join(
                nxpimage_data_dir,
                "sb_sources",
                "keys_and_certs",
                "root_k0_signed_cert0_noca.der.cert",
            ),
            "-R",
            os.path.join(
                nxpimage_data_dir,
                "sb_sources",
                "keys_and_certs",
                "root_k0_signed_cert0_noca.der.cert",
            ),
            "-R",
            os.path.join(
                nxpimage_data_dir,
                "sb_sources",
                "keys_and_certs",
                "root_k1_signed_cert0_noca.der.cert",
            ),
            "-R",
            os.path.join(
                nxpimage_data_dir,
                "sb_sources",
                "keys_and_certs",
                "root_k2_signed_cert0_noca.der.cert",
            ),
            "-R",
            os.path.join(
                nxpimage_data_dir,
                "sb_sources",
                "keys_and_certs",
                "root_k3_signed_cert0_noca.der.cert",
            ),
            "-h",
            os.path.join(tmpdir, "hash.bin"),
        ]
        result = cli_runner.invoke(nxpimage.main, cmd, expected_code=1)
        assert result.exc_info
        assert issubclass(result.exc_info[0], SPSDKError)


def test_nxpimage_parse_cli(cli_runner: CliRunner, tmpdir: str, nxpimage_data_dir: str) -> None:
    """Test nxpimage CLI parsing functionality for SB21 files.

    This test verifies that the nxpimage CLI can successfully parse a legacy SB21 file
    and generate the expected output files including certificates, parsed information,
    and section data files.

    :param cli_runner: CLI test runner for invoking command line interface.
    :param tmpdir: Temporary directory path for test output files.
    :param nxpimage_data_dir: Path to directory containing test data files.
    """
    with use_working_directory(f"{nxpimage_data_dir}/sb_sources"):
        parsed_output = f"{tmpdir}/parsed_sb"
        cmd = f"sb21 parse -b SB_files/legacy_real_example1.sb -k keys/SBkek_PUF.txt -o {parsed_output}"
        cli_runner.invoke(nxpimage.main, cmd.split())

        assert os.path.isfile(os.path.join(parsed_output, "certificate_0_der.cer"))
        assert os.path.isfile(os.path.join(parsed_output, "parsed_info.txt"))
        assert os.path.isfile(os.path.join(parsed_output, "section_0_load_command_3_data.bin"))
        assert os.path.isfile(os.path.join(parsed_output, "section_0_load_command_9_data.bin"))


def test_nxpimage_parse_cli_invalid(
    cli_runner: CliRunner, tmpdir: str, nxpimage_data_dir: str
) -> None:
    """Test CLI parsing of invalid/corrupted SB2.1 file.

    This test verifies that the nxpimage CLI properly handles and reports errors
    when attempting to parse a corrupted Secure Binary 2.1 file with valid keys.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory path for test output files.
    :param nxpimage_data_dir: Path to test data directory containing SB files and keys.
    """
    with use_working_directory(f"{nxpimage_data_dir}/sb_sources"):
        parsed_output = f"{tmpdir}/parsed_sb"
        cmd = f"sb21 parse -b SB_files/corrupted.sb -k keys/SBkek_PUF.txt -o {parsed_output}"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=1)


@pytest.mark.parametrize("bd_file,legacy_sb,external,family", SB21_TEST_CONFIGURATIONS)
def test_nxpimage_sb21_hex_values(
    bd_file: str,
    legacy_sb: str,
    external: list[str],
    nxpimage_data_dir: str,
    family: str,
    tmpdir: str,
) -> None:
    """Test that hexadecimal values in SB21 configuration are properly accepted and processed.

    This test verifies that the BootImageV21 class can handle configuration files where
    numeric values are provided as hexadecimal strings instead of integers. It converts
    various numeric fields (flags, addresses, patterns, lengths) to hex format and
    ensures the boot image can still be created successfully.

    :param bd_file: Path to the boot descriptor file containing SB21 configuration
    :param legacy_sb: Path to legacy secure boot file for reference
    :param external: List of external file paths referenced in the configuration
    :param nxpimage_data_dir: Directory containing test data files and certificates
    :param family: Target MCU family name for the boot image
    :param tmpdir: Temporary directory path for output files
    """
    with use_working_directory(nxpimage_data_dir):
        parsed_config = BootImageV21.parse_sb21_config(bd_file, external_files=external)

        # update all options which may be also a hex string
        parsed_config["options"]["flags"] = hex(parsed_config["options"]["flags"])
        for key_blob in parsed_config.get("keyblobs", {}):
            if isinstance(key_blob["keyblob_content"], list):
                key_blob["keyblob_content"][0]["start"] = hex(
                    key_blob["keyblob_content"][0]["start"]
                )
                key_blob["keyblob_content"][0]["end"] = hex(key_blob["keyblob_content"][0]["end"])
            else:
                key_blob["keyblob_content"]["start"] = hex(key_blob["keyblob_content"]["start"])
                key_blob["keyblob_content"]["end"] = hex(key_blob["keyblob_content"]["end"])
        for section in parsed_config.get("sections", {}):
            for command in section.get("commands", {}):
                if "address" in command:
                    command["address"] = hex(command["address"])
                elif "pattern" in command:
                    command["pattern"] = hex(command["pattern"])
                elif "length" in command:
                    command["length"] = hex(command["length"])

        root_key_certs = [
            os.path.join(
                nxpimage_data_dir, "sb_sources/keys_and_certs/root_k0_signed_cert0_noca.der.cert"
            ),
            os.path.join(
                nxpimage_data_dir, "sb_sources/keys_and_certs/root_k1_signed_cert0_noca.der.cert"
            ),
            os.path.join(
                nxpimage_data_dir, "sb_sources/keys_and_certs/root_k2_signed_cert0_noca.der.cert"
            ),
            os.path.join(
                nxpimage_data_dir, "sb_sources/keys_and_certs/root_k3_signed_cert0_noca.der.cert"
            ),
        ]
        parsed_config["signer"] = os.path.join(
            nxpimage_data_dir, "sb_sources/keys_and_certs/k0_cert0_2048.pem"
        )
        sb2 = BootImageV21.load_from_config(
            config=parsed_config,
            key_file_path=os.path.join(nxpimage_data_dir, "sb_sources/keys/SBkek_PUF.txt"),
            signing_certificate_file_paths=[
                os.path.join(
                    nxpimage_data_dir,
                    "sb_sources/keys_and_certs/root_k0_signed_cert0_noca.der.cert",
                )
            ],
            root_key_certificate_paths=root_key_certs,
            rkth_out_path=os.path.join(tmpdir, "hash.bin"),
        )
        sb2.export()


@pytest.mark.parametrize("conf", ["conf1", "conf2", "conf3", "conf4", "conf5", "conf6"])
def test_nxpimage_sb21_yaml(
    cli_runner: CliRunner, conf: str, nxpimage_data_dir: str, tmpdir: str
) -> None:
    """Test SB21 YAML configuration file processing and binary generation.

    This test validates the nxpimage SB21 export functionality by:
    1. Processing a YAML configuration file to generate a secure binary
    2. Parsing both the newly generated and reference binaries using KEK
    3. Comparing the parsed content while excluding timestamp and digest fields
    4. Ensuring the generated binary matches the reference implementation

    :param cli_runner: Click CLI test runner for invoking nxpimage commands
    :param conf: Configuration directory name containing the test YAML files
    :param nxpimage_data_dir: Path to the test data directory with SB sources
    :param tmpdir: Temporary directory path for output files
    """
    KEK_PATH = os.path.join(nxpimage_data_dir, "sb_sources/keys/SBkek_PUF.txt")
    with use_working_directory(nxpimage_data_dir):
        # for conf in conf_dir:
        conf_path = os.path.join(nxpimage_data_dir, "sb_sources", "YAML_files", conf, "config.yaml")
        ref_binary, new_binary, new_config = process_config_file(conf_path, tmpdir)
        cmd = [
            "sb21",
            "export",
            "-c",
            new_config,
        ]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(new_binary)
        ref_path = os.path.join(nxpimage_data_dir, "sb_sources", "YAML_files", conf, ref_binary)

        with open(KEK_PATH) as f:
            # transform text-based KEK into bytes
            sb_kek = unhexlify(f.read())

        # read generated secure binary image
        with open(new_binary, "rb") as f:
            sb_file_data_new = f.read()

        sb_new = BootImageV21.parse(data=sb_file_data_new, kek=sb_kek)

        # # read reference SB file
        with open(ref_path, "rb") as f:
            sb_file_data_old = f.read()

        sb_old = BootImageV21.parse(data=sb_file_data_old, kek=sb_kek)

        sb_new_lines = str(sb_new).split("\n")
        sb_old_lines = str(sb_old).split("\n")

        DIGEST_LINE = 4
        TIMESTAMP_LINE = 14
        # Remove lines containing digest and timestamp, as these will always differ
        # -1 for indexing starting from 0
        del sb_new_lines[DIGEST_LINE - 1]
        # -1 for indexing starting from 0, -1 for previously removed line => -2
        del sb_new_lines[TIMESTAMP_LINE - 2]

        # -1 for indexing starting from 0
        del sb_old_lines[DIGEST_LINE - 1]
        # -1 for indexing starting from 0, -1 for previously removed line => -2
        del sb_old_lines[TIMESTAMP_LINE - 2]

        for i in zip_longest(sb_new_lines, sb_old_lines, fillvalue=None):
            assert i[0] == i[1]


@pytest.mark.parametrize("conf", ["advanced_params"])
def test_nxpimage_sb21_zero_padding(
    cli_runner: CliRunner, conf: str, nxpimage_data_dir: str, tmpdir: str
) -> None:
    """Test SB21 zero padding functionality with CLI export command.

    This test verifies that the SB21 export command generates a secure binary image
    that matches the reference binary when zero padding is applied. It processes
    a configuration file, exports the SB21 image, and compares the generated
    binary with the expected reference file.

    :param cli_runner: CLI test runner for invoking nxpimage commands.
    :param conf: Configuration directory name containing test files.
    :param nxpimage_data_dir: Base directory path containing test data files.
    :param tmpdir: Temporary directory path for output files.
    :raises AssertionError: When generated binary doesn't match reference or file doesn't exist.
    """
    with use_working_directory(nxpimage_data_dir):
        # for conf in conf_dir:
        conf_path = os.path.join(nxpimage_data_dir, "sb_sources", "YAML_files", conf, "config.yaml")
        ref_binary, new_binary, new_config = process_config_file(conf_path, tmpdir)
        cmd = [
            "sb21",
            "export",
            "-c",
            new_config,
        ]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(new_binary)
        ref_path = os.path.join(nxpimage_data_dir, "sb_sources", "YAML_files", conf, ref_binary)

        # read generated secure binary image
        with open(new_binary, "rb") as f:
            sb_file_data_new = f.read()

        # # read reference SB file
        with open(ref_path, "rb") as f:
            sb_file_data_old = f.read()

        assert sb_file_data_new == sb_file_data_old
