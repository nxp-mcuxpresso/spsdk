#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK nxpcrypto command-line tool test suite.

This module contains comprehensive tests for the nxpcrypto CLI application,
covering cryptographic operations, key management, certificate handling,
and signature operations within the SPSDK framework.
"""

import filecmp
import glob
import hashlib
import logging
import os
import shutil
from itertools import zip_longest
from typing import Optional, Type, Union
from unittest.mock import patch

import pytest
from click.testing import Result

from spsdk.apps import nxpcrypto
from spsdk.crypto.certificate import Certificate
from spsdk.crypto.crc import Crc, CrcAlg, from_crc_algorithm
from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.keys import (
    IS_DILITHIUM_SUPPORTED,
    IS_OSCCA_SUPPORTED,
    ECDSASignature,
    PrivateKey,
    PrivateKeyRsa,
    PublicKey,
    PublicKeyDilithium,
    PublicKeyRsa,
)
from spsdk.exceptions import SPSDKError, SPSDKIndexError, SPSDKKeyError, SPSDKSyntaxError
from spsdk.utils.misc import Endianness, load_binary, load_text, use_working_directory, write_file
from tests.cli_runner import CliRunner
from tests.misc import GetPassMock

if IS_DILITHIUM_SUPPORTED:
    from spsdk_pqc.wrapper import DILITHIUM_LEVEL, KEY_INFO

    from spsdk.crypto.keys import PrivateKeyDilithium


def run_nxpcrypto(cli_runner: CliRunner, cmd: str, cwd: str, expected_code: int = 0) -> Result:
    """Run nxpcrypto CLI command in specified working directory.

    This function executes a nxpcrypto command using the provided CLI runner
    within a specific working directory context and validates the exit code.

    :param cli_runner: Click CLI runner instance for command execution.
    :param cmd: Command string to be executed (will be split on spaces).
    :param cwd: Working directory path where the command should be executed.
    :param expected_code: Expected exit code for command validation.
    :return: Click Result object containing command execution details.
    """
    with use_working_directory(cwd):
        logging.debug(f"Running {cmd}")
        result = cli_runner.invoke(nxpcrypto.main, cmd.split(), expected_code=expected_code)
    return result


@pytest.mark.parametrize(
    "key1, key2, expected_result",
    [
        ("prk_secp256_d_3.pem", "puk_secp256_d_3.pem", 0),
        ("prk_secp256_d_5.der", "puk_secp256_d_5.der", 0),
        ("prk_secp256_d_5.der", "puk_secp256_d_5.pem", 0),
        ("prk_secp256_d_3.bin", "puk_secp256_d_5.bin", 1),
        ("prk_secp256_d_3.pem", "puk_secp256_d_5.der", 1),
        ("prk_rsa4096.pem", "puk_rsa4096.pem", 0),
    ],
)
def test_nxpcrypto_key_verify(
    cli_runner: CliRunner, data_dir: str, key1: str, key2: str, expected_result: int
) -> None:
    """Test nxpcrypto key verification command functionality.

    This test verifies that the nxpcrypto CLI key verify command works correctly
    by comparing two keys and checking the expected result code.

    :param cli_runner: Click CLI test runner for executing commands.
    :param data_dir: Directory path containing test data files.
    :param key1: First key file path or identifier for comparison.
    :param key2: Second key file path or identifier for comparison.
    :param expected_result: Expected exit code from the command execution.
    """
    cmd = f"key verify -k1 {key1} -k2 {key2}"
    run_nxpcrypto(cli_runner, cmd, data_dir, expected_result)


@pytest.mark.parametrize(
    "key, transform, expected",
    [
        ("prk_secp256_d_3.bin", "-e pem", "prk_secp256_d_3.pem"),
        ("prk_secp256_d_3.pem", "-e raw", "prk_secp256_d_3.bin"),
        ("prk_secp256_d_3.bin", "-e pem --puk", "puk_secp256_d_3.pem"),
        ("puk_secp256_d_5.pem", "-e der", "puk_secp256_d_5.der"),
        ("prk_rsa4096.pem", "-e der", "prk_rsa4096.der"),
        ("prk_rsa4096.pem", "-e pem --puk", "puk_rsa4096.pem"),
    ],
)
def test_nxpcrypto_key_convert(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, key: str, transform: str, expected: str
) -> None:
    """Test nxpcrypto key conversion functionality.

    This test validates the key conversion command by converting a key using the specified
    transformation and comparing the output with the expected result. Different validation
    methods are used based on the transformation type: raw conversions compare integer
    values to handle padding differences, DER conversions use direct file comparison,
    and PEM conversions compare line-by-line to handle line-ending differences.

    :param cli_runner: Click CLI test runner for executing commands.
    :param data_dir: Directory containing test data files.
    :param tmpdir: Temporary directory for output files.
    :param key: Input key identifier or filename.
    :param transform: Transformation type to apply (raw, der, or pem).
    :param expected: Expected output filename for comparison.
    """
    src_key = f"{data_dir}/{expected}"
    dst_key = f"{tmpdir}/{expected}"
    cmd = f"key convert -i {key} {transform} -o {dst_key}"
    run_nxpcrypto(cli_runner, cmd, data_dir)

    # to validate RAW conversion we need to compare raw data as INT (there might be difference in padding)
    if "raw" in transform:
        src_num = int.from_bytes(load_binary(src_key), byteorder=Endianness.BIG.value)
        dst_num = int.from_bytes(load_binary(dst_key), byteorder=Endianness.BIG.value)
        assert src_num == dst_num
    # DER conversion is fine
    if "der" in transform:
        assert filecmp.cmp(src_key, dst_key)
    # in PEM we need to care about line-endings
    if "pem" in transform:
        src_lines = load_text(src_key).splitlines(keepends=False)
        dst_lines = load_text(dst_key).splitlines(keepends=False)
        # zip_longest ensures there will be an error if one file is longer
        for src_line, dst_line in zip_longest(src_lines, dst_lines):
            assert src_line == dst_line


@pytest.mark.parametrize(
    "key, encoding, expected",
    [
        ("prk_secp256_d_3.bin", "pem", "prk_secp256_d_3.pem"),
        ("prk_secp256_d_3.pem", "raw", "prk_secp256_d_3.bin"),
        ("prk_secp256_d_3.bin", "der", "puk_secp256_d_3.pem"),
        ("puk_secp256_d_5.pem", "der", "puk_secp256_d_5.der"),
        ("puk_secp256_d_5.bin", "der", "puk_secp256_d_5.der"),
        ("prk_rsa4096.pem", "der", "prk_rsa4096.der"),
        ("prk_rsa4096.pem", "pem", "puk_rsa4096.pem"),
    ],
)
def test_nxpcrypto_extract_puk(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, key: str, encoding: str, expected: str
) -> None:
    """Test extraction of public key from private key using nxpcrypto CLI.

    This test verifies that the nxpcrypto key convert command can successfully
    extract a public key from a private key file and that the extracted public
    key matches the expected public key component of the original private key.

    :param cli_runner: Click CLI test runner for executing commands.
    :param data_dir: Directory containing test data files.
    :param tmpdir: Temporary directory for output files.
    :param key: Input key file name or identifier.
    :param encoding: Key encoding format for conversion.
    :param expected: Expected output file name.
    :raises AssertionError: If extracted public key doesn't match expected key.
    """
    src_key = f"{data_dir}/{expected}"
    dst_key = f"{tmpdir}/{expected}"
    cmd = f"key convert -i {key} -e {encoding} --puk -o {dst_key}"
    run_nxpcrypto(cli_runner, cmd, data_dir)

    src_key_data = load_binary(src_key)
    prk = nxpcrypto.reconstruct_key(src_key_data)
    dst_key_data = load_binary(dst_key)
    puk = nxpcrypto.reconstruct_key(dst_key_data)
    try:
        if isinstance(prk, PrivateKey):
            assert prk.get_public_key() == puk
        else:
            assert prk == puk
    except AttributeError:  # in case input key is public
        assert prk == puk


def test_nxpcrypto_convert_rsa_raw_not_supported(
    cli_runner: CliRunner, data_dir: str, tmpdir: str
) -> None:
    """Test that RSA key conversion to raw format is not supported.

    This test verifies that attempting to convert an RSA key to raw binary format
    fails with the expected error code and exception type, as raw format conversion
    is not supported for RSA keys.

    :param cli_runner: Click CLI test runner for executing commands.
    :param data_dir: Directory path containing test data files.
    :param tmpdir: Temporary directory path for output files.
    """
    dst_key = f"{tmpdir}/prk_rsa4096.bin"
    cmd = f"key convert -i prk_rsa4096.pem -e raw -o {dst_key}"
    result = run_nxpcrypto(cli_runner, cmd, data_dir, expected_code=1)
    if result.exc_info is not None:
        assert result.exc_info[0] is SPSDKError


def test_generate_rsa_key(cli_runner: CliRunner, tmpdir: str) -> None:
    """Test RSA key pair generation functionality.

    This test verifies that the nxpcrypto CLI can successfully generate RSA key pairs,
    create both private and public key files, and that the generated keys have the
    correct properties and can be loaded properly.

    :param cli_runner: Click CLI runner instance for executing commands.
    :param tmpdir: Temporary directory path for storing generated key files.
    """

    cmd = f'{os.path.join(tmpdir, "key_rsa.pem")}'
    run_nxpcrypto(cli_runner, f"key generate -k rsa2048 -o {cmd}", tmpdir)
    assert os.path.isfile(os.path.join(tmpdir, "key_rsa.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "key_rsa.pub"))

    pub_key_from_file = PublicKeyRsa.load(os.path.join(tmpdir, "key_rsa.pub"))
    assert isinstance(pub_key_from_file, PublicKeyRsa)
    assert pub_key_from_file.key_size == 2048

    priv_key_from_file = PrivateKeyRsa.load(os.path.join(tmpdir, "key_rsa.pem"))
    assert priv_key_from_file.key_size == 2048


def test_generate_invalid_key(cli_runner: CliRunner, tmpdir: str) -> None:
    """Test generate invalid key pair command.

    Verifies that the key generation command fails appropriately when provided
    with an invalid key type and ensures no output files are created.

    :param cli_runner: Click CLI runner for executing commands.
    :param tmpdir: Temporary directory path for test files.
    """

    cmd = f'key generate -k invalid-key-type -o {os.path.join(tmpdir, "key_invalid.pem")}'
    run_nxpcrypto(cli_runner, cmd, tmpdir, expected_code=-1)
    assert not os.path.isfile(os.path.join(tmpdir, "key_invalid.pem"))
    assert not os.path.isfile(os.path.join(tmpdir, "key_invalid.pub"))


def test_force_actual_dir(cli_runner: CliRunner, tmpdir: str) -> None:
    """Test force flag functionality for key generation in actual directory.

    This test verifies that the --force flag works correctly when generating keys
    in a real directory. It checks that key generation fails when attempting to
    overwrite an existing key without the force flag, and succeeds when the force
    flag is provided.

    :param cli_runner: Click CLI test runner for executing commands.
    :param tmpdir: Temporary directory path for test file operations.
    """
    run_nxpcrypto(cli_runner, "key generate -k rsa2048 -o key", tmpdir)
    # attempt to rewrite the key should fail
    run_nxpcrypto(cli_runner, "key generate -k rsa2048 -o key", tmpdir, expected_code=1)
    # attempt to rewrite should pass due to --forces
    run_nxpcrypto(cli_runner, "key generate -k rsa2048 -o key --force", tmpdir)


@pytest.mark.parametrize(
    "key, valid",
    [
        ("secp256r1", True),
        ("secp384r1", True),
        ("secp521r1", True),
    ],
)
def test_key_types(cli_runner: CliRunner, tmpdir: str, key: str, valid: bool) -> None:
    """Test key generation functionality for different key types.

    This test verifies that the nxpcrypto CLI tool can generate cryptographic keys
    for valid key types and properly handles invalid key types with appropriate
    error codes.

    :param cli_runner: CLI test runner instance for executing commands
    :param tmpdir: Temporary directory path for output files
    :param key: Key type string to test (e.g., 'rsa2048', 'secp256r1')
    :param valid: Boolean flag indicating if the key type should be valid
    """
    if valid:
        run_nxpcrypto(cli_runner, f"key generate -k {key} -o my_key_{key}.pem", tmpdir)
        assert os.path.isfile(os.path.join(tmpdir, f"my_key_{key}.pem"))
        assert os.path.isfile(os.path.join(tmpdir, f"my_key_{key}.pub"))
    else:
        run_nxpcrypto(
            cli_runner, f"key generate -k {key} -o my_key_{key}.pem", tmpdir, expected_code=-1
        )


@pytest.mark.parametrize(
    "keys, family, ref_rotkth, base64",
    [
        (
            ["ec_secp256r1_cert0.pem"],
            "mcxn9xx",
            "671e3f7108621830c08df03c339d2ce9700c0a4bd74f7bfbcc48fbe27c78bf05",
            False,
        ),
        (
            ["ec_secp256r1_cert0.pem", "ec_secp256r1_cert1.pem"],
            "mcxn9xx",
            "8ba978ef5dd132a4462d8f93abdba11c89d3f8060b3dd4ba6d6d5c9fbb7c38fa",
            False,
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "mcxn9xx",
            "3f1f71ccd8dfcbcff3e445c21f003a974f8c40ce9aa7d8c567416b9ab45d1655",
            False,
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "rw61x",
            "3f1f71ccd8dfcbcff3e445c21f003a974f8c40ce9aa7d8c567416b9ab45d1655",
            False,
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "kw45xx",
            "3f1f71ccd8dfcbcff3e445c21f003a974f8c40ce9aa7d8c567416b9ab45d1655",
            False,
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "k32w1xx",
            "3f1f71ccd8dfcbcff3e445c21f003a974f8c40ce9aa7d8c567416b9ab45d1655",
            False,
        ),
        (
            ["ec_secp256r1_cert0.pem"],
            "lpc55s0x",
            "7eb98e20a565ba54e866a3920967c3a56a1acf07043ab08fc36a90d55a6e0eb0",
            False,
        ),
        (
            ["ec_secp256r1_cert0.pem", "ec_secp256r1_cert1.pem"],
            "lpc55s0x",
            "3e3bfcd794c998eeaef6347a2a438ec36e5e5132d350d31fcbd927bfcc120c9e",
            False,
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "lpc55s0x",
            "3f1f71ccd8dfcbcff3e445c21f003a974f8c40ce9aa7d8c567416b9ab45d1655",
            False,
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "mimxrt1189",
            "34f1cd4517440f815cf57ae9f80346c74cff8804f8f5fb02b202657271e94d81",
            False,
        ),
        (
            [
                "SRK1_sha256_secp384r1_v3_ca_crt.pem",
                "SRK2_sha256_secp384r1_v3_ca_crt.pem",
                "SRK3_sha256_secp384r1_v3_ca_crt.pem",
                "SRK4_sha256_secp384r1_v3_ca_crt.pem",
            ],
            "mimxrt1176",
            "bcd8f444bd7f9ccd8048a8bcf8c2764f085058ed527c6978037a94ffb81c14e8",
            False,
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "mimxrt1189",
            "NPHNRRdED4Fc9Xrp+ANGx0z/iAT49fsCsgJlcnHpTYE=",
            True,
        ),
    ],
)
def test_nxpcrypto_rot_calc_hash(
    cli_runner: CliRunner,
    data_dir: str,
    tmpdir: str,
    keys: list,
    family: str,
    ref_rotkth: str,
    base64: bool,
) -> None:
    """Test NXP Crypto ROT hash calculation command.

    This test verifies the 'rot calculate-hash' command functionality by running it with
    specified parameters and validating the generated hash output against a reference value.

    :param cli_runner: Click CLI test runner for executing commands.
    :param data_dir: Directory path containing test data files.
    :param tmpdir: Temporary directory path for output files.
    :param keys: List of key file paths to be used for hash calculation.
    :param family: Target MCU family name for the operation.
    :param ref_rotkth: Reference ROT key table hash value for validation.
    :param base64: Flag indicating whether to use base64 encoding for output.
    :raises AssertionError: If output file is not created or hash doesn't match reference.
    """
    out_file = os.path.join(tmpdir, "rot_hash.bin")
    cmd = f"rot calculate-hash -f {family} -o {out_file}"
    for key in keys:
        cmd = " ".join([cmd, f"-k {key}"])
    if base64:
        cmd += " -b"
    run_nxpcrypto(cli_runner, cmd, data_dir)
    assert os.path.isfile(out_file)
    rotkth_bin = load_binary(out_file)
    rotkth = rotkth_bin.decode("utf-8") if base64 else rotkth_bin.hex()
    assert rotkth == ref_rotkth


@pytest.mark.parametrize(
    "keys, family, ref_rot",
    [
        (
            ["ec_secp256r1_cert0.pem"],
            "lpc55s0x",
            "rot_lpc550x_1_key.bin",
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "lpc55s0x",
            "rot_lpc550x.bin",
        ),
        (
            [
                "SRK1_sha256_secp384r1_v3_ca_crt.pem",
                "SRK2_sha256_secp384r1_v3_ca_crt.pem",
                "SRK3_sha256_secp384r1_v3_ca_crt.pem",
                "SRK4_sha256_secp384r1_v3_ca_crt.pem",
            ],
            "mimxrt1176",
            "rot_mimxrt1176.bin",
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "mimxrt1189",
            "rot_mimxrt1189.bin",
        ),
    ],
)
def test_nxpcrypto_rot_export(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, keys: list, family: str, ref_rot: str
) -> None:
    """Test NXP crypto ROT (Root of Trust) export functionality.

    This test verifies that the ROT export command correctly generates a binary file
    containing the Root of Trust table from provided keys and matches the expected
    reference output.

    :param cli_runner: Click CLI test runner for executing commands
    :param data_dir: Directory path containing test data files
    :param tmpdir: Temporary directory path for output files
    :param keys: List of key file paths to include in ROT table
    :param family: Target MCU family name for ROT generation
    :param ref_rot: Reference ROT file name for comparison
    """
    out_file = os.path.join(tmpdir, "rot_table.bin")
    ref_file = os.path.join(data_dir, ref_rot)
    cmd = f"rot export -f {family} -o {out_file}"
    for key in keys:
        cmd = " ".join([cmd, f"-k {key}"])
    run_nxpcrypto(cli_runner, cmd, data_dir)
    assert os.path.isfile(out_file)
    assert load_binary(out_file) == load_binary(ref_file)


@pytest.mark.parametrize(
    "keys, family, ref_rot",
    [
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "mimxrt1189",
            "rot_mimxrt1189.bin",
        ),
    ],
)
def test_nxpcrypto_rot_parse(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, keys: list, family: str, ref_rot: str
) -> None:
    """Test nxpcrypto rot parse command."""
    ref_file = os.path.join(data_dir, ref_rot)

    # Test the parse command
    parse_output_dir = os.path.join(tmpdir, "parsed_keys")
    parse_cmd = f"rot parse -f {family} -b {ref_file} -o {parse_output_dir}"

    result = run_nxpcrypto(cli_runner, parse_cmd, data_dir)

    # Verify parse command succeeded
    assert result.exit_code == 0
    assert os.path.isdir(parse_output_dir)

    # Verify public keys were extracted
    expected_key_files = [f"public_key_{i}.pem" for i in range(len(keys))]
    for key_file in expected_key_files:
        key_path = os.path.join(parse_output_dir, key_file)
        assert os.path.isfile(key_path), f"Expected key file {key_file} not found"

    # Verify correct number of keys extracted
    extracted_files = [f for f in os.listdir(parse_output_dir) if f.startswith("public_key_")]
    assert len(extracted_files) == len(
        keys
    ), f"Expected {len(keys)} keys, found {len(extracted_files)}"


def test_npxcrypto_cert_get_template(cli_runner: CliRunner, tmpdir: str) -> None:
    """Test NXPCRYPTO CLI certificate template generation functionality.

    Verifies that the 'cert get-template' command successfully creates a certificate
    template file at the specified output location.

    :param cli_runner: CLI test runner instance for invoking commands
    :param tmpdir: Temporary directory path for test file output
    :raises AssertionError: If the expected certificate template file is not created
    """
    cmd = ["cert", "get-template", "--output", f"{tmpdir}/cert.yml"]
    cli_runner.invoke(nxpcrypto.main, cmd)
    assert os.path.isfile(f"{tmpdir}/cert.yml")


@pytest.mark.parametrize("password", [None, "password123"])
@pytest.mark.parametrize(
    "key_type",
    ["SECP256R1", "SECP384R1", "SECP521R1", "RSA2048", "RSA4096"],
)
@pytest.mark.parametrize("encoding", ["PEM", "DER"])
def test_nxpcrypto_cert_generate(
    cli_runner: CliRunner,
    data_dir: str,
    tmpdir: str,
    key_type: str,
    password: Optional[str],
    encoding: str,
) -> None:
    """Test certificate generation workflow using nxpcrypto CLI commands.

    This test validates the complete certificate lifecycle including key generation,
    certificate creation, verification, and format conversion between PEM and DER.
    It tests both subject and issuer key pair generation, certificate generation
    from configuration, certificate verification against public key, and certificate
    format conversion operations.

    :param cli_runner: Click CLI test runner for invoking nxpcrypto commands
    :param data_dir: Directory containing test data files including cert.yaml configuration
    :param tmpdir: Temporary directory for storing generated files during test execution
    :param key_type: Type of cryptographic key to generate (e.g., 'rsa2048', 'secp256r1')
    :param password: Optional password for protecting the issuer private key
    :param encoding: Certificate encoding format ('PEM' or 'DER')
    """
    # Generate subject key pair
    subject_key = os.path.join(tmpdir, "subject_key.pem")
    subject_public_key = os.path.join(tmpdir, "subject_key.pub")
    cmd = ["key", "generate", "-k", key_type, "-o", subject_key, "-e", encoding]
    cli_runner.invoke(nxpcrypto.main, cmd)

    # Generate issuer key pair
    issuer_key = os.path.join(tmpdir, "issuer_key.pem")
    cmd = ["key", "generate", "-k", key_type, "-o", issuer_key, "-e", encoding]
    if password:
        cmd.extend(["--password", password])
    cli_runner.invoke(nxpcrypto.main, cmd)

    shutil.copy(os.path.join(data_dir, "cert.yaml"), tmpdir)
    crt_config = os.path.join(tmpdir, "cert.yaml")
    out_crt = os.path.join(tmpdir, "cert.crt")
    cmd = ["cert", "generate", "-c", crt_config, "-o", out_crt, "-e", encoding]

    with patch("spsdk.crypto.keys.getpass", GetPassMock(password)):
        cli_runner.invoke(nxpcrypto.main, cmd)
    assert os.path.isfile(out_crt)
    Certificate.load(out_crt)

    cmd = ["cert", "verify", "-c", out_crt, "-p", subject_public_key]
    result = cli_runner.invoke(nxpcrypto.main, cmd)
    assert "Public key in certificate matches the input" in result.output

    # Convert the certificate to DER
    cmd = ["cert", "convert", "-i", out_crt, "-e", "DER", "-o", f"{tmpdir}/cert.der"]
    result = cli_runner.invoke(nxpcrypto.main, cmd)
    assert os.path.isfile(f"{tmpdir}/cert.der")

    # Convert the certificate to PEM
    cmd = ["cert", "convert", "-i", f"{tmpdir}/cert.der", "-e", "PEM", "-o", f"{tmpdir}/cert.pem"]
    result = cli_runner.invoke(nxpcrypto.main, cmd)
    assert os.path.isfile(f"{tmpdir}/cert.pem")


SIGNATURE_NOT_MATCHING = "Signature IS NOT matching the public key"
SIGNATURE_MATCHING = "Signature IS matching the public key"


def get_key_path(data_dir: str, key_type: str) -> tuple[str, str]:
    """Get paths to pre-generated key pairs.

    This method constructs file paths for private and public key files based on the
    key type and validates that both files exist in the signature tool directory.

    :param data_dir: Base directory containing test data files.
    :param key_type: Type of cryptographic key (e.g., 'sm2', 'dil*', or standard types).
    :raises AssertionError: If private or public key files do not exist.
    :return: Tuple containing paths to private key file and public key file.
    """
    sign_data_dir = os.path.join(data_dir, "signature_tool")
    private_ext = "pem"
    if key_type == "sm2":
        private_ext = "der"
    if key_type.startswith("dil"):
        private_ext = "bin"

    private = os.path.join(sign_data_dir, f"{key_type}.{private_ext}")
    public = os.path.join(sign_data_dir, f"{key_type}.pub")
    assert os.path.isfile(private)
    assert os.path.isfile(public)
    return private, public


def run_signature(
    cli_runner: CliRunner,
    data_dir: str,
    tmpdir: str,
    key_type: str,
    algorithm: Optional[EnumHashAlgorithm],
) -> None:
    """Run signature creation and verification test.

    Tests the nxpcrypto signature creation command with specified key type and hash algorithm,
    then verifies the generated signature using the corresponding public key.

    :param cli_runner: CLI runner instance for executing commands.
    :param data_dir: Directory containing test data files and keys.
    :param tmpdir: Temporary directory for output files.
    :param key_type: Type of cryptographic key to use for signing.
    :param algorithm: Hash algorithm to use for signature creation, None for default.
    """
    priv_key, pub_key = get_key_path(data_dir, key_type)

    input_file = os.path.join(data_dir, "data_to_sign.bin")
    output_file = os.path.join(tmpdir, f"signature_{key_type}_{algorithm}.bin")

    cmd = f"signature create -s {priv_key} -i {input_file} -o {output_file}"
    if algorithm:
        cmd += f" --algorithm {algorithm.label}"
    run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert os.path.isfile(output_file)

    pub = PublicKey.load(pub_key)
    signature = load_binary(output_file)

    extra_params = {}
    if algorithm:
        extra_params["algorithm"] = algorithm
    assert pub.verify_signature(signature, load_binary(input_file), **extra_params)


@pytest.mark.parametrize(
    "key_type, algorithms",
    [
        ("secp256r1", [None, EnumHashAlgorithm.SHA256]),
        ("secp384r1", [None, EnumHashAlgorithm.SHA384]),
        ("secp521r1", [None, EnumHashAlgorithm.SHA512]),
        ("rsa2048", [None, EnumHashAlgorithm.SHA256]),
        ("rsa4096", [None, EnumHashAlgorithm.SHA256]),
    ],
)
def test_nxpcrypto_create_signature_algorithm_mandatory(
    cli_runner: CliRunner,
    data_dir: str,
    tmpdir: str,
    key_type: str,
    algorithms: list[Optional[EnumHashAlgorithm]],
) -> None:
    """Test nxpcrypto signature algorithm creation with mandatory parameters.

    This test method iterates through a list of hash algorithms and runs signature
    tests for each algorithm using the specified key type and test environment.

    :param cli_runner: Click CLI test runner for executing command-line operations.
    :param data_dir: Directory path containing test data files.
    :param tmpdir: Temporary directory path for test output files.
    :param key_type: Type of cryptographic key to use for signature testing.
    :param algorithms: List of hash algorithms to test, may contain None values.
    """
    for algorithm in algorithms:
        run_signature(cli_runner, data_dir, tmpdir, key_type, algorithm)


@pytest.mark.xfail(reason="Some Linux distributions allows only certain combinations of key-hash")
@pytest.mark.parametrize(
    "key_type, algorithms",
    [
        ("secp256r1", [EnumHashAlgorithm.SHA384, EnumHashAlgorithm.SHA512]),
        ("secp384r1", [EnumHashAlgorithm.SHA256, EnumHashAlgorithm.SHA512]),
        ("secp521r1", [EnumHashAlgorithm.SHA256, EnumHashAlgorithm.SHA384]),
        ("rsa2048", [EnumHashAlgorithm.SHA384, EnumHashAlgorithm.SHA512]),
        ("rsa4096", [EnumHashAlgorithm.SHA384, EnumHashAlgorithm.SHA512]),
    ],
)
def test_nxpcrypto_create_signature_algorithm_optional(
    cli_runner: CliRunner,
    data_dir: str,
    tmpdir: str,
    key_type: str,
    algorithms: list[Optional[EnumHashAlgorithm]],
) -> None:
    """Test nxpcrypto signature creation with optional algorithm parameter.

    This test function iterates through a list of hash algorithms (including None values)
    and runs signature operations for each one to verify that the nxpcrypto functionality
    works correctly with optional algorithm specifications.

    :param cli_runner: Click CLI test runner for executing command-line operations.
    :param data_dir: Directory path containing test data files.
    :param tmpdir: Temporary directory path for test output files.
    :param key_type: Type of cryptographic key to use for signature generation.
    :param algorithms: List of hash algorithms to test, may contain None values.
    """
    for algorithm in algorithms:
        run_signature(cli_runner, data_dir, tmpdir, key_type, algorithm)


@pytest.mark.skipif(not IS_OSCCA_SUPPORTED, reason="OSCCA support is not installed")
def test_nxpcrypto_create_signature_algorithm_oscca(
    cli_runner: CliRunner, data_dir: str, tmpdir: str
) -> None:
    """Test NXPCRYPTO signature creation with OSCCA SM3 algorithm.

    This test verifies that the NXPCRYPTO CLI can successfully create a digital signature
    using the SM3 hash algorithm (part of the OSCCA cryptographic standards) and validate
    the signature using the corresponding public key.

    :param cli_runner: Click CLI test runner for executing command line operations.
    :param data_dir: Directory path containing test data files including keys and input data.
    :param tmpdir: Temporary directory path for storing test output files.
    """
    input_file = os.path.join(data_dir, "data_to_sign.bin")
    output_file = os.path.join(tmpdir, "signature.bin")
    priv_key, pub_key = get_key_path(data_dir, "sm2")

    cmd = f"signature create -s {priv_key} -i {input_file} -o {output_file} -a sm3"
    run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert os.path.isfile(output_file)

    pub = PublicKey.load(pub_key)
    signature = load_binary(output_file)

    assert pub.verify_signature(signature, load_binary(input_file))


@pytest.mark.skipif(not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed")
@pytest.mark.parametrize(
    "level", PrivateKeyDilithium.SUPPORTED_LEVELS if IS_DILITHIUM_SUPPORTED else []
)  # this would fail on ImportError if not handled when pqc is not installed
def test_nxpcrypto_create_signature_algorithm_dilithium(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, level: int
) -> None:
    """Test Dilithium signature creation algorithm functionality.

    This test verifies that the nxpcrypto CLI can successfully create a digital signature
    using the Dilithium post-quantum cryptographic algorithm at the specified security level.
    It validates the signature creation process, output file generation, and signature
    verification using the corresponding public key.

    :param cli_runner: Click CLI test runner for executing command-line operations.
    :param data_dir: Directory path containing test data files including keys and input data.
    :param tmpdir: Temporary directory path for storing test output files.
    :param level: Dilithium security level parameter for key selection and validation.
    """
    input_file = os.path.join(data_dir, "data_to_sign.bin")
    output_file = os.path.join(tmpdir, "signature.bin")
    priv_key, pub_key = get_key_path(data_dir, f"dil{level}")

    cmd = f"signature create -s {priv_key} -i {input_file} -o {output_file}"
    run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert os.path.isfile(output_file)

    pub = PublicKey.load(pub_key)

    assert isinstance(pub, PublicKeyDilithium)
    signature = load_binary(output_file)

    assert len(signature) == KEY_INFO[DILITHIUM_LEVEL[level]].signature_size
    assert pub.verify_signature(signature, load_binary(input_file))


@pytest.mark.parametrize("signature_provider", [True, False])
@pytest.mark.parametrize(
    "encoding",
    [SPSDKEncoding.DER, SPSDKEncoding.NXP],
)
@pytest.mark.parametrize(
    "key_type",
    [
        "secp256r1",
        "secp384r1",
        "secp521r1",
        "rsa2048",
        "rsa4096",
        pytest.param(
            "sm2",
            marks=pytest.mark.skipif(
                not IS_OSCCA_SUPPORTED, reason="OSCCA support is not installed"
            ),
        ),
        pytest.param(
            "dil2",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "dil3",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "dil5",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
    ],
)
def test_nxpcrypto_signature_create_signature_encoding(
    cli_runner: CliRunner,
    data_dir: str,
    signature_provider: bool,
    key_type: str,
    encoding: SPSDKEncoding,
    tmpdir: str,
) -> None:
    """Test signature creation with different encodings using nxpcrypto CLI.

    This test verifies that the nxpcrypto signature create command properly handles
    different signature encodings for various key types (ECDSA, RSA, Dilithium).
    It creates a signature file and validates the encoding format and size based
    on the key type used.

    :param cli_runner: Click CLI test runner for executing commands.
    :param data_dir: Directory path containing test data files.
    :param signature_provider: Flag indicating whether to use signature provider format.
    :param key_type: Type of cryptographic key to use for signing.
    :param encoding: SPSDK encoding format for the signature output.
    :param tmpdir: Temporary directory path for output files.
    """
    priv_key, _ = get_key_path(data_dir, key_type)

    input_file = os.path.join(data_dir, "data_to_sign.bin")
    output_file = os.path.join(tmpdir, "signature.bin")
    cmd = f"signature create -i {input_file} -o {output_file} -e {encoding.value} "
    cmd += f"-s type=file;file_path={priv_key}" if signature_provider else f"-s {priv_key}"
    run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert os.path.isfile(output_file)

    signature = load_binary(output_file)
    if "secp" in key_type or "sm2" == key_type:
        assert ECDSASignature.get_encoding(signature) == encoding
    if "rsa" in key_type:
        assert len(signature) == {"rsa2048": 256, "rsa4096": 512}[key_type]
    if "dil" in key_type:
        assert (
            len(signature)
            == KEY_INFO[DILITHIUM_LEVEL[int(key_type.replace("dil", ""))]].signature_size
        )


@patch("spsdk.crypto.keys.getpass", GetPassMock("test1234"))
@pytest.mark.parametrize(
    "key_type",
    ["secp256r1", "secp384r1", "secp521r1", "rsa2048", "rsa4096"],
)
def test_nxpcrypto_create_signature_password(
    cli_runner: CliRunner, data_dir: str, key_type: str, tmpdir: str
) -> None:
    """Test nxpcrypto signature creation with password-protected keys.

    This test verifies that the nxpcrypto CLI can create digital signatures using
    password-protected private keys. It tests both command-line password input
    and interactive password prompting scenarios.

    :param cli_runner: Click CLI test runner for executing commands.
    :param data_dir: Directory path containing test data files.
    :param key_type: Type of cryptographic key to generate for testing.
    :param tmpdir: Temporary directory path for test file operations.
    """
    password = "test1234"
    priv_key_path = os.path.join(tmpdir, "key.pem")

    cmd = f"key generate -k {key_type} -o {priv_key_path} --password {password}"
    run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert os.path.isfile(priv_key_path)

    input_file = os.path.join(data_dir, "data_to_sign.bin")
    # Password as cmd input
    out = os.path.join(tmpdir, "signature_1.bin")
    cmd = f"signature create -s {priv_key_path} -i {input_file} -o {out} --password {password}"
    run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert os.path.isfile(out)

    # Password as interactive prompt
    out = os.path.join(tmpdir, "signature_2.bin")
    cmd = f"signature create -s {priv_key_path} -i {input_file} -o {out}"
    run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert os.path.isfile(out)


@pytest.mark.parametrize(
    "key_type, regions, signature",
    [
        (
            "rsa2048",
            ["[:10]"],
            "76c3221ffa8f58ed3649ccbc8ce4924649c9142e08256d22d6daa39fdb72207167a44b383fabd3eac52f734db6778f0b49739b1866d2cb652c464526d8585f5ba1e199ca50d0e7c99c1c81aee105d29212a0b9b00f224839ac9d5a1a2819128f49eb6cfe44db5b471e69ff7c2289a9f85609cbc1c687b1c3dd1bf344495f12c27211a3fae7886a96ed9de37bf43522584aa719a3b7128536857449c12f3ddbfd6a7786e2047ce8b9e6446f5ffc3fd18c19278e4667e252758627631698295b50f129ae96255b3d2ae1e3b981a96f7fc7d9298290141b4db2a5fe6fb224ad54109c5d4cc6a39ed8f04fd6af2959b187d344afc186b3b7abc1954fba5c4da0ee0f",
        ),
        (
            "rsa2048",
            ["[-10:]"],
            "41bc090357946fd809e61ce2e32b19e93cb4e5317bd8b4374671ae8e5e9e90e29bb833c5ec574ab13091145fc6147784af7df4210f7acadc0a407b44fb67dcd1b402e7e166d844dfb9afb366f7828c278f006072b021faecf22fed9c0d8deaef092ec63d94d3bef63fba4c909fdc556315b583b728217967db885b5943e3db8298a9b1d7e4ee65cbc6465dd275e1dc2992eb5ec0867aa20d1668fd813e85bcaad17e255910a7a14d8e6bef069922e511eca797ceb998d1e9eb0722b9f12b2e656e10de105aaa1ab031fac69e5dbbab02dd26adb7de8fb1e8a54efafd84c00690920a5135347fb4ff9ce7b86e60469601065cf346431100fd32bd90a3d45aa76f",
        ),
        (
            "rsa2048",
            ["[5:10]", "[-5:]"],
            "3c85fb947e646655cecd6138702801e7ad43b47396ff5fc61080e89ae7eee08512d34382d1ac53f3bcd809f7ca80665863087b2a907a1d06016f27584a332e927d6b98df37ef7a9ea0400bd2dd4a7f9bad0749a61f1ee0f311fc35e55fe06a5ef662ecac88b1c0e312398367b003e403100c491b6454aa5e2eda8026eeaccf8c97f51d450601c231398ebb41af0ef33be690feb06f8130ba2f0dae284fd876466140693891d0acf7752c46aa9677a1d1458cb301ae6d4ccaf1b62c06d9309c791e5a9f8dc394ff73b5f5fd9979dc9b3d801128d8199f64ff26cac3e3635637b540871b41ed2a80002ad2d17441d794b0baf5c3ba28b02c89f3be02f37def3f10",
        ),
    ],
)
def test_nxpcrypto_create_signature_regions_rsa(
    cli_runner: CliRunner,
    data_dir: str,
    key_type: str,
    regions: list[str],
    signature: str,
    tmpdir: str,
) -> None:
    """Test RSA signature creation and verification with regions.

    This test verifies the complete workflow of creating an RSA signature with specific
    regions and then verifying it. It tests both negative case (verification without
    regions should fail) and positive case (verification with matching regions should succeed).

    :param cli_runner: Click CLI runner for executing commands.
    :param data_dir: Directory containing test data files.
    :param key_type: Type of cryptographic key to use for signing.
    :param regions: List of region specifications for signature creation.
    :param signature: Expected signature value in hexadecimal format.
    :param tmpdir: Temporary directory for output files.
    """
    priv_key, pub_key = get_key_path(data_dir, key_type)

    input_file = os.path.join(data_dir, "data_to_sign.bin")
    out = os.path.join(tmpdir, "signature.bin")
    cmd = f"signature create -s {priv_key} -i {input_file} -o {out}"
    for region in regions:
        cmd += f" -r {region}"
    run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert os.path.isfile(out)
    gen_signature = load_binary(out)
    assert gen_signature.hex() == signature

    cmd = f"signature verify -k {pub_key} -i {input_file} -s {out}"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert SIGNATURE_NOT_MATCHING in result.output

    for region in regions:
        cmd += f" -r {region}"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert SIGNATURE_MATCHING in result.output


@pytest.mark.parametrize(
    "regions, exception",
    [
        (["[:33]"], None),
        (["[-33:]"], None),
        (["[33]"], SPSDKIndexError),
        (["[:20]", "[21:25]", "[33]"], SPSDKIndexError),
        (["[:33:1:5]"], SPSDKSyntaxError),
        (["blabla"], SPSDKSyntaxError),
    ],
)
def test_nxpcrypto_create_signature_regions_rsa_invalid(
    cli_runner: CliRunner,
    data_dir: str,
    tmpdir: str,
    regions: list[str],
    exception: Optional[Type[Exception]],
) -> None:
    """Test RSA signature creation with invalid region parameters.

    This test verifies that the nxpcrypto signature creation command properly handles
    invalid region specifications when using RSA keys, ensuring appropriate error
    handling and exit codes.

    :param cli_runner: Click CLI test runner for command execution.
    :param data_dir: Directory containing test data files.
    :param tmpdir: Temporary directory for output files.
    :param regions: List of region specifications to test.
    :param exception: Expected exception type, None if no exception expected.
    """
    priv_key, _ = get_key_path(data_dir, "secp521r1")
    out = os.path.join(tmpdir, "signature.bin")

    input_file = os.path.join(data_dir, "data_to_sign.bin")
    cmd = f"signature create -s {priv_key} -i {input_file} -o {out}"
    for region in regions:
        cmd += f" -r {region}"
    expected_code = 1 if exception else 0
    result = run_nxpcrypto(cli_runner, cmd, tmpdir, expected_code=expected_code)
    if exception:
        assert isinstance(result.exception, exception)


@pytest.mark.parametrize(
    "encoding",
    [SPSDKEncoding.DER, SPSDKEncoding.NXP],
)
@pytest.mark.parametrize(
    "key_type",
    [
        "secp256r1",
        "secp384r1",
        "secp521r1",
        "rsa2048",
        "rsa4096",
        pytest.param(
            "sm2",
            marks=pytest.mark.skipif(
                not IS_OSCCA_SUPPORTED, reason="OSCCA support is not installed"
            ),
        ),
        pytest.param(
            "dil2",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "dil3",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
        pytest.param(
            "dil5",
            marks=pytest.mark.skipif(
                not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed"
            ),
        ),
    ],
)
def test_nxpcrypto_verify_signature(
    cli_runner: CliRunner, data_dir: str, key_type: str, encoding: SPSDKEncoding, tmpdir: str
) -> None:
    """Test nxpcrypto signature verification functionality.

    This test verifies that the nxpcrypto CLI can correctly create and verify digital signatures
    using different key types and encodings. It tests both positive case (signature matches)
    and negative case (signature doesn't match when data is modified).

    :param cli_runner: Click CLI test runner for executing commands.
    :param data_dir: Directory path containing test data files.
    :param key_type: Type of cryptographic key to use for signing.
    :param encoding: Encoding format for the signature output.
    :param tmpdir: Temporary directory path for test output files.
    """
    priv_key, pub_key = get_key_path(data_dir, key_type)

    input_file = os.path.join(data_dir, "data_to_sign.bin")
    output_file = os.path.join(tmpdir, "signature.bin")
    cmd = f"signature create -s {priv_key} -i {input_file} -o {output_file} -e {encoding.value}"
    run_nxpcrypto(cli_runner, cmd, tmpdir)

    cmd = f"signature verify -k {pub_key} -i {input_file} -s {output_file}"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert SIGNATURE_MATCHING in result.output

    input_data = load_binary(input_file)
    input_data += b"0"
    modified_file = os.path.join(tmpdir, "modified_data_to_sign.bin")
    write_file(input_data, modified_file, mode="wb")

    cmd = f"signature verify -k {pub_key} -i {modified_file} -s {output_file}"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert SIGNATURE_NOT_MATCHING in result.output


def test_nxpcrypto_digest(cli_runner: CliRunner, data_dir: str, tmpdir: str) -> None:
    """Test nxpcrypto digest command functionality.

    Tests the digest command with various scenarios including direct hash comparison,
    file-based comparison, negative testing, and SSL format support. Verifies that
    the digest command correctly computes SHA256 hashes and performs comparisons
    against expected values in different formats.

    :param cli_runner: Click CLI test runner for executing commands.
    :param data_dir: Directory containing test data files.
    :param tmpdir: Temporary directory for test output files.
    """
    # Setup test environment
    input_file = os.path.join(data_dir, "data_to_digest.bin")
    output_digest_file = os.path.join(tmpdir, "output_digest.txt")
    content = b"Test data for digest"
    expected_digest = hashlib.sha256(content).hexdigest()
    write_file(expected_digest, output_digest_file)
    ssl_format = f"SHA256(/expected_digest.txt)= {expected_digest}\n"

    # Run digest command with compare from CLI
    cmd = f"digest -i {input_file} -h sha256 -c {expected_digest}"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert result.exit_code == 0, "Digest command failed"
    assert expected_digest in result.stdout

    # Run digest command with compare from CLI negative test
    cmd = f"digest -i {input_file} -h sha256 -c {expected_digest}1"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir, expected_code=1)

    # Run digest command with compare from file
    cmd = f"digest -i {input_file} -h sha256 -c {output_digest_file}"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert result.exit_code == 0, "Digest command failed"

    write_file(ssl_format, output_digest_file)
    # Run digest command with compare from file SSL format
    cmd = f"digest -i {input_file} -h sha256 -c {output_digest_file}"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert result.exit_code == 0, "Digest command failed"


@pytest.mark.parametrize(
    "encoding",
    ["pem"],
)
@pytest.mark.parametrize(
    "pki_type",
    ["ahab", "hab"],
)
@pytest.mark.parametrize(
    "key_type",
    [
        "secp521r1",
        "rsa4096",
    ],
)
@pytest.mark.parametrize(
    "key_number",
    [4],
)
@pytest.mark.parametrize(
    "ca",
    [True, False],
)
def test_nxpcrypto_pki_tree(
    cli_runner: CliRunner,
    pki_type: str,
    tmpdir: str,
    key_type: str,
    encoding: str,
    key_number: int,
    ca: bool,
) -> None:
    """Test PKI tree generation and extension functionality.

    This test verifies the creation of PKI trees for different types (AHAB/HAB),
    key types, encodings, and configurations. It validates the generated directory
    structure, counts the expected number of keys and certificates, and tests
    tree extension capabilities for both PKI types.

    :param cli_runner: Click CLI test runner for executing commands.
    :param pki_type: Type of PKI tree to generate ('ahab' or 'hab').
    :param tmpdir: Temporary directory path for test output files.
    :param key_type: Type of cryptographic keys to generate.
    :param encoding: File encoding format for generated keys and certificates.
    :param key_number: Number of SRK keys to generate in the PKI tree.
    :param ca: Flag indicating whether to generate Certificate Authority structure.
    """
    ca_flag = "-ca" if ca else ""
    cmd = f"pki-tree {pki_type} -k {key_type} -o {tmpdir}/tree_{key_type}_{encoding} -e {encoding} {ca_flag} -n {key_number}"
    result = run_nxpcrypto(cli_runner, cmd, tmpdir)
    assert result.exit_code == 0, "PKI Tree command failed"
    assert os.path.isfile(
        f"{tmpdir}/tree_{key_type}_{encoding}/crts/CA0_{key_type}_ca_cert.{encoding}"
    )

    # Count the number of SRK keys in keys directory using glob
    srk_keys = glob.glob(f"{tmpdir}/tree_{key_type}_{encoding}/keys/SRK*.pem")
    assert len(srk_keys) == key_number
    srk_certs = glob.glob(f"{tmpdir}/tree_{key_type}_{encoding}/crts/SRK*.pem")
    assert len(srk_certs) == key_number

    if ca:
        assert os.path.isfile(
            f"{tmpdir}/tree_{key_type}_{encoding}/keys/SRK0_{key_type}_ca_key.{encoding}"
        )
        if pki_type == "ahab":
            # Check if the SGK is generated
            assert os.path.isfile(
                f"{tmpdir}/tree_{key_type}_{encoding}/keys/SGK0_{key_type}_key.{encoding}"
            )
        else:
            assert os.path.isfile(
                f"{tmpdir}/tree_{key_type}_{encoding}/keys/CSF0_0_{key_type}_key.{encoding}"
            )
    else:
        assert os.path.isfile(
            f"{tmpdir}/tree_{key_type}_{encoding}/keys/SRK0_{key_type}_key.{encoding}"
        )

    if pki_type == "ahab":
        # Extend the tree
        cmd = f"pki-tree ahab-extend -i {tmpdir}/tree_{key_type}_{encoding} -n {key_number}"
        result = run_nxpcrypto(cli_runner, cmd, tmpdir)
        assert result.exit_code == 0, "PKI Tree command failed"

        # Count the number of SRK keys in keys directory using glob
        srk_keys = glob.glob(f"{tmpdir}/tree_{key_type}_{encoding}/keys/SRK*.pem")
        assert len(srk_keys) == key_number * 2
        srk_certs = glob.glob(f"{tmpdir}/tree_{key_type}_{encoding}/crts/SRK*.pem")
        assert len(srk_certs) == key_number * 2

        if ca:
            # count the number of SGK keys in keys directory using glob
            sgk_keys = glob.glob(f"{tmpdir}/tree_{key_type}_{encoding}/keys/SGK*.pem")
            assert len(sgk_keys) == key_number * 2

    elif pki_type == "hab":
        # Extend the tree
        cmd = f"pki-tree hab-extend -i {tmpdir}/tree_{key_type}_{encoding} -n {key_number}"
        result = run_nxpcrypto(cli_runner, cmd, tmpdir)
        assert result.exit_code == 0, "PKI Tree command failed"

        # Count the number of SRK keys in keys directory using glob
        srk_keys = glob.glob(f"{tmpdir}/tree_{key_type}_{encoding}/keys/SRK*.pem")
        assert len(srk_keys) == key_number * 2
        srk_certs = glob.glob(f"{tmpdir}/tree_{key_type}_{encoding}/crts/SRK*.pem")
        assert len(srk_certs) == key_number * 2


CRC_TEST_VECTORS = [
    (CrcAlg.CRC32, 127766482),
    (CrcAlg.CRC32_MPEG, 992315916),
    (CrcAlg.CRC16_XMODEM, 41226),
]


@pytest.mark.parametrize(
    "alg,ref_crc",
    CRC_TEST_VECTORS,
)
def test_nxpcrypto_crc_calculate(alg: Union[CrcAlg, str], ref_crc: int) -> None:
    """Test CRC calculation functionality with specified algorithm and reference value.

    Validates that the CRC calculation using the provided algorithm produces
    the expected reference CRC value for a predefined test data sequence.

    :param alg: CRC algorithm to test, either as CrcAlg enum or string identifier
    :param ref_crc: Expected CRC value to validate against
    """
    data = bytes.fromhex("123ABC")
    crc_obj = from_crc_algorithm(alg)
    crc = crc_obj.calculate(data)
    assert crc == ref_crc


@pytest.mark.parametrize(
    "alg,ref_crc",
    CRC_TEST_VECTORS,
)
def test_nxpcrypto_crc_verify(alg: Union[CrcAlg, str], ref_crc: int) -> None:
    """Test CRC verification functionality with given algorithm and reference value.

    Verifies that the CRC calculation using the specified algorithm matches
    the provided reference CRC value for test data.

    :param alg: CRC algorithm to use for verification, either as CrcAlg enum or string identifier
    :param ref_crc: Expected CRC value to verify against
    """
    data = bytes.fromhex("123ABC")
    crc_obj = from_crc_algorithm(alg)
    is_matching = crc_obj.verify(data, ref_crc)
    assert is_matching


@pytest.mark.parametrize(
    "alg,exception",
    [
        (CrcAlg.CRC32, None),
        (CrcAlg.CRC32_MPEG, None),
        (CrcAlg.CRC16_XMODEM, None),
        ("crc32-mpeg", None),
        ("invalid", SPSDKKeyError),
    ],
)
def test_nxpcrypto_crc_from_alg(
    alg: Union[CrcAlg, str], exception: Optional[Type[Exception]]
) -> None:
    """Test CRC object creation from algorithm specification.

    This test function verifies that the from_crc_algorithm function correctly
    creates CRC objects from algorithm specifications or raises appropriate
    exceptions for invalid inputs.

    :param alg: CRC algorithm specification, either as CrcAlg enum or string name.
    :param exception: Expected exception type to be raised, or None if no exception expected.
    """
    if exception:
        with pytest.raises(exception):
            from_crc_algorithm(alg)
    else:
        crc_obj = from_crc_algorithm(alg)
        assert isinstance(crc_obj, Crc)


@pytest.mark.parametrize(
    "verification_key", ["issuer_private_secp256.pem", "issuer_public_secp256.pem"]
)
def test_signature(cli_runner: CliRunner, data_dir: str, verification_key: str) -> None:
    """Test certificate verification with signature validation.

    This test verifies that the nxpcrypto CLI can successfully validate a certificate
    signature using the specified verification key.

    :param cli_runner: Click CLI test runner for executing commands.
    :param data_dir: Directory path containing test data files.
    :param verification_key: Name of the verification key file to use for signature validation.
    """
    cmd = f"cert verify -c cert/cert_secp256.crt --sign cert/{verification_key}"
    run_nxpcrypto(cli_runner, cmd, data_dir)


@pytest.mark.parametrize(
    "verification_key", ["subject_public_secp256.pem", "subject_private_secp256.pem"]
)
def test_puk(cli_runner: CliRunner, data_dir: str, verification_key: str) -> None:
    """Test certificate verification using public key file.

    This test verifies that the nxpcrypto CLI can successfully validate a certificate
    using a separate public key file for verification.

    :param cli_runner: Click CLI test runner for executing commands.
    :param data_dir: Directory path containing test data files.
    :param verification_key: Filename of the public key file used for verification.
    """
    cmd = f"cert verify -c cert/cert_secp256.crt --puk cert/{verification_key}"
    run_nxpcrypto(cli_runner, cmd, data_dir)


@pytest.mark.parametrize(
    "verification_key", ["subject_public_secp256.pem", "subject_private_secp256.pem"]
)
def test_signature_incorrect_key(
    cli_runner: CliRunner, data_dir: str, verification_key: str
) -> None:
    """Test certificate verification with incorrect signature key.

    This test verifies that the certificate verification command fails appropriately
    when provided with an incorrect verification key for the signature.

    :param cli_runner: Click CLI test runner for executing commands.
    :param data_dir: Directory path containing test data files.
    :param verification_key: Path to the verification key file to use for testing.
    """
    cmd = f"cert verify -c cert_secp256.crt --sign {verification_key}"
    run_nxpcrypto(cli_runner, cmd, data_dir, expected_code=-1)


@pytest.mark.parametrize(
    "verification_key", ["issuer_private_secp256.pem", "issuer_public_secp256.pem"]
)
def test_puk_incorrect_key(cli_runner: CliRunner, data_dir: str, verification_key: str) -> None:
    """Test certificate verification with incorrect public key.

    This test verifies that the certificate verification command fails appropriately
    when provided with an incorrect public key for verification.

    :param cli_runner: Click CLI test runner for executing commands.
    :param data_dir: Directory path containing test data files.
    :param verification_key: Incorrect public key to use for verification.
    """
    cmd = f"cert verify -c cert_secp256.crt --puk {verification_key}"
    run_nxpcrypto(cli_runner, cmd, data_dir, expected_code=-1)


def test_incorrect_cert_format(cli_runner: CliRunner, data_dir: str) -> None:
    """Test certificate verification with incorrect certificate format.

    This test verifies that the nxpcrypto cert verify command properly handles
    and reports errors when provided with an incorrectly formatted certificate file.
    It expects the command to fail and checks that the error message contains "ECDSA".

    :param cli_runner: Click CLI test runner for executing commands.
    :param data_dir: Path to the test data directory containing certificate files.
    """
    cmd = "cert verify -c cert/satyr.crt --sign cert/subject_public_secp256.pem"
    result = run_nxpcrypto(cli_runner, cmd, data_dir, expected_code=-1)
    assert "ECDSA" in str(result.exception)
