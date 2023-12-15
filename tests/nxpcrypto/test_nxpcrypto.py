#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import filecmp
import logging
import os
from itertools import zip_longest
from typing import List

import pytest
from click.testing import Result

from spsdk.apps import nxpcrypto
from spsdk.crypto.keys import PrivateKeyRsa, PublicKeyRsa
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import load_binary, load_text, use_working_directory
from tests.cli_runner import CliRunner


def run_nxpcrypto(cli_runner: CliRunner, cmd: str, cwd: str, expected_code=0) -> Result:
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
):
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
def test_nxpcrypto_convert(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, key: str, transform: str, expected: str
):
    src_key = f"{data_dir}/{expected}"
    dst_key = f"{tmpdir}/{expected}"
    cmd = f"key convert -i {key} {transform} -o {dst_key}"
    run_nxpcrypto(cli_runner, cmd, data_dir)

    # to validate RAW conversion we need to compare raw data as INT (there might be difference in padding)
    if "raw" in transform:
        src_num = int.from_bytes(load_binary(src_key), byteorder="big")
        dst_num = int.from_bytes(load_binary(dst_key), byteorder="big")
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


def test_nxpcrypto_convert_rsa_raw_not_supported(cli_runner: CliRunner, data_dir: str, tmpdir: str):
    dst_key = f"{tmpdir}/prk_rsa4096.bin"
    cmd = f"key convert -i prk_rsa4096.pem -e raw -o {dst_key}"
    result = run_nxpcrypto(cli_runner, cmd, data_dir, expected_code=1)
    assert result.exc_info[0] is SPSDKError


def test_generate_rsa_key(cli_runner: CliRunner, tmpdir) -> None:
    """Test generate rsa key pair."""

    cmd = f'{os.path.join(tmpdir, "key_rsa.pem")}'
    run_nxpcrypto(cli_runner, f"key generate -k rsa2048 -o {cmd}", tmpdir)
    assert os.path.isfile(os.path.join(tmpdir, "key_rsa.pem"))
    assert os.path.isfile(os.path.join(tmpdir, "key_rsa.pub"))

    pub_key_from_file = PublicKeyRsa.load(os.path.join(tmpdir, "key_rsa.pub"))
    assert isinstance(pub_key_from_file, PublicKeyRsa)
    assert pub_key_from_file.key_size == 2048

    priv_key_from_file = PrivateKeyRsa.load(os.path.join(tmpdir, "key_rsa.pem"))
    assert priv_key_from_file.key_size == 2048


def test_generate_invalid_key(cli_runner: CliRunner, tmpdir) -> None:
    """Test generate invalid key pair."""

    cmd = f'key generate -k invalid-key-type -o {os.path.join(tmpdir, "key_invalid.pem")}'
    run_nxpcrypto(cli_runner, cmd, tmpdir, expected_code=-1)
    assert not os.path.isfile(os.path.join(tmpdir, "key_invalid.pem"))
    assert not os.path.isfile(os.path.join(tmpdir, "key_invalid.pub"))


def test_force_actual_dir(cli_runner: CliRunner, tmpdir):
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
def test_key_types(cli_runner: CliRunner, tmpdir, key, valid):
    if valid:
        run_nxpcrypto(cli_runner, f"key generate -k {key} -o my_key_{key}.pem", tmpdir)
        assert os.path.isfile(os.path.join(tmpdir, f"my_key_{key}.pem"))
        assert os.path.isfile(os.path.join(tmpdir, f"my_key_{key}.pub"))
    else:
        run_nxpcrypto(
            cli_runner, f"key generate -k {key} -o my_key_{key}.pem", tmpdir, expected_code=-1
        )


@pytest.mark.parametrize(
    "keys, family, ref_rotkth",
    [
        (
            ["ec_secp256r1_cert0.pem"],
            "mcxn9xx",
            "671e3f7108621830c08df03c339d2ce9700c0a4bd74f7bfbcc48fbe27c78bf05",
        ),
        (
            ["ec_secp256r1_cert0.pem", "ec_secp256r1_cert1.pem"],
            "mcxn9xx",
            "8ba978ef5dd132a4462d8f93abdba11c89d3f8060b3dd4ba6d6d5c9fbb7c38fa",
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
        ),
        (
            ["ec_secp256r1_cert0.pem"],
            "lpc550x",
            "7eb98e20a565ba54e866a3920967c3a56a1acf07043ab08fc36a90d55a6e0eb0",
        ),
        (
            ["ec_secp256r1_cert0.pem", "ec_secp256r1_cert1.pem"],
            "lpc550x",
            "3e3bfcd794c998eeaef6347a2a438ec36e5e5132d350d31fcbd927bfcc120c9e",
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "lpc550x",
            "3f1f71ccd8dfcbcff3e445c21f003a974f8c40ce9aa7d8c567416b9ab45d1655",
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "rt118x",
            "c132cd7a8d0ac8f096dbf0968608e47fc6592f4bc93c17e5bda50d103d80db09",
        ),
        (
            [
                "SRK1_sha256_secp384r1_v3_ca_crt.pem",
                "SRK2_sha256_secp384r1_v3_ca_crt.pem",
                "SRK3_sha256_secp384r1_v3_ca_crt.pem",
                "SRK4_sha256_secp384r1_v3_ca_crt.pem",
            ],
            "rt117x",
            "bcd8f444bd7f9ccd8048a8bcf8c2764f085058ed527c6978037a94ffb81c14e8",
        ),
    ],
)
def test_nxpcrypto_rot_calc_hash(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, keys: List, family: str, ref_rotkth: str
):
    out_file = os.path.join(tmpdir, "rot_hash.bin")
    cmd = f"rot calculate-hash -f {family} -o {out_file}"
    for key in keys:
        cmd = " ".join([cmd, f"-k {key}"])
    run_nxpcrypto(cli_runner, cmd, data_dir)
    assert os.path.isfile(out_file)
    rotkth = load_binary(out_file)
    assert rotkth.hex() == ref_rotkth


@pytest.mark.parametrize(
    "keys, family, ref_rot",
    [
        (
            ["ec_secp256r1_cert0.pem"],
            "lpc550x",
            "rot_lpc550x_1_key.bin",
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "lpc550x",
            "rot_lpc550x.bin",
        ),
        (
            [
                "SRK1_sha256_secp384r1_v3_ca_crt.pem",
                "SRK2_sha256_secp384r1_v3_ca_crt.pem",
                "SRK3_sha256_secp384r1_v3_ca_crt.pem",
                "SRK4_sha256_secp384r1_v3_ca_crt.pem",
            ],
            "rt117x",
            "rot_rt117x.bin",
        ),
        (
            [
                "ec_secp256r1_cert0.pem",
                "ec_secp256r1_cert1.pem",
                "ec_secp256r1_cert2.pem",
                "ec_secp256r1_cert3.pem",
            ],
            "rt118x",
            "rot_rt118x.bin",
        ),
    ],
)
def test_nxpcrypto_rot_export(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, keys: List, family: str, ref_rot: str
):
    out_file = os.path.join(tmpdir, "rot_table.bin")
    ref_file = os.path.join(data_dir, ref_rot)
    cmd = f"rot export -f {family} -o {out_file}"
    for key in keys:
        cmd = " ".join([cmd, f"-k {key}"])
    run_nxpcrypto(cli_runner, cmd, data_dir)
    assert os.path.isfile(out_file)
    assert load_binary(out_file) == load_binary(ref_file)


def test_npxcrypto_cert_get_template(cli_runner: CliRunner, tmpdir):
    """Test NXPCRYPTO CLI - Generation of template."""
    cmd = ["cert", "get-template", "--output", f"{tmpdir}/cert.yml"]
    cli_runner.invoke(nxpcrypto.main, cmd)
    assert os.path.isfile(f"{tmpdir}/cert.yml")
