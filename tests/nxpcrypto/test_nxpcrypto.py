#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import filecmp
import logging
from itertools import zip_longest

import pytest
from click.testing import CliRunner, Result

from spsdk.apps import nxpcrypto
from spsdk.utils.misc import load_binary, load_text, use_working_directory


def run_nxpcrypto(cmd: str, cwd: str) -> Result:
    with use_working_directory(cwd):
        runner = CliRunner()
        logging.debug(f"Running {cmd}")
        result = runner.invoke(nxpcrypto.main, cmd.split())
    return result


@pytest.mark.parametrize(
    "key1, key2, expected_result",
    [
        ("prk_secp256_d_3.bin", "prk_secp256_d_3.pem", 0),
        ("prk_secp256_d_3.pem", "puk_secp256_d_3.pem", 0),
        ("prk_secp256_d_5.der", "puk_secp256_d_5.der", 0),
        ("prk_secp256_d_5.der", "puk_secp256_d_5.pem", 0),
        ("prk_secp256_d_3.bin", "puk_secp256_d_5.bin", 1),
        ("prk_secp256_d_3.pem", "puk_secp256_d_5.der", 1),
    ],
)
def test_nxpcrypto_key_verify(data_dir: str, key1: str, key2: str, expected_result: int):
    cmd = f"key verify {key1} {key2}"
    result = run_nxpcrypto(cmd, data_dir)
    assert result.exit_code == expected_result


@pytest.mark.parametrize(
    "key, transform, expected",
    [
        ("prk_secp256_d_3.bin", "-f pem", "prk_secp256_d_3.pem"),
        ("prk_secp256_d_3.pem", "-f raw", "prk_secp256_d_3.bin"),
        ("prk_secp256_d_3.bin", "-f pem --puk", "puk_secp256_d_3.pem"),
        ("puk_secp256_d_5.pem", "-f der", "puk_secp256_d_5.der"),
    ],
)
def test_nxpcrypto_convert(data_dir: str, tmpdir: str, key: str, transform: str, expected: str):
    src_key = f"{data_dir}/{expected}"
    dst_key = f"{tmpdir}/{expected}"
    cmd = f"key convert -i {key} {transform} -o {dst_key}"
    result = run_nxpcrypto(cmd, data_dir)
    assert result.exit_code == 0

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
