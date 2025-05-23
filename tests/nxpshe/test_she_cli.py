#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import filecmp
import os

from spsdk.apps import nxpshe
from spsdk.utils.misc import load_secret
from tests.cli_runner import CliRunner


def test_update(cli_runner: CliRunner, data_dir: str, tmpdir: str) -> None:
    config = f"{data_dir}/config.yaml"
    output = f"{tmpdir}/output.bin"
    reference = f"{data_dir}/messages.bin"

    result = cli_runner.invoke(nxpshe.main, ["update", "-c", config, "-o", output])
    assert result.exit_code == 0
    assert os.path.isfile(output)
    assert filecmp.cmp(reference, output)


def test_get_template(cli_runner: CliRunner, tmpdir: str) -> None:
    output = f"{tmpdir}/she_template.yaml"
    result = cli_runner.invoke(nxpshe.main, ["get-template", "-f", "mcxe247", "-o", output])
    assert result.exit_code == 0
    assert os.path.isfile(output)


def test_boot_mac(cli_runner: CliRunner, data_dir: str, tmpdir: str) -> None:
    boot_mac_key = f"{data_dir}/boot_mac_key.txt"
    data = f"{data_dir}/data.bin"
    output = f"{tmpdir}/boot_mac.txt"
    result = cli_runner.invoke(
        nxpshe.main, ["calc-boot-mac", "-k", boot_mac_key, "-d", data, "-o", output]
    )
    assert result.exit_code == 0
    assert os.path.isfile(output)
    assert filecmp.cmp(output, f"{data_dir}/boot_mac.txt")


def test_derive_key(cli_runner: CliRunner, data_dir: str, tmpdir: str) -> None:
    master_key = f"{data_dir}/master_key.txt"
    output = f"{tmpdir}/mac_key.txt"
    exp_mac_key = load_secret(f"{data_dir}/mac_key.txt")

    result = cli_runner.invoke(
        # the word MAC is capitalized weirdly on purpose, to check case-insensitivity
        nxpshe.main,
        ["derive-key", "-k", master_key, "-t", "maC", "-o", output],
    )
    assert result.exit_code == 0
    assert os.path.isfile(output)
    mac_key = load_secret(output)
    assert mac_key == exp_mac_key, "Derived key does not match expected key"
