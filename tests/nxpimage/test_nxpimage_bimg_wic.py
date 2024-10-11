#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test WIC part of nxpimage app."""

import os
import pytest

from spsdk.apps import nxpimage
from spsdk.image.wic import UBOOT_OFFSET, generate_tag, match_uboot_tag
from spsdk.utils.misc import load_binary, use_working_directory
from tests.cli_runner import CliRunner


def generate_test_wic(test_file: str, uboot_length: int) -> None:
    """Generate test WIC file.

    :param test_file: path to file where to save it.
    :param uboot_length: length of uboot.
    """
    with open(test_file, "wb") as outfile:
        data = b"\x00" * UBOOT_OFFSET
        data += b"\xff" * uboot_length
        data += generate_tag(uboot_length)
        outfile.write(data)


def generate_test_uboot(output_path: str, length: int) -> None:
    """Generate test uboot file.

    :param output_path: path to uboot.
    :param length: length of test file.
    """
    with open(output_path, "wb") as outfile:
        data = b"\xdd" * length
        outfile.write(data)


@pytest.mark.parametrize(
    "uboot_length_wic,uboot_length",
    [
        (1024 * 1024, 1024 * 512),
        (1024 * 1024, 1024 * 1024),
        (1024 * 1024, 1024 * 2048),
    ],
)
def test_nxpimage_wic_uboot(cli_runner: CliRunner, tmpdir, uboot_length_wic, uboot_length):
    with use_working_directory(tmpdir):
        test_wic = os.path.join(tmpdir, "test_wic")
        test_uboot = os.path.join(tmpdir, "test_uboot")
        generate_test_wic(test_wic, uboot_length_wic)
        generate_test_uboot(test_uboot, uboot_length)

        cmd = f"bootable-image wic update-uboot -b {test_wic} -u {test_uboot}"
        cli_runner.invoke(nxpimage.main, cmd.split())

        wic_binary = load_binary(test_wic)
        end_address = match_uboot_tag(wic_binary[UBOOT_OFFSET:])

        assert end_address == uboot_length

        os.remove(test_wic)
        os.remove(test_uboot)
