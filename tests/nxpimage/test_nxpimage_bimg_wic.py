#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for nxpimage WIC functionality.

This module contains unit tests for Windows Imaging and Configuration (WIC)
related features in the nxpimage application, specifically testing U-Boot
image generation and processing within WIC containers.
"""

import os
from typing import Any

import pytest

from spsdk.apps import nxpimage
from spsdk.image.wic import UBOOT_OFFSET, generate_tag, match_uboot_tag
from spsdk.utils.misc import load_binary, use_working_directory
from tests.cli_runner import CliRunner


def generate_test_wic(test_file: str, uboot_length: int) -> None:
    """Generate test WIC file for testing purposes.

    Creates a test WIC (Windows Imaging Component) file with a specific structure
    containing zero-padded data, U-Boot binary data, and a generated tag.

    :param test_file: Path to the output file where the test WIC will be saved.
    :param uboot_length: Length of the U-Boot binary data in bytes.
    :raises OSError: If the file cannot be created or written to.
    """
    with open(test_file, "wb") as outfile:
        data = b"\x00" * UBOOT_OFFSET
        data += b"\xff" * uboot_length
        data += generate_tag(uboot_length)
        outfile.write(data)


def generate_test_uboot(output_path: str, length: int) -> None:
    """Generate test U-Boot binary file for testing purposes.

    Creates a binary file filled with repeated 0xDD bytes to simulate a U-Boot image
    for use in SPSDK image testing scenarios.

    :param output_path: Absolute or relative path where the test U-Boot file will be created.
    :param length: Size of the generated test file in bytes.
    :raises OSError: If the output file cannot be created or written to.
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
def test_nxpimage_wic_uboot(
    cli_runner: CliRunner, tmpdir: Any, uboot_length_wic: int, uboot_length: int
) -> None:
    """Test WIC bootable image U-Boot update functionality.

    This test verifies that the nxpimage CLI can successfully update U-Boot content
    in a WIC (Windows Imaging Component) bootable image file. It creates test files,
    executes the update command, and validates that the U-Boot section was properly
    updated with the correct length.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test file operations.
    :param uboot_length_wic: Length of U-Boot section in the WIC file.
    :param uboot_length: Expected length of the updated U-Boot content.
    """
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
