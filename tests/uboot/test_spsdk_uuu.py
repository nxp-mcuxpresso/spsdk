#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK UUU utility testing module.

This module contains unit tests for the SPSDK UUU (Universal Update Utility)
functionality, specifically testing argument replacement and processing
capabilities within the SPSDKUUU class.
"""

from typing import Any

from spsdk.uboot.spsdk_uuu import SPSDKUUU


def test_replace_arguments() -> None:
    """Test the replace_arguments method of SPSDKUUU class.

    This test verifies that the replace_arguments method correctly substitutes
    placeholders in a string with actual file paths from the arguments list,
    handling both direct replacements and optional key fallbacks.

    :param: No parameters - this is a test function.
    """
    arguments_dict: dict[str, dict[str, Any]] = {
        "_flash.bin": {"description": "bootloader", "optional_key": None},
        "_image": {
            "description": "image burn to emmc, default is the same as bootloader",
            "optional_key": "_flash.bin",
        },
    }
    arguments = ["some/path/bootable_image/flash.bin"]
    input_string = "This is a test string with _flash.bin and _image."
    result = SPSDKUUU.replace_arguments(input_string, arguments_dict, arguments)
    assert (
        result
        == "This is a test string with some/path/bootable_image/flash.bin and some/path/bootable_image/flash.bin."
    )


def test_replace_arguments_with_backslashes() -> None:
    """Test replacement of arguments containing backslashes in file paths.

    Verifies that the SPSDKUUU.replace_arguments method correctly handles Windows-style
    file paths with backslashes and converts them to forward slashes in the output.
    The test ensures that both direct argument replacement and optional key fallback
    work properly with backslash-containing paths.

    :raises AssertionError: If the argument replacement does not produce expected result.
    """
    arguments_dict: dict[str, dict[str, Any]] = {
        "_flash.bin": {"description": "bootloader", "optional_key": None},
        "_image": {
            "description": "image burn to emmc, default is the same as bootloader",
            "optional_key": "_flash.bin",
        },
    }
    arguments = [r"some\path\bootable_image\flash.bin"]
    input_string = "This is a test string with _flash.bin and _image."
    result = SPSDKUUU.replace_arguments(input_string, arguments_dict, arguments)
    assert (
        result
        == "This is a test string with some/path/bootable_image/flash.bin and some/path/bootable_image/flash.bin."
    )
