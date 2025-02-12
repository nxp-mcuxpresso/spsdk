#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
from spsdk.uboot.spsdk_uuu import SPSDKUUU


def test_replace_arguments():
    arguments_dict = {
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


def test_replace_arguments_with_backslashes():
    arguments_dict = {
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
