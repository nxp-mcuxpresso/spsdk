#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import os
import filecmp

from spsdk import SPSDK_EXAMPLES_FOLDER
from spsdk.apps import nxpimage
from spsdk.utils.misc import load_binary, use_working_directory, write_file
from tests.cli_runner import CliRunner

IMX93_EXAMPLE_DIR = os.path.join(SPSDK_EXAMPLES_FOLDER, "imx93")
IMX93_BOOTABLE_CONFIG = "u-boot-bootable.yaml"
REF_BINARY = os.path.join(IMX93_EXAMPLE_DIR, "outputs", "flash.bin")

# Cannot be tested because file are no longer distributed in repository
# def test_uboot_mx93(cli_runner: CliRunner, tmpdir):
#     with use_working_directory(IMX93_EXAMPLE_DIR):
#         binary_output = os.path.join(tmpdir, "flash.bin")
#         cmd = f"bootable-image merge --config {IMX93_BOOTABLE_CONFIG} --output {binary_output}"
#         cli_runner.invoke(nxpimage.main, cmd.split())
#         assert os.path.isfile(binary_output)
#         data_output = load_binary(binary_output)
#         data_ref = load_binary(REF_BINARY)

#         data_path = os.path.join(tmpdir, "new_flash.bin")
#         ref_path = os.path.join(tmpdir, "ref_flash.bin")
#         # we have to do it like this, because difflib cannot handle large files
#         write_file(data_output[:-200], data_path, "wb")
#         write_file(data_ref[:-200], ref_path, "wb")
#         # the end contains SPSDK version, we don't want to compare it
#         filecmp.cmp(data_path, ref_path)
