#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test FCB part of nxpimage app."""
import filecmp
import os

import pytest

from spsdk.apps import nxpimage
from spsdk.exceptions import SPSDKError
from spsdk.image.fcb.fcb import FCB
from spsdk.image.mem_type import MemoryType
from spsdk.utils.misc import use_working_directory
from tests.cli_runner import CliRunner


@pytest.mark.parametrize(
    "family,mem_type",
    [
        ("rt5xx", "flexspi_nor"),
        ("rt6xx", "flexspi_nor"),
        ("rt105x", "flexspi_nor"),
        ("rt106x", "flexspi_nor"),
        ("rt117x", "flexspi_nor"),
        ("lpc55s3x", "flexspi_nor"),
        ("mcxn9xx", "flexspi_nor"),
    ],
)
def test_nxpimage_fcb_export(cli_runner: CliRunner, tmpdir, data_dir, family, mem_type):
    with use_working_directory(data_dir):
        config_file = os.path.join(data_dir, "fcb", family, f"fcb_{family}_{mem_type}.yaml")
        out_file = os.path.join(tmpdir, f"fcb_{family}_exported.bin")
        cmd = ["bootable-image", "fcb", "export", "-c", config_file, "-o", out_file]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file)
        assert filecmp.cmp(
            os.path.join(data_dir, "fcb", family, "fcb.bin"),
            out_file,
            shallow=False,
        )


@pytest.mark.parametrize(
    "family,mem_type,binary",
    [
        ("rt5xx", "flexspi_nor", "fcb.bin"),
        ("rt6xx", "flexspi_nor", "fcb.bin"),
        ("rt105x", "flexspi_nor", "fcb.bin"),
        ("rt106x", "flexspi_nor", "fcb.bin"),
        ("rt117x", "flexspi_nor", "fcb.bin"),
        ("lpc55s3x", "flexspi_nor", "fcb.bin"),
        ("mcxn9xx", "flexspi_nor", "fcb.bin"),
    ],
)
def test_nxpimage_fcb_parse_cli(cli_runner: CliRunner, tmpdir, data_dir, family, mem_type, binary):
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "fcb", family)
        binary_path = os.path.join(data_folder, binary)
        out_config = os.path.join(tmpdir, f"fcb_{family}_{mem_type}.yaml")
        cmd = [
            "bootable-image",
            "fcb",
            "parse",
            "-f",
            family,
            "-m",
            mem_type,
            "-b",
            binary_path,
            "-o",
            out_config,
        ]
        cli_runner.invoke(nxpimage.main, cmd)

        assert os.path.isfile(out_config)


@pytest.mark.parametrize(
    "family,mem_types",
    [
        ("mimxrt595s", ["flexspi_nor"]),
        ("mimxrt685s", ["flexspi_nor"]),
        ("mimxrt1010", ["flexspi_nor"]),
        ("mimxrt1015", ["flexspi_nor"]),
        ("mimxrt1024", ["flexspi_nor"]),
        ("mimxrt1040", ["flexspi_nor"]),
        ("mimxrt1050", ["flexspi_nor"]),
        ("mimxrt1064", ["flexspi_nor"]),
        ("mimxrt1166", ["flexspi_nor"]),
        ("mimxrt1176", ["flexspi_nor"]),
        ("mimxrt1189", ["flexspi_nor"]),
        ("lpc55s36", ["flexspi_nor"]),
        ("rw612", ["flexspi_nor"]),
        ("mcxn947", ["flexspi_nor"]),
        ("lpc5536", ["flexspi_nor"]),
    ],
)
def test_nxpimage_fcb_template_cli(cli_runner: CliRunner, tmpdir, family, mem_types):
    cmd = f"bootable-image fcb get-templates -f {family} --output {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())

    for mem_type in mem_types:
        template_name = os.path.join(tmpdir, f"fcb_{family}_{mem_type}.yaml")
        assert os.path.isfile(template_name)


@pytest.mark.parametrize(
    "binary,fail",
    [
        (b"0" * 512, True),
        (b"FCFB" + b"0" * 507, True),
        (b"FCFB" + b"0" * 508, False),
        (b"FCFB" + b"0" * 512, False),
        (b"CFBF" + b"0" * 512, False),
    ],
)
@pytest.mark.parametrize(
    "family,mem_type",
    [
        ("rt5xx", MemoryType.FLEXSPI_NOR),
        ("rt117x", MemoryType.FLEXSPI_NOR),
        ("mimxrt1189", MemoryType.FLEXSPI_NOR),
    ],
)
def test_fcb_parse_invalid(binary, fail, family, mem_type):
    if fail:
        with pytest.raises(SPSDKError):
            FCB.parse(binary, family=family, mem_type=mem_type)
    else:
        FCB.parse(binary, family=family, mem_type=mem_type)
