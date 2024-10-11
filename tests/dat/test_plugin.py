#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


from spsdk.apps import nxpdebugmbox
from spsdk.utils.misc import use_working_directory
from tests.cli_runner import CliRunner


def test_nxpkeygen_plugin(cli_runner: CliRunner, tmpdir, data_dir):
    out_dc = f"{tmpdir}/file.dc"
    cmd = [
        "gendc",
        "-c",
        "plugin_dck_rsa_2048.yml",
        "--plugin",
        "signature_provider.py",
        "-o",
        out_dc,
    ]
    with use_working_directory(data_dir):
        cli_runner.invoke(nxpdebugmbox.main, cmd)
    with open(out_dc, "rb") as f:
        dc_data = f.read()
    assert dc_data[-256:] == 256 * b"x"
