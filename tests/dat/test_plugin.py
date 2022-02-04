#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from click.testing import CliRunner

from spsdk.apps import nxpdebugmbox
from spsdk.utils.misc import use_working_directory


def test_nxpkeygen_plugin(tmpdir, data_dir):
    out_dc = f"{tmpdir}/file.dc"
    cmd = f"gendc -c plugin_dck_rsa_2048.yml --plugin signature_provider.py {out_dc}"
    with use_working_directory(data_dir):
        result = CliRunner().invoke(nxpdebugmbox.main, cmd.split())
        assert result.exit_code == 0, result.output
    with open(out_dc, "rb") as f:
        dc_data = f.read()
    assert dc_data[-256:] == 256 * b"x"
