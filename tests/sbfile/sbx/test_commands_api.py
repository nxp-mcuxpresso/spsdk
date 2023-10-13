#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test of commands."""


from spsdk.sbfile.sb31.commands import CmdReset


def test_cmd_reset():
    """Test cmd reset command."""
    cmd = CmdReset()
    assert cmd.address == 0
    assert cmd.length == 0
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16

    cmd_parsed = CmdReset.parse(data=data)
    assert cmd == cmd_parsed
