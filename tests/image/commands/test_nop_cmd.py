#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.image.commands import CmdNop, CmdSet


def test_nop_cmd():
    cmd = CmdNop(param=0)
    assert "CmdNop" in repr(cmd)
    assert cmd is not None
    assert cmd.size == 4


def test_nop_cmd_eq():
    cmd = CmdNop()
    cmd_set = CmdSet()
    assert cmd != cmd_set


def test_nop_cmd_info():
    cmd = CmdNop()
    assert 'Command "No Operation' in str(cmd)


def test_nop_export_parse():
    cmd = CmdNop()
    data = cmd.export()
    assert len(data) == 4
    assert cmd == CmdNop.parse(data)
