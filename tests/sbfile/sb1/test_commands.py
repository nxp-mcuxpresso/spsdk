#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb1 import CmdNop
from spsdk.sbfile.sb1.commands import parse_v1_command


def test_parse_command():
    cmd = CmdNop()
    parsed_cmd = parse_v1_command(cmd.export())
    assert parsed_cmd == cmd


def test_parse_invalid_command_tag():
    # invalid tag
    with pytest.raises(SPSDKError):
        parse_v1_command(b"\xEE" * 16)
    # unsupported command
    with pytest.raises(SPSDKError):
        parse_v1_command(b"\x0D" * 16)
