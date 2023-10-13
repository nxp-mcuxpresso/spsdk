#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.commands import CmdBase, CmdTag


def test_base_command():
    base = CmdBase(CmdTag.NOP, 0)
    assert str(base)
    assert base.export()
    assert len(base.export()) == base.size
    with pytest.raises(NotImplementedError):
        base.parse(b"")


def test_no_supported():
    base = CmdBase(CmdTag.NOP, 0)
    with pytest.raises(SPSDKError):
        base.cmd_data_reference = 0
    with pytest.raises(SPSDKError):
        base.cmd_data_offset = 0
    with pytest.raises(SPSDKError):
        base.parse_cmd_data(data=None)
