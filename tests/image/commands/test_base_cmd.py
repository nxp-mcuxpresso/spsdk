#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest


def test_base_command():
    from spsdk.image.commands import CmdBase, CmdTag

    base = CmdBase(CmdTag.NOP, 0)
    assert base.info()
    assert base.export()
    assert len(base.export()) == base.size
    with pytest.raises(NotImplementedError):
        base.parse(b"")
