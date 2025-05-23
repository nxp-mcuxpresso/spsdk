#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.image.hab.commands.commands import CmdBase


def test_base_command():
    with pytest.raises(AttributeError):
        CmdBase(0)
