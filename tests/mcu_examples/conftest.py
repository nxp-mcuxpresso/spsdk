#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest
from os import path


@pytest.fixture(scope="module")
def data_dir():
    return path.join(path.dirname(path.abspath(__file__)), 'data')
