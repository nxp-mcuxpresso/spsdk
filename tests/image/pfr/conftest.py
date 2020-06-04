# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest
from os import path


@pytest.fixture
def data_dir():
    return path.join(path.dirname(path.abspath(__file__)), 'data')
