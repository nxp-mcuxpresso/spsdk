#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
from os import path
import pytest


@pytest.fixture
def data_dir():
    return path.join(path.dirname(__file__), 'data')
