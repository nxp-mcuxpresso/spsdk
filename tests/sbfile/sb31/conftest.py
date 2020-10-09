# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Create path to file function."""

from os import path

import pytest


@pytest.fixture
def data_dir():
    """Function to specify path to file."""
    return path.join(path.dirname(path.abspath(__file__)), "..", "data", "sb31")
