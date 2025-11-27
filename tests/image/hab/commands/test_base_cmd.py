#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB base command unit tests.

This module contains unit tests for the base command functionality in the
HAB (High Assurance Boot) image processing system, ensuring proper behavior
of the CmdBase class and its core methods.
"""

import pytest

from spsdk.image.hab.commands.commands import CmdBase


def test_base_command() -> None:
    """Test that CmdBase constructor raises AttributeError with invalid argument.

    This test verifies that the CmdBase class properly validates its constructor
    arguments and raises an AttributeError when initialized with an integer
    instead of the expected argument type.

    :raises AttributeError: Expected exception when CmdBase is initialized with invalid argument type.
    """
    with pytest.raises(AttributeError):
        CmdBase(0)
