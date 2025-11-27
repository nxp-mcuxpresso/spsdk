#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023, 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK self-test module for testing infrastructure validation.

This module contains basic self-tests to verify that the testing infrastructure
is properly configured and the test suite is functioning correctly.
"""


def test_always_pass() -> None:
    """Test that basic arithmetic operations work correctly.

    This is a simple sanity test to verify that the test framework is functioning
    properly and basic Python operations are working as expected.
    """
    assert 1 + 1 == 2
