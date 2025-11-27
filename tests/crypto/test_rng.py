#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK RNG (Random Number Generator) testing module.

This module contains unit tests for the SPSDK random number generation
functionality, ensuring proper operation of cryptographic random byte
generation across the NXP MCU portfolio.
"""

from spsdk.crypto.rng import random_bytes


def test_random_bytes() -> None:
    """Test random bytes generation functionality.

    Verifies that the random_bytes function generates proper random byte sequences
    by checking the return type, length, and randomness properties.

    :raises AssertionError: If random bytes generation fails validation checks.
    """
    random = random_bytes(16)
    assert isinstance(random, bytes)
    assert len(random) == 16
    assert random != random_bytes(16)
