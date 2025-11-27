#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""HAB signature functionality unit tests.

This module contains comprehensive unit tests for the HAB (High Assurance Boot)
signature functionality in SPSDK. It validates the Signature class behavior
including object creation, equality comparison, and size calculations.
"""

import pytest

from spsdk.image.hab.hab_signature import Signature


def test_signature_class() -> None:
    """Test the Signature class basic functionality.

    Verifies that a Signature object can be created with the correct version,
    has the expected size, and can be converted to string representation.
    """
    sig = Signature(version=0x40)
    assert sig.size == 4
    assert str(sig)


def test_signature_equality() -> None:
    """Test equality comparison functionality of Signature objects.

    Verifies that Signature objects with identical version values are considered
    equal, while Signature objects with different version values are not equal.
    This test ensures the __eq__ method works correctly for the Signature class.
    """
    # Test equality comparison
    sig1 = Signature(version=0x40)
    sig2 = Signature(version=0x40)
    sig3 = Signature(version=0x42)

    assert sig1 == sig2
    assert sig1 != sig3


@pytest.mark.parametrize(
    "version,expected_size",
    [
        (0x40, 4),
        (0x42, 4),
    ],
)
def test_signature_size_calculation(version: int, expected_size: int) -> None:
    """Test signature size calculation for different HAB versions.

    Verifies that the Signature object correctly calculates its size
    based on the provided version parameter.

    :param version: HAB signature version to test
    :param expected_size: Expected size in bytes for the given version
    """
    # Test size calculation for different versions
    sig = Signature(version=version)
    assert sig.size == expected_size
