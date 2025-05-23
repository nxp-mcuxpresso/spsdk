#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import pytest
from spsdk.image.hab.hab_signature import Signature


def test_signature_class():
    sig = Signature(version=0x40)
    assert sig.size == 4
    assert str(sig)


def test_signature_equality():
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
def test_signature_size_calculation(version, expected_size):
    # Test size calculation for different versions
    sig = Signature(version=version)
    assert sig.size == expected_size
