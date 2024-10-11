#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for RTF calculator testing."""

import pytest

from spsdk.dice.rtf import calculate_rtf
from spsdk.utils.misc import load_binary


@pytest.mark.parametrize(
    "file, family, expected_rtf",
    [
        (
            "mbi_4key_no-isk.bin",
            "mcxn9xx",
            "72c6371b2f827a986ca20789c708f2f11639342315f8fc93ae8150044bcdce01",
        )
    ],
)
def test_rtf(data_dir, file, family, expected_rtf):
    mbi_data = load_binary(f"{data_dir}/{file}")

    rtf = calculate_rtf(family=family, mbi_data=mbi_data)
    assert rtf == bytes.fromhex(expected_rtf)
