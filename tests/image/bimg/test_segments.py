#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK Bootable Image Segments testing module.

This module contains unit tests for bootable image segments functionality,
specifically focusing on the SegmentImageVersionAntiPole class which handles
image version antipole segments in bootable images.
"""

from typing import Any

import pytest

from spsdk.image.bootable_image.segments import SegmentImageVersionAntiPole
from spsdk.image.mem_type import MemoryType
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision


@pytest.mark.parametrize(
    "config,binary",
    [
        ({}, "ffffffff"),  # unprogrammed
        ({"image_version": 65535}, "ffff0000"),  # max value
        ({"image_version": 12345}, "3930c6cf"),  # valid version
        ({"image_version": 98765}, "cd81327e"),  # more than 4 bytes
    ],
)
def test_segment_image_version_antipole_load_from_config(
    config: dict[str, Any], binary: str
) -> None:
    """Test segment image version antipole configuration loading.

    This test verifies that a SegmentImageVersionAntiPole can be properly loaded
    from a configuration dictionary and produces the expected binary output.

    :param config: Configuration dictionary containing image version antipole settings.
    :param binary: Expected hexadecimal string representation of the exported segment.
    """
    segment = SegmentImageVersionAntiPole(
        0, family=FamilyRevision("lpc55s3x"), mem_type=MemoryType.FLEXSPI_NOR
    )
    segment.load_config(Config(config))
    assert segment.cfg_key() == "image_version"
    assert segment.export().hex() == binary


@pytest.mark.parametrize(
    "binary,config",
    [
        ("ffffffff", 65535),  # unprogrammed
        ("ffff0000", 65535),  # max value
        ("3930c6cf", 12345),  # valid version
        ("cd81327e", 33229),  # more than 4 bytes
    ],
)
def test_segment_image_version_antipole_parse(binary: str, config: int) -> None:
    """Test segment image version antipole parsing functionality.

    This test verifies that a SegmentImageVersionAntiPole can correctly parse
    binary data and generate the expected configuration value.

    :param binary: Hexadecimal string representation of binary data to parse
    :param config: Expected configuration integer value after parsing
    :raises AssertionError: When parsed configuration doesn't match expected value
    """
    segment = SegmentImageVersionAntiPole(
        0, family=FamilyRevision("lpc55s3x"), mem_type=MemoryType.FLEXSPI_NOR
    )
    segment.parse_binary(bytes.fromhex(binary))
    assert segment.create_config("") == config
