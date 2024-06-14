#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import pytest

from spsdk.image.bootable_image.segments import SegmentImageVersionAntiPole


@pytest.mark.parametrize(
    "config,binary",
    [
        ({}, "ffffffff"),  # unprogrammed
        ({"image_version": 65535}, "ffff0000"),  # max value
        ({"image_version": 12345}, "3930c6cf"),  # valid version
        ({"image_version": 98765}, "cd81327e"),  # more than 4 bytes
    ],
)
def test_segment_image_version_antipole_load_from_config(config, binary):
    segment = SegmentImageVersionAntiPole(0, family="lpc55s3x", mem_type="flexspi_nor")
    segment.load_config(config)
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
def test_segment_image_version_antipole_parse(binary, config):
    segment = SegmentImageVersionAntiPole(0, family="lpc55s3x", mem_type="flexspi_nor")
    segment.parse_binary(bytes.fromhex(binary))
    assert segment.create_config("") == config
