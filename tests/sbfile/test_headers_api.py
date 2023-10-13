#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.crypto.rng import random_bytes
from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb2.headers import ImageHeaderV2


def test_image_header_v2():
    header = ImageHeaderV2()
    assert header.nonce is None
    assert header.version == "2.0"
    assert header.flags == 8
    assert header.image_blocks == 0
    assert header.first_boot_section_id == 0
    assert header.offset_to_certificate_block == 0
    assert header.header_blocks == 0
    assert header.key_blob_block == 8
    assert header.key_blob_block_count == 5
    assert header.max_section_mac_count == 0
    assert str(header.product_version) == "1.0.0"
    assert str(header.component_version) == "1.0.0"
    assert header.build_number == 0

    assert str(header)  # test info prints any non-empty output

    with pytest.raises(SPSDKError):
        _ = header.export()
    with pytest.raises(SPSDKError):
        _ = header.export()

    header.nonce = random_bytes(16)
    data = header.export()
    assert len(data) == ImageHeaderV2.SIZE

    header_parsed = ImageHeaderV2.parse(data)
    assert header == header_parsed

    header.version = "2.1"
    assert header != header_parsed


def test_image_header_v2_invalid():
    header = ImageHeaderV2(nonce=bytes(16))
    with pytest.raises(SPSDKError, match="Invalid length of padding"):
        header.export(padding=bytes(9))
    with pytest.raises(SPSDKError, match="Invalid length of header"):
        header.SIZE = 5
        header.export()
