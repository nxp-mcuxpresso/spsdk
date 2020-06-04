#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.sbfile.headers import ImageHeaderV2
from spsdk.utils.crypto.backend_internal import internal_backend


def test_image_header_v2():
    header = ImageHeaderV2()
    assert header.nonce is None
    assert header.version == '2.0'
    assert header.flags == 8
    assert header.image_blocks == 0
    assert header.first_boot_section_id == 0
    assert header.offset_to_certificate_block == 0
    assert header.header_blocks == 0
    assert header.key_blob_block == 8
    assert header.key_blob_block_count == 5
    assert header.max_section_mac_count == 0
    assert str(header.product_version) == '1.0.0'
    assert str(header.component_version) == '1.0.0'
    assert header.build_number == 0

    assert header.info()  # test info prints any non-empty output

    with pytest.raises(AttributeError):
        _ = header.export()
    with pytest.raises(AttributeError):
        _ = header.export()

    header.nonce = internal_backend.random_bytes(16)
    data = header.export()
    assert len(data) == ImageHeaderV2.SIZE

    header_parsed = ImageHeaderV2.parse(data)
    assert header == header_parsed

    header.version = '2.1'
    assert header != header_parsed
