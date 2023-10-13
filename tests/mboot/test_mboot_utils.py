#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.mboot.mcuboot import McuBoot, PropertyTag, _clamp_down_memory_id


def test_data_splitting(mcuboot: McuBoot):
    """Test splitting data in MBOOT.

    If the underlying device requires a data slitting (such as UART does; indicating by INTERFACE.need_data_split)
    MBOOT need to split data according to MAX_PACKET_SIZE property of the target
    """

    max_packet_size = mcuboot.get_property(PropertyTag.MAX_PACKET_SIZE)[0]

    # No splitting required (USB for example)
    mcuboot._interface.need_data_split = False

    data_in = bytes(4 * max_packet_size)
    data_out = mcuboot._split_data(data_in)
    assert len(data_out) == 1
    assert len(data_out[0]) == 4 * max_packet_size

    mcuboot._interface.need_data_split = True

    data_in = bytes(4 * max_packet_size)
    # data size is aligned to MAX_PACKET_SIZE
    data_out = mcuboot._split_data(data_in)
    assert len(data_out) == 4
    assert all(len(chunk) == max_packet_size for chunk in data_out)

    # data size is misaligned
    data_in = bytes(max_packet_size + 10)
    data_out = mcuboot._split_data(data_in)
    assert len(data_out) == 2
    assert len(data_out[0]) == max_packet_size
    assert len(data_out[1]) == 10


@pytest.mark.parametrize(
    "memory_id, clamped_mem_id",
    [(0, 0), (1, 0), (0xA, 0), (256, 256), (1000, 1000), (0x102, 0x102)],
)
def test_memory_id_clamp_down(memory_id, clamped_mem_id):
    new_memory_id = _clamp_down_memory_id(memory_id)
    assert new_memory_id == clamped_mem_id
