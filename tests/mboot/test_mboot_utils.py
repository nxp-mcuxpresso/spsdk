#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.mboot.mcuboot import PropertyTag

def test_data_splitting(mcuboot):
    """Test splitting data in MBOOT.

    If the underlying device requires a data slitting (such as UART does; indicating by INTERFACE.need_data_split)
    MBOOT need to split data according to MAX_PACKET_SIZE property of the target
    """

    max_packet_size = mcuboot.get_property(PropertyTag.MAX_PACKET_SIZE)[0]

    # No splitting required (USB for example)
    mcuboot._device._need_data_split = False

    data_in = bytes(4 * max_packet_size)
    data_out = mcuboot._split_data(data_in)
    assert len(data_out) == 1
    assert len(data_out[0]) == 4 * max_packet_size


    mcuboot._device._need_data_split = True

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
