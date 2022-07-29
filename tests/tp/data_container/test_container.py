#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import pytest

from spsdk.tp.data_container import Container, PayloadType
from spsdk.tp.data_container.data_container import DestinationType, SPSDKTpError


def test_container_info(sample_container: Container):
    assert len(sample_container) == 3

    info = str(sample_container)
    assert "count: 3" in info

    info = str(sample_container._entries[0])
    assert "Entry type:   0xa0 - Standard Entry" in info

    info = repr(sample_container)
    assert "Container" in info


def test_container_lookup(sample_container: Container):
    entries = sample_container.get_entries(PayloadType.CUST_PROD_CMPA_DATA_SECRET)
    assert len(entries) == 1
    assert entries[0] == sample_container._entries[0]

    entries = sample_container.get_entries(PayloadType.OEM_PROD_COUNTER)
    assert len(entries) == 1
    assert entries[0] == sample_container._entries[2]


def test_container_order(sample_container: Container):
    org_cont_data = sample_container.export()
    new_cont = Container.parse(org_cont_data)

    assert new_cont._entries[0].header.payload_type == PayloadType.CUST_PROD_CMPA_DATA_SECRET
    assert new_cont._entries[0].payload == bytes(20)

    assert new_cont._entries[1].header.payload_type == PayloadType.OEM_DIE_DEVATTEST_ID_CERT
    assert new_cont._entries[1].payload == bytes(30)
    assert new_cont._entries[1].destination_header.destination_type == DestinationType.MEMORY

    assert new_cont._entries[2].header.payload_type == PayloadType.OEM_PROD_COUNTER
    assert new_cont._entries[2].payload == b"1234"


def test_container_parse(data_dir: str):
    with open(f"{data_dir}/big_cont.bin", "rb") as f:
        cont_data = f.read()

    c = Container.parse(cont_data)
    assert len(c._entries) == 2


def test_invalid_header(data_dir: str):
    with open(f"{data_dir}/big_cont.bin", "rb") as f:
        cont_data = f.read()
    cont_data = bytearray(cont_data)

    # invalidate the header tag
    cont_data[3] = 0x11

    with pytest.raises(SPSDKTpError):
        Container.parse(cont_data)
