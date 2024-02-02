#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import pytest

from spsdk.tp.data_container import (
    Container,
    DataDestinationEntry,
    DataEntry,
    DestinationType,
    PayloadType,
)


@pytest.fixture
def sample_container():
    container = Container()
    container.add_entry(
        entry=DataEntry(payload=bytes(20), payload_type=PayloadType.CUST_PROD_CMPA_DATA_SECRET.tag)
    )
    container.add_entry(
        entry=DataDestinationEntry(
            payload=bytes(30),
            payload_type=PayloadType.OEM_DIE_DEVATTEST_ID_CERT.tag,
            destination=0x100,
            destination_type=DestinationType.MEMORY,
        )
    )
    container.add_entry(
        entry=DataDestinationEntry(
            payload=b"1234",
            payload_type=PayloadType.OEM_PROD_COUNTER.tag,
            destination=1,
            destination_type=DestinationType.OTP,
        )
    )
    return container
