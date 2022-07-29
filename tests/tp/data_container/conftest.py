#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import pytest

from spsdk.tp.data_container import (
    AuthenticationType,
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
        entry=DataEntry(payload=bytes(20), payload_type=PayloadType.CUST_PROD_CMPA_DATA_SECRET)
    )
    container.add_entry(
        entry=DataDestinationEntry(
            payload=bytes(30),
            payload_type=PayloadType.OEM_DIE_DEVATTEST_ID_CERT,
            destination=0x100,
            destination_type=DestinationType.MEMORY,
        )
    )
    container.add_entry(
        entry=DataDestinationEntry(
            payload=b"1234",
            payload_type=PayloadType.OEM_PROD_COUNTER,
            destination=1,
            destination_type=DestinationType.OTP,
        )
    )
    return container
