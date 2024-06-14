#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from unittest.mock import patch

from spsdk.tp.adapters import TpTargetBlHost
from spsdk.tp.adapters.tptarget_blhost import TpBlHostIntfDescription
from tests.mboot.mboot_fixtures import *


@pytest.fixture
def trgt_blhost(device) -> TpTargetBlHost:
    tblh_descr = TpBlHostIntfDescription(
        "Virtual BLHOST",
        "Virtual BLHOST device for testing",
        {
            "buffer_address": 1024,
            "buffer_size": 0x1000,
        },
    )
    tblh_descr.interface = device
    tblh = TpTargetBlHost(tblh_descr, "N/A")
    return tblh


@pytest.fixture
def trgt_blhost_ready(trgt_blhost: TpTargetBlHost) -> TpTargetBlHost:
    trgt_blhost.open()
    yield trgt_blhost
    trgt_blhost.close()
