#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Trust provisioning adapters."""

from typing import Type

from spsdk.tp.adapters.tpdev_scard import TpDevSmartCard
from spsdk.tp.adapters.tptarget_blhost import TpTargetBlHost
from spsdk.tp.tp_intf import TpDevInterface, TpTargetInterface

# Dict mapping TP device name to its adapter
TP_DEVICES: dict[str, Type[TpDevInterface]] = {
    TpDevSmartCard.NAME: TpDevSmartCard,
}

# Dict mapping TP target name to its adapter
TP_TARGETS: dict[str, Type[TpTargetInterface]] = {
    TpTargetBlHost.NAME: TpTargetBlHost,
}

try:
    # Import TP Device model if present in this build
    from spsdk.tp.adapters.tpdev_model import TpDevSwModel

    TP_DEVICES.update({TpDevSwModel.NAME: TpDevSwModel})
except ImportError:
    pass


try:
    # Import TP Target model if present in this build
    from spsdk.tp.adapters.tptarget_model import TpTargetSwModel

    TP_TARGETS.update({TpTargetSwModel.NAME: TpTargetSwModel})
except ImportError:
    pass
