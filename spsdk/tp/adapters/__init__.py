#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Trust provisioning adapters."""

from typing import Dict, Type

from .. import TpDevInterface, TpTargetInterface
from .tpdev_scard import TpDevSmartCard
from .tptarget_blhost import TpTargetBlHost

# Dict mapping TP device name to its adapter
TP_DEVICES: Dict[str, Type[TpDevInterface]] = {
    TpDevSmartCard.NAME: TpDevSmartCard,
}

# Dict mapping TP target name to its adapter
TP_TARGETS: Dict[str, Type[TpTargetInterface]] = {
    TpTargetBlHost.NAME: TpTargetBlHost,
}

try:
    # Import TP Device model if present in this build
    from .tpdev_model import TpDevSwModel

    TP_DEVICES.update({TpDevSwModel.NAME: TpDevSwModel})
except ImportError:
    pass


try:
    # Import TP Target model if present in this build
    from .tptarget_model import TpTargetSwModel

    TP_TARGETS.update({TpTargetSwModel.NAME: TpTargetSwModel})
except ImportError:
    pass
