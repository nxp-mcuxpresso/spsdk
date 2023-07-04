#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Trust provisioning."""
import os

from spsdk import SPSDK_DATA_FOLDER

TP_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "tp")
TP_DATABASE: str = os.path.join(TP_DATA_FOLDER, "database.yaml")
TP_SCH_FILE: str = os.path.join(TP_DATA_FOLDER, "sch_tp.yaml")

from .exceptions import SPSDKTpConfigError, SPSDKTpError, SPSDKTpTargetError, SPSDKTpTimeoutError
from .tp_intf import TpDevInterface, TpIntfDescription, TpTargetInterface
from .tpconfig import TrustProvisioningConfig
from .tphost import TrustProvisioningHost
from .utils import (
    get_supported_devices,
    get_tp_device_class,
    get_tp_device_types,
    get_tp_target_class,
    get_tp_target_types,
    scan_tp_devices,
)
