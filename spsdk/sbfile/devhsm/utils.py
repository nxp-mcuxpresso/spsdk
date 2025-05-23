#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Utils for DevHSM."""

import logging
from typing import Type, Union

from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb31.devhsm import DevHsmSB31
from spsdk.sbfile.sbc.devhsm import DevHsmSBc
from spsdk.sbfile.sbx.devhsm import DevHsmSBx
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db

logger = logging.getLogger(__name__)


def get_devhsm_class(family: FamilyRevision) -> Type[Union["DevHsmSB31", "DevHsmSBx", "DevHsmSBc"]]:
    """Get name of DevHsm class based on family.

    :param family: name of the family
    :raises SPSDKError: If the class is not found
    :return: name of the class that supports given family
    """
    devhsm_sub_features = get_db(family).get_list(DatabaseManager.DEVHSM, "sub_features")
    if "DevHsmSB31" in devhsm_sub_features:
        return DevHsmSB31
    if "DevHsmSBx" in devhsm_sub_features:
        return DevHsmSBx
    if "DevHsmSBc" in devhsm_sub_features:
        return DevHsmSBc

    raise SPSDKError(f"Device HSM is not supported for {family}.")
