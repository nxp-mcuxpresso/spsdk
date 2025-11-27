#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK DevHSM utility functions for secure boot file processing.

This module provides utility functions for working with DevHSM (Development Hardware
Security Module) implementations across different secure boot file formats in SPSDK.
"""

import logging
from typing import Type, Union

from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb4.devhsm import DevHsmSB4
from spsdk.sbfile.sb31.devhsm import DevHsmSB31
from spsdk.sbfile.sbc.devhsm import DevHsmSBc
from spsdk.sbfile.sbx.devhsm import DevHsmSBx
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db

logger = logging.getLogger(__name__)


def get_devhsm_class(
    family: FamilyRevision,
) -> Type[Union["DevHsmSB4", "DevHsmSB31", "DevHsmSBx", "DevHsmSBc"]]:
    """Get DevHSM class based on chip family.

    The method retrieves the appropriate DevHSM class implementation by checking the database
    for supported sub-features of the given family and returning the corresponding class type.

    :param family: Chip family revision to get DevHSM class for.
    :raises SPSDKError: If DevHSM is not supported for the specified family.
    :return: DevHSM class type that supports the given family.
    """
    devhsm_sub_features = get_db(family).get_list(DatabaseManager.DEVHSM, "sub_features")
    if "DevHsmSB4" in devhsm_sub_features:
        return DevHsmSB4
    if "DevHsmSB31" in devhsm_sub_features:
        return DevHsmSB31
    if "DevHsmSBx" in devhsm_sub_features:
        return DevHsmSBx
    if "DevHsmSBc" in devhsm_sub_features:
        return DevHsmSBc

    raise SPSDKError(f"Device HSM is not supported for {family}.")
