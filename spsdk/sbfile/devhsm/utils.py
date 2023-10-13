#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Utils for DevHSM."""

from inspect import isclass
from typing import Type, Union

from spsdk.exceptions import SPSDKError
from spsdk.sbfile.devhsm.devhsm import NXPDEVHSM_DATABASE_FILE, DevHsm
from spsdk.sbfile.sb31.devhsm import DevHsmSB31
from spsdk.sbfile.sbx.devhsm import DevHsmSBx
from spsdk.utils.database import Database


def get_devhsm_class(family: str) -> Type[Union["DevHsmSB31", "DevHsmSBx"]]:
    """Get name of DevHsm class based on family.

    :param family: name of the family
    :raises SPSDKError: If the class is not found
    :return: name of the class that supports given family
    """
    devhsm_cls = Database(NXPDEVHSM_DATABASE_FILE).get_device_value("devhsm_class", family)
    try:
        obj = globals()[devhsm_cls]
    except KeyError as exc:
        raise SPSDKError(f"Class for {family} is unknown") from exc
    if isclass(obj) and issubclass(obj, DevHsm) and obj is not DevHsm:
        assert isinstance(obj, type(DevHsmSB31)) or isinstance(obj, type(DevHsmSBx))
        return obj
    raise SPSDKError(f"Class {obj} is not supported.")
