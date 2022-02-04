#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module containing various functions/modules used throughout the SPSDK."""

import os

from spsdk import SPSDK_DATA_FOLDER

REGS_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "regs")
UTILS_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "utils")

from .exceptions import (
    SPSDKRegsError,
    SPSDKRegsErrorBitfieldNotFound,
    SPSDKRegsErrorEnumNotFound,
    SPSDKRegsErrorRegisterGroupMishmash,
    SPSDKRegsErrorRegisterNotFound,
)
