#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module containing various functions/modules used throughout the SPSDK."""

import os

from spsdk import SPSDK_DATA_FOLDER

REGS_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, 'regs')

from .exceptions import (
    SPSDKRegsError,
    SPSDKRegsErrorRegisterGroupMishmash,
    SPSDKRegsErrorRegisterNotFound,
    SPSDKRegsErrorBitfieldNotFound,
    SPSDKRegsErrorEnumNotFound
)
