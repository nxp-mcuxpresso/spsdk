#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains XMCD (External Memory Configuration Data) related code."""
import os

from spsdk import SPSDK_DATA_FOLDER

XMCD_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "image", "xmcd")
XMCD_SCH_FILE: str = os.path.join(XMCD_DATA_FOLDER, "sch_xmcd.yml")
XMCD_DATABASE_FILE: str = os.path.join(XMCD_DATA_FOLDER, "database.yml")
