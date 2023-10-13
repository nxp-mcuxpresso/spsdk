#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains support for Debug Authentication Tool."""
import os

from spsdk import SPSDK_DATA_FOLDER

DAT_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "dat")
DAT_DC_SCH_FILE: str = os.path.join(DAT_DATA_FOLDER, "sch_dc.yaml")
