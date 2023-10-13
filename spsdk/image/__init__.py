#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module implementing functionality of srktool, dcdgen, mkimage and other similar tools."""

import os

from spsdk import SPSDK_DATA_FOLDER

IMG_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "image")
TZ_SCH_FILE: str = os.path.join(IMG_DATA_FOLDER, "sch_tz.yaml")
MBI_SCH_FILE: str = os.path.join(IMG_DATA_FOLDER, "mbi", "sch_mbi.yaml")
