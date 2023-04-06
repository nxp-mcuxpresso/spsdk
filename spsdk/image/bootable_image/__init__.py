#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains Bootable image related code."""
import os

from spsdk import SPSDK_DATA_FOLDER

BIMG_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "image", "bootable_image")
BIMG_SCH_FILE: str = os.path.join(BIMG_DATA_FOLDER, "sch_bimg.yaml")
BIMG_DATABASE_FILE: str = os.path.join(BIMG_DATA_FOLDER, "database.yaml")
