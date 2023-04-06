#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains FCB (Flash Configuration Block) related code."""
import os

from spsdk import SPSDK_DATA_FOLDER

FCB_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "image", "fcb")
FCB_SCH_FILE: str = os.path.join(FCB_DATA_FOLDER, "sch_fcb.yaml")
FCB_DATABASE_FILE: str = os.path.join(FCB_DATA_FOLDER, "database.yaml")
