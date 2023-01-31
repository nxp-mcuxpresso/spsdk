#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains AHAB related code."""
import os

from spsdk import SPSDK_DATA_FOLDER

AHAB_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "ahab")
AHAB_SCH_FILE: str = os.path.join(AHAB_DATA_FOLDER, "sch_ahab.yml")
AHAB_DATABASE_FILE: str = os.path.join(AHAB_DATA_FOLDER, "database.yml")
SIGNED_MSG_SCH_FILE: str = os.path.join(AHAB_DATA_FOLDER, "sch_signed_msg.yml")
