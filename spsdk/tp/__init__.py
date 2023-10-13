#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Trust provisioning."""
import os

from spsdk import SPSDK_DATA_FOLDER

TP_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "tp")
TP_DATABASE: str = os.path.join(TP_DATA_FOLDER, "database.yaml")
TP_SCH_FILE: str = os.path.join(TP_DATA_FOLDER, "sch_tp.yaml")
