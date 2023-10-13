#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for cryptographic utilities."""

import os

from spsdk.utils import UTILS_DATA_FOLDER

CRYPTO_SCH_FILE: str = os.path.join(UTILS_DATA_FOLDER, "sch_crypto.yaml")
OTFAD_DATA_FOLDER: str = os.path.join(UTILS_DATA_FOLDER, "otfad")
OTFAD_SCH_FILE: str = os.path.join(OTFAD_DATA_FOLDER, "sch_otfad.yaml")
OTFAD_DATABASE_FILE: str = os.path.join(OTFAD_DATA_FOLDER, "database.yaml")

IEE_DATA_FOLDER: str = os.path.join(UTILS_DATA_FOLDER, "iee")
IEE_SCH_FILE: str = os.path.join(IEE_DATA_FOLDER, "sch_iee.yaml")
IEE_DATABASE_FILE: str = os.path.join(IEE_DATA_FOLDER, "database.yaml")
