#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for crypto operations (certificate and key management)."""
import os

from spsdk import SPSDK_DATA_FOLDER

CRYPTO_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, "crypto")
