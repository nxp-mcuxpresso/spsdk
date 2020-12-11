#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for working with Protected Flash Region."""

import os

from spsdk import SPSDK_DATA_FOLDER

PFR_DATA_FOLDER: str = os.path.join(SPSDK_DATA_FOLDER, 'pfr')

from .pfr import CMPA, CFPA
from .translator import Translator
from .processor import Processor
