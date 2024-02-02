#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
# Script for copying examples directory to docs
import os
import shutil
from sphinx.util.fileutil import copy_asset

DOC_PATH = os.path.abspath(".")
EXAMPLES_DESTINATION_PATH = os.path.join(DOC_PATH, "examples")
EXAMPLES_SOURCE_PATH = os.path.join(DOC_PATH, "..", "examples")


def copy_examples():
    shutil.rmtree(EXAMPLES_DESTINATION_PATH, ignore_errors=True)
    if not os.path.exists(EXAMPLES_DESTINATION_PATH):
        os.makedirs(EXAMPLES_DESTINATION_PATH)
    copy_asset(EXAMPLES_SOURCE_PATH, EXAMPLES_DESTINATION_PATH)
    print("Copying examples directory")


def setup(app):
    copy_examples()
