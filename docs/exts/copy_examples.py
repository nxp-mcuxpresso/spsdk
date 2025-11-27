#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK documentation build extension for copying examples.

This module provides a Sphinx extension that automatically copies example files
from the source directory to the documentation build directory during the
documentation generation process.
"""

# Script for copying examples directory to docs
import os
import shutil
from typing import Any

from sphinx.util.fileutil import copy_asset

DOC_PATH = os.path.abspath(".")
EXAMPLES_DESTINATION_PATH = os.path.join(DOC_PATH, "examples")
EXAMPLES_SOURCE_PATH = os.path.join(DOC_PATH, "..", "examples")


def copy_examples() -> None:
    """Copy examples directory from source to destination path.

    This function removes any existing examples at the destination, creates the
    destination directory if it doesn't exist, and copies all examples from the
    source location. Progress is indicated with a print statement.

    :raises OSError: If directory creation or file operations fail.
    :raises shutil.Error: If copying files encounters errors.
    """
    shutil.rmtree(EXAMPLES_DESTINATION_PATH, ignore_errors=True)
    if not os.path.exists(EXAMPLES_DESTINATION_PATH):
        os.makedirs(EXAMPLES_DESTINATION_PATH)
    copy_asset(EXAMPLES_SOURCE_PATH, EXAMPLES_DESTINATION_PATH)
    print("Copying examples directory")


def setup(app: Any) -> None:
    """Setup Sphinx extension for copying examples.

    This function registers the copy_examples functionality as a Sphinx extension
    by calling the copy_examples function during Sphinx initialization.

    :param app: The Sphinx application object used for extension registration.
    """
    copy_examples()
