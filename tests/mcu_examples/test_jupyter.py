#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK Jupyter notebook testing utilities.

This module provides test functionality for validating SPSDK example
Jupyter notebooks to ensure they execute correctly and produce
expected outputs.
"""

import os
import sys

import pytest
from pytest_notebook.nb_regression import NBRegressionFixture

from spsdk import SPSDK_EXAMPLES_FOLDER

GENERAL_NOTEBOOKS = [
    "crypto/keys",
    "crypto/certificates",
    "hab/srk_table/srk_table",
    "hab/dcd/image_dcd",
    "ahab/srk_table/srk_table",
]

notebook_paths = []
for notebook in GENERAL_NOTEBOOKS:
    notebook_paths.append(os.path.join(SPSDK_EXAMPLES_FOLDER, f"{notebook}.ipynb"))


@pytest.mark.parametrize("notebook_path", notebook_paths)
@pytest.mark.skipif(
    sys.platform != "linux", reason="Test notebooks only on Linux due to performance"
)
def test_general_notebooks(notebook_path: str) -> None:
    """Test general Jupyter notebooks for regression.

    This function executes a Jupyter notebook and compares its output against
    expected results, ignoring metadata differences and normalizing text output
    formatting across different platforms.

    :param notebook_path: Path to the Jupyter notebook file to be tested
    :raises NBRegressionError: When notebook execution fails or output differs from expected results
    """
    fixture = NBRegressionFixture(
        exec_timeout=60,
        diff_ignore=("/metadata/kernelinfo", "/metadata/language_info", "/metadata/vscode"),
        diff_replace=(
            ("/cells/*/outputs/*/text", "\r\n", "\n"),
            ("/cells/*/outputs/*/text", " \n", "\n"),
            (
                "/cells/*/outputs/*/text",
                "([^\n]*Existing cached quick DB[^\n]*)\n?",
                "",
            ),
        ),
        # on Windows one extra space is added to the cell output
        # also the the test should ignore different line-endings
    )
    fixture.check(notebook_path)
