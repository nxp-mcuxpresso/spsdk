#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
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
@pytest.mark.skipif(sys.platform == "darwin", reason="jupyter produces different results on macOS")
def test_general_notebooks(notebook_path):
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
        # TODO: remove the last regex once the bug SPSDK-4302 is closed
    )
    fixture.check(notebook_path)
