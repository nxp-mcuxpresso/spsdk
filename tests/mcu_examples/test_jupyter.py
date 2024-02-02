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

GENERAL_NOTEBOOKS = ["crypto", "image_dcd", "image"]

notebook_paths = []
for notebook in GENERAL_NOTEBOOKS:
    notebook_paths.append(os.path.join(SPSDK_EXAMPLES_FOLDER, "general", f"{notebook}.ipynb"))


@pytest.mark.parametrize("notebook_path", notebook_paths)
@pytest.mark.skipif(sys.platform == "darwin", reason="jupyter produces different results on macOS")
def test_general_notebooks(notebook_path):
    fixture = NBRegressionFixture(
        exec_timeout=10,
        diff_ignore=("/metadata/kernelinfo", "/metadata/language_info", "/metadata/vscode"),
    )
    fixture.check(notebook_path)
