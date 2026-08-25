#!/usr/bin/env python
#
# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Jupyter notebook testing utilities.

This module provides test functionality for validating SPSDK example
Jupyter notebooks to ensure they execute correctly without errors.
"""

import os
import sys
from pathlib import Path

import nbclient
import nbformat
import pytest

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
    """Test general Jupyter notebooks by executing them and checking for errors.

    This function executes a Jupyter notebook using nbclient and verifies
    it completes without raising any cell execution exceptions.

    :param notebook_path: Path to the Jupyter notebook file to be tested
    :raises nbclient.exceptions.CellExecutionError: When a notebook cell fails during execution
    """
    nb = nbformat.read(notebook_path, as_version=4)
    notebook_dir = str(Path(notebook_path).resolve().parent)
    client = nbclient.NotebookClient(nb, timeout=60, resources={"metadata": {"path": notebook_dir}})
    client.execute()
