#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK documentation generator for project structure.

This module generates RST table documentation for the SPSDK project structure
by scanning Python packages and modules. It creates a structured table showing
the organization of the SPSDK codebase for documentation purposes.
"""

# Script for generation of project structure table
import importlib
import os.path
import pkgutil
from typing import Any

from pytablewriter import RstGridTableWriter

import spsdk

DOC_PATH = os.path.abspath(".")
TABLE_DIR = os.path.join(DOC_PATH, "_prebuild")
TABLE_FILE = os.path.join(TABLE_DIR, "table_project_structure.inc")


def write_table(header: list[str], values: list[list[str]]) -> None:
    """Write RST table to file using pytablewriter.

    Creates the output directory if it doesn't exist and writes the table data
    to a predefined RST file using RstGridTableWriter.

    :param header: Table column headers.
    :param values: Matrix of table cell values, where each inner list represents a row.
    :raises OSError: If the output directory cannot be created or file cannot be written.
    """
    writer = RstGridTableWriter(
        table_name="List of SPSDK modules",
        headers=header,
        value_matrix=values,
    )

    if not os.path.exists(TABLE_DIR):
        os.makedirs(TABLE_DIR)

    with open(TABLE_FILE, "w", encoding="utf-8") as f:
        writer.stream = f
        writer.write_table()


def main() -> None:
    """Generate project structure documentation table.

    Iterates through all SPSDK modules, imports them to extract their documentation,
    and creates a table with module names and descriptions. The generated table
    is written to output for documentation purposes.

    :raises ImportError: When a module cannot be imported.
    :raises AttributeError: When a module doesn't have __doc__ attribute.
    """
    print("Generating project structure table")
    doc_list = []
    pkgpath = os.path.dirname(spsdk.__file__)
    # iterate through spsdk modules, import them and get docs
    for _, name, should_import in pkgutil.walk_packages([pkgpath]):
        if should_import:
            importlib.import_module("spsdk." + name)
            module_doc = eval("spsdk." + name + ".__doc__").partition(  # pylint: disable=eval-used
                "\n"
            )[0]
            doc = [name, module_doc]
            doc_list.append(doc)

    header = ["Module name", "Description"]
    write_table(header, doc_list)


def setup(app: Any) -> None:
    """Setup Sphinx extension for generating project structure documentation.

    This function registers the extension with Sphinx and triggers the main
    documentation generation process for the project structure.

    :param app: The Sphinx application instance used for documentation building.
    """
    main()


if __name__ == "__main__":
    main()
