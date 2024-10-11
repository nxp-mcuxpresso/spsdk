#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
# Script for generation of project structure table
import importlib
import os.path
import pkgutil
from typing import List

from pytablewriter import RstGridTableWriter

import spsdk

DOC_PATH = os.path.abspath(".")
TABLE_DIR = os.path.join(DOC_PATH, "_prebuild")
TABLE_FILE = os.path.join(TABLE_DIR, "table_project_structure.inc")


def write_table(header: List[str], values: List[List[str]]):
    """Write RST table to file using pytablewriter

    :param header: table header
    :param values: values to be written
    """
    writer = RstGridTableWriter(
        table_name="List of SPSDK modules",
        headers=header,
        value_matrix=values,
    )

    if not os.path.exists(TABLE_DIR):
        os.makedirs(TABLE_DIR)

    with open(TABLE_FILE, "w") as f:
        writer.stream = f
        writer.write_table()


def main():
    print("Generating project structure table")
    doc_list = []
    pkgpath = os.path.dirname(spsdk.__file__)
    # iterate through spsdk modules, import them and get docs
    for _, name, should_import in pkgutil.walk_packages([pkgpath]):
        if should_import:
            importlib.import_module("spsdk." + name)
            module_doc = eval("spsdk." + name + ".__doc__").partition("\n")[0]
            doc = [name, module_doc]
            doc_list.append(doc)

    header = ["Module name", "Description"]
    write_table(header, doc_list)


def setup(app):
    main()


if __name__ == "__main__":
    main()
