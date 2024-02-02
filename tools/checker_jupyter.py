#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Script to check Jupyter Notebook consistency."""

import argparse
import json
import logging
import os
import pathlib
import sys
from typing import List, Optional

JUPYTER_EXTENSIONS = ("ipynb",)
THIS_DIR = pathlib.Path(__file__).absolute().parent
REPO_ROOT = THIS_DIR.parent
with open(THIS_DIR / "approved_jupyter_exceptions.json") as exc_file:
    EXCEPTIONS = json.load(exc_file)


logger = logging.getLogger(__name__)


def outputs(sources: List[str]) -> int:
    """Command for checking that code cells have output."""
    error_counter = 0
    file_counter = 0
    for source in sources:
        if os.path.isfile(source) and source.endswith(JUPYTER_EXTENSIONS):
            file_counter += 1
            error_counter += check_jupyter_output(path=source)
        if os.path.isdir(source):
            for root, _, files in os.walk(source):
                for file in files:
                    if file.endswith(JUPYTER_EXTENSIONS):
                        file_counter += 1
                        error_counter += check_jupyter_output(os.path.join(root, file))

    print(f"Found {error_counter} errors in {file_counter} files.")
    return error_counter


def check_jupyter_output(path: str) -> int:
    full_path = pathlib.Path(path).absolute().resolve()
    logger.debug(f"Checking {full_path}")
    with open(full_path) as f:
        data = json.load(f)
    if "cells" not in data or len(data["cells"]) == 0:
        print(f"File {full_path} doesn't have any cells")
        return 1
    error_count = 0
    for i, cell in enumerate(data["cells"], start=1):
        if cell["cell_type"] != "code":
            continue
        if len(cell["outputs"]) == 0:
            rel_path = full_path.relative_to(REPO_ROOT).as_posix()

            # if there's an exception record for this file
            # and record contains either this cell number or "*"
            if rel_path in EXCEPTIONS["outputs"]:
                if "*" == EXCEPTIONS["outputs"][rel_path] or i in EXCEPTIONS["outputs"][rel_path]:
                    logger.debug(f"{full_path} cell #{i} is amongst exceptions")
                    continue
            # cell was executed, but didn't produce any output
            if cell["execution_count"] and cell["execution_count"] > 0:
                logger.debug(f"{full_path} cell #{i} doesn't provide an output")
                continue
            print(f"{full_path} cell #{i} doesn't have output")
            error_count += 1
    return error_count


def parse_inputs(input_args: Optional[List[str]] = None) -> dict:
    parser = argparse.ArgumentParser(
        description="Tool for checking Jupyter Notebook's consistency.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug messages")

    subcommands = parser.add_subparsers(dest="command", metavar="SUB-COMMAND", required=True)

    outputs_parser = subcommands.add_parser(
        "outputs", help="Command for checking that code cells have output."
    )
    outputs_parser.add_argument(
        "sources",
        nargs="*",
        metavar="SOURCE",
        help="Path(s) to Notebooks or directory(ies) where to look for Notebooks. Every directory is traversed recursively.",
    )

    args = vars(parser.parse_args(input_args))
    return args


def main(input_args: Optional[List[str]] = None) -> int:
    args = parse_inputs(input_args=input_args)
    logging.basicConfig(level=logging.DEBUG if args["debug"] else logging.WARNING)

    logger.debug(f"Inputs: {args}")

    error_code = 0
    if args["command"] == "outputs":
        error_code = outputs(sources=args["sources"])

    return error_code


if __name__ == "__main__":
    sys.exit(main())
