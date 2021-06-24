#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Script used during pre-commit to check if changed files have valid copyright year."""
import argparse
import datetime
import os
import re
import sys
from typing import Sequence

EXTENSIONS = [".py"]
COPYRIGHT_REGEX_STR = r"Copyright.*(?P<till>\d{4}) (?P<holder>.*)"
COPYRIGHT_REGEX = re.compile(COPYRIGHT_REGEX_STR)
THIS_YEAR = datetime.datetime.now().year

EXCLUDED_FILES = ["docs/conf.py"]


def check_file(file: str) -> int:
    """Run the check on single file."""
    ret_val = 0
    if not os.path.isfile(file):
        print(f"'{file}' doesn't exist anymore")
        return 0
    with open(file) as f:
        content = f.read()
    copyrights = COPYRIGHT_REGEX.findall(content)
    for cp_instance in copyrights:
        cp_year = int(cp_instance[0])
        if cp_year == THIS_YEAR:
            break
    else:
        print(f"File: '{file}' doesn't have {THIS_YEAR} Copyright")
        ret_val = 1
    return ret_val


def check_files(files: Sequence[str]) -> int:
    """Run the check on a list of files."""
    ret_val = 0
    for file in files:
        if file in EXCLUDED_FILES:
            continue
        _, extension = os.path.splitext(file)
        if extension in EXTENSIONS:
            ret_val += check_file(file)
    return ret_val


def main(argv: Sequence[str] = None) -> int:
    """Main function."""
    parser = argparse.ArgumentParser(
        description="""Check whether "files" have the current year in Copyright."""
    )
    parser.add_argument("files", nargs="*", help="Files to analyze")
    args = parser.parse_args(argv)

    return check_files(args.files)


if __name__ == "__main__":
    sys.exit(main())
