#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Script used during pre-commit to check if changed files have valid copyright year."""
import argparse
import os
import sys
from typing import List, Optional, Sequence

EXCLUDED_FILES = ["docs/conf.py"]
DEFAULT_HEADER = ["#!/usr/bin/env python", "# -*- coding: utf-8 -*-"]


def check_file(file: str, header_lines: Sequence[str], silent: bool = False) -> int:
    """Run the check on single file."""
    if not os.path.isfile(file):
        if not silent:
            print(f"'{file}' doesn't exist anymore")
        return 0
    with open(file) as f:
        lines = f.read().splitlines()
    for idx, line in enumerate(header_lines):
        if lines[idx].lower() != line.lower():
            if not silent:
                print(f"File: '{file}' doesn't have valid header")
            return 1
    return 0


def fix_file(file: str, header_lines: Sequence[str]) -> None:
    """Fix copyright on single file."""
    result = check_file(file, header_lines=header_lines, silent=True)
    if result:
        with open(file) as f:
            content_lines = f.read().splitlines(keepends=True)
            requires_empty_comment = (
                content_lines[0].startswith("#") and content_lines[0].strip() != "#"
            )
        for index in range(len(header_lines)):
            content_lines.insert(index, header_lines[index] + "\n")
        # Add empty comment between header and following comment
        if requires_empty_comment:
            content_lines.insert(len(header_lines), "#\n")
        with open(file, "w") as f:
            f.write("".join(content_lines))


def fix_py_headers_in_files(files: Sequence[str], header_lines: Sequence[str]) -> None:
    """Fix copyright in list of files."""
    files = filter_files(files)
    for file in files:
        fix_file(file, header_lines)


def check_files(files: Sequence[str], header_lines: Sequence[str]) -> int:
    """Run the check on a list of files."""
    ret_val = 0
    files = filter_files(files)
    for file in files:
        ret_val += check_file(file, header_lines)
    return ret_val


def filter_files(files: Sequence[str]) -> Sequence[str]:
    """Filter files to be checked."""
    collected_files: List[str] = []
    for file in files:
        if file in EXCLUDED_FILES:
            continue
        extension = os.path.splitext(file)[1][1:]
        if extension == "py":
            collected_files.append(file)
    return collected_files


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Check whether py "files" have the correct header."""
    parser = argparse.ArgumentParser(
        description="""Check whether py "files" have the correct header."""
    )
    parser.add_argument("--fix", action="store_true", help="Fix the headers in files")
    parser.add_argument("--header", required=False, help="Header to be tested")
    parser.add_argument("files", nargs="*", help="Files to analyze")
    args = parser.parse_args(argv)

    if not args.header:
        header_lines = DEFAULT_HEADER
    else:
        header_lines = args.header.split("\n")
    if args.fix:
        fix_py_headers_in_files(args.files, header_lines)
        ret_val = 0
    else:
        ret_val = check_files(args.files, header_lines)
    sys.exit(ret_val)


if __name__ == "__main__":
    main()
