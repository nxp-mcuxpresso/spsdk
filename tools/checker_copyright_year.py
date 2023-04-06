#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Script used during pre-commit to check if changed files have valid copyright year."""
import argparse
import datetime
import os
import re
import sys
from typing import List, Optional, Sequence

COPYRIGHT_EXTENSIONS = ["py", "yml", "yaml", "xml"]
COPYRIGHT_REGEX_STR = r"Copyright.*?(?P<from>\d{4})?-?(?P<till>\d{4}) (?P<holder>.*)"
COPYRIGHT_REGEX = re.compile(COPYRIGHT_REGEX_STR)
NXP_HOLDER_NAME = "NXP"
THIS_YEAR = datetime.datetime.now().year

EXCLUDED_FILES = ["docs/conf.py", ".pre-commit-config.yaml"]


def check_file(file: str, silent: bool = False) -> int:
    """Run the check on single file."""
    ret_val = 0
    if not os.path.isfile(file):
        if not silent:
            print(f"'{file}' doesn't exist anymore")
        return 0
    with open(file) as f:
        content = f.read()
    copyrights = COPYRIGHT_REGEX.findall(content)
    for cp_instance in copyrights:
        till_year = int(cp_instance[1])
        if till_year == THIS_YEAR:
            break
    else:
        if not silent:
            print(f"File: '{file}' doesn't have {THIS_YEAR} Copyright")
        ret_val = 1
    return ret_val


def fix_file(file: str) -> None:
    """Fix copyright on single file."""
    result = check_file(file, silent=True)
    if result:
        with open(file) as f:
            content = f.read()
        if len(COPYRIGHT_REGEX.findall(content)) > 0:
            fixed_content = update_copyright(content)
        else:
            ext = os.path.splitext(file)[1][1:]
            fixed_content = add_copyright(content, ext)
        with open(file, "w") as f:
            f.write(fixed_content)


def update_copyright(content: str) -> str:
    """Update copyright comment section of an existing file content."""
    copyrights = COPYRIGHT_REGEX.findall(content)
    for cp_instance in copyrights:
        if cp_instance[2] != NXP_HOLDER_NAME:
            continue
        from_year = int(cp_instance[0]) if cp_instance[0] else None
        till_year = int(cp_instance[1]) if cp_instance[1] else None
        assert till_year
        if not from_year:
            from_year = till_year
        till_year = THIS_YEAR
        year_string = generate_copyright_year_clause(till_year=till_year, from_year=from_year)
        nxp_copyright_regex_str = COPYRIGHT_REGEX_STR.replace(
            COPYRIGHT_REGEX_STR.split(" ")[-1], NXP_HOLDER_NAME
        )
        content = re.sub(nxp_copyright_regex_str, year_string, content)
    return content


def add_copyright(content: str, extension: str) -> str:
    """Add copyright comment section to an existing file content."""
    lines = content.splitlines(keepends=True)
    index = find_copyright_line_index(lines, extension)
    # Add one more empty line between comment sections
    leading_line = True if extension in ["py", "yml", "yaml"] and index != 0 else False

    comment = generate_copyright_comment(
        file_extension=extension, till_year=THIS_YEAR, leading_empty_line=leading_line
    )
    for i in range(len(comment)):
        lines.insert(index + i, comment[i] + "\n")
    fixed_content = "".join(lines)
    return fixed_content


def find_copyright_line_index(lines: list, file_extension: str) -> int:
    """Find the index of line in source code, where copyright text should be placed."""
    if file_extension in ["yml", "yaml"]:
        return 0
    elif file_extension == "py":
        index = 0
        for i, s in enumerate(lines):
            if not s.startswith("#"):
                index = i
                break
        return index
    elif file_extension == "xml":
        return 1 if re.match(r"<\?xml version.*\?>", lines[0]) else 0
    else:
        raise TypeError(f"Unsupported file type {file_extension}")


def comment_text(text_lines: list, file_extension: str) -> list:
    """Build a commented text from list of text lines."""
    if file_extension in ["py", "yml", "yaml"]:
        for i, s in enumerate(text_lines):
            text_lines[i] = f"# {s}" if s else "#"
    elif file_extension in ["xml"]:
        for i, s in enumerate(text_lines):
            text_lines[i] = f"  {s}"
        text_lines.insert(0, "<!--")
        text_lines.append("-->")
    else:
        raise TypeError(f"Unsupported file type {file_extension}")
    return text_lines


def generate_copyright_comment(
    file_extension: str,
    till_year: int,
    from_year: Optional[int] = None,
    leading_empty_line: bool = False,
) -> list:
    """Create full copyright text with leading empty line if required."""
    year_string = generate_copyright_year_clause(till_year=till_year, from_year=from_year)
    copyright_lines = [year_string, "", "SPDX-License-Identifier: BSD-3-Clause"]
    if leading_empty_line:
        copyright_lines.insert(0, "")
    return comment_text(copyright_lines, file_extension)


def generate_copyright_year_clause(till_year: int, from_year: Optional[int] = None) -> str:
    """Create copyright sentence with years range."""
    years = f"{from_year}-{till_year}" if from_year else till_year
    return f"Copyright {years} {NXP_HOLDER_NAME}"


def fix_copyright_in_files(files: Sequence[str]) -> None:
    """Fix copyright in list of files."""
    files = filter_files(files)
    for file in files:
        fix_file(file)


def check_files(files: Sequence[str]) -> int:
    """Run the check on a list of files."""
    ret_val = 0
    files = filter_files(files)
    for file in files:
        ret_val += check_file(file)
    return ret_val


def filter_files(files: Sequence[str]) -> Sequence[str]:
    """Filter files to be checked."""
    collected_files: List[str] = []
    for file in files:
        if file in EXCLUDED_FILES:
            continue
        extension = os.path.splitext(file)[1][1:]
        if extension in COPYRIGHT_EXTENSIONS:
            collected_files.append(file)
    return collected_files


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Main function."""
    parser = argparse.ArgumentParser(
        description="""Check whether "files" have the current year in Copyright."""
    )
    parser.add_argument("files", nargs="*", help="Files to analyze")
    parser.add_argument("--fix", action="store_true", help="Fix the copyright in files")
    args = parser.parse_args(argv)

    ret_val = check_files(args.files)
    if args.fix:
        fix_copyright_in_files(args.files)
    return ret_val


if __name__ == "__main__":
    sys.exit(main())
