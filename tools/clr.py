#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Copyright and License Review script.

Generates a report of files that are:
- missing Copyright information
- missing NXP Copyright
- missing this year's copyright
- missing license info
- having other license than BSD-3-Clause
"""

import os
import re
from collections import namedtuple
from datetime import datetime
from typing import List, Tuple

ROOT_FOLDERS = ["spsdk", "tests", "examples", "tools"]
CWD = os.path.abspath(os.curdir)
ROOT_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
ROOT_FOLDERS = [os.path.relpath(os.path.join(ROOT_DIR, path), CWD) for path in ROOT_FOLDERS]

CLRInfo = namedtuple("CLRInfo", ["path", "copyrights", "license"])

COPYRIGHT_REGEX = re.compile(r"Copyright.*(?P<from>\d{4})?-?(?P<till>\d{4}) (?P<holder>.*)")
LICENSE_REGEX = re.compile(r"SPDX-License-Identifier:[#\s]*(?P<license>.*)", re.MULTILINE)


def format_copyright_instance(copyright_instance: tuple) -> str:
    """Transform Copyright info from tuple to string.

    ('YEAR_FROM', 'YEAR_TO', 'HOLDER') -> '[YEAR_FROM-]YEAR_TO HOLDER'
    """
    from_year, to_year, holder = copyright_instance
    msg = f"{from_year}-" if from_year else ""
    msg += f"{to_year}"
    msg += f" {holder}"
    return msg


def format_copyright(copyright_info: List[Tuple[str]]) -> List[str]:
    """Transforms a list of tuples of Copyright info into a list."""
    return [format_copyright_instance(instance) for instance in copyright_info]


def process_file(file_path: str) -> CLRInfo:
    """Gather copyright and license into from a file."""
    with open(file_path) as f:
        file_content = f.read()
    copyrights = COPYRIGHT_REGEX.findall(file_content)
    lic = LICENSE_REGEX.findall(file_content)
    lic = lic[0] if len(lic) > 0 else []
    return CLRInfo(file_path, format_copyright(copyrights), lic)


def get_all_files(root_folders: List[str]) -> List[str]:
    """Gather all python files in root_folders."""
    all_files = []
    for root_folder in root_folders:
        for root, _, file_names in os.walk(root_folder):
            for file_name in file_names:
                if file_name.endswith(".py"):
                    all_files.append(os.path.join(root, file_name))
    return all_files


def main() -> None:
    """Main function."""
    clr_info_list = [process_file(file_path) for file_path in get_all_files(ROOT_FOLDERS)]

    no_cr_list = [item for item in clr_info_list if len(item.copyrights) == 0]
    print(f"{len(no_cr_list)} Files without copyright info")
    for clr_info in no_cr_list:
        print(f" - {clr_info.path}")

    no_nxp_cp = [item for item in clr_info_list if not any("NXP" in x for x in item.copyrights)]
    print(f'{len(no_nxp_cp)} Files without "NXP" copyright')
    for clr_info in no_nxp_cp:
        print(f" - {clr_info.path}: {clr_info.copyrights}")

    no_lic = [item for item in clr_info_list if not item.license]
    print(f"{len(no_lic)} Files without license info")
    for clr_info in no_lic:
        print(f" - {clr_info.path}")

    no_bsd_3 = [item for item in clr_info_list if item.license != "BSD-3-Clause"]
    print(f'{len(no_bsd_3)} Files without "BSD-3-Clause" license')
    for clr_info in no_bsd_3:
        print(f" - {clr_info.path}: {clr_info.license}")

    this_year = datetime.now().year
    not_this_year = [
        item for item in clr_info_list if not any(f"{this_year} NXP" in x for x in item.copyrights)
    ]
    print(f'{len(not_this_year)} Files without "{this_year} NXP" copyright')
    for clr_info in not_this_year:
        print(f" - {clr_info.path}: {clr_info.copyrights}")


if __name__ == "__main__":
    main()
