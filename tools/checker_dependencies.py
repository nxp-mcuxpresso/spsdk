#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Script to list all SPSDK dependencies and their dependencies."""

import argparse
import itertools
import json
import os
import sys
from typing import Dict, Iterator, List, NamedTuple, Optional, Union, no_type_check

from pip._internal.commands.show import search_packages_info

APPROVED_LICENSES_FILE_NAME = "approved_packages.json"
APPROVED_LICENSES_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), APPROVED_LICENSES_FILE_NAME)
)
ROOT_PACKAGE = "spsdk"


class DependencyInfo(NamedTuple):
    """Basic infomartion about a python package."""

    name: str
    license: str
    home_page: str
    is_manual: str

    def __str__(self) -> str:
        dep_info = f"{self.name:20} -> {self.license}"
        if self.is_manual:
            dep_info += f" (Manual license entry; please check {self.home_page})"
        return dep_info

    @staticmethod
    def from_pgk_meta(pgk_meta_item: dict) -> "DependencyInfo":
        """Extract data from package's meta info."""
        return DependencyInfo(
            name=pgk_meta_item["name"],
            license=pgk_meta_item["license"],
            home_page=pgk_meta_item["home-page"],
            is_manual=pgk_meta_item["license"] == "UNKNOWN",
        )


# pylint: disable=not-an-iterable, no-member
class DependenciesList(List[DependencyInfo]):
    """List of dependencies."""

    def names(self) -> List[str]:
        """Get names of all dependencies."""
        return [item.name for item in self]

    def licenses(self) -> List[str]:
        """Get licenses of all dependencies."""
        return [item.license for item in self]

    def get(self, name: str) -> Optional[DependencyInfo]:
        """Fetch dependency with given `name`."""
        for item in self:
            if item.name == name:
                return item
        return None

    @staticmethod
    def load(file_path: str) -> "DependenciesList":
        """Load DependenciesList portion of the json config file."""
        with open(file_path) as f:
            data = json.load(f)
        return DependenciesList([DependencyInfo(**item) for item in data["packages"]])

    @staticmethod
    def load_licenses(file_path: str) -> List[str]:
        """Load licenses portion of the json config file."""
        with open(file_path) as f:
            data = json.load(f)
        return data["licenses"]

    @staticmethod
    def from_pip_meta(root_package: str = ROOT_PACKAGE) -> "DependenciesList":
        """Create DependenciesList from pip."""
        dep_names_iterator = itertools.chain(*DependenciesList._get_requires([root_package]))
        # exhaust the iterator and filter duplicates
        dep_names = list(set(list(dep_names_iterator)))
        pkg_meta = search_packages_info(dep_names)
        dependencies_list = DependenciesList(
            [DependencyInfo.from_pgk_meta(item) for item in pkg_meta]
        )
        dependencies_list.sort(key=lambda x: x.name)
        return dependencies_list

    @staticmethod
    @no_type_check  # Mypy doesn't like the recursive 'yield from' magic
    def _get_requires(module_names: List[str]) -> Iterator[List[str]]:
        """Get `requires` fields from given set of package names."""
        for pkg_info in search_packages_info(module_names):
            yield pkg_info["requires"]
            yield from DependenciesList._get_requires(pkg_info["requires"])


def parse_inputs(input_args: List[str] = None) -> dict:
    """Parse user input parameters."""
    parser = argparse.ArgumentParser(
        description="Utility for checking licenses of all dependencies",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    commands_parser_opts: Dict[str, Union[str, bool]] = {
        "dest": "command",
        "metavar": "SUB-COMMAND",
    }
    # the 'required' argument for subparser is available only Python 3.7+
    if sys.version_info.minor > 6:
        commands_parser_opts["required"] = True
    # Mypy really doesn't like dictionary unpacking
    commands_parser = parser.add_subparsers(**commands_parser_opts)  # type: ignore
    commands_parser.add_parser("print", help="Only print dependencies and their licenses")
    commands_parser.add_parser("print_lic", help="Only print licenses of dependencies")
    commands_parser.add_parser("check", help="Check whether all dependencies are approved")
    commands_parser.add_parser("init", help="Initialize the approved licenses list file")
    parser.add_argument(
        "-r", "--root-package", default=ROOT_PACKAGE, help="Main package to investigate"
    )
    args = vars(parser.parse_args(input_args))
    # fallback check for Python < 3.7
    if args["command"] is None:
        print("error: the following arguments are required: command")
        sys.exit(1)
    return args


def print_dependencies(actual_list: DependenciesList) -> int:
    """Print dependencies and their licenses."""
    approved_list = DependenciesList.load(APPROVED_LICENSES_FILE)
    for actual_dep in actual_list:
        # look up the package info from approved list if package meta doesn't contain license
        if actual_dep.is_manual:
            print(approved_list.get(actual_dep.name))
        else:
            print(actual_dep)
    return 0


def print_licenses(actual_list: DependenciesList) -> int:
    """Print licenses."""
    approved_list = DependenciesList.load(APPROVED_LICENSES_FILE)
    licenses = []
    for item in actual_list:
        if item.is_manual:
            approved_item = approved_list.get(item.name)
            assert approved_item
            licenses.append(approved_item.license)
        else:
            licenses.append(item.license)

    licenses = sorted(list(set(licenses)))
    for lic in licenses:
        print(lic)
    return 0


def check_dependencies(actual_list: DependenciesList) -> int:
    """Check if all dependencies are approved.

    :param actual_list: List of actual dependencies
    :return: Number of violations
    """
    approved_list = DependenciesList.load(APPROVED_LICENSES_FILE)
    approved_names = approved_list.names()
    approved_licenses = DependenciesList.load_licenses(APPROVED_LICENSES_FILE)
    issues_counter = 0
    for actual_dep in actual_list:

        lic = actual_dep.license
        if actual_dep.is_manual:
            fall_back = approved_list.get(actual_dep.name)
            if fall_back is None:
                print(f"License for package '{actual_dep.name}' can't be determined!!!")
                issues_counter += 1
                continue
            lic = fall_back.license

        if lic not in approved_licenses:
            print(f"License '{lic}' used by '{actual_dep.name}' is not approved!!!")
            issues_counter += 1
            continue

        if actual_dep.name not in approved_names:
            print(
                f"Package '{actual_dep.name}' uses valid license '{lic}', but it's not among approved packages"
            )

    return issues_counter


def init_approved_file(actual_list: DependenciesList) -> int:
    """Create a file with approved dependencies.

    :param actual_list: List of dependencies
    :return: 1 of the approved list already exists, 0 otherwise
    """
    if os.path.isfile(APPROVED_LICENSES_FILE):
        print(f"'{APPROVED_LICENSES_FILE}' already exists.")
        print("If you're sure you want to write it, remove/rename the original")
        return 1
    print(f"Writing packages info to {APPROVED_LICENSES_FILE}")
    licenses = actual_list.licenses()
    licenses = sorted(list(set(licenses)))
    data = {"licenses": licenses, "packages": [package._asdict() for package in actual_list]}

    with open(APPROVED_LICENSES_FILE, "w") as f:
        json.dump(data, f, indent=2)
    for pkg_info in actual_list:
        if pkg_info.is_manual:
            print(f"Warning: '{pkg_info.name}' need manual lincense entry")
    return 0


def main() -> int:
    """Main function."""
    args = parse_inputs()

    actual_dep_list = DependenciesList.from_pip_meta(root_package=args["root_package"])

    handlers = {
        "print": print_dependencies,
        "print_lic": print_licenses,
        "check": check_dependencies,
        "init": init_approved_file,
    }
    handler = handlers[args["command"]]
    return handler(actual_list=actual_dep_list)


if __name__ == "__main__":
    sys.exit(main())
