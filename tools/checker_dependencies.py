#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Script to list all SPSDK dependencies and their dependencies."""

import argparse
import json
import math
import os
import subprocess
import sys
from typing import Dict, List, NamedTuple, Optional, Tuple, Union

from pip import __version__ as pip_version
from pip._internal.cli.main import main as pip_main

APPROVED_LICENSES_FILE_NAME = "approved_packages.json"
APPROVED_LICENSES_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), APPROVED_LICENSES_FILE_NAME)
)
ROOT_PACKAGE = "spsdk"
MIN_PIP_VERSION = "21.2.0"


class DependencyInfo(NamedTuple):
    """Basic infomartion about a python package."""

    name: str
    license: str
    home_page: str
    is_manual: bool

    def __str__(self) -> str:
        dep_info = f"{self.name:20} -> {self.license}"
        if self.is_manual:
            dep_info += f" (Manual license entry; please check {self.home_page})"
        return dep_info


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
    def decode_package_info(package_str: str) -> Tuple[DependencyInfo, List[str]]:
        """Decode package info from pip show output.

        :param package_str: Package info string.
        :return: Tuple with DependencyInfo and List of package dependencies.
        """

        def get_line_value(lines: List[str], key: str) -> str:
            """Get the value of line.

            :param key: Key of value
            :return: Value of key
            """
            line_start = f"{key}: "
            for line in lines:
                if line.startswith(line_start):
                    return line.replace(line_start, "")
            return ""

        lines = package_str.splitlines()
        name = get_line_value(lines, "Name")
        license = get_line_value(lines, "License")
        home_page = get_line_value(lines, "Home-page")
        is_manual = license in ["UNKNOWN", ""]
        dependencies = get_line_value(lines, "Requires").split(", ")
        dependencies = [] if dependencies == [""] else dependencies
        return DependencyInfo(name, license, home_page, is_manual), dependencies

    @staticmethod
    def get_packages_info(packages: List[str]) -> List[Tuple[DependencyInfo, List[str]]]:
        """Get packages info for list of packages.

        :param packages: List of packages names.
        :return: List of Tuples with DependencyInfo and List of package dependencies.
        """
        packages_info: List[str] = []
        try:
            output = subprocess.check_output(f"pip show {' '.join(packages)}".split()).decode(
                "utf-8"
            )
            if "WARNING: Package(s) not found:" in output:
                raise ValueError(f"Some package(s) not found: \n{output}")

            packages_info = output.split("---")

        except BaseException as exc:
            print(f"Some package(s) from {packages} has not been found: {str(exc)}")

        ret = []
        for package_info in packages_info:
            ret.append(DependenciesList.decode_package_info(package_info))

        return ret

    @staticmethod
    def _from_pip_meta(packages: List[str], base_list: "DependenciesList") -> None:
        """Recursive function to get the full list of dependencies."""
        packages_info = DependenciesList.get_packages_info(packages)
        dependencies_info = []
        dependencies = []
        for package_info_dep, dependency in packages_info:
            dependencies_info.append(package_info_dep)
            dependencies.extend(dependency)
        base_list.extend(dependencies_info)
        packages_names = list(set(dependencies) - set(base_list.names()))
        if len(packages_names) > 0:
            DependenciesList._from_pip_meta(packages_names, base_list)

    @staticmethod
    def from_pip_meta(root_package: str = ROOT_PACKAGE) -> "DependenciesList":
        """Create DependenciesList from pip."""
        actual_list = DependenciesList()
        DependenciesList._from_pip_meta([root_package], actual_list)
        actual_list.sort()
        return actual_list


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
    commands_parser.add_parser("print-lic", help="Only print licenses of dependencies")
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


def numberify_version(version: str, separator: str = ".") -> int:
    """Turn version string into a number.

    Each group is weighted by a multiple of 1000

    1.2.3    -> 1  * 1_000_000 +   2 * 1_000 + 3 * 1 =  1_002_003
    21.100.9 -> 21 * 1_000_000 + 100 * 1_000 + 9 * 1 = 21_100_009

    :param version: Version string numbers separated by `separator`
    :param separator: Separator used in the version string, defaults to "."
    :return: Number representing the version
    """
    sanitized_version = sanitize_version(version=version, separator=separator, valid_numbers=3)
    return int(
        sum(
            int(number) * math.pow(10, 3 * order)
            for order, number in enumerate(reversed(sanitized_version.split(separator)))
        )
    )


def sanitize_version(version: str, separator: str = ".", valid_numbers: int = 3) -> str:
    """Sanitize version string.

    Append '.0' in case version string has fewer parts than `valid_numbers`
    Remove right-most version parts after `valid_numbers` amount of parts

    1.2     -> 1.2.0
    1.2.3.4 -> 1.2.3

    :param version: Original version string
    :param separator: Separator used in the version string, defaults to "."
    :param valid_numbers: Amount of numbers to sanitize, defaults to 3
    :return: Sanitized version string
    """
    version_parts = version.split(separator)
    version_parts += ["0"] * (valid_numbers - len(version_parts))
    return separator.join(version_parts[:valid_numbers])


def main() -> int:
    """Main function."""
    if numberify_version(pip_version) < numberify_version(MIN_PIP_VERSION):
        print("Please install newer version of pip")
        print(f"Minimum version required: {MIN_PIP_VERSION}, you have: {pip_version}")
        print("To update pip run: 'python -m pip install --upgrade pip'")
        return 1

    args = parse_inputs()

    actual_dep_list = DependenciesList.from_pip_meta(root_package=args["root_package"])

    handlers = {
        "print": print_dependencies,
        "print-lic": print_licenses,
        "check": check_dependencies,
        "init": init_approved_file,
    }
    handler = handlers[args["command"]]
    return handler(actual_list=actual_dep_list)


if __name__ == "__main__":
    sys.exit(main())
