#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Script to list all SPSDK dependencies and their dependencies."""

import argparse
import json
import os
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Set, Tuple

import packaging
from mypy_extensions import KwArg
from packaging.metadata import Metadata
from packaging.requirements import Requirement
from packaging.version import Version
from pip import __version__ as pip_version
from typing_extensions import Self

from spsdk.exceptions import SPSDKError

THIS_DIR = Path(__file__).parent.resolve()
ROOT_DIR = THIS_DIR.parent
APPROVED_PACKAGES_FILE_NAME = "approved_packages.json"
APPROVED_PACKAGES_FILE = Path(THIS_DIR, APPROVED_PACKAGES_FILE_NAME)

LIBRARY_PATH = Path(packaging.__path__[0]).parent

ROOT_PACKAGE = "spsdk[all]"
MIN_PIP_VERSION = "21.2.0"

with open(APPROVED_PACKAGES_FILE) as package_file:
    SPDX_LICENSES: Dict[str, List[str]] = json.load(package_file)["spdx"]


class DependencyInfo(NamedTuple):
    """Basic information about a python package."""

    name: str
    license: str
    home_page: str
    spdx: str

    def __str__(self) -> str:
        dep_info = f"{self.name:20} -> {self.spdx}"
        if self.is_manual:
            dep_info += f" (Manual license entry: '{self.license}' -> '{self.spdx}'"
            dep_info += f"; please check {self.home_page})"
        return dep_info

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, self.__class__):
            return NotImplemented
        return self.name.lower() == __value.name.lower()

    def __repr__(self) -> str:
        return f"<DepInfo name={self.name}>"

    @property
    def is_manual(self) -> bool:
        if self.spdx == self.license:
            return False
        if self.spdx in SPDX_LICENSES and self.license in SPDX_LICENSES[self.spdx]:
            return False
        return True

    @classmethod
    def decode_package(cls, requirement: Requirement) -> Tuple[Self, List[Requirement]]:
        meta = get_metadata(name=requirement.name)
        lic = meta.license.split("\n")[0]
        spdx = lic if lic in SPDX_LICENSES else ""
        return (
            cls(name=meta.name, license=lic, home_page=meta.home_page, spdx=spdx),
            get_requirements(meta=meta, extras=requirement.extras),
        )


# pylint: disable=not-an-iterable, no-member
class DependenciesList(List[DependencyInfo]):
    """List of dependencies."""

    def __repr__(self) -> str:
        return f"<DepList len={len(self)}>"

    def names(self) -> List[str]:
        """Get names of all dependencies."""
        return [item.name for item in self]

    def licenses(self) -> List[str]:
        """Get licenses of all dependencies."""
        temp_list = [item.license for item in self]
        return sorted(list(set(temp_list)))

    def spdx_licenses(self) -> List[str]:
        """Get SPDX licenses of all dependencies."""
        temp_list = [item.spdx for item in self]
        return sorted(list(set(temp_list)))

    def get(self, name: str) -> DependencyInfo:
        """Fetch dependency with given `name`."""
        for item in self:
            if item.name == name:
                return item
        raise SPSDKError(f"DependencyInfo({name}) wasn't found!")

    def extend(self, __iterable: Iterable) -> None:
        for other in __iterable:
            self.append(other)

    def append(self, __object: DependencyInfo) -> None:
        assert isinstance(__object, DependencyInfo)
        if __object not in self:
            return super().append(__object)

    def _import_requirement(self, requirement: Requirement) -> None:
        package, dependencies = DependencyInfo.decode_package(requirement=requirement)
        if package in self:
            return
        self.append(package)
        for dep in dependencies:
            if dep not in self.names():
                self._import_requirement(requirement=dep)

    @classmethod
    def from_metadata(cls, root_package: str = ROOT_PACKAGE) -> Self:
        root_req = Requirement(root_package)
        obj = cls()
        obj._import_requirement(requirement=root_req)
        obj.sort()
        return obj

    @classmethod
    def from_approved_packages(cls, file_path: Path = APPROVED_PACKAGES_FILE) -> Self:
        with open(file_path) as f:
            data = json.load(f)
        return cls([DependencyInfo(**item) for item in data["packages"]])


def get_metadata(name: str) -> Metadata:
    new_name = name.replace("-", "_")
    gen = Path(LIBRARY_PATH).glob(f"{new_name}-*dist-info/METADATA")
    try:
        meta_file = next(gen)
    except StopIteration:
        # this is for cases where maintainers doesn't use proper casing
        # Case-insensitive glob is available starting 3.12
        def make_case_ignore(string: str) -> str:
            parts = [f"[{c.lower()}{c.upper()}]" if c.isalpha() else c for c in string]
            return "".join(parts)

        new_name = make_case_ignore(new_name)
        gen = Path(LIBRARY_PATH).glob(f"{new_name}-*dist-info/METADATA")
        meta_file = next(gen)

    return Metadata.from_email(meta_file.read_text(encoding="utf-8"), validate=False)


def get_requirements(meta: Metadata, extras: Optional[Set[str]] = None) -> List[Requirement]:
    def is_included(req: Requirement) -> bool:
        if not req.marker:
            return True
        if not extras:
            return req.marker.evaluate()
        return any(req.marker.evaluate({"extra": e}) for e in extras)

    reqs = filter(is_included, meta.requires_dist)
    return list(reqs)


def print_dependencies(**kwargs: Any) -> int:
    """Print dependencies and their licenses."""
    approved_list = DependenciesList.from_approved_packages()
    for dependency in approved_list:
        print(dependency)
    return 0


def print_licenses(**kwargs: Any) -> int:
    """Print licenses."""
    approved_list = DependenciesList.from_approved_packages()
    for lic in approved_list.spdx_licenses():
        print(lic)
    return 0


def check_dependencies(strict: bool = False, **kwargs: Any) -> int:
    """Check if all dependencies are approved.

    :return: Number of violations
    """
    actual_dep_list = DependenciesList.from_metadata()
    approved_list = DependenciesList.from_approved_packages()
    approved_names = approved_list.names()
    issues_counter = 0
    for actual_dep in actual_dep_list:
        if actual_dep.name not in approved_names:
            print(f"Package '{actual_dep.name}' is not among approved packages!")
            issues_counter += 1
            continue

        if not strict:
            continue

        approved_dependency = approved_list.get(actual_dep.name)
        if not approved_dependency.is_manual:
            package_license = actual_dep.license
            if package_license != approved_dependency.license:
                print(f"Package '{actual_dep.name}' licenses differs. ")
                issues_counter += 1
                continue

    return issues_counter


def init_approved_file(**kwargs: Any) -> int:
    """Update file with approved dependencies."""
    if os.path.isfile(APPROVED_PACKAGES_FILE):
        print(f"'{APPROVED_PACKAGES_FILE}' already exists.")
        answer = input("Do you want to continue? This will rewrite the file: (y/N): ")
        if answer.lower() != "y":
            return 0

    actual_list = DependenciesList.from_metadata()
    print(f"Writing packages info to {APPROVED_PACKAGES_FILE}")
    data = {"spdx": SPDX_LICENSES, "packages": [package._asdict() for package in actual_list]}

    with open(APPROVED_PACKAGES_FILE, "w") as f:
        json.dump(data, f, indent=2)
    for pkg_info in actual_list:
        if pkg_info.is_manual:
            print(f"Warning: '{pkg_info.name}' need manual license entry")
    return 0


def parse_inputs(input_args: Optional[List[str]] = None) -> dict:
    """Parse user input parameters."""
    parser = argparse.ArgumentParser(
        description="Utility for checking licenses of all dependencies",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    commands_parser = parser.add_subparsers(dest="command", metavar="SUB-COMMAND", required=True)
    check_parser = commands_parser.add_parser(
        "check", help="Check whether all dependencies are approved"
    )
    check_parser.add_argument(
        "--strict",
        action="store_true",
        help="License name in package must match string in database",
    )
    commands_parser.add_parser("print", help="Only print dependencies and their licenses")
    commands_parser.add_parser("print-lic", help="Only print licenses of dependencies")
    commands_parser.add_parser("init", help="Initialize the approved licenses list file")
    parser.add_argument(
        "-r", "--root-package", default=ROOT_PACKAGE, help="Main package to investigate"
    )
    args = vars(parser.parse_args(input_args))
    return args


def main() -> int:
    """Main function."""
    if Version(pip_version) < Version(MIN_PIP_VERSION):
        print("Please install newer version of pip")
        print(f"Minimum version required: {MIN_PIP_VERSION}, you have: {pip_version}")
        print("To update pip run: 'python -m pip install --upgrade pip'")
        return 1

    args = parse_inputs()

    handlers: Dict[str, Callable[[KwArg(Any)], int]] = {
        "print": print_dependencies,
        "print-lic": print_licenses,
        "check": check_dependencies,
        "init": init_approved_file,
    }
    handler = handlers[args["command"]]
    return handler(**args)


if __name__ == "__main__":
    sys.exit(main())
