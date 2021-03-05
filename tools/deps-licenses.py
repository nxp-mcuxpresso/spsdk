#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Script to list all SPSDK dependencies and their dependencies."""

from typing import List, Iterator
from pip._internal.commands.show import search_packages_info
import itertools


def get_requires(module_names: List[str]) -> Iterator[List[str]]:
    for pkg_info in search_packages_info(module_names):
        yield pkg_info['requires']
        yield from get_requires(pkg_info['requires'])


def get_licenses(module_names: List[str]) -> Iterator[str]:
    for pkg_info in search_packages_info(module_names):
        yield pkg_info['license']

   
if __name__ == "__main__":
    items = set(itertools.chain(*get_requires(['spsdk'])))
    
    for module in sorted(list(items)):
        print(f"{module:20} -> {next(search_packages_info([module]))['license']}")
