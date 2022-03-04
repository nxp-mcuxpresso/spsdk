#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for any git operations needed for checkers."""

import logging
import re
import subprocess


def get_number_of_commits(repo_path: str, parent_branch: str = "origin/master") -> int:
    """Get number of commits.

    :param parent_branch: branch to examine
    :param repo_path: path to the repository
    :return nuumber of commits
    """
    cmd = f"git log --oneline {parent_branch}..HEAD"
    logging.debug(f"Executing: {cmd}")
    logs = subprocess.check_output(cmd.split(), cwd=repo_path).decode("utf-8")
    distance = len(logs.splitlines())
    logging.debug(f"Current branch is {distance} commits away from {parent_branch}")
    return distance


def get_changed_files(
    repo_path: str, commits: int = 1, cached: bool = False, file_extension_regex: str = r"\.py"
) -> list:
    """Get list of changed files.

    :param repo_path: path to the repository
    :param commits: number of commits
    :param cached: bool value if cached or not
    :param file_extension_regex: What type of files should be taken into consideration
    :return list with changed files
    """
    file_regex_str = r"^(?P<op>[AM])\s+(?P<path>[a-zA-Z0-9_/\\]+" + file_extension_regex + r")$"
    file_regex = re.compile(file_regex_str)

    cmd = f"git diff --name-status {'--cached' if cached else f'HEAD~{commits}'}"
    logging.debug(f"Executing: {cmd}")
    all_files = subprocess.check_output(cmd.split(), cwd=repo_path).decode("utf-8")
    filtered = []
    for item in all_files.split("\n"):
        matched = file_regex.match(item)
        if matched:
            filtered.append(matched.group("path"))
    return filtered
