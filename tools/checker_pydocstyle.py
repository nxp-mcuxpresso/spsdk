#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Checker for pydocstyle."""
import logging
import re
import subprocess
import sys

import click
from git_operations import get_changed_files, get_number_of_commits


@click.command()
@click.option(
    "-p",
    "--repo-path",
    required=False,
    default=".",
    help="Path to root of repository",
    show_default=True,  # type: ignore  # Mypy is getting confused here
)
@click.option(
    "-m",
    "--module",
    required=False,
    default="spsdk",
    help="Module for branch coverage analysis",
    show_default=True,
)
@click.option(
    "-b",
    "--parent-branch",
    required=False,
    default="origin/master",
    help="Branch to compare HEAD to",
    show_default=True,
)
@click.option("-a", "--all-files", is_flag=True, help="Check pydostyle for all files in spsdk")  # type: ignore
@click.option(
    "-v", "--verbose", "log_level", flag_value=logging.INFO, help="Display more verbose output"
)
@click.option("-d", "--debug", "log_level", flag_value=logging.DEBUG, help="Display debugging info")
def main(repo_path, parent_branch, module, log_level, all_files):
    """Run pydocstyle of changed lines of code."""
    logging.basicConfig(level=log_level or logging.WARNING)
    if all_files:
        error_counter = execute_pydocstyle(module)
    else:
        commits = get_number_of_commits(repo_path, parent_branch)
        files = get_changed_files(repo_path, commits)
        files = [f for f in files if f.startswith(module)]
        logging.debug(f"files to process: {files}\n")
        error_counter = sum(execute_pydocstyle(f) for f in files)
    if error_counter == 0:
        logging.info("No errors found")
    else:
        logging.error(f"Total errors: {error_counter}")
    return error_counter


def execute_pydocstyle(scope: str) -> int:
    """Execute pydocstyle.

    :param scope: define the scope/file to be checked by pydocstyle
    :return number of found errors
    """
    err = 0
    logging.info(f"processing files: {scope}")
    try:
        cmd = "pydocstyle " + scope
        subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        output = e.output.decode("utf-8")
        logging.info(f"pydocstyle output:\n{output}")
        err = get_error_number_from_output(output)
    return err


def get_error_number_from_output(output_str: str) -> int:
    """Calculate the errors from pydocstyle's output.

    :param output_str: output string from pydocstyle
    :return number of errors
    """
    return len(re.findall(r"D[100-500]", output_str))


if __name__ == "__main__":
    import os
    from pathlib import Path

    os.chdir(Path(__file__).parent.parent)
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter
