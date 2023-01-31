#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Checker for annotations within mypy."""
import logging
import subprocess
import sys

import click

from .git_operations import get_changed_files, get_number_of_commits


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
@click.option(
    "-v", "--verbose", "log_level", flag_value=logging.INFO, help="Display more verbose output"
)  # type: ignore
@click.option("-d", "--debug", "log_level", flag_value=logging.DEBUG, help="Display debugging info")
@click.option("-a", "--all-files", is_flag=True, help="Check mypy for all files")
def main(repo_path, parent_branch, module, log_level, all_files):
    """Run mypy with --disallow-untyped-defs option on changed files."""
    logging.basicConfig(level=log_level or logging.WARNING)
    module = module.replace("\\", "/")
    output = execute_mypy(module)
    if all_files:
        filtered_output = [line for line in output.splitlines() if line.startswith(module)]
        logging.debug(f"post filter: {filtered_output}")
        filtered_output = "\n".join(filtered_output)
    else:
        commits = get_number_of_commits(repo_path, parent_branch)
        files = get_changed_files(repo_path, commits, file_extension_regex=r"\.pyi?")
        files = [f for f in files if f.startswith(module)]
        logging.debug(f"files to process: {files}\n")
        filtered_output = filter_files(output, files)
    logging.info(f"Mypy output:\n{filtered_output}")
    error_counter = get_number_of_errors(filtered_output)
    if error_counter == 0:
        logging.info("No errors found")
    else:
        logging.error(f"Total errors: {error_counter}")
    return error_counter


def filter_files(mypy_output: str, files: list) -> str:
    """Filter only lines, which contain the changed  files.

    :param mypy_output: the whole output from mypy command
    :param files: list of changed files
    :return: string, which contains the changed  files
    """
    result = []
    for line in mypy_output.splitlines():
        if any(file in line for file in files):
            result.append(line)
    return "\n".join(result)


def execute_mypy(scope: str) -> str:
    """Execute mypy.

    :param scope: define the scope to be checked by mypy
    :return output from mypy
    """
    try:
        cmd = "mypy " + scope + " --disallow-untyped-defs"
        logging.debug(f"running: {cmd}")
        subprocess.check_output(cmd)
        return ""
    except subprocess.CalledProcessError as e:
        output = e.output.decode("utf-8")
        output = output.replace("\\", "/")
        logging.debug(f"mypy output:\n{output}")
        return output


def get_number_of_errors(output_str: str) -> int:
    """Calculate the errors from mypy's output.

    :param output_str: output string from mypy
    :return number of errors
    """
    result = 0
    for line in output_str.splitlines():
        if ": error:" in line:
            result += 1
    return result


if __name__ == "__main__":
    import os
    from pathlib import Path

    os.chdir(Path(__file__).parent.parent)
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter
