#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""GitCov script is to calculate code coverage for changed files."""

import argparse
import logging
import re
import subprocess
import sys
from configparser import ConfigParser
from os import path
from typing import Sequence, Tuple
from xml.etree import ElementTree as et


class MyFormatter(
        argparse.ArgumentDefaultsHelpFormatter,
        argparse.RawDescriptionHelpFormatter,
):
    """Class customizing behavior for argparse."""


def parse_input(input_args: Sequence[str] = None) -> argparse.Namespace:
    """Parse default configuration file and process user inputs."""
    # read the gitcov-defaults.ini use values to set defaults to argparse
    config = ConfigParser()
    config.read(path.join(path.dirname(__file__), "gitcov-defaults.ini"))
    gitcov_config = config["gitcov"]

    parser = argparse.ArgumentParser(
        description="""
    Check test coverage of changed lines of code.
!!! For accurate results, make sure to update your reference branch     !!!
!!! The name of reference branch is passed as 'parent_branch' parameter !!!""",
        formatter_class=MyFormatter
    )
    parser.add_argument(
        "-p", "--repo-path", required=False, default=gitcov_config["repo-path"],
        help="Path to root of repository"
    )
    parser.add_argument(
        "-m", "--module", required=False, default=gitcov_config["module"],
        help="Module for branch coverage analysis"
    )
    parser.add_argument(
        "-cr", "--coverage-report", required=False, default=gitcov_config["coverage-report"],
        help="File containing the XML coverage report"
    )
    parser.add_argument(
        "-cc", "--coverage-cutoff", required=False, default=gitcov_config.getfloat("coverage-cutoff"),
        help="Cutoff for success", type=float
    )
    parser.add_argument(
        "-b", "--parent-branch", required=False, default=gitcov_config["parent-branch"],
        help="Branch to compare HEAD to"
    )
    parser.add_argument(
        "-i", "--include-merges", default=config.BOOLEAN_STATES[gitcov_config["include-merges"]],
        action="store_true", required=False, help="Include files brought in by merge commits"
    )
    parser.add_argument(
        "-v", "--verbose", default=config.BOOLEAN_STATES[gitcov_config["verbose"]],
        required=False, action='store_true', help="Verbose output"
    )
    parser.add_argument(
        "-d", "--debug", default=config.BOOLEAN_STATES[gitcov_config["debug"]],
        required=False, action='store_true', help="Debugging output"
    )
    parser.add_argument(
        "-c", "--config-file", required=False,
        help=("""Path to config .ini file.
        You can create your custom config file by copy-modify the gitcov-defaults.ini""")
    )

    args = parser.parse_args(input_args)

    if args.config_file:
        if path.isfile(args.config_file):
            config.read(args.config_file)
            # if the custom file exists let's use the files's location as base ;)
            args.repo_path = path.normpath(
                path.join(path.dirname(args.config_file), gitcov_config["repo-path"])
            )
        else:
            parser.error(f"Given config file '{args.config_file}' doesn't exists!")

    log_level = logging.WARNING
    if gitcov_config.getint("verbose", fallback=0) or args.verbose:
        log_level = logging.INFO
    if gitcov_config.getint("debug", fallback=0) or args.debug:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)

    assert path.isdir(args.repo_path), f"Repo path '{args.repo_path}' doesn't exist"
    args.repo_path = path.abspath(args.repo_path)
    if not path.isabs(args.coverage_report):
        args.coverage_report = path.normpath(path.join(args.repo_path, args.coverage_report))
    assert path.isfile(args.coverage_report), f"Coverage report '{args.coverage_report}' doesn't exist"

    args.skip_files = gitcov_config.get("skip-files").replace("\n", "").split(",")

    return args


def get_changed_files(repo_path: str, parent_branch: str, include_merges: bool) -> Sequence[str]:
    """Get a list of changed files.

    :param repo_path: Path to the root of the repository
    :param parent_branch: Git branch to compare to
    :param include_merges: Include changes done via merge-commits
    :return: List of changed files
    """
    file_regex_str = r"^(?P<op>[AM])\s+(?P<path>[a-zA-Z0-9_/\\]+\.py)$"
    file_regex = re.compile(file_regex_str)

    # fetch changed files from previous commits
    logging.info("Fetching files from previous commits\n")
    cmd = f"git log {'' if include_merges else '--no-merges --first-parent'} --name-status {parent_branch}..HEAD"
    logging.debug(f"Executing: {cmd}")
    all_files = subprocess.check_output(cmd.split(), cwd=repo_path).decode("utf-8")
    logging.debug(f"Result:\n{all_files}")

    # fetch changed files that are potentionally not committed yet
    logging.info("Fetching uncommitted files\n")
    cmd = f"git diff --name-status"
    logging.debug(f"Executing: {cmd}")
    uncommitted = subprocess.check_output(cmd.split(), cwd=repo_path).decode("utf-8")
    logging.debug(f"Result:\n{uncommitted}")
    all_files += uncommitted

    # fetch staged new files
    logging.info("Fetching new files... those need to be stagged\n")
    cmd = f"git diff --name-status --cached"
    logging.debug(f"Executing: {cmd}")
    staged = subprocess.check_output(cmd.split(), cwd=repo_path).decode("utf-8")
    logging.debug(f"Result:\n{staged}")
    all_files += staged

    filtered = []
    for item in all_files.split("\n"):
        match = file_regex.match(item)
        if match:
            filtered.append(match.group("path"))
    # remove duplicates
    filtered = list(set(filtered))
    logging.debug(f"Files to consider: {len(filtered)}: {filtered}")
    return list(set(filtered))


def extract_linenumber(base_dir: str, file_path: str, parent_branch: str) -> Sequence[int]:
    """Get changed lines in given file.

    :param base_dir: Path to root of the repository
    :param file_path: Path to file
    :param parent_branch: Git branch to compare to
    :return: List of changed lines in file
    """
    line_regex_str = r"^@@ -\d{1,3}[0-9,]*\s\+(?P<start>\d{1,3}),?(?P<count>\d*)"
    line_regex = re.compile(line_regex_str)

    cmd = f"git diff {parent_branch} --unified=0 -- {file_path}"
    logging.debug(f"Executing: {cmd}")
    git_diff = subprocess.check_output(cmd.split(), cwd=base_dir).decode("utf-8")
    line_numbers = []
    for line in git_diff.split("\n"):
        match = line_regex.match(line)
        if match:
            start = int(match.group("start"))
            count = int(match.group("count") or 1)
            for i in range(count):
                line_numbers.append(start + i)
    return line_numbers


def _cov_statement_category(line: et.Element) -> str:
    """Get the coverate category for one record of statement coverage."""
    hit = int(line.attrib["hits"])
    return "hit" if hit else "miss"


def _cov_branch_category(line: et.Element) -> str:
    """Get the coverage category for one record of branch coverage."""
    category = _cov_statement_category(line)
    if "missing-branches" in line.attrib:
        category = "partial"
    return category


def extract_coverage(cov_report: et.ElementTree, file_path: str, line_numbers: Sequence[int]) -> dict:
    """Extract coverage data for a given file.

    :param cov_report: Parsed xml coverage report
    :param file_path: Path to file to get the data for
    :param line_numbers: List of changed line numbers
    :return: Coverage data for a given file
    """
    lines_elem = cov_report.findall(f".//*/class[@filename='{file_path}']/lines/line")
    data: dict = {"statement": {"hit": [], "miss": []}, "branch": {"hit": [], "miss": [], "partial": []}}
    for item in lines_elem:
        line_num = int(item.attrib["number"])
        if line_num not in line_numbers:
            continue
        data["statement"][_cov_statement_category(item)].append(line_num)
        if "branch" in item.attrib:
            data["branch"][_cov_branch_category(item)].append(line_num)
    return data


def calc_statement_coverage(statement_data: dict) -> float:
    """Calculate result statement coverage."""
    hit = len(statement_data["hit"])
    total = hit + len(statement_data["miss"])
    return (hit/total) if total else -1


def calc_branch_coverage(branch_data: dict) -> float:
    """Calculate result branch coverage."""
    hit = len(branch_data["hit"])
    miss = len(branch_data["miss"])
    partial = len(branch_data["partial"])
    total = 2 * (hit + miss + partial)
    if total == 0:
        return -1
    return (2 * hit + partial) / total


def calc_coverage(cov_data: dict) -> Tuple[float, float]:
    """Calculate overall coverage."""
    statement = calc_statement_coverage(cov_data["statement"])
    brach = calc_branch_coverage(cov_data["branch"])
    return statement, brach


def did_pass(number: float, cutoff: float) -> bool:
    """Check whether cutoff treshold is met."""
    return number == -1 or number >= cutoff


def stringify_pass(number: float, cutoff: float) -> str:
    """Stringify treshold result to human-friendly format."""
    msg = "OK" if did_pass(number, cutoff) else "FAILED"
    msg += f" ({number*100:2.2f}%)" if number != -1 else " (Not Used)"
    return msg


def is_skipped(file_path: str, skip_patterns: Sequence[str]) -> bool:
    """Find whether file should qualifies given filer patterns."""
    return any(skip_pattern in file_path for skip_pattern in skip_patterns)


def main(argv: Sequence[str] = None) -> int:
    """Main function."""
    args = parse_input(argv)
    logging.debug(args)

    files = get_changed_files(
        repo_path=args.repo_path, parent_branch=args.parent_branch,
        include_merges=args.include_merges
    )
    files = [f for f in files if f.startswith(args.module)]
    logging.debug(f"files to process: {len(files)}: {files}\n")
    cov_report = et.parse(args.coverage_report)
    error_counter = 0
    for f in files:
        logging.info(f"processing: {f}")
        is_skipped_file = is_skipped(f, args.skip_files)
        if is_skipped_file:
            logging.info("This file is skipped and will not contribute to the error counter.")

        git_numbers = extract_linenumber(args.repo_path, f, args.parent_branch)
        logging.debug(f"git lines: {git_numbers}")
        # the coverage.xml removes the module name from path
        sanitized_name = f.replace(f"{args.module}/", "")
        cov_numbers = extract_coverage(cov_report, sanitized_name, git_numbers)
        logging.debug(f"cov lines: {cov_numbers}")
        statement_cov, branch_cov = calc_coverage(cov_numbers)
        logging.info(f"uncovered lines: {cov_numbers['statement']['miss']}")
        if not did_pass(statement_cov, args.coverage_cutoff) and not is_skipped_file:
            error_counter += 1
        logging.info(f"uncovered branches: {cov_numbers['branch']['miss']}")
        logging.info(f"partially covered branches: {cov_numbers['branch']['partial']}")
        if not did_pass(branch_cov, args.coverage_cutoff) and not is_skipped_file:
            error_counter += 1
        logging.info(f"Statement coverage: {stringify_pass(statement_cov, args.coverage_cutoff)}")
        logging.info(f"Branch coverage: {stringify_pass(branch_cov, args.coverage_cutoff)}\n")

    if error_counter == 0:
        logging.info("No errors found")
    else:
        logging.error(f"Total errors: {error_counter}")

    return error_counter


if __name__ == "__main__":
    sys.exit(main())
