#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import logging
import re
import subprocess
import sys
from os import path
from xml.etree import ElementTree as et

class MyFormatter(
    argparse.ArgumentDefaultsHelpFormatter,
    argparse.RawDescriptionHelpFormatter,
):
    pass

def parse_input(input_args=None):
    parser = argparse.ArgumentParser(
        description="""
    Check test coverage of changed lines of code.
!!! For accurate results, make sure to update your referrence branch     !!!
!!! The name of referrence branch is passed as 'parent_branch' parameter !!!""",
        formatter_class=MyFormatter
    )
    parser.add_argument(
        "-p", "--repo-path", required=False, default=".", 
        help="Path to root of repository"
    )
    parser.add_argument(
        "-m", "--module", required=False, default="spsdk",
        help="Module for branch coverage analysis"
    )
    parser.add_argument(
        "-cr", "--coverage-report", required=False, default="coverage.xml",
        help="File containing the XML coverage report"
    )
    parser.add_argument(
        "-cc", "--coverage-cutoff", required=False, default=0.8,
        help="Cutoff for success"
    )
    parser.add_argument(
        "-b", "--parent-branch", required=False, default='origin/master',
        help="Branch to compare HEAD to"
    )
    parser.add_argument(
        "--cached", required=False, default=False, action="store_true",
        help="Analyze staged files on current branch"
    )
    parser.add_argument(
        "-v", "--verbose", dest='log_level', action='store_const',
        help="Verbose output", const=logging.INFO, default=logging.WARNING
    )
    parser.add_argument(
        "-d", "--debug", dest='log_level', action='store_const',
        help="Debugging output", const=logging.DEBUG)

    args = parser.parse_args(input_args)

    logging.basicConfig(level=args.log_level)
    args.coverage_cutoff = float(args.coverage_cutoff)
    assert path.isdir(args.repo_path), f"Repo path '{args.repo_path}' doesn't exist"
    args.repo_path = path.abspath(args.repo_path)
    if not path.isabs(args.coverage_report):
        args.coverage_report = path.normpath(path.join(args.repo_path, args.coverage_report))
    assert path.isfile(args.coverage_report), f"Coverage report '{args.coverage_report}' doesn't exist"
    return args


def get_number_of_commits(path, parent_branch='origin/master'):
    cmd = f"git log --oneline {parent_branch}..HEAD"
    logging.debug(f"Executing: {cmd}")
    logs = subprocess.check_output(cmd.split(), cwd=path).decode("utf-8")
    distance = len(logs.splitlines())
    logging.debug(f"Current branch is {distance} commits away from {parent_branch}")
    return distance

def get_changed_files(path, commits=1, cached=False):
    file_regex_str = r"^(?P<op>[AM])\s+(?P<path>[a-zA-Z0-9_/\\]+\.py)$"
    file_regex = re.compile(file_regex_str)

    cmd = f"git diff --name-status {'--cached' if cached else f'HEAD~{commits}'}"
    logging.debug(f"Executing: {cmd}")
    all_files = subprocess.check_output(cmd.split(), cwd=path).decode("utf-8")
    filtered = []
    for item in all_files.split("\n"):
        m = file_regex.match(item)
        if m:
            filtered.append(m.group("path"))
    return filtered

def extract_linenumber(base_dir, file_path, commits=1, cached=False):
    line_regex_str = r"^@@ -\d{1,3}[0-9,]*\s\+(?P<start>\d{1,3}),?(?P<count>\d*)"
    line_regex = re.compile(line_regex_str)

    cmd = f"git diff {'--cached' if cached else f'HEAD~{commits}'} --unified=0 -- {file_path}"
    git_diff = subprocess.check_output(cmd.split(), cwd=base_dir).decode("utf-8")
    line_nums = []
    for line in git_diff.split("\n"):
        m = line_regex.match(line)
        if m:
            start = int(m.group("start"))
            count = int(m.group("count") or 1)
            for i in range(count):
                line_nums.append(start + i)
    return line_nums

def _cov_statement_category(line):
    hit = int(line.attrib["hits"])
    return "hit" if hit else "miss"

def _cov_branch_category(line):
    category = _cov_statement_category(line)
    if "missing-branches" in line.attrib:
        category = "partial"
    return category

def extract_coverage(cov_report, file_path, line_numbers):
    lines_elem = cov_report.findall(f".//*/class[@filename='{file_path}']/lines/line")
    data = {"statement": {"hit": [], "miss": []}, "branch": {"hit": [], "miss": [], "partial": []}}
    for item in lines_elem:
        line_num = int(item.attrib["number"])
        if line_num not in line_numbers:
            continue
        data["statement"][_cov_statement_category(item)].append(line_num)
        if "branch" in item.attrib:
            data["branch"][_cov_branch_category(item)].append(line_num)
    return data

def calc_statement_coverage(stamenent_data):
    hit = len(stamenent_data["hit"])
    total = hit + len(stamenent_data["miss"])
    return (hit/total) if total else -1

def calc_branch_coverage(branc_data):
    hit = len(branc_data["hit"])
    miss = len(branc_data["miss"])
    partial = len(branc_data["partial"])
    total = 2 * (hit + miss + partial)
    if total == 0:
        return -1
    return (2 * hit + partial) / total

def calc_coverage(cov_data):
    statement = calc_statement_coverage(cov_data["statement"])
    brach = calc_branch_coverage(cov_data["branch"])
    return statement, brach

def did_pass(number, cutoff):
    return number == -1 or number >= cutoff

def stringify_pass(number, cutoff):
    msg = "OK" if did_pass(number, cutoff) else "FAILED"
    msg += f" ({number*100:2.2f}%)" if number != -1 else " (Not Used)"
    return msg


def main():
    args = parse_input()
    logging.debug(args)
    commits = get_number_of_commits(args.repo_path, args.parent_branch)
    files = get_changed_files(args.repo_path, commits, args.cached)
    files = [f for f in files if f.startswith(args.module)]
    # files = filter(lambda x: x.startswith(args.module), files)
    logging.debug(f"files to process: {files}\n")
    cov_report = et.parse(args.coverage_report)
    error_counter = 0
    for f in files:
        logging.info(f"processing: {f}")
        git_numbers = extract_linenumber(args.repo_path, f, commits, args.cached)
        logging.debug(f"git lines: {git_numbers}")
        # the coverage.xml removes the module name from path
        sanitized_name = f.replace(f"{args.module}/", "")
        cov_numbers = extract_coverage(cov_report, sanitized_name, git_numbers)
        logging.debug(f"cov lines: {cov_numbers}")
        statement_cov, branch_cov = calc_coverage(cov_numbers)
        if not did_pass(statement_cov, args.coverage_cutoff):
            logging.info(f"uncovered lines: {cov_numbers['statement']['miss']}")
            error_counter += 1
        if not did_pass(branch_cov, args.coverage_cutoff):
            logging.info(f"uncovered branches: {cov_numbers['branch']['miss']}")
            logging.info(f"partially covered branches: {cov_numbers['branch']['partial']}")
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
