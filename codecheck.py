#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This Python script runs the development checks on SPSDK project."""

import logging
import os
import re
import shutil
import subprocess
import sys
from typing import List, Optional

import click
import colorama
import prettytable

from tools import gitcov
from tools.task_scheduler import PrettyProcessRunner, TaskInfo, TaskList, TaskResult

OUTPUT_FOLDER = "reports"
CPU_CNT = os.cpu_count() or 1
CHECK_LIST = [
    "PYTEST",
    "GITCOV",
    "PYLINT",
    # "PYLINT_TOOLS",  # This is covered by PYLINT
    "PYLINT_DOCS",
    "PYLINT_ALL",
    "MYPY",
    "MYPY_TOOLS",
    "DEPENDENCIES",
    "PYDOCSTYLE",
    "RADON_ALL",
    "RADON_C",
    "RADON_D",
    "BLACK",
    "ISORT",
    "COPYRIGHT",
]
log = logging.getLogger(__name__)
colorama.init()


def print_results(tasks: List[TaskInfo], info_checks: Optional[List[str]] = None) -> None:
    """Print Code Check results in table."""
    table = prettytable.PrettyTable(["#", "Test", "Result", "Exec Time", "Error count", "Log"])
    table.align = "l"
    table.header = True
    table.border = True
    table.hrules = prettytable.HEADER
    table.vrules = prettytable.NONE

    result_colors = {
        "PASS": colorama.Fore.GREEN,
        "FAILED": colorama.Fore.RED,
        "INFO": colorama.Fore.CYAN,
    }

    for i, task in enumerate(tasks, start=1):
        result_text = "FAILED"
        assert task.result
        if task.result.error_count == 0:
            result_text = "PASS"
        if info_checks and task.name in info_checks:
            result_text = "INFO"

        table.add_row(
            [
                colorama.Fore.YELLOW + str(i),
                colorama.Fore.WHITE + task.name,
                result_colors[result_text] + result_text,
                colorama.Fore.WHITE + task.get_exec_time(),
                colorama.Fore.CYAN + str(task.result.error_count),
                colorama.Fore.BLUE + task.result.output_log,
            ]
        )
    click.echo(table)
    click.echo(colorama.Style.RESET_ALL)


def check_results(tasks: List[TaskInfo], info_check: List[str], output: str = "reports") -> int:
    """Print Code Check results in table."""
    ret = 0

    for task in tasks:

        err_cnt = task.result.error_count if task.result else -1
        output_log: List[str] = []
        if task.exception:
            sanity_name = task.name.replace(" ", "_").replace("'", "_")
            exc_log = os.path.join(output, f"{sanity_name}_exc.txt")
            with open(exc_log, "w", encoding="utf-8") as f:
                f.write(str(task.exception))
            output_log.append(exc_log)

        if not task.result or err_cnt != 0:
            if not info_check or (info_check and task.name not in info_check):
                ret = 1

        if task.result:
            res_log = task.result.output_log
            output_log.append(res_log)
            task.result.output_log = " , ".join(output_log)
        else:
            task.result = TaskResult(error_count=1, output_log=" , ".join(output_log))

    return ret


def check_pytest(output: str = OUTPUT_FOLDER) -> TaskResult:
    """Get the code coverage."""
    output_folder = os.path.join(output, "htmlcov")
    output_xml = os.path.join(output, "coverage.xml")
    output_log = os.path.join(output, "coverage.txt")
    junit_report = os.path.join(output, "tests.xml")

    if os.path.isdir(output_folder):
        shutil.rmtree(output_folder, ignore_errors=True)

    args = (
        f"pytest -n {CPU_CNT//2 or 1} tests --cov spsdk --cov-branch --junit-xml {junit_report}"
        f" --cov-report term --cov-report html:{output_folder} --cov-report xml:{output_xml}"
    )
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(args.split(), stdout=f, stderr=f)

    return TaskResult(error_count=res, output_log=output_log)


def check_gitcov(output: str = OUTPUT_FOLDER) -> TaskResult:
    """Get the code coverage."""
    output_log = os.path.join(output, "gitcov.txt")
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(
            f"python tools/gitcov.py --coverage-report {os.path.join(output, 'coverage.xml')}".split(),
            stdout=f,
            stderr=f,
        )

    return TaskResult(error_count=res, output_log=output_log)


def check_dependencies(output: str = OUTPUT_FOLDER) -> TaskResult:
    """Check the dependencies and their licenses."""
    output_log = os.path.join(output, "dependencies.txt")
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(
            "python tools/checker_dependencies.py check", stdout=f, stderr=f, shell=True
        )
    return TaskResult(error_count=res, output_log=output_log)


def check_pydocstyle(output: str = OUTPUT_FOLDER) -> TaskResult:
    """Check the dependencies and their licenses."""
    output_log = os.path.join(output, "pydocstyle.txt")

    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call("pydocstyle spsdk".split(), stdout=f, stderr=f)

    with open(output_log, "r", encoding="utf-8") as f:
        err_cnt = re.findall(r":\d+ in", f.read())
        if err_cnt:
            res = len(err_cnt)

    return TaskResult(error_count=res, output_log=output_log)


def check_mypy(args: List[str], output_log: str) -> TaskResult:
    """Check the project against mypy tool."""
    res = 0
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(f"mypy {' '.join(args)}".split(), stdout=f, stderr=f)

    with open(output_log, "r", encoding="utf-8") as f:
        err_cnt = re.findall(r"Found \d+ error", f.read())
        if err_cnt:
            res = int(err_cnt[0].replace("Found ", "").replace(" error", ""))

    return TaskResult(error_count=res, output_log=output_log)


def check_pylint(args: str, output_log: str) -> TaskResult:
    """Call pylint with given configuration and output log."""
    cmd = f"pylint {args} -j {CPU_CNT//2 or 1}"
    with open(output_log, "w", encoding="utf-8") as f:
        subprocess.call(cmd.split(), stdout=f, stderr=f)

    with open(output_log, "r", encoding="utf-8") as f:
        err_cnt = re.findall(r": [IRCWEF]\d{4}:", f.read())

    return TaskResult(error_count=len(err_cnt), output_log=output_log)


def check_pylint_errors(input_log: str, output_log: str) -> TaskResult:
    """Check Pylint log for errors."""
    with open(input_log, "r", encoding="utf-8") as f:
        errors = re.findall(r".*: [EF]\d{4}:.*", f.read())
    with open(output_log, "w", encoding="utf-8") as f:
        f.write("\n".join(errors))

    return TaskResult(error_count=len(errors), output_log=output_log)


def check_radon(output_log: str) -> TaskResult:
    """Check the project against radon rules."""
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call("radon cc --show-complexity spsdk".split(), stdout=f, stderr=f)

    return TaskResult(error_count=res, output_log=output_log)


def check_radon_errors(input_log: str, radon_type: str, output_log: str) -> TaskResult:
    """Check radon log for records with given radon_type."""
    with open(input_log, "r", encoding="utf-8") as f:
        errors = re.findall(rf".* - {radon_type} .*", f.read())
    with open(output_log, "w", encoding="utf-8") as f:
        f.write("\n".join(errors))

    return TaskResult(error_count=len(errors), output_log=output_log)


def check_black(output: str = OUTPUT_FOLDER) -> TaskResult:
    """Check the project against black formatter rules."""
    output_log = os.path.join(output, "black.txt")
    res = 0
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(
            "black --check --diff spsdk examples tests".split(), stdout=f, stderr=f
        )

    return TaskResult(error_count=res, output_log=output_log)


def check_isort(output: str = OUTPUT_FOLDER) -> TaskResult:
    """Check the project against isort imports formatter rules."""
    output_log = os.path.join(output, "isort.txt")
    res = 0
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call("isort -c spsdk examples tests".split(), stdout=f, stderr=f)

    if res:
        with open(output_log, "r", encoding="utf-8") as f:
            res = len(f.read().splitlines())

    return TaskResult(error_count=res, output_log=output_log)


def check_copyright_year(output: str = OUTPUT_FOLDER) -> TaskResult:
    """Check the project against copy right year rules."""
    output_log = os.path.join(output, "copyright_year.txt")
    res = 0
    changed_files = gitcov.get_changed_files(repo_path=".", include_merges=True)
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(
            f"python tools/checker_copyright_year.py {' '.join(changed_files)}".split(),
            stdout=f,
            stderr=f,
        )

    if res:
        with open(output_log, "r", encoding="utf-8") as f:
            res = len(f.read().splitlines())

    return TaskResult(error_count=res, output_log=output_log)


@click.command(no_args_is_help=False)
@click.option(
    "-c",
    "--check",
    type=click.Choice(
        CHECK_LIST,
        case_sensitive=False,
    ),
    multiple=True,
    help="Run just selected test(s) instead of all. Can be specify multiple.",
)
@click.option(
    "-ic",
    "--info-check",
    type=click.Choice(
        CHECK_LIST,
        case_sensitive=False,
    ),
    multiple=True,
    help="Just select tests that result won't be added to final exit code. Can be specify multiple.",
)
@click.option(
    "-j",
    "--job-cnt",
    type=click.IntRange(1, 32),
    default=CPU_CNT,
    help="Choose concurrent count of running check jobs.",
)
@click.option(
    "-s",
    "--silence",
    count=True,
    help="The level of silence, -s: Only summary table is printed, -ss: Nothing is printed.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    required=False,
    default="reports",
    help="Output folder to store reports files.",
)
def main(
    check: List[str],
    info_check: List[str],
    job_cnt: int,
    silence: int,
    output: click.Path,
) -> None:
    """Simple tool to check the SPSDK development rules.

    Overall result is passed to OS.

    :param check: List of tests to run.
    :param info_check: List of tests to run which don't affect the overall result.
    :param silence: Level of silence 0: full print; 1: print only summary; 2: print nothing.
    :param job_cnt: Select count of concurrent tests.
    :param output: Output folder for reports.
    """
    # logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)
    logging.basicConfig(level=logging.INFO)
    output_dir = str(output) if output else OUTPUT_FOLDER
    ret = 1
    try:
        available_checks = TaskList(
            [
                TaskInfo("PYTEST", check_pytest, output=output_dir),
                TaskInfo("GITCOV", check_gitcov, output=output_dir, dependencies=["PYTEST"]),
                TaskInfo(
                    "PYLINT_ALL",
                    check_pylint,
                    args="spsdk examples tools codecheck.py",
                    output_log=os.path.join(output_dir, "pylint_all.txt"),
                ),
                TaskInfo(
                    "PYLINT",
                    check_pylint_errors,
                    input_log=os.path.join(output_dir, "pylint_all.txt"),
                    output_log=os.path.join(output_dir, "pylint.txt"),
                    dependencies=["PYLINT_ALL"],
                ),
                # This is already covered by PYLINT
                # TaskInfo(
                #     "PYLINT_TOOLS",
                #     check_pylint,
                #     args="tools codecheck.py -E",
                #     output_log=os.path.join(output, "pylint_tools.txt"),
                # ),
                TaskInfo(
                    "PYLINT_DOCS",
                    check_pylint,
                    args="spsdk --rcfile pylint-doc-rules.ini",
                    output_log=os.path.join(output_dir, "pylint_docs.txt"),
                ),
                TaskInfo(
                    "MYPY",
                    check_mypy,
                    args=["spsdk", "examples"],
                    output_log=os.path.join(output_dir, "mypy.txt"),
                ),
                TaskInfo(
                    "MYPY_TOOLS",
                    check_mypy,
                    args=["tools", "codecheck.py"],
                    output_log=os.path.join(output_dir, "mypy_tools.txt"),
                ),
                TaskInfo("DEPENDENCIES", check_dependencies, output=output),
                TaskInfo("PYDOCSTYLE", check_pydocstyle, output=output_dir),
                TaskInfo(
                    "RADON_ALL", check_radon, output_log=os.path.join(output_dir, "radon_all.txt")
                ),
                TaskInfo(
                    "RADON_C",
                    check_radon_errors,
                    radon_type="C",
                    input_log=os.path.join(output_dir, "radon_all.txt"),
                    output_log=os.path.join(output_dir, "radon_c.txt"),
                    dependencies=["RADON_ALL"],
                ),
                TaskInfo(
                    "RADON_D",
                    check_radon_errors,
                    radon_type="D",
                    input_log=os.path.join(output_dir, "radon_all.txt"),
                    output_log=os.path.join(output_dir, "radon_d.txt"),
                    dependencies=["RADON_ALL"],
                ),
                TaskInfo("BLACK", check_black, output=output_dir),
                TaskInfo("ISORT", check_isort, output=output_dir),
                TaskInfo("COPYRIGHT", check_copyright_year, output=output_dir),
            ]
        )
        checks = TaskList()
        # pylint: disable=not-an-iterable,unsupported-membership-test   # TaskList is a list
        for task in available_checks:
            if check and task.name not in check:
                pass
            else:
                if check and task.dependencies and len(set(task.dependencies) - set(check)) != 0:
                    # insert missing dependencies
                    for dependency_name in task.dependencies:
                        extra_task = available_checks.get_task_by_name(dependency_name)
                        if extra_task not in checks:
                            checks.append(extra_task)
                checks.append(task)

        # the baseline PYLINT_ALL, RADON_ALL, and RADON_C checkers are always just informative
        info_check = list(info_check)
        info_check.append("PYLINT_ALL")
        info_check.append("RADON_ALL")
        info_check.append("RADON_C")

        if not os.path.isdir(output_dir):
            os.mkdir(output_dir)

        runner = PrettyProcessRunner(checks, print_func=(lambda x: None) if silence else click.echo)
        runner.run(job_cnt, True)

        ret = check_results(checks, info_check, output_dir)
        if silence < 2:
            print_results(checks, info_check)
            click.echo(f"Overall time: {round(runner.process_time, 1)} second(s).")
            click.echo(
                f"Overall result: {(colorama.Fore.GREEN+'PASS') if ret == 0 else (colorama.Fore.RED+'FAILED')}."
            )

    except Exception as exc:  # pylint: disable=broad-except
        click.echo(exc)
        ret = 1
    sys.exit(ret)


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter
