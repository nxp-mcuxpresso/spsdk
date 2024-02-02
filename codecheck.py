#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This Python script runs the development checks on SPSDK project."""

import logging
import os
import re
import shutil
import subprocess
import sys
from typing import List, Optional, Sequence

import click
import colorama
import prettytable

from tools import gitcov
from tools.checker_copyright_year import fix_copyright_in_files
from tools.checker_py_headers import fix_py_headers_in_files
from tools.task_scheduler import PrettyProcessRunner, TaskInfo, TaskList, TaskResult

OUTPUT_FOLDER = "reports"
CPU_CNT = os.cpu_count() or 1


CHECK_LIST = [
    "PYTEST",
    "GITCOV",
    "PYLINT",
    "PYLINT_DOCS",
    "MYPY",
    "DEPENDENCIES",
    "PYDOCSTYLE",
    "RADON_C",
    "RADON_D",
    "BLACK",
    "ISORT",
    "COPYRIGHT",
    "PY_HEADERS",
    "JUPYTER",
]
log = logging.getLogger(__name__)
colorama.init()


def print_results(tasks: List[TaskInfo]) -> None:
    """Print Code Check results in table."""
    table = prettytable.PrettyTable(["#", "Test", "Result", "Exec Time", "Error count", "Log"])
    table.align = "l"
    table.header = True
    table.border = True
    table.hrules = prettytable.HEADER
    table.vrules = prettytable.NONE

    for i, task in enumerate(tasks, start=1):
        assert task.result

        table.add_row(
            [
                colorama.Fore.YELLOW + str(i),
                colorama.Fore.WHITE + task.name,
                task.status_str(),
                colorama.Fore.WHITE + task.get_exec_time(),
                colorama.Fore.CYAN + str(task.result.error_count),
                colorama.Fore.BLUE + task.result.output_log,
            ]
        )
    click.echo(table)
    click.echo(colorama.Style.RESET_ALL)


def check_results(tasks: List[TaskInfo], output: str = "reports") -> int:
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

        if not task.result or (err_cnt != 0 and not task.info_only):
            ret = 1

        if task.result:
            res_log = task.result.output_log
            output_log.append(res_log)
            task.result.output_log = " , ".join(output_log)
        else:
            task.result = TaskResult(error_count=1, output_log=" , ".join(output_log))

    return ret


def check_pytest(output: str, disable_xdist: bool = False) -> TaskResult:
    """Get the code coverage."""
    output_folder = os.path.join(output, "htmlcov")
    output_xml = os.path.join(output, "coverage.xml")
    output_log = os.path.join(output, "coverage.txt")
    junit_report = os.path.join(output, "tests.xml")
    coverage_file = os.path.join(output, ".coverage")

    if os.path.isdir(output_folder):
        shutil.rmtree(output_folder, ignore_errors=True)

    parallel = "" if disable_xdist else f"-n {CPU_CNT//2 or 1}"
    args = (
        f"pytest {parallel} tests --cov spsdk --cov-branch --junit-xml {junit_report}"
        f" --cov-report term --cov-report html:{output_folder} --cov-report xml:{output_xml}"
    )
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(
            args.split(), stdout=f, stderr=f, env=dict(os.environ, COVERAGE_FILE=coverage_file)
        )

    return TaskResult(error_count=res, output_log=output_log)


def check_gitcov(output: str) -> TaskResult:
    """Get the code coverage."""
    output_log = os.path.join(output, "gitcov.txt")
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(
            f"{sys.executable} tools/gitcov.py --coverage-report {os.path.join(output, 'coverage.xml')}".split(),
            stdout=f,
            stderr=f,
        )

    return TaskResult(error_count=res, output_log=output_log)


def check_dependencies(output: str) -> TaskResult:
    """Check the dependencies and their licenses."""
    output_log = os.path.join(output, "dependencies.txt")
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(
            f"{sys.executable} tools/checker_dependencies.py check".split(), stdout=f, stderr=f
        )

    return TaskResult(error_count=res, output_log=output_log)


def check_pydocstyle(output: str) -> TaskResult:
    """Check the dependencies and their licenses."""
    output_log = os.path.join(output, "pydocstyle.txt")
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call("pydocstyle spsdk".split(), stdout=f, stderr=f)

    with open(output_log, "r", encoding="utf-8") as f:
        err_cnt = re.findall(r":\d+ in", f.read())
        if err_cnt:
            res = len(err_cnt)

    return TaskResult(error_count=res, output_log=output_log)


def check_mypy(output: str, args: str) -> TaskResult:
    """Check the project against mypy tool."""
    output_log = os.path.join(output, "mypy.txt")
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(f"mypy {args}".split(), stdout=f, stderr=f)

    with open(output_log, "r", encoding="utf-8") as f:
        err_cnt = re.findall(r"Found \d+ error", f.read())
        if err_cnt:
            res = int(err_cnt[0].replace("Found ", "").replace(" error", ""))

    return TaskResult(error_count=res, output_log=output_log)


def check_pylint_all(output: str, args: str) -> TaskResult:
    """Call pylint with given configuration and output log."""
    output_log = os.path.join(output, "pylint_docs.txt")
    with open(output_log, "w", encoding="utf-8") as f:
        subprocess.call(f"pylint {args} -j {CPU_CNT//2 or 1}".split(), stdout=f, stderr=f)

    with open(output_log, "r", encoding="utf-8") as f:
        err_cnt = re.findall(r": [IRCWEF]\d{4}:", f.read())

    return TaskResult(error_count=len(err_cnt), output_log=output_log)


def check_pylint(
    output: str,
    args: str,
    disable: Optional[List[str]] = None,
    enable: Optional[List[str]] = None,
) -> TaskResult:
    """Check Pylint log for errors."""
    output_log = os.path.join(output, "pylint.txt")
    cmd = f"pylint {args} -j {CPU_CNT//2 or 1}"
    if disable:
        cmd += f" --disable {','.join(disable)}"
    if enable:
        cmd += f" --enable {','.join(enable)}"
    with open(output_log, "w", encoding="utf-8") as f:
        subprocess.call(cmd.split(), stdout=f, stderr=f)

    with open(output_log, "r", encoding="utf-8") as f:
        err_cnt = re.findall(r": [IRCWEF]\d{4}:", f.read())

    return TaskResult(error_count=len(err_cnt), output_log=output_log)


def check_radon(
    output_log: str,
    paths: List[str],
    min_rank: Optional[str] = None,
    max_rank: Optional[str] = None,
) -> TaskResult:
    """Check the project against radon rules."""
    cmd = "radon cc --show-complexity"
    if min_rank:
        cmd += f" --min {min_rank}"
    if max_rank:
        cmd += f" --max {max_rank}"
    cmd += f" {' '.join(paths)}"
    with open(output_log, "w", encoding="utf-8") as f:
        subprocess.call(cmd.split(), stdout=f, stderr=f)

    with open(output_log, "r", encoding="utf-8") as f:
        err_cnt = re.findall(r"[ABCDEF] \(\d{1,3}\)", f.read())

    return TaskResult(error_count=len(err_cnt), output_log=output_log)


def check_black(output: str, args: str) -> TaskResult:
    """Check the project against black formatter rules."""
    output_log = os.path.join(output, "black.txt")
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(f"black --check --diff {args}".split(), stdout=f, stderr=f)

    return TaskResult(error_count=res, output_log=output_log)


def check_isort(output: str, args: str) -> TaskResult:
    """Check the project against isort imports formatter rules."""
    output_log = os.path.join(output, "isort.txt")
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(f"isort -c {args}".split(), stdout=f, stderr=f)

    if res:
        with open(output_log, "r", encoding="utf-8") as f:
            res = len(f.read().splitlines())

    return TaskResult(error_count=res, output_log=output_log)


def check_copyright_year(
    output: str,
    changed_files: Sequence[str],
) -> TaskResult:
    """Check the project against copy right year rules."""
    output_log = os.path.join(output, "copyright_year.txt")
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(
            f"{sys.executable} tools/checker_copyright_year.py {' '.join(changed_files)}".split(),
            stdout=f,
            stderr=f,
        )

    if res:
        with open(output_log, "r", encoding="utf-8") as f:
            res = len(f.read().splitlines())

    return TaskResult(error_count=res, output_log=output_log)


def check_py_file_headers(output: str, changed_files: Sequence[str]) -> TaskResult:
    """Check that python files have valid header."""
    output_log = os.path.join(output, "py_header.txt")
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(
            f"{sys.executable} tools/checker_py_headers.py {' '.join(changed_files)}".split(),
            stdout=f,
            stderr=f,
        )

    if res:
        with open(output_log, "r", encoding="utf-8") as f:
            res = len(f.read().splitlines())

    return TaskResult(error_count=res, output_log=output_log)


def check_jupyter_outputs(output: str, changed_files: Sequence[str]) -> TaskResult:
    output_log = os.path.join(output, "jupyter_outputs.txt")
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(
            f"{sys.executable} tools/checker_jupyter.py outputs {' '.join(changed_files)}".split(),
            stdout=f,
            stderr=f,
        )
    return TaskResult(error_count=res, output_log=output_log)


def fix_found_problems(checks: TaskList, silence: int = 0, run_check_again: bool = True) -> None:
    """Fix the failed checks automatically is possible."""
    re_checks = TaskList()
    for check in checks:
        if not check.fixer:
            continue
        if check.result and check.result.error_count != 0:
            check.fixer()
            click.echo(f"{colorama.Fore.GREEN}{check.name} problems fixed.{colorama.Fore.RESET}")
            check.reset()
            re_checks.append(check)
    if run_check_again and len(re_checks) > 0:
        click.echo("Running the failed codechecks again.")
        runner = PrettyProcessRunner(
            re_checks, print_func=(lambda x: None) if silence else click.echo
        )
        runner.run(CPU_CNT, True)
        if silence < 2:
            print_results(re_checks)


@click.command(no_args_is_help=False)
@click.option(
    "-c",
    "--check",
    type=click.Choice(
        CHECK_LIST,
        case_sensitive=False,
    ),
    multiple=True,
    help="Run only selected test instead of all. Can be specified multiple times.",
)
@click.option(
    "-ic",
    "--info-check",
    type=click.Choice(
        CHECK_LIST,
        case_sensitive=False,
    ),
    multiple=True,
    help="Mark selected test as INFO ONLY. Test's result won't be added to final exit code. Can be specified multiple times.",
)
@click.option(
    "-dc",
    "--disable-check",
    type=click.Choice(CHECK_LIST, case_sensitive=False),
    multiple=True,
    help="Disable selected test. Can be specified multiple times.",
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
@click.option(
    "-f",
    "--fix",
    is_flag=True,
    default=False,
    help="Fix the problems automatically if possible.",
)
@click.option(
    "-dx",
    "--disable-xdist",
    is_flag=True,
    default=False,
    help=(
        "Disable parallel pytest execution (using pytest-xdist). "
        "This is useful on Linux machines with lower CPU count."
    ),
)
@click.option(
    "-dm",
    "--disable-merges",
    is_flag=True,
    default=False,
    help="Disable scan for files which were introduced via merge into development branch.",
)
@click.option(
    "-pb",
    "--parent-branch",
    default="origin/master",
    help="Name of the upstream branch for PR integration/merge.",
)
def main(
    check: List[str],
    info_check: List[str],
    disable_check: List[str],
    job_cnt: int,
    silence: int,
    output: click.Path,
    fix: bool,
    disable_xdist: bool,
    disable_merges: bool,
    parent_branch: str,
) -> None:
    """Simple tool to check the SPSDK development rules.

    Overall result is passed to OS.
    """
    # logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)
    logging.basicConfig(level=logging.INFO)
    output_dir = str(output) if output else OUTPUT_FOLDER
    ret = 1
    info_check = [x.upper() for x in list(info_check)]
    disable_check = [x.upper() for x in list(disable_check)]
    changed_files = gitcov.get_changed_files(
        repo_path=".", include_merges=not disable_merges, parent_branch=parent_branch
    )
    try:
        available_checks = TaskList(
            [
                TaskInfo(
                    "PYTEST",
                    check_pytest,
                    output=output_dir,
                    disable_xdist=disable_xdist,
                    info_only="PYTEST" in info_check,
                ),
                TaskInfo(
                    "GITCOV",
                    check_gitcov,
                    output=output_dir,
                    dependencies=["PYTEST"],
                    info_only="GITCOV" in info_check,
                ),
                TaskInfo(
                    "PYLINT",
                    check_pylint,
                    args="spsdk examples tools codecheck.py",
                    output=output_dir,
                    disable=[
                        "R",
                        "C",
                        "W0511",
                        "W0212",
                        "W0237",
                        "W0718",
                        "W0613",
                        "W0223",
                        "W1401",
                    ],
                    enable=[],
                    info_only="PYLINT" in info_check,
                ),
                TaskInfo(
                    "PYLINT_DOCS",
                    check_pylint_all,
                    args="spsdk --rcfile pylint-doc-rules.ini",
                    output=output_dir,
                    info_only="PYLINT_DOCS" in info_check,
                ),
                TaskInfo(
                    "MYPY",
                    check_mypy,
                    args="spsdk examples tools codecheck.py",
                    output=output_dir,
                    info_only="MYPY" in info_check,
                ),
                TaskInfo(
                    "DEPENDENCIES",
                    check_dependencies,
                    output=output,
                    info_only="DEPENDENCIES" in info_check,
                ),
                TaskInfo(
                    "PYDOCSTYLE",
                    check_pydocstyle,
                    output=output_dir,
                    info_only="PYDOCSTYLE" in info_check,
                ),
                TaskInfo(
                    "RADON_C",
                    check_radon,
                    paths=["spsdk"],
                    min_rank="C",
                    output_log=os.path.join(output_dir, "radon_c.txt"),
                    info_only=True,
                ),
                TaskInfo(
                    "RADON_D",
                    check_radon,
                    paths=["spsdk"],
                    min_rank="D",
                    output_log=os.path.join(output_dir, "radon_d.txt"),
                    info_only="RADON_D" in info_check,
                ),
                TaskInfo(
                    "BLACK",
                    check_black,
                    output=output_dir,
                    args="spsdk examples tools codecheck.py tests",
                    info_only="BLACK" in info_check,
                    fixer=lambda: subprocess.call(
                        "black spsdk examples tools codecheck.py tests".split()
                    ),
                ),
                TaskInfo(
                    "ISORT",
                    check_isort,
                    args="spsdk examples tools codecheck.py tests",
                    output=output_dir,
                    info_only="ISORT" in info_check,
                    fixer=lambda: subprocess.call(
                        "isort spsdk examples tools codecheck.py tests".split()
                    ),
                ),
                TaskInfo(
                    "COPYRIGHT",
                    check_copyright_year,
                    info_only="COPYRIGHT" in info_check,
                    output=output_dir,
                    changed_files=changed_files,
                    fixer=lambda: fix_copyright_in_files(files=changed_files),
                ),
                TaskInfo(
                    "PY_HEADERS",
                    check_py_file_headers,
                    output=output_dir,
                    changed_files=changed_files,
                    info_only="PY_HEADERS" in info_check,
                    fixer=lambda: fix_py_headers_in_files(files=changed_files),
                ),
                TaskInfo(
                    "JUPYTER",
                    check_jupyter_outputs,
                    output=output_dir,
                    changed_files=changed_files,
                    info_only="JUPYTER" in info_check,
                ),
            ]
        )
        checks = TaskList()
        # pylint: disable=not-an-iterable,unsupported-membership-test   # TaskList is a list
        for task in available_checks:
            if disable_check and task.name in disable_check:
                continue
            if (
                disable_check
                and task.dependencies
                and any(dependency in disable_check for dependency in task.dependencies)
            ):
                continue

            if check and task.name not in check:
                continue
            if check and task.dependencies and len(set(task.dependencies) - set(check)) != 0:
                # insert missing dependencies
                for dependency_name in task.dependencies:
                    extra_task = available_checks.get_task_by_name(dependency_name)
                    if extra_task not in checks:
                        checks.append(extra_task)
            checks.append(task)

        if not os.path.isdir(output_dir):
            os.mkdir(output_dir)

        runner = PrettyProcessRunner(checks, print_func=(lambda x: None) if silence else click.echo)
        runner.run(job_cnt, True)

        ret = check_results(checks, output_dir)
        if silence < 2:
            print_results(checks)
            click.echo(f"Overall time: {round(runner.process_time, 1)} second(s).")
            click.echo(
                f"Overall result: {(colorama.Fore.GREEN+'PASS') if ret == 0 else (colorama.Fore.RED+'FAILED')}. {colorama.Fore.RESET}"
            )

        if fix:
            fix_found_problems(checks, silence=silence)
            ret = 0

    except Exception as exc:  # pylint: disable=broad-except
        click.echo(exc)
        ret = 1

    sys.exit(ret)


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter
