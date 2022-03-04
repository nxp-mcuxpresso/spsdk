#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This Python script runs the development checks on SPSDK project."""

import logging
import os
import re
import shutil
import subprocess
import sys
from io import StringIO
from typing import Any, Dict, List

import click
import colorama
import prettytable

from tools import checker_dependencies, gitcov
from tools.task_scheduler import PrettyProcessRunner, TaskInfo, TaskList

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


def print_results(tasks: List[TaskInfo], info_checks: List[str] = None) -> None:
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
        if task.result["err_cnt"] == 0:
            result_text = "PASS"
        if info_checks and task.name in info_checks:
            result_text = "INFO"

        table.add_row(
            [
                colorama.Fore.YELLOW + str(i),
                colorama.Fore.WHITE + task.name,
                result_colors[result_text] + result_text,
                colorama.Fore.WHITE + task.get_exec_time(),
                colorama.Fore.CYAN + str(task.result["err_cnt"]),
                colorama.Fore.BLUE + task.result["output_log"],
            ]
        )
    click.echo(table)
    click.echo(colorama.Style.RESET_ALL)


def check_results(tasks: List[TaskInfo], info_check: List[str], output: str = "reports") -> int:
    """Print Code Check results in table."""
    ret = 0

    for task in tasks:

        err_cnt = task.result["err_cnt"] if task.result else -1
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
            res_log = task.result["output_log"]
            output_log.append(res_log)
            task.result["output_log"] = " , ".join(output_log)
        else:
            task.result = {}
            task.result["err_cnt"] = -1
            task.result["output_log"] = " , ".join(output_log)

    return ret


def check_pytest(output: str = OUTPUT_FOLDER) -> Dict[str, Any]:
    """Get the code coverage."""
    output_folder = os.path.join(output, "htmlcov")
    output_xml = os.path.join(output, "coverage.xml")
    output_log = os.path.join(output, "coverage.txt")
    junit_report = os.path.join(output, "tests.xml")

    if os.path.isdir(output_folder):
        shutil.rmtree(output_folder, ignore_errors=True)

    args = (
        f"pytest --cov spsdk --cov-branch --junit-xml {junit_report}"
        f" --cov-report term --cov-report html:{output_folder} --cov-report xml:{output_xml}"
    )
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(args.split(), stdout=f, stderr=f)

    return {"err_cnt": res, "output_log": output_log}


def check_gitcov(output: str = OUTPUT_FOLDER) -> Dict[str, Any]:
    """Get the code coverage."""
    output_log = os.path.join(output, "gitcov.txt")
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(
            f"python tools/gitcov.py --coverage-report {os.path.join(output, 'coverage.xml')}".split(),
            stdout=f,
            stderr=f,
        )

    return {"err_cnt": res, "output_log": output_log}


def check_dependencies(output: str = OUTPUT_FOLDER) -> Dict[str, Any]:
    """Check the dependencies and their licenses."""
    output_log = os.path.join(output, "dependencies.txt")
    original_stdout = sys.stdout
    original_argv = sys.argv
    sys.stdout = stdout = StringIO()
    sys.argv = [
        os.path.join(os.getcwd(), "tools/checker_dependencies.py").replace("\\", "/"),
        "check",
    ]
    res = checker_dependencies.main()
    sys.stdout = original_stdout
    sys.argv = original_argv
    with open(output_log, "w", encoding="utf-8") as f:
        f.write(stdout.getvalue())
    # res = len(stdout.getvalue().splitlines())
    return {"err_cnt": res, "output_log": output_log}


def check_pydocstyle(output: str = OUTPUT_FOLDER) -> Dict[str, Any]:
    """Check the dependencies and their licenses."""
    output_log = os.path.join(output, "pydocstyle.txt")

    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call("pydocstyle spsdk".split(), stdout=f, stderr=f)

    with open(output_log, "r", encoding="utf-8") as f:
        err_cnt = re.findall(r":\d+ in", f.read())
        if err_cnt:
            res = len(err_cnt)

    return {"err_cnt": res, "output_log": output_log}


def check_mypy(args: List[str], output_log: str) -> Dict[str, Any]:
    """Check the project against mypy tool."""
    res = 0
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(f"mypy {' '.join(args)}".split(), stdout=f, stderr=f)

    with open(output_log, "r", encoding="utf-8") as f:
        err_cnt = re.findall(r"Found \d+ error", f.read())
        if err_cnt:
            res = int(err_cnt[0].replace("Found ", "").replace(" error", ""))

    return {"err_cnt": res, "output_log": output_log}


def check_pylint(args: str, output_log: str) -> Dict[str, Any]:
    """Call pylint with given configuration and output log."""
    cmd = f"pylint {args} -j {CPU_CNT//2 or 1}"
    with open(output_log, "w", encoding="utf-8") as f:
        subprocess.call(cmd.split(), stdout=f, stderr=f)

    with open(output_log, "r", encoding="utf-8") as f:
        err_cnt = re.findall(r": [IRCWEF]\d{4}:", f.read())

    return {"err_cnt": len(err_cnt), "output_log": output_log}


def check_pylint_errors(input_log: str, output_log: str) -> Dict[str, Any]:
    """Check Pylint log for errors."""
    with open(input_log, "r", encoding="utf-8") as f:
        errors = re.findall(r".*: [EF]\d{4}:.*", f.read())
    with open(output_log, "w", encoding="utf-8") as f:
        f.write("\n".join(errors))

    return {"err_cnt": len(errors), "output_log": output_log}


def check_radon(output_log: str) -> Dict[str, Any]:
    """Check the project against radon rules."""
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call("radon cc --show-complexity spsdk".split(), stdout=f, stderr=f)

    return {"err_cnt": res, "output_log": output_log}


def check_radon_errors(input_log: str, radon_type: str, output_log: str) -> Dict[str, Any]:
    """Check radon log for records with given radon_type."""
    with open(input_log, "r", encoding="utf-8") as f:
        errors = re.findall(rf".* - {radon_type} .*", f.read())
    with open(output_log, "w", encoding="utf-8") as f:
        f.write("\n".join(errors))

    return {"err_cnt": len(errors), "output_log": output_log}


def check_black(output: str = OUTPUT_FOLDER) -> Dict[str, Any]:
    """Check the project against black formatter rules."""
    output_log = os.path.join(output, "black.txt")
    res = 0
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call(
            "black --check --diff spsdk examples tests".split(), stdout=f, stderr=f
        )

    return {"err_cnt": res, "output_log": output_log}


def check_isort(output: str = OUTPUT_FOLDER) -> Dict[str, Any]:
    """Check the project against isort imports formatter rules."""
    output_log = os.path.join(output, "isort.txt")
    res = 0
    with open(output_log, "w", encoding="utf-8") as f:
        res = subprocess.call("isort -c spsdk examples tests".split(), stdout=f, stderr=f)

    if res:
        with open(output_log, "r", encoding="utf-8") as f:
            res = len(f.read().splitlines())

    return {"err_cnt": res, "output_log": output_log}


def check_copyright_year(output: str = OUTPUT_FOLDER) -> Dict[str, Any]:
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

    return {"err_cnt": res, "output_log": output_log}


def print_nothing(*args: Any) -> None:
    """Just dummy print function."""


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
) -> int:
    """Simple tool to check the SPSDK development rules.

    :param check: List of tests to run.
    :param job_cnt: Select count of concurrent tests.
    :param output: Output folder for reports.
    :return: Exit code.
    """
    # logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)
    logging.basicConfig(level=logging.INFO)
    ret = 1
    try:
        available_checks = TaskList(
            [
                TaskInfo("PYTEST", check_pytest, output=output),
                TaskInfo("GITCOV", check_gitcov, output=output, dependencies=["PYTEST"]),
                TaskInfo(
                    "PYLINT_ALL",
                    check_pylint,
                    args="spsdk examples tools codecheck.py",
                    output_log=os.path.join(output, "pylint_all.txt"),
                ),
                TaskInfo(
                    "PYLINT",
                    check_pylint_errors,
                    input_log=os.path.join(output, "pylint_all.txt"),
                    output_log=os.path.join(output, "pylint.txt"),
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
                    output_log=os.path.join(output, "pylint_docs.txt"),
                ),
                TaskInfo(
                    "MYPY",
                    check_mypy,
                    args=["spsdk", "examples"],
                    output_log=os.path.join(output, "mypy.txt"),
                ),
                TaskInfo(
                    "MYPY_TOOLS",
                    check_mypy,
                    args=["tools", "codecheck.py"],
                    output_log=os.path.join(output, "mypy_tools.txt"),
                ),
                TaskInfo("DEPENDENCIES", check_dependencies, output=output),
                TaskInfo("PYDOCSTYLE", check_pydocstyle, output=output),
                TaskInfo(
                    "RADON_ALL", check_radon, output_log=os.path.join(output, "radon_all.txt")
                ),
                TaskInfo(
                    "RADON_C",
                    check_radon_errors,
                    radon_type="C",
                    input_log=os.path.join(output, "radon_all.txt"),
                    output_log=os.path.join(output, "radon_c.txt"),
                    dependencies=["RADON_ALL"],
                ),
                TaskInfo(
                    "RADON_D",
                    check_radon_errors,
                    radon_type="D",
                    input_log=os.path.join(output, "radon_all.txt"),
                    output_log=os.path.join(output, "radon_d.txt"),
                    dependencies=["RADON_ALL"],
                ),
                TaskInfo("BLACK", check_black, output=output),
                TaskInfo("ISORT", check_isort, output=output),
                TaskInfo("COPYRIGHT", check_copyright_year, output=output),
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

        if not os.path.isdir(output):
            os.mkdir(output)

        runner = PrettyProcessRunner(checks, print_func=print_nothing if silence else click.echo)
        runner.run(job_cnt, True)

        ret = check_results(checks, info_check, output)
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
