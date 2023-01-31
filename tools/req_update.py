#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Tool for updating requirements.txt files."""


import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Optional

import click
import pkg_resources
import requests

THIS_DIR = os.path.abspath(os.path.dirname(__file__))
REPO_ROOT = os.path.normpath(os.path.join(THIS_DIR, ".."))
IGNORE_LIST = ["cmsis-pack-manager"]
REQUIRED_PYTHON = (3, 10)


class NextVersion(str, Enum):
    NONE = "none"
    MINOR = "minor"
    MAJOR = "major"

    @staticmethod
    def from_str(selector: Optional[str] = None) -> "NextVersion":
        if not selector or selector == "current":
            return NextVersion.NONE
        if selector == "minor":
            return NextVersion.MINOR
        if selector == "major":
            return NextVersion.MAJOR
        raise ValueError(f"Unknown NextVersion selector '{selector}'. Use 'minor' or 'major'")


@dataclass
class RequirementsRecord:
    name: str
    original: Optional[pkg_resources.Requirement] = None
    min_version: Optional[str] = None
    max_version: Optional[str] = None
    extras: Optional[List[str]] = None
    condition: Optional[str] = None

    @staticmethod
    def from_req(requirement: pkg_resources.Requirement) -> "RequirementsRecord":
        name = requirement.key
        min_version = None
        max_version = None
        for spec in requirement.specs:
            operator, value = spec
            if "<" in operator:
                max_version = value
                continue
            if ">" in operator:
                min_version = value
                continue
            max_version = value
        return RequirementsRecord(
            original=requirement,
            name=name,
            min_version=min_version,
            max_version=max_version,
            extras=list(requirement.extras),
        )

    def get_next_version(self, selector: NextVersion) -> str:
        if not self.max_version:
            raise ValueError("max_version is not defined")
        if selector == NextVersion.NONE:
            return self.max_version
        version = pkg_resources.parse_version(self.max_version)
        if selector == NextVersion.MINOR:
            return f"{version.major}.{version.minor + 1}"
        if selector == NextVersion.MAJOR:
            return f"{version.major + 1}"
        raise ValueError(f"Unknown next version selector: {selector}")

    @staticmethod
    def from_str(req_line: str) -> "RequirementsRecord":
        return RequirementsRecord.from_req(next(pkg_resources.parse_requirements(req_line)))

    @property
    def name_extra(self) -> str:
        result = self.name
        if self.extras:
            result += f"[{','.join(self.extras)}]"
        return result

    def to_str(
        self,
        include_min_version: bool = True,
        include_max_version: bool = True,
        use_next_version: NextVersion = NextVersion.NONE,
    ) -> str:
        result = self.name_extra
        if include_min_version and self.min_version:
            result += f">={self.min_version}"
        if include_max_version and self.max_version:
            result += f"{',' if '>' in result else ''}{'<' if use_next_version != NextVersion.NONE else '<='}"
            result += self.get_next_version(selector=use_next_version)
        return result


class RequirementsList(List[RequirementsRecord]):
    def get_record(self, name: str) -> RequirementsRecord:
        for req in self:
            if req.name == name:
                return req
        raise ValueError(f"Requirement named {name} wasn't found")

    @staticmethod
    def from_pip() -> "RequirementsList":
        output = subprocess.check_output("pip freeze", text=True, shell=True).splitlines()
        return RequirementsList.from_lines(req_lines=output)

    @staticmethod
    def load(path: str) -> "RequirementsList":
        with open(path) as f:
            req_lines = f.readlines()
        return RequirementsList.from_lines(req_lines=req_lines)

    @staticmethod
    def from_lines(req_lines: List[str]) -> "RequirementsList":
        req_lines = [line for line in req_lines if not line.startswith(("-", "#"))]
        result = RequirementsList([RequirementsRecord.from_str(req) for req in req_lines])
        return result


def prepare_file(path: str) -> None:
    click.echo(f"Preparing: {path}")
    with open(path) as f:
        main_reqs = f.readlines()
    with open(path, "w") as f:
        for req_line in main_reqs:
            if req_line.startswith(("#", "-")):
                f.write(req_line)
                continue
            req = RequirementsRecord.from_str(req_line=req_line)
            if req.name in IGNORE_LIST:
                f.write(req_line)
                continue
            f.write(req.to_str(include_min_version=True, include_max_version=False) + "\n")


def finalize_file(
    path: str,
    requirements: RequirementsList,
    use_next_version: NextVersion = NextVersion.NONE,
) -> None:
    click.echo(f"Finalizing: {path}")
    with open(path) as f:
        main_reqs = f.readlines()
    with open(path, "w") as f:
        for req_line in main_reqs:
            if req_line.startswith(("#", "-")):
                f.write(req_line)
                continue
            req = RequirementsRecord.from_str(req_line=req_line)
            if req.name in IGNORE_LIST:
                f.write(req_line)
                continue
            req.max_version = requirements.get_record(req.name).max_version
            f.write(
                req.to_str(
                    include_min_version=True,
                    include_max_version=True,
                    use_next_version=use_next_version,
                )
                + "\n"
            )


@click.group(no_args_is_help=True)
def main() -> int:
    """Tool for manipulating requirements files."""
    if sys.version_info < REQUIRED_PYTHON:
        click.secho(
            f"Please run this tool with python {'.'.join(str(i) for i in REQUIRED_PYTHON)}.",
            fg="red",
        )
        click.get_current_context().exit(1)

    if os.path.abspath(os.curdir) != REPO_ROOT:
        click.secho("Please run this script from the root of the repository!", fg="red")
        click.get_current_context().exit(1)
    return 0


@main.command("prepare")
def prepare() -> None:
    """Removes version info from a requirements file."""
    prepare_file("requirements.txt")
    prepare_file("requirements-develop.txt")
    click.echo("Now update your venv by running the following commands:")
    click.echo("python -m pip install --upgrade pip")
    click.echo('pip install --upgrade --force-reinstall --editable ".[tp]"')
    click.echo("pip install --upgrade --force-reinstall --requirement requirements-develop.txt")
    click.echo("After that, update the requirements files using `req_update.py finalize`")


@main.command("update")
def update() -> None:
    """Update all dependencies."""
    try:
        click.echo("Updating pip")
        subprocess.check_call("python -m pip install --upgrade pip", shell=True)
        click.echo("Updating project")
        subprocess.check_call('pip install --upgrade --force-reinstall -e ".[tp]"', shell=True)
        click.echo("Updating development requirements")
        subprocess.check_call(
            "pip install --upgrade --force-reinstall -r requirements-develop.txt", shell=True
        )
    except subprocess.CalledProcessError:
        click.secho("Automated venv update failed! Please run the following commands:", fg="red")
        click.echo("python -m pip install --upgrade pip")
        click.echo('pip install --upgrade --force-reinstall --editable ".[tp]"')
        click.echo("pip install --upgrade --force-reinstall --requirement requirements-develop.txt")
        click.echo("After that, update the requirements files using `req_update.py finalize`")


@main.command("finalize")
@click.option(
    "-u",
    "--use-version",
    type=click.Choice(["minor", "major", "current"], case_sensitive=False),
    default="minor",
    help="Which version to use for upper bound. Default: use next minor version.",
)
def finalize(use_version: str) -> None:
    """Update `max_version` in requirements.txt files."""
    actual_req = RequirementsList.from_pip()
    next_version = NextVersion.from_str(use_version)
    finalize_file("requirements.txt", actual_req, use_next_version=next_version)
    finalize_file("requirements-develop.txt", actual_req, use_next_version=next_version)


@main.command("branch")
@click.option(
    "-b",
    "--branch-name",
    help="Name for the new branch. Default: 'dependencies_update_<datetime>'",
)
def branch(branch_name: str) -> None:
    """Create branch and add changes onto it."""
    changes = subprocess.check_output("git status --short", shell=True, text=True).strip()
    if "requirement" not in changes:
        click.echo("No changes detected; nothing to do.")
        click.get_current_context().exit(0)

    if not branch_name:
        branch_name = "dependencies_update_" + datetime.now().strftime("%Y_%m_%d")
    current_branch = subprocess.check_output(
        "git rev-parse --abbrev-ref HEAD", shell=True, text=True
    ).strip()
    if branch_name != current_branch:
        try:
            subprocess.check_call(f"git checkout -b {branch_name}", shell=True)
        except subprocess.CalledProcessError:
            # branch may exist from the past, delete it and re-create
            subprocess.check_call(f"git branch -d {branch_name}", shell=True)
            subprocess.check_call(f"git checkout -b {branch_name}", shell=True)

    subprocess.check_call("git add .", shell=True)
    subprocess.check_call('git commit -m "Changes in requirements versions"', shell=True)
    subprocess.check_call(f"git push origin {branch_name}", shell=True)


@main.command("pull-request")
@click.option(
    "-t",
    "--auth_token_path",
    help="Path to file with BitBucket HTTP token. Default: path in BB_AUTH_TOKEN env variable",
)
@click.option(
    "-s",
    "--src-branch",
    help="Source branch for the pull request. Default: current branch",
)
@click.option(
    "-d",
    "--dest-branch",
    help="Destination branch for the pull request. Default: 'master'",
    default="master",
)
def pull_request(auth_token_path: str, src_branch: str, dest_branch: str) -> None:
    """Create pull request."""
    with open(auth_token_path or os.environ["BB_AUTH_TOKEN"]) as f:
        token = f.readline()

    if not src_branch:
        src_branch = subprocess.check_output(
            "git rev-parse --abbrev-ref HEAD", shell=True, text=True
        ).strip()

    url = "https://bitbucket.sw.nxp.com/rest/api/1.0/projects/SPSDK/repos/spsdk/pull-requests"

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    commit_datetime_str = subprocess.check_output(
        'git log -1 --format="%cI"', shell=True, text=True
    ).strip()
    commit_datetime = datetime.fromisoformat(commit_datetime_str)
    # This is the minimal set of data required for API call
    # https://developer.atlassian.com/server/bitbucket/rest/v805/api-group-pull-requests/#api-group-pull-requests
    data = {
        "title": "Dependencies update",
        "description": f"Update made on {commit_datetime.strftime('%Y-%m-%d at %H:%M')}",
        "fromRef": {
            "id": f"refs/heads/{src_branch}",
            "type": "BRANCH",
            "displayId": src_branch,
        },
        "toRef": {
            "id": f"refs/heads/{dest_branch}",
            "type": "BRANCH",
            "displayId": dest_branch,
        },
    }
    response = requests.post(url, headers=headers, data=json.dumps(data), timeout=10)
    if response.status_code in [200, 201]:
        click.secho("Pull request created", fg="green")
        click.echo(f"Visit: {response.json()['links']['self'][0]['href']}")
    else:
        click.secho("Pull request creation failed!", fg="red")
        click.echo(json.dumps(response.json(), sort_keys=True, indent=4))


@main.command("batch")
@click.option(
    "-u",
    "--use-version",
    type=click.Choice(["minor", "major", "current"], case_sensitive=False),
    default="minor",
    help="Which version to use for upper bound. Default: use next minor version.",
)
@click.option(
    "-b",
    "--branch-name",
    help="Name for new branch. Default: 'dependencies_update_<datetime>'",
)
@click.option(
    "-t",
    "--auth-token-path",
    help="Path to file with BitBucket HTTP token. Default: path in BB_AUTH_TOKEN env variable",
)
@click.option(
    "-s",
    "--src-branch",
    help="Source branch for the pull request. Default: <current branch>",
)
@click.option(
    "-d",
    "--dest-branch",
    help="Destination branch for the pull request. Default: 'master'",
    default="master",
)
def batch(
    use_version: str, branch_name: str, auth_token_path: str, src_branch: str, dest_branch: str
) -> None:
    """Perform all actions in a single run."""
    context = click.get_current_context()
    context.invoke(prepare)
    context.invoke(update)
    context.invoke(finalize, use_version=use_version)
    context.invoke(branch, branch_name=branch_name)
    context.invoke(
        pull_request,
        auth_token_path=auth_token_path,
        src_branch=src_branch,
        dest_branch=dest_branch,
    )


if __name__ == "__main__":
    sys.exit(main())
