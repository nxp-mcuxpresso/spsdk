#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tool for updating requirements.txt files."""


import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional

import click
from packaging.requirements import Requirement
from packaging.specifiers import Specifier
from packaging.version import Version

THIS_DIR = os.path.abspath(os.path.dirname(__file__))
REPO_ROOT = os.path.normpath(os.path.join(THIS_DIR, ".."))
REQUIRED_PYTHON = (3, 9)


class NextVersion(str, Enum):
    """Next version selector class."""

    NONE = "none"
    MINOR = "minor"
    MAJOR = "major"

    @staticmethod
    def from_str(selector: Optional[str] = None) -> "NextVersion":
        """Load next version selector from string format.

        :param selector: Version in string format, defaults to None
        :raises ValueError: Unknown string on input
        :return: Version selector object
        """
        if not selector or selector == "current":
            return NextVersion.NONE
        if selector == "minor":
            return NextVersion.MINOR
        if selector == "major":
            return NextVersion.MAJOR
        raise ValueError(f"Unknown NextVersion selector '{selector}'. Use 'minor' or 'major'")


@dataclass
class RequirementsRecord:
    """Requirement record class."""

    original: Requirement
    max_version: Optional[str] = None
    act_version: Optional[str] = None

    @property
    def name(self) -> str:
        """Name of requirement."""
        return self.original.name

    @staticmethod
    def from_req(requirement: Requirement) -> "RequirementsRecord":
        """Get requirement record from requirement.

        :param requirement: Input requirement
        :return: Requirement record
        """
        max_version = None
        act_version = None
        for spec in list(requirement.specifier):
            if "<" in spec.operator:
                max_version = spec.version
            if "==" == spec.operator:
                act_version = spec.version
        specs = [s for s in list(requirement.specifier) if s.version != max_version]
        requirement.specifier._specs = frozenset(specs)
        return RequirementsRecord(
            original=requirement, max_version=max_version, act_version=act_version
        )

    def get_next_version(self, selector: NextVersion) -> str:
        """Get the next version of package.

        :param selector: Select which version severity should be updated
        :raises ValueError: Maximal version is not defined
        :return: New version in string
        """
        if not self.max_version:
            raise ValueError("max_version is not defined")
        if selector == NextVersion.NONE:
            return self.max_version
        version = Version(self.max_version)
        if selector == NextVersion.MINOR:
            return f"{version.major}.{version.minor + 1}"
        if selector == NextVersion.MAJOR:
            return f"{version.major + 1}"

    @staticmethod
    def from_str(req_line: str) -> "RequirementsRecord":
        """Get requirement from line record.

        :param req_line: Input line to decode
        :return: Requirement object.
        """
        return RequirementsRecord.from_req(Requirement(req_line))

    def to_str(
        self,
        include_max_version: bool = True,
        use_next_version: NextVersion = NextVersion.NONE,
    ) -> str:
        """Print Requirement to string."""
        if include_max_version and self.max_version:
            specs = list(self.original.specifier)
            specs.append(Specifier(f"<{self.get_next_version(selector=use_next_version)}"))
            self.original.specifier._specs = frozenset(specs)
        return str(self.original)


class RequirementsList(list[RequirementsRecord]):
    """List of requirements class."""

    def get_record(self, name: str) -> RequirementsRecord:
        """Get requirement record by its name."""
        for req in self:
            if self.normalize_name(req.name) == self.normalize_name(name):
                return req
        raise ValueError(f"Requirement named {name} wasn't found")

    @staticmethod
    def normalize_name(name: str) -> str:
        """Normalize to standard name format."""
        return name.replace("-", "_").replace(".", "_").lower()

    @staticmethod
    def from_pip() -> "RequirementsList":
        """Get Requirements from pip package."""
        output = subprocess.check_output("uv pip freeze".split(), text=True).splitlines()
        return RequirementsList.from_lines(req_lines=output)

    @staticmethod
    def load(path: str) -> "RequirementsList":
        """Get Requirements from file."""
        with open(path, encoding="utf-8") as f:
            req_lines = f.readlines()
        return RequirementsList.from_lines(req_lines=req_lines)

    @staticmethod
    def from_lines(req_lines: list[str]) -> "RequirementsList":
        """Get Requirements from text lines."""
        req_lines = [line for line in req_lines if not line.startswith(("-", "#"))]
        result = RequirementsList([RequirementsRecord.from_str(req) for req in req_lines])
        return result


def prepare_file(path: str) -> None:
    """Prepare requirements file.

    :param path: File path
    """
    click.echo(f"Preparing: {path}")
    with open(path, encoding="utf-8") as f:
        main_reqs = f.readlines()
    with open(path, "w", encoding="utf-8") as f:
        for req_line in main_reqs:
            if req_line.startswith(("#", "-")):
                f.write(req_line)
                continue
            req = RequirementsRecord.from_str(req_line=req_line)
            f.write(req.to_str(include_max_version=False) + "\n")


def finalize_file(
    path: str,
    requirements: RequirementsList,
    use_next_version: NextVersion = NextVersion.NONE,
) -> None:
    """Finalize output requirement file.

    :param path: File path
    :param requirements: List of requirements
    :param use_next_version: Using a new version, defaults to NextVersion.NONE
    """
    click.echo(f"Finalizing: {path}")
    with open(path, encoding="utf-8") as f:
        main_reqs = f.readlines()
    with open(path, "w", encoding="utf-8") as f:
        for req_line in main_reqs:
            # omit pip as pip itself is by design not shown in 'pip list'
            if req_line.startswith(("#", "-")) or req_line.startswith("pip"):
                f.write(req_line)
                continue
            req = RequirementsRecord.from_str(req_line=req_line)
            req.max_version = requirements.get_record(req.name).act_version
            f.write(req.to_str(include_max_version=True, use_next_version=use_next_version) + "\n")


def get_token(token: Optional[str]) -> str:
    """Get token value from input token(as a value or path to a file) or environment variable."""
    if not token:
        token = os.environ.get("BB_AUTH_TOKEN")
    if not token:
        raise ValueError("Token must be specified as argument or as env variable")
    token = os.path.expanduser(os.path.expandvars(token))
    if os.path.isfile(token):
        with open(token, encoding="utf-8") as f:
            return f.readline()
    return token


@click.group("req-update", no_args_is_help=True)
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
    ctx = click.get_current_context()
    # the command is called as a standalone command, not from batch
    if ctx.parent and ctx.parent.invoked_subcommand is not None:
        click.echo("Now update your venv by running the following commands:")
        click.echo("uv pip install --upgrade --force-reinstall .")
        click.echo(
            "uv pip install --upgrade --force-reinstall --requirement requirements-develop.txt"
        )
        click.echo("After that, update the requirements files using `req_update.py finalize`")


@main.command("update")
def update() -> None:
    """Update all dependencies."""
    try:
        click.echo("Updating project")
        subprocess.check_call("uv pip install --upgrade --force-reinstall -e .".split())
        click.echo("Updating development requirements")
        subprocess.check_call(
            "uv pip install --upgrade --force-reinstall -r requirements-develop.txt".split()
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Automated venv update failed: {e}") from e


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
    changes = subprocess.check_output("git status --short".split(), text=True).strip()
    if "requirement" not in changes:
        click.echo("No changes detected; nothing to do.")
        click.get_current_context().exit(0)

    if not branch_name:
        branch_name = "dependencies_update_" + datetime.now().strftime("%Y_%m_%d")

    git_path = shutil.which("git")
    if not git_path:
        click.secho("Git not found in PATH!", fg="red")
        click.get_current_context().exit(1)
    current_branch = subprocess.check_output(
        f"{git_path} rev-parse --abbrev-ref HEAD".split(), text=True
    ).strip()
    if branch_name != current_branch:
        try:
            subprocess.check_call(f"{git_path} checkout -b {branch_name}".split())
        except subprocess.CalledProcessError:
            # branch may exist from the past, delete it and re-create
            subprocess.check_call(f"{git_path} branch -d {branch_name}".split())
            subprocess.check_call(f"{git_path} checkout -b {branch_name}".split())

    subprocess.check_call(f"{git_path} add requirements.txt requirements-develop.txt".split())
    subprocess.check_call([git_path, "commit", "-m", "Changes in requirements versions"])
    subprocess.check_call(f"{git_path} push origin {branch_name}".split())


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
    import requests

    token = get_token(auth_token_path)
    git_path = shutil.which("git")
    if not git_path:
        click.secho("Git not found in PATH!", fg="red")
        click.get_current_context().exit(1)

    if not src_branch:
        src_branch = subprocess.check_output(
            f"{git_path} rev-parse --abbrev-ref HEAD".split(), text=True
        ).strip()

    url = "https://bitbucket.sw.nxp.com/rest/api/1.0/projects/SPSDK/repos/spsdk/pull-requests"

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    commit_datetime_str = subprocess.check_output(
        f"{git_path} log -1 --format=%cI".split(), text=True
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
    try:
        response.raise_for_status()
        click.secho("Pull request created", fg="green")
        click.echo(f"Visit: {response.json()['links']['self'][0]['href']}")
    except requests.HTTPError as e:
        raise RuntimeError(
            f"Pull request creation failed!:{json.dumps(response.json(), sort_keys=True, indent=4)}"
        ) from e


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
