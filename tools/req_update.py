#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK requirements.txt management and update automation tool.

This module provides comprehensive functionality for managing Python package
requirements across the SPSDK project, including automated updates, version
management, and CI/CD integration.
"""


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
    """Version selector enumeration for SPSDK release management.

    This enumeration defines the available options for selecting the next version
    type during release processes, supporting none, minor, and major version increments.

    :cvar NONE: No version increment (current version)
    :cvar MINOR: Minor version increment
    :cvar MAJOR: Major version increment
    """

    NONE = "none"
    MINOR = "minor"
    MAJOR = "major"

    @staticmethod
    def from_str(selector: Optional[str] = None) -> "NextVersion":
        """Load next version selector from string format.

        Converts string representation of version increment type to NextVersion enum.
        Accepts 'minor', 'major', 'current', or None values.

        :param selector: Version selector string ('minor', 'major', 'current', or None), defaults to None.
        :raises ValueError: Unknown string selector provided.
        :return: NextVersion enum instance corresponding to the input selector.
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
    """Requirements record for package dependency management.

    This class represents a single requirement record that tracks package dependencies
    with their original specification, maximum allowed version, and actual version.
    It provides functionality to parse requirement specifications and generate
    updated version strings for dependency management operations.
    """

    original: Requirement
    max_version: Optional[str] = None
    act_version: Optional[str] = None

    @property
    def name(self) -> str:
        """Get the name of the requirement.

        :return: The name of the requirement as stored in the original requirement object.
        """
        return self.original.name

    @staticmethod
    def from_req(requirement: Requirement) -> "RequirementsRecord":
        """Create a RequirementsRecord from a Requirement object.

        This method extracts version constraints from the requirement specifier,
        identifying maximum version limits (using '<' operators) and exact versions
        (using '==' operators). It modifies the requirement's specifier by removing
        maximum version constraints.

        :param requirement: The input requirement object to process.
        :return: A new RequirementsRecord containing the processed requirement data.
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

        The method calculates the next version based on the provided selector type.
        For NONE selector, returns the current max version. For MINOR selector,
        increments the minor version. For MAJOR selector, increments the major version.

        :param selector: Select which version severity should be updated.
        :raises ValueError: Maximal version is not defined.
        :return: New version in string format.
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
        """Parse requirement from string line format.

        Converts a string representation of a requirement into a RequirementsRecord object
        by first parsing it as a Requirement and then converting to the internal format.

        :param req_line: String line containing requirement specification to decode.
        :return: RequirementsRecord object parsed from the input line.
        """
        return RequirementsRecord.from_req(Requirement(req_line))

    def to_str(
        self,
        include_max_version: bool = True,
        use_next_version: NextVersion = NextVersion.NONE,
    ) -> str:
        """Convert Requirement object to string representation.

        The method optionally includes maximum version constraints and can use
        different next version selection strategies for version boundary calculation.

        :param include_max_version: Whether to include maximum version constraint in output.
        :param use_next_version: Strategy for selecting next version boundary.
        :return: String representation of the requirement with optional version constraints.
        """
        if include_max_version and self.max_version:
            specs = list(self.original.specifier)
            specs.append(Specifier(f"<{self.get_next_version(selector=use_next_version)}"))
            self.original.specifier._specs = frozenset(specs)
        return str(self.original)


class RequirementsList(list[RequirementsRecord]):
    """SPSDK Requirements List Manager.

    This class manages a collection of Python package requirements, providing
    functionality to load, parse, and query requirement records from various
    sources including pip freeze output and requirements files.
    """

    def get_record(self, name: str) -> RequirementsRecord:
        """Get requirement record by its name.

        Searches through the requirements collection to find a record with the specified name.
        Name comparison is performed using normalized names to ensure case-insensitive matching.

        :param name: Name of the requirement record to search for.
        :raises ValueError: When no requirement with the given name is found.
        :return: The requirement record matching the specified name.
        """
        for req in self:
            if self.normalize_name(req.name) == self.normalize_name(name):
                return req
        raise ValueError(f"Requirement named {name} wasn't found")

    @staticmethod
    def normalize_name(name: str) -> str:
        """Normalize package name to standard format.

        Converts package names to a standardized format by replacing hyphens and dots
        with underscores and converting to lowercase. This ensures consistent naming
        across the SPSDK project.

        :param name: Package name to normalize.
        :return: Normalized package name with underscores and lowercase letters.
        """
        return name.replace("-", "_").replace(".", "_").lower()

    @staticmethod
    def from_pip() -> "RequirementsList":
        """Get requirements from currently installed pip packages.

        Uses 'uv pip freeze' command to retrieve currently installed packages
        and their versions, then converts the output into a RequirementsList object.

        :raises subprocess.CalledProcessError: If the 'uv pip freeze' command fails to execute.
        :raises FileNotFoundError: If the 'uv' command is not found in the system PATH.
        :return: RequirementsList object containing all installed packages and their versions.
        """
        output = subprocess.check_output("uv pip freeze".split(), text=True).splitlines()
        return RequirementsList.from_lines(req_lines=output)

    @staticmethod
    def load(path: str) -> "RequirementsList":
        """Load requirements list from a file.

        Reads a requirements file and parses it into a RequirementsList object.
        The file is expected to contain requirement specifications in standard format.

        :param path: Path to the requirements file to load.
        :raises FileNotFoundError: If the specified file does not exist.
        :raises OSError: If there are issues reading the file.
        :return: RequirementsList object containing parsed requirements.
        """
        with open(path, encoding="utf-8") as f:
            req_lines = f.readlines()
        return RequirementsList.from_lines(req_lines=req_lines)

    @staticmethod
    def from_lines(req_lines: list[str]) -> "RequirementsList":
        """Parse requirements from text lines into a RequirementsList object.

        Filters out comment lines (starting with '-' or '#') and converts valid
        requirement lines into RequirementsRecord objects.

        :param req_lines: List of text lines containing requirement specifications.
        :return: RequirementsList object containing parsed requirements.
        """
        req_lines = [line for line in req_lines if not line.startswith(("-", "#"))]
        result = RequirementsList([RequirementsRecord.from_str(req) for req in req_lines])
        return result


def prepare_file(path: str) -> None:
    """Prepare requirements file by removing version pinning constraints.

    The method reads a requirements file, processes each line to remove maximum
    version constraints while preserving comments and pip options, then writes
    the modified content back to the same file.

    :param path: Absolute or relative path to the requirements file to process.
    :raises FileNotFoundError: If the specified requirements file does not exist.
    :raises PermissionError: If the file cannot be read or written due to permissions.
    :raises UnicodeDecodeError: If the file cannot be decoded as UTF-8.
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

    Updates a requirements file by setting maximum versions for packages based on
    the provided requirements list. Preserves comments and exact version specifications.

    :param path: Path to the requirements file to be finalized.
    :param requirements: List of requirements containing version information.
    :param use_next_version: Strategy for version handling, defaults to NextVersion.NONE.
    :raises FileNotFoundError: If the specified requirements file does not exist.
    :raises PermissionError: If the file cannot be read or written due to permissions.
    """
    click.echo(f"Finalizing: {path}")
    with open(path, encoding="utf-8") as f:
        main_reqs = f.readlines()
    with open(path, "w", encoding="utf-8") as f:
        for req_line in main_reqs:
            if req_line.startswith(("#", "-")):
                f.write(req_line)
                continue
            req = RequirementsRecord.from_str(req_line=req_line)
            # Skip updating requirements with exact versions (==)
            if req.act_version:
                f.write(req_line)
                continue
            req.max_version = requirements.get_record(req.name).act_version
            f.write(req.to_str(include_max_version=True, use_next_version=use_next_version) + "\n")


def get_token(token: Optional[str]) -> str:
    """Get token value from input token or environment variable.

    The method retrieves authentication token from multiple sources with fallback logic.
    First tries the provided token parameter, then falls back to BB_AUTH_TOKEN
    environment variable. The token can be provided as a direct value or as a
    file path containing the token.

    :param token: Token value or path to file containing token, None to use environment variable.
    :raises ValueError: When no token is found in parameter or environment variable.
    :return: Token value as string.
    """
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
    """Main entry point for the requirements file manipulation tool.

    Validates the Python version and ensures the script is run from the repository root.
    The function will exit the application with error code 1 if validation fails.

    :return: Exit code 0 on successful validation, otherwise exits with code 1.
    """
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
    """Prepare requirements files by removing version constraints.

    This function removes version information from both requirements.txt and
    requirements-develop.txt files to prepare them for dependency updates. When run
    as a standalone command, it also provides instructions for updating the virtual
    environment and finalizing the requirements files.

    :raises SPSDKError: If requirements files cannot be processed or are not found.
    """
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
    """Update all project dependencies to their latest versions.

    This method performs a complete update of both the main project dependencies
    and development requirements using uv package manager. It forces reinstallation
    to ensure clean dependency resolution.

    :raises RuntimeError: When the dependency update process fails due to subprocess errors.
    """
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
    """Update max_version in requirements.txt files.

    This method reads the current pip requirements, parses the specified version,
    and updates both requirements.txt and requirements-develop.txt files with
    the new maximum version constraints.

    :param use_version: Version string to be used as the maximum version constraint.
    :raises SPSDKValueError: Invalid version string format.
    :raises SPSDKError: Error during requirements file processing or update.
    """
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
    """Create a Git branch and commit requirement file changes.

    The method detects changes in requirement files, creates a new Git branch with
    the specified name (or generates a timestamp-based name), commits the changes,
    and pushes the branch to origin. If no requirement changes are detected, the
    operation exits early.

    :param branch_name: Name of the Git branch to create. If empty, generates a name with current date.
    :raises SystemExit: When no changes are detected or Git is not found in PATH.
    :raises subprocess.CalledProcessError: When Git operations fail during branch creation or commit process.
    """
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
    """Create pull request for dependencies update.

    Creates a pull request on the SPSDK Bitbucket repository with automatic title
    and description based on the latest commit timestamp. Uses git commands to
    retrieve branch information and commit details.

    :param auth_token_path: Path to file containing authentication token for Bitbucket API.
    :param src_branch: Source branch name for pull request. If empty, uses current git branch.
    :param dest_branch: Destination branch name for pull request.
    :raises RuntimeError: When pull request creation fails due to API errors.
    """
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
    """Perform all actions in a single run.

    Executes the complete workflow by invoking prepare, update, finalize, branch,
    and pull_request commands in sequence to automate the entire requirements
    update process.

    :param use_version: Version to use for the update process.
    :param branch_name: Name of the branch to create for the changes.
    :param auth_token_path: Path to the authentication token file for API access.
    :param src_branch: Source branch name for the pull request.
    :param dest_branch: Destination branch name for the pull request.
    """
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
