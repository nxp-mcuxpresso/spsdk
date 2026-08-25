#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Automate SPSDK branch-aware tagging for Bitbucket pipelines.

Rules implemented by this script:
- release/X.Y.Z:
  - Keep RC tags on every new commit: vX.Y.Z-RC0, RC1, ...
  - Ensure a DEV anchor exists for X.Y.Z (vX.Y.Z-DEVn).
- master:
  - Create exactly one next-minor DEV0 tag once release branch exists.
  - Do not generate additional master tags.

The script is idempotent and safe to re-run on the same commit.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass


TAG_RE = re.compile(r"^v(?P<maj>\d+)\.(?P<min>\d+)\.(?P<pat>\d+)-(?P<kind>DEV|RC)(?P<num>\d+)$")
RELEASE_BRANCH_RE = re.compile(r"^release/(?P<maj>\d+)\.(?P<min>\d+)\.(?P<pat>\d+)$")


@dataclass(frozen=True)
class ParsedTag:
    """Parsed tag representation."""

    raw: str
    major: int
    minor: int
    patch: int
    kind: str
    number: int


#: Global verbose flag toggled by --verbose / SPSDK_TAG_VERBOSE.
VERBOSE = False


def set_verbose(enabled: bool) -> None:
    """Enable or disable verbose debug logging.

    :param enabled: True to print detailed flow/debug logs.
    """
    global VERBOSE  # pylint: disable=global-statement
    VERBOSE = enabled


def log_step(title: str) -> None:
    """Print a highlighted flow-step header (the WHAT).

    :param title: Step title to display.
    """
    print(f"\n=== {title} ===")


def log_decision(action: str, reason: str) -> None:
    """Print a taken decision together with its reasoning (the WHY).

    :param action: What the script decided to do.
    :param reason: Why this decision was taken.
    """
    print(f"-> {action}")
    print(f"   reason: {reason}")


def vlog(message: str) -> None:
    """Print a debug message only when verbose mode is enabled.

    :param message: Debug message to display.
    """
    if VERBOSE:
        print(f"[DEBUG] {message}")


def run_git(*args: str, check: bool = True) -> str:
    """Execute git command and return stripped stdout.

    :param args: Git command arguments.
    :param check: Raise if command fails.
    :return: Command stdout.
    """
    vlog(f"git {' '.join(args)}")
    process = subprocess.run(
        ["git", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if check and process.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed with code {process.returncode}: {process.stderr.strip()}"
        )
    return process.stdout.strip()


def parse_tag(tag: str) -> ParsedTag | None:
    """Parse supported tag format.

    :param tag: Tag name.
    :return: ParsedTag when matched, otherwise None.
    """
    match = TAG_RE.match(tag)
    if not match:
        return None
    return ParsedTag(
        raw=tag,
        major=int(match.group("maj")),
        minor=int(match.group("min")),
        patch=int(match.group("pat")),
        kind=match.group("kind"),
        number=int(match.group("num")),
    )


def get_all_tags() -> list[str]:
    """Return all repository tags.

    :return: List of tag names.
    """
    output = run_git("tag", "-l")
    return [line.strip() for line in output.splitlines() if line.strip()]


def get_head_tags() -> list[str]:
    """Return tags pointing to HEAD.

    :return: List of tag names at HEAD.
    """
    output = run_git("tag", "--points-at", "HEAD")
    return [line.strip() for line in output.splitlines() if line.strip()]


def tag_exists(tag: str) -> bool:
    """Check if a tag exists.

    :param tag: Tag name.
    :return: True if tag exists.
    """
    return bool(run_git("tag", "-l", tag))


def tag_target(tag: str) -> str:
    """Return target commit hash of a tag.

    :param tag: Tag name.
    :return: Commit hash.
    """
    return run_git("rev-list", "-n", "1", tag)


def create_and_push_tag(tag: str, message: str, dry_run: bool) -> None:
    """Create annotated tag and push it to origin.

    :param tag: Tag name.
    :param message: Tag annotation message.
    :param dry_run: If True, only print action.
    """
    if dry_run:
        print(f"[DRY-RUN] Would create and push tag: {tag}")
        return

    run_git("tag", "-a", tag, "-m", message)
    run_git("push", "origin", tag)
    print(f"Created and pushed tag: {tag}")


def filter_tags_for_version(tags: list[str], major: int, minor: int, patch: int, kind: str) -> list[ParsedTag]:
    """Filter tags by version and kind.

    :param tags: Raw tag names.
    :param major: Major version.
    :param minor: Minor version.
    :param patch: Patch version.
    :param kind: Tag kind (DEV or RC).
    :return: Matching parsed tags sorted by numeric suffix.
    """
    parsed = [parse_tag(tag) for tag in tags]
    matches = [
        item
        for item in parsed
        if item
        and item.major == major
        and item.minor == minor
        and item.patch == patch
        and item.kind == kind
    ]
    return sorted(matches, key=lambda item: item.number)


def ensure_release_dev_anchor(all_tags: list[str], major: int, minor: int, patch: int, dry_run: bool) -> bool:
    """Ensure release version has at least one DEV tag anchor.

    :param all_tags: All repository tags.
    :param major: Major version.
    :param minor: Minor version.
    :param patch: Patch version.
    :param dry_run: If True, no git mutation.
    :return: True if DEV anchor was created in this run, otherwise False.
    """
    dev_tags = filter_tags_for_version(all_tags, major, minor, patch, "DEV")
    if dev_tags:
        vlog(f"Existing DEV anchors for {major}.{minor}.{patch}: "
             f"{[item.raw for item in dev_tags]}")
        return False

    new_tag = f"v{major}.{minor}.{patch}-DEV0"
    if tag_exists(new_tag):
        log_decision(
            f"Skip creating {new_tag}",
            "DEV anchor tag already exists in the repository.",
        )
        return False

    log_decision(
        f"Create DEV anchor {new_tag}",
        f"release/{major}.{minor}.{patch} has no DEV anchor yet; "
        "an anchor is required before RC tagging can start.",
    )
    create_and_push_tag(new_tag, f"Auto DEV anchor tag for release/{major}.{minor}.{patch}", dry_run)
    return True


def handle_release_branch(branch: str, dry_run: bool) -> int:
    """Handle tagging for release/X.Y.Z branch.

    :param branch: Branch name.
    :param dry_run: If True, no git mutation.
    :return: Exit code.
    """
    log_step(f"Release branch flow: {branch}")
    match = RELEASE_BRANCH_RE.match(branch)
    if not match:
        log_decision(
            f"Skip branch '{branch}'",
            "Branch name does not match the release/X.Y.Z pattern.",
        )
        return 0

    major = int(match.group("maj"))
    minor = int(match.group("min"))
    patch = int(match.group("pat"))
    vlog(f"Parsed release version: {major}.{minor}.{patch}")

    all_tags = get_all_tags()
    if ensure_release_dev_anchor(all_tags, major, minor, patch, dry_run):
        log_decision(
            "Stop after DEV anchor creation",
            "DEV anchor was just created; RC tagging starts only from the next commit.",
        )
        return 0

    all_tags = get_all_tags()

    head_tags = get_head_tags()
    vlog(f"Tags pointing at HEAD: {head_tags or '<none>'}")
    head_parsed = [item for item in (parse_tag(tag) for tag in head_tags) if item]
    for item in head_parsed:
        if (
            item.major == major
            and item.minor == minor
            and item.patch == patch
            and item.kind == "RC"
        ):
            log_decision(
                f"Skip tagging (no-op) for {item.raw}",
                "HEAD commit is already tagged with a matching RC tag.",
            )
            return 0

    rc_tags = filter_tags_for_version(all_tags, major, minor, patch, "RC")
    vlog(f"Existing RC tags for {major}.{minor}.{patch}: "
         f"{[item.raw for item in rc_tags]}")
    next_rc = rc_tags[-1].number + 1 if rc_tags else 0
    new_tag = f"v{major}.{minor}.{patch}-RC{next_rc}"

    if tag_exists(new_tag):
        if tag_target(new_tag) == run_git("rev-parse", "HEAD"):
            log_decision(
                f"Skip tagging (no-op) for {new_tag}",
                "Computed RC tag already exists and points at the current HEAD.",
            )
            return 0
        raise RuntimeError(f"Tag already exists on a different commit: {new_tag}")

    log_decision(
        f"Create RC tag {new_tag}",
        f"New commit on {branch}; next sequential RC number is {next_rc}.",
    )
    create_and_push_tag(new_tag, f"Auto RC tag for {branch}", dry_run)
    return 0


def get_release_versions_from_origin() -> list[tuple[int, int, int]]:
    """Get parsed release branch versions from origin.

    :return: List of version tuples.
    """
    refs = run_git(
        "for-each-ref",
        "--format=%(refname:short)",
        "refs/remotes/origin/release",
        check=False,
    )
    versions: list[tuple[int, int, int]] = []
    for ref in refs.splitlines():
        ref = ref.strip()
        if not ref:
            continue
        branch_name = ref.replace("origin/", "", 1)
        match = RELEASE_BRANCH_RE.match(branch_name)
        if not match:
            continue
        versions.append(
            (int(match.group("maj")), int(match.group("min")), int(match.group("pat")))
        )
    return versions


def handle_master_branch(dry_run: bool) -> int:
    """Handle one-time DEV0 tag creation on master.

    :param dry_run: If True, no git mutation.
    :return: Exit code.
    """
    log_step("Master branch flow")
    release_versions = get_release_versions_from_origin()
    if not release_versions:
        log_decision(
            "Skip master tag automation",
            "No origin/release/* branches exist yet, so the next DEV0 target is unknown.",
        )
        return 0

    current_release = max(release_versions)
    vlog(f"Highest origin release version: {current_release}")
    # Bumping the minor version always resets the patch component to 0.
    # Carrying over the release branch patch would create wrong tags
    # (e.g. v3.11.1-DEV0) and break the "exactly one DEV0" master rule.
    next_version = (current_release[0], current_release[1] + 1, 0)
    new_tag = f"v{next_version[0]}.{next_version[1]}.{next_version[2]}-DEV0"
    vlog(f"Computed next-minor DEV0 target: {new_tag}")

    if tag_exists(new_tag):
        log_decision(
            f"Skip creating {new_tag}",
            "Master DEV0 already exists; master creates this tag exactly once.",
        )
        return 0

    head_tags = get_head_tags()
    vlog(f"Tags pointing at HEAD: {head_tags or '<none>'}")
    if any(parse_tag(tag) for tag in head_tags):
        log_decision(
            "Skip tagging HEAD",
            "HEAD already carries a managed tag; avoid stacking duplicate tags.",
        )
        return 0

    log_decision(
        f"Create master DEV0 {new_tag}",
        f"Highest release branch is {current_release[0]}.{current_release[1]}."
        f"{current_release[2]}; the next development minor is opened on master.",
    )
    create_and_push_tag(new_tag, "Auto DEV0 tag for first master commit after release branching", dry_run)
    return 0


def setup_git_context() -> None:
    """Refresh tags and release refs for deterministic calculations."""
    log_step("Refreshing git context (tags + release refs)")
    run_git("fetch", "--tags", "origin")
    run_git(
        "fetch",
        "origin",
        "+refs/heads/release/*:refs/remotes/origin/release/*",
        check=False,
    )


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments.

    :return: Parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Branch-aware SPSDK tag automation")
    parser.add_argument(
        "--branch",
        default=os.environ.get("BITBUCKET_BRANCH", ""),
        help="Branch name (defaults to BITBUCKET_BRANCH)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show actions without creating/pushing tags",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=os.environ.get("SPSDK_TAG_VERBOSE", "").lower() in ("1", "true", "yes"),
        help="Print detailed debug logs (also enabled via SPSDK_TAG_VERBOSE=1)",
    )
    return parser.parse_args()


def main() -> int:
    """Entrypoint.

    :return: Exit code.
    """
    args = parse_args()
    set_verbose(args.verbose)
    branch = args.branch or run_git("rev-parse", "--abbrev-ref", "HEAD")

    log_step("SPSDK auto tag flow")
    print(f"Branch    : {branch}")
    print(f"Dry-run   : {args.dry_run}")
    print(f"Verbose   : {args.verbose}")
    vlog(f"HEAD commit: {run_git('rev-parse', 'HEAD')}")

    setup_git_context()

    if branch == "master":
        return handle_master_branch(args.dry_run)
    if branch.startswith("release/"):
        return handle_release_branch(branch, args.dry_run)

    log_decision(
        f"Skip branch '{branch}'",
        "Branch is outside the managed master / release flow.",
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pylint: disable=broad-except
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc