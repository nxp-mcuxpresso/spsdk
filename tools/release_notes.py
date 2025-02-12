#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Helper script for generating Release Notes."""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from getpass import getpass
from typing import NamedTuple, Optional

from cachier import cachier
from cryptography.hazmat.primitives import hashes
from jira import JIRA, Issue

from spsdk.exceptions import SPSDKError

TICKET_REGEX = re.compile(r"(SPSDK-\d+)")
JIRA_SERVER = "https://jira.sw.nxp.com"


class RNParams(NamedTuple):
    """Release Notes Parameters."""

    since: str
    till: str
    include_id: bool
    log_level: int
    cache_file: Optional[str]
    offline: bool
    netrc: bool
    user: Optional[str]


class TicketRecord(NamedTuple):
    """JIRA Ticket Record."""

    issue_id: str
    issue_type: str
    summary: str
    component: str

    @staticmethod
    def from_jira_issue(issue: Issue) -> "TicketRecord":
        """Coverts JIRA Issue into TicketRecord."""
        # ticket may not have a component assigned, in that case use 'N/A'
        try:
            component_name = issue.fields.components[0].name
        except IndexError:
            component_name = "N/A"
        # issue type unification: Bug -> Bugfix, else -> Task
        issue_type = "Bugfix" if issue.fields.issuetype.name == "Bug" else "Task"

        return TicketRecord(
            issue_id=issue.key,
            issue_type=issue_type,
            summary=issue.fields.summary,
            component=component_name,
        )


class RecordsList(list[TicketRecord]):
    """JIRA records list."""

    def get_components(self) -> list[str]:
        """Get component names from data."""
        return self.get_attributes("component")

    def get_types(self) -> list[str]:
        """Get issue type names from data."""
        return self.get_attributes("issue_type")

    def get_attributes(self, attribute_name: str) -> list[str]:
        """Get all attributes with `attribute_name` from data."""
        group = [getattr(item, attribute_name) for item in self]
        return sorted(list(set(group)))

    def filter(self, attrib_name: str, attrib_value: str) -> "RecordsList":
        """Filter records based on attribute name and its value."""
        return RecordsList([item for item in self if getattr(item, attrib_name) == attrib_value])

    def save(self, file_path: str) -> None:
        """Store data for later custom re-use/inspection."""
        # to load data back, use object_hook=lambda x: TicketRecord(**x)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump([x._asdict() for x in self], f, indent=2)

    @classmethod
    def load(cls, file_path: str) -> "RecordsList":
        """Load previously saved RecordList."""
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f, object_hook=lambda x: TicketRecord(**x))
        return cls(data)


def parse_inputs(input_args: Optional[list[str]] = None) -> RNParams:
    """Parse user inputs."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="This utility is meant to help compiling Release notes.",
    )
    parser.add_argument(
        "-s",
        "--since",
        required=True,
        help="tag or commit-sha where to start collecting JIRA ticket ids",
    )
    parser.add_argument(
        "-t",
        "--till",
        required=False,
        default="HEAD",
        help="tag or commit-sha where to stop collecting JIRA ticket ids",
    )
    parser.add_argument(
        "-i",
        "--include-id",
        required=False,
        action="store_true",
        help="Include JIRA ticket ID in output",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_const",
        dest="log_level",
        const=logging.INFO,
        help="Print out verbose output",
        default=logging.WARNING,
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_const",
        dest="log_level",
        const=logging.DEBUG,
        help="Print out debug messages",
    )
    parser.add_argument(
        "-c",
        "--cache-file",
        required=False,
        help="Path to json file to store data retrieved from JIRA server",
    )
    parser.add_argument(
        "-o",
        "--offline",
        action="store_true",
        help="Work in off-line mode with pre-captured data from previous runs",
    )
    login_group = parser.add_mutually_exclusive_group(required=True)
    login_group.add_argument(
        "-n",
        "--netrc",
        action="store_true",
        default=True,
        help="User login specified in ~/.netrc",
    )
    login_group.add_argument(
        "-u",
        "--user",
        help="Use logging into JIRA via username and password, you'll be prompted for password later",
    )
    args = parser.parse_args(input_args)
    if args.user:
        args.netrc = False
    return RNParams(**vars(args))


def get_commit_messages(since: str, till: str) -> str:
    """Get git commit messages delimited by `since` and `till` commit-ids/tags."""
    logging.info("Getting git information")
    cmd = f'git log --pretty="%s" {since}..{till}'
    logging.debug(f"Running: {cmd}")
    output = subprocess.check_output(cmd.split()).decode("utf-8")
    logging.debug(f"Git output:\n{output}")
    return output


def get_jira_ids(git_output: str) -> list[str]:
    """Parse text for JIRA ids. see: `TICKET_REGEX`."""
    logging.info("Extracting JIRA ticket ids from commit messages")
    ids = re.findall(TICKET_REGEX, git_output)
    ids = sorted(list(set(ids)))
    logging.debug(f"JIRA ids found: {ids}")
    return ids


def ticket_info_hasher(args: tuple, kwargs: dict) -> str:
    """Helper function providing hash value of arguments for `get_ticket_info` function.

    To optimize caching persistent caching, we need function with consistent return values.
    As the built-in hash function doesn't compute same values across multiple runs,
    we use MD5 hashing.
    """
    to_hash: str = kwargs["ticket"] if "ticket" in kwargs else args[0]
    digest = hashes.Hash(hashes.MD5())  # nosec
    digest.update(to_hash.encode("utf-8"))
    digest_string = digest.finalize().hex()
    logging.debug(f"cache param hashing: {to_hash} -> {digest_string}")
    return digest_string


@cachier(hash_func=ticket_info_hasher)
def get_ticket_info(ticket: str, jira: Optional[JIRA]) -> TicketRecord:
    """Extract info for `ticket` from JIRA.

    The `@cachier` decorator produces persistent cache to alleviate load on JIRA server.
    """
    if not jira:
        raise SPSDKError(f"Info for {ticket} is not pre-recorded, can't work in offline mode")
    logging.info(f"Fetching info for ticket: {ticket}")
    issue = jira.issue(ticket)
    return TicketRecord.from_jira_issue(issue=issue)


def main() -> None:
    """Main function."""
    args = parse_inputs()
    logging.basicConfig(level=args.log_level)
    logging.debug(f"Input args: {args}")

    git_output = get_commit_messages(args.since, args.till)
    ticket_ids = get_jira_ids(git_output)

    if not ticket_ids:
        logging.info("No tickets found in commit messages.")
        sys.exit(1)

    password = None
    # ask for password if running in online mode, user doesn't uses netrc, but specifies username
    if not args.offline and args.user:
        password = getpass(f"Enter password for '{args.user}': ")

    # auth option is omitted for offline mode and online using netrc
    # auth = None if args.offline or args.netrc else (args.user, password)
    if args.offline or args.netrc:
        auth = None
    else:
        assert isinstance(args.user, str)
        assert isinstance(password, str)
        auth = (args.user, password)

    if args.netrc and not os.path.isfile(os.path.expanduser("~/.netrc")):
        logging.error("NetRC authentication selected (-n) but ~/.netrc file not found")
        logging.error("Either create .netrc file or use username/pass authentication (-u)")
        sys.exit(1)

    # for offline mode, we don't instantiate the JIRA connection
    jira_obj = None if args.offline else JIRA(server=JIRA_SERVER, max_retries=0, basic_auth=auth)

    ticket_infos = RecordsList(
        [get_ticket_info(ticket_id, jira=jira_obj) for ticket_id in ticket_ids]
    )

    if args.cache_file:
        ticket_infos.save(args.cache_file)

    type_names = ticket_infos.get_types()
    for type_name in type_names:
        print(f"{type_name}")
        type_data = ticket_infos.filter("issue_type", type_name)
        type_data.sort(key=lambda x: x.component)
        for item in type_data:
            prelude = f"{item.issue_id} - " if args.include_id else ""
            print(f"  {prelude}[{item.component}] {item.summary}")


if __name__ == "__main__":
    main()
