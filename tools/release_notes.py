#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Release Notes generation utilities.

This module provides functionality for automatically generating release notes
by analyzing Git commit messages and extracting JIRA ticket information.
"""

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
    """Release Notes Parameters container.

    This NamedTuple holds all configuration parameters required for generating
    release notes, including version range, output options, and authentication
    settings for repository access.
    """

    since: str
    till: str
    include_id: bool
    log_level: int
    cache_file: Optional[str]
    offline: bool
    netrc: bool
    user: Optional[str]


class TicketRecord(NamedTuple):
    """JIRA Ticket Record for release notes generation.

    This NamedTuple represents a standardized ticket record extracted from JIRA issues,
    containing essential information needed for generating release notes. It provides
    a simplified and consistent interface for handling ticket data across different
    JIRA issue types and configurations.
    """

    issue_id: str
    issue_type: str
    summary: str
    component: str

    @staticmethod
    def from_jira_issue(issue: Issue) -> "TicketRecord":
        """Convert JIRA Issue into TicketRecord.

        Creates a TicketRecord instance from a JIRA Issue object, extracting relevant
        fields and normalizing issue types and component information. Issue types are
        unified where 'Bug' becomes 'Bugfix' and all others become 'Task'. If no
        component is assigned, 'N/A' is used as default.

        :param issue: JIRA Issue object to convert.
        :return: TicketRecord instance with extracted issue information.
        """
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
    """SPSDK JIRA ticket records collection.

    This class extends the built-in list to provide specialized functionality
    for managing and manipulating collections of JIRA ticket records. It offers
    filtering, attribute extraction, and persistence capabilities for release
    note generation workflows.
    """

    def get_components(self) -> list[str]:
        """Get component names from data.

        Retrieves a list of all unique component names found in the release notes data
        by extracting the 'component' attribute from all entries.

        :return: List of component names extracted from the data.
        """
        return self.get_attributes("component")

    def get_types(self) -> list[str]:
        """Get issue type names from data.

        Retrieves a list of all unique issue type names that are present
        in the collected data.

        :return: List of issue type names found in the data.
        """
        return self.get_attributes("issue_type")

    def get_attributes(self, attribute_name: str) -> list[str]:
        """Get all unique attributes with specified name from collection items.

        Extracts the specified attribute from each item in the collection, removes duplicates,
        and returns them in sorted order.

        :param attribute_name: Name of the attribute to extract from each item.
        :raises AttributeError: If any item in the collection doesn't have the specified attribute.
        :return: Sorted list of unique attribute values.
        """
        group = [getattr(item, attribute_name) for item in self]
        return sorted(list(set(group)))

    def filter(self, attrib_name: str, attrib_value: str) -> "RecordsList":
        """Filter records based on attribute name and its value.

        Creates a new RecordsList containing only the records where the specified
        attribute matches the given value.

        :param attrib_name: Name of the attribute to filter by.
        :param attrib_value: Value that the attribute must match.
        :raises AttributeError: If the specified attribute does not exist on record items.
        :return: New RecordsList containing filtered records.
        """
        return RecordsList([item for item in self if getattr(item, attrib_name) == attrib_value])

    def save(self, file_path: str) -> None:
        """Save ticket records to a JSON file for later reuse or inspection.

        The method serializes all ticket records in the collection to a JSON file
        with proper formatting and UTF-8 encoding.

        :param file_path: Path to the output JSON file where data will be saved.
        :raises OSError: If the file cannot be created or written to.
        :raises PermissionError: If there are insufficient permissions to write the file.
        """
        # to load data back, use object_hook=lambda x: TicketRecord(**x)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump([x._asdict() for x in self], f, indent=2)

    @classmethod
    def load(cls, file_path: str) -> "RecordsList":
        """Load previously saved RecordsList from a JSON file.

        This method deserializes a JSON file containing ticket records and reconstructs
        a RecordsList instance with the loaded data.

        :param file_path: Path to the JSON file containing the saved records.
        :raises FileNotFoundError: If the specified file does not exist.
        :raises json.JSONDecodeError: If the file contains invalid JSON data.
        :raises TypeError: If the JSON data cannot be converted to TicketRecord objects.
        :return: New RecordsList instance populated with loaded ticket records.
        """
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f, object_hook=lambda x: TicketRecord(**x))
        return cls(data)


def parse_inputs(input_args: Optional[list[str]] = None) -> RNParams:
    """Parse command line arguments for release notes generation.

    This function sets up and processes command line arguments for the release notes
    utility, including Git commit range specification, JIRA authentication options,
    output formatting preferences, and caching configuration.

    :param input_args: Optional list of command line arguments to parse. If None,
                      arguments are taken from sys.argv.
    :return: Parsed parameters as RNParams object containing all configuration options.
    """
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
    """Get git commit messages between two commits or tags.

    Retrieves commit messages from git log using the specified range delimited
    by since and till commit-ids or tags.

    :param since: Starting commit-id or tag for the range.
    :param till: Ending commit-id or tag for the range.
    :raises subprocess.CalledProcessError: Git command execution failed.
    :return: Git commit messages as a string with newline separators.
    """
    logging.info("Getting git information")
    cmd = f'git log --pretty="%s" {since}..{till}'
    logging.debug(f"Running: {cmd}")
    output = subprocess.check_output(cmd.split()).decode("utf-8")
    logging.debug(f"Git output:\n{output}")
    return output


def get_jira_ids(git_output: str) -> list[str]:
    """Parse text for JIRA ticket IDs using the configured regex pattern.

    Extracts and deduplicates JIRA ticket identifiers from git commit messages
    or other text input. The extraction pattern is defined by TICKET_REGEX constant.

    :param git_output: Text content to search for JIRA ticket IDs, typically git log output.
    :return: Sorted list of unique JIRA ticket IDs found in the input text.
    """
    logging.info("Extracting JIRA ticket ids from commit messages")
    ids = re.findall(TICKET_REGEX, git_output)
    ids = sorted(list(set(ids)))
    logging.debug(f"JIRA ids found: {ids}")
    return ids


def ticket_info_hasher(args: tuple, kwargs: dict) -> str:
    """Generate MD5 hash for ticket information arguments.

    Helper function providing hash value of arguments for `get_ticket_info` function.
    To optimize persistent caching, we need function with consistent return values.
    As the built-in hash function doesn't compute same values across multiple runs,
    we use MD5 hashing.

    :param args: Positional arguments tuple containing ticket information.
    :param kwargs: Keyword arguments dictionary that may contain 'ticket' key.
    :return: MD5 hash string of the ticket parameter.
    """
    to_hash: str = kwargs["ticket"] if "ticket" in kwargs else args[0]
    digest = hashes.Hash(hashes.MD5())  # nosec
    digest.update(to_hash.encode("utf-8"))
    digest_string = digest.finalize().hex()
    logging.debug(f"cache param hashing: {to_hash} -> {digest_string}")
    return digest_string


@cachier(hash_func=ticket_info_hasher)
def get_ticket_info(ticket: str, jira: Optional[JIRA]) -> TicketRecord:
    """Extract ticket information from JIRA.

    The @cachier decorator produces persistent cache to alleviate load on JIRA server.

    :param ticket: JIRA ticket identifier to fetch information for.
    :param jira: JIRA instance for API communication, None for offline mode.
    :raises SPSDKError: When JIRA instance is None and ticket info is not pre-recorded.
    :return: Ticket record containing extracted JIRA issue information.
    """
    if not jira:
        raise SPSDKError(f"Info for {ticket} is not pre-recorded, can't work in offline mode")
    logging.info(f"Fetching info for ticket: {ticket}")
    issue = jira.issue(ticket)
    return TicketRecord.from_jira_issue(issue=issue)


def main() -> None:
    """Main entry point for the release notes generation tool.

    Parses command line arguments, retrieves commit messages from Git repository,
    extracts JIRA ticket IDs, fetches ticket information (online or offline mode),
    and generates formatted release notes grouped by issue type and component.
    The function handles authentication for JIRA access either through username/password
    or .netrc file, supports offline mode using cached data, and outputs release notes
    in a structured format.

    :raises SystemExit: When no tickets are found in commit messages or when .netrc
        file is missing but netrc authentication is selected.
    """
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
