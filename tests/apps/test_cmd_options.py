#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK command-line interface options testing utilities.

This module provides comprehensive testing functionality for SPSDK CLI applications,
focusing on command option validation, template handling, and option conflict detection.
"""


import logging
from collections import defaultdict
from typing import Callable, Generator, Iterator, Optional, Union

import click

from spsdk.apps.spsdk_apps import main as spsdk_main


def gather(
    group: Union[click.Group, click.Command],
    func: Callable,
    command_name: str = "",
    excluded_commands: Optional[list[str]] = None,
) -> Iterator[bool]:
    """Recursively gather and process Click commands from a command group.

    This method traverses a Click command hierarchy, applying a given function to each
    command while optionally excluding specified commands from processing.

    :param group: Click Group or Command object to traverse and process.
    :param func: Callable function to apply to each discovered command.
    :param command_name: Current command path name for tracking hierarchy.
    :param excluded_commands: List of command names to skip during traversal.
    :return: Iterator yielding boolean results from the applied function.
    """
    if isinstance(group, click.Group):
        for name in sorted(group.commands):
            if excluded_commands and name in excluded_commands:
                continue
            sub_group = group.commands[name]
            next_level = f"{command_name} {name}" if command_name else name
            yield from gather(group=sub_group, func=func, command_name=next_level)
    elif isinstance(group, click.Command):
        yield from func(group=group, command_name=command_name)


def test_get_template_has_force() -> None:
    """Test that all get-template commands have a force parameter.

    This test verifies that every command starting with "get-template" includes
    a 'force' parameter option. It uses a generator function to check each
    command's parameters and ensures all get-template commands are consistent
    in providing the force option.
    """

    def get_template_has_force(
        group: click.Command, command_name: str
    ) -> Generator[bool, None, None]:
        """Check if a click command group has a 'force' parameter and is a get-template command.

        This function examines a click command group to determine if it starts with "get-template"
        and contains a parameter named "force". It yields a boolean result indicating whether
        both conditions are met.

        :param group: The click command group to examine for force parameter.
        :param command_name: Name of the command being checked (used for logging).
        :return: Generator yielding boolean indicating if command has force parameter.
        """
        if group.name and group.name.startswith("get-template"):
            result = any(param.name == "force" for param in group.params)
            logging.debug(f"Checking command: {command_name} -> {result}")
            yield result

    results = gather(
        group=spsdk_main,
        func=get_template_has_force,
        excluded_commands=["blhost", "sdphost", "sdpshost", "dk6prog"],
    )
    assert all(results)


def test_templates_to_dirs() -> None:
    """Test that template commands have correct directory/file output configurations.

    This test verifies that 'get-templates' commands are configured to accept only
    directories as output, while 'get-template' commands are configured to accept
    only files as output. It uses a nested function to check each command's output
    parameter configuration and validates the results across the SPSDK command suite.

    :raises AssertionError: When template commands have incorrect output configurations.
    """

    def templates_to_dirs(group: click.Command, command_name: str) -> Generator[bool, None, None]:
        """Check if template commands have correct output directory configuration.

        This method validates that 'get-template' and 'get-templates' commands have
        appropriate output parameter configurations. For 'get-templates', the output
        should be directory-only, while for 'get-template', it should allow files.

        :param group: Click command group to analyze for template output configuration.
        :param command_name: Name of the command being checked for logging purposes.
        :return: Generator yielding boolean indicating if command has correct output configuration.
        """
        if group.name in ["get-template", "get-templates"]:
            output = next(filter(lambda x: x.name == "output", group.params))
            if (
                isinstance(output, click.Option)
                and hasattr(output.type, "dir_okay")
                and hasattr(output.type, "file_okay")
            ):
                is_dir = output.type.dir_okay and not output.type.file_okay
                result = (group.name == "get-templates" and is_dir) or (
                    group.name == "get-template" and not is_dir
                )
                logging.debug(f"Checking command: {command_name} -> {result}")
                yield result

    results = gather(
        group=spsdk_main,
        func=templates_to_dirs,
        excluded_commands=["blhost", "sdphost", "sdpshost", "dk6prog"],
    )
    assert all(results)


def get_option_names(command: click.Command) -> dict[str, list[click.Option]]:
    """Get all option names for a command.

    Extracts and maps all short and long option names from a Click command's parameters,
    removing the leading dashes for clean option name identification.

    :param command: The Click command to extract options from.
    :return: Dictionary mapping clean option names (without dashes) to list of corresponding Click Option objects.
    """
    option_map = defaultdict(list)

    for param in command.params:
        if isinstance(param, click.Option):
            # Get all short and long option names
            for opt in param.opts:
                # Extract just the option name without dashes
                clean_opt = opt.lstrip("-")
                option_map[clean_opt].append(param)

    return option_map


def test_no_conflicting_options() -> None:
    """Test that there are no conflicting options in any command.

    This test function validates that no SPSDK command has duplicate or conflicting
    option definitions. It iterates through all commands and their options to detect
    cases where the same option name is defined multiple times within a single command,
    which would cause CLI parsing issues.

    :raises AssertionError: When conflicting options are found in any command.
    """

    def conflicting_options(
        group: click.Command, command_name: str
    ) -> Generator[list[str], None, None]:
        """Find conflicting command line options in a Click command.

        This method analyzes a Click command to identify options that have conflicting names
        or definitions, which could cause ambiguity or errors in command line parsing.

        :param group: The Click command to analyze for conflicting options.
        :param command_name: Name of the command being analyzed for error reporting.
        :return: Generator yielding lists of conflict descriptions as strings.
        """
        conflicts = []

        option_map = get_option_names(group)

        # Find options with multiple definitions
        for opt_name, options in option_map.items():
            if len(options) > 1:
                option_details = [f"{opt.name} ({', '.join(opt.opts)})" for opt in options]
                conflicts.append(
                    f"Command '{command_name}' has conflicting option '{opt_name}' used by: {', '.join(option_details)}"
                )
        yield conflicts

    conflicts_gen = gather(group=spsdk_main, func=conflicting_options)
    conflicts = [item for sublist in conflicts_gen for item in sublist]  # type: ignore
    assert not conflicts, f"Found {len(conflicts)} option conflicts"
