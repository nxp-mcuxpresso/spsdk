#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test various command options."""


from collections import defaultdict
import logging
from typing import Callable, Dict, Iterator, List, Tuple, Union

import click

from spsdk.apps.spsdk_apps import main as spsdk_main


def gather(
    group: Union[click.Group, click.Command], func: Callable, command_name: str = "", excluded_commands: List[str] = None
) -> Iterator[bool]:
    if isinstance(group, click.Group):
        for name in sorted(group.commands):
            if excluded_commands and name in excluded_commands:
                continue
            sub_group = group.commands[name]
            next_level = f"{command_name} {name}" if command_name else name
            yield from gather(group=sub_group, func=func, command_name=next_level)
    elif isinstance(group, click.Command):
        yield from func(group=group, command_name=command_name)


def test_get_template_has_force():
    def get_template_has_force(group: click.Command, command_name: str) -> bool:
        if group.name.startswith("get-template"):
            result = any(param.name == "force" for param in group.params)
            logging.debug(f"Checking command: {command_name} -> {result}")
            yield result

    results = gather(group=spsdk_main, func=get_template_has_force, excluded_commands=["blhost", "sdphost", "sdpshost", "dk6prog"])
    assert all(results)


def test_templates_to_dirs():
    def templates_to_dirs(group: click.Command, command_name: str) -> str:
        if group.name in ["get-template", "get-templates"]:
            output: click.Option = next(filter(lambda x: x.name == "output", group.params))
            is_dir = output.type.dir_okay == True and output.type.file_okay == False
            result = (group.name == "get-templates" and is_dir) or (
                group.name == "get-template" and not is_dir
            )
            logging.debug(f"Checking command: {command_name} -> {result}")
            yield result

    results = gather(group=spsdk_main, func=templates_to_dirs, excluded_commands=["blhost", "sdphost", "sdpshost", "dk6prog"])
    assert all(results)


def get_option_names(command: click.Command) -> Dict[str, List[click.Option]]:
    """Get all option names for a command.

    Args:
        command: The command to get options from

    Returns:
        Dictionary mapping option names to the options
    """
    option_map = defaultdict(list)

    for param in command.params:
        if isinstance(param, click.Option):
            # Get all short and long option names
            for opt in param.opts:
                # Extract just the option name without dashes
                clean_opt = opt.lstrip('-')
                option_map[clean_opt].append(param)

    return option_map

def test_no_conflicting_options():
    """Test that there are no conflicting options in any command."""
    def conflicting_options(group: click.Command, command_name: str):
        conflicts = []

        option_map = get_option_names(group)

        # Find options with multiple definitions
        for opt_name, options in option_map.items():
            if len(options) > 1:
                option_details = [
                    f"{opt.name} ({', '.join(opt.opts)})"
                    for opt in options
                ]
                conflicts.append(
                    f"Command '{command_name}' has conflicting option '{opt_name}' used by: {', '.join(option_details)}"
                )
        yield conflicts
    conflicts = list(gather(group=spsdk_main, func=conflicting_options))
    conflicts = [item for sublist in conflicts for item in sublist]
    assert not conflicts, f"Found {len(conflicts)} option conflicts"

