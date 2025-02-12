#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test various command options."""


import logging
from typing import Callable, Iterator, Union

import click

from spsdk.apps.spsdk_apps import main as spsdk_main


def gather(
    group: Union[click.Group, click.Command], func: Callable, command_name: str = ""
) -> Iterator[bool]:
    if isinstance(group, click.Group):
        for name in sorted(group.commands):
            if name in ["blhost", "sdphost", "sdpshost", "dk6prog"]:
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

    results = gather(group=spsdk_main, func=get_template_has_force)
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

    results = gather(group=spsdk_main, func=templates_to_dirs)
    assert all(results)


def test_export_has_plugin():
    EXPORTS_WITHOUT_PLUGIN = [
        "nxpimage bee export",
        "nxpimage bootable-image fcb export",
        "nxpimage bootable-image xmcd export",
        "nxpimage iee export",
        "nxpimage bca export",
        "nxpimage fcf export",
        "nxpimage otfad export",
        "nxpimage tz export",
        "nxpcrypto rot export",
        "nxpmemcfg export",
    ]

    def export_has_plugin(group: click.Command, command_name: str) -> bool:
        if group.name == "export" and command_name not in EXPORTS_WITHOUT_PLUGIN:
            result = any(param.name == "plugin" for param in group.params)
            logging.debug(f"Checking command: {command_name} -> {result}")
            yield result

    results = gather(group=spsdk_main, func=export_has_plugin)
    assert all(results)
