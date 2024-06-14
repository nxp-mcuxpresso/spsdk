#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to covert XML style of register description to new JSON style."""

import logging
import os
import sys
from typing import List, Optional

import click

from spsdk.apps.utils.common_cli_options import spsdk_apps_common_options
from spsdk.apps.utils.utils import SPSDKAppError, catch_spsdk_error
from spsdk.utils.misc import Endianness
from spsdk.utils.registers import Registers

logger = logging.getLogger(__name__)


def get_all_files(source: str) -> List[str]:
    """Gather all python files in root_folders."""
    all_files = []

    if os.path.isfile(source):
        all_files.append(source)
    else:
        for root, _, file_names in os.walk(
            source,
        ):
            for file_name in file_names:
                ext = os.path.splitext(file_name)[1]
                if ext and ext in (".xml"):
                    all_files.append(os.path.join(root, file_name))
    return all_files


def convert_xml_to_json(xml: str, json: Optional[str] = None) -> None:
    """Convert XML file to JSON.

    :param xml: Path to XML
    :param json: Path to result Json
    """
    print(f"Converting {xml}")
    regs = Registers(family="General", feature="test", base_endianness=Endianness.LITTLE)
    regs.load_registers_from_xml(xml)
    if json == None:
        json = xml.replace(".xml", ".json")
    assert json
    regs.write_spec(json)

    # Validation
    regs2 = Registers(family="General", feature="test", base_endianness=Endianness.LITTLE)
    regs2._load_spec(json)
    if regs2 != regs:
        raise SPSDKAppError(f"Cannot convert {xml}")


@click.command()
@click.option("-x", "--xml", type=str, required=True)
@click.option("-j", "--json", type=str)
@spsdk_apps_common_options
def main(xml: str, json: str, log_level: int) -> int:
    """Main CLI function."""
    logging.basicConfig(level=log_level or logging.WARNING)
    if not os.path.exists(xml):
        raise SPSDKAppError("Input path doesn't exists")
    if os.path.isdir(xml):
        all_xmls = get_all_files(xml)
        for xml_file in all_xmls:
            convert_xml_to_json(xml=xml_file)
    else:
        convert_xml_to_json(xml, json)

    return 0


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
