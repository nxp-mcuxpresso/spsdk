#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK TrustZone configuration converter tool.

This module provides functionality to convert C-code TrustZone data into
YAML configuration files for SPSDK usage. It parses C source files containing
TrustZone register definitions and transforms them into structured YAML format.
"""

import logging
import re
import sys

import click

from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import value_to_int
from spsdk.utils.registers import Register, Registers

regex = re.compile(r"\s+(?P<value>[x0-9a-fA-F]+).*// ?(?P<name>\w+);\s+/[!<\* ]+(?P<desc>[^\*]+).*")


def parse_c(code: str) -> dict[str, str]:
    """Extract TrustZone settings from C code.

    Parses C code line by line to extract TrustZone configuration settings
    using regex pattern matching. Each matched line is converted to a key-value
    pair where the key combines description and name, and value contains the
    setting value.

    :param code: C source code containing TrustZone settings to parse.
    :return: Dictionary mapping setting descriptions with names to their values.
    """
    result = {}
    for line in code.splitlines():
        logging.debug(line)
        if m := regex.match(line):
            logging.debug(f"  {m.groupdict()}")
            key = f"{m.group('desc').replace(':','')} ({m.group('name')})"
            value = m.group("value")
            result[key] = value
        else:
            logging.debug("  Not found")
    return result


@click.command(name="tz2yaml", no_args_is_help=True)
@click.option(
    "-f",
    "--family",
    type=str,
    required=True,
    help="Select the chip family.",
)
@click.option(
    "-r",
    "--revision",
    type=str,
    default="latest",
    required=False,
    help="Chip revision; if not specified, most recent one will be used",
)
@click.option(
    "-c",
    "--c-file",
    type=click.Path(exists=True),
    default="main.c",
    help="Path to TrustZone .c file.",
    required=True,
)
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    default="tz_data.yaml",
    help="Path to output YAML file. (default: tz_data.yaml)",
)
@click.option("-d", "--debug", is_flag=True, default=False, help="Enable more detailed logging.")
def main(family: str, revision: str, c_file: str, output: str, debug: bool) -> None:
    """Extract TrustZone settings from the C code and generate register specification.

    The method parses C code to extract TrustZone register settings, creates a register
    specification with proper offsets and descriptions, and writes the output to a file.

    :param family: Target MCU family name for register specification.
    :param revision: MCU revision identifier.
    :param c_file: Path to the C source file containing TrustZone settings.
    :param output: Output file path for the generated register specification.
    :param debug: Enable debug logging when True, otherwise use warning level.
    :raises FileNotFoundError: If the input C file cannot be found.
    :raises UnicodeDecodeError: If the C file cannot be decoded as UTF-8.
    """
    logging.basicConfig(level=logging.DEBUG if debug else logging.WARNING)
    with open(c_file, encoding="utf-8") as f:
        code = f.read()

    tz_data = parse_c(code=code)

    click.echo(f"Found {len(tz_data)} registers")
    family_c = FamilyRevision(family, revision)
    offset = 0
    regs = Registers(family_c, DatabaseManager.TZ, base_key="invalid", do_not_raise_exception=True)
    for key, val in tz_data.items():
        reg = Register(
            name=key,
            offset=offset,
            width=32,
            uid=f"field{offset:03X}",
            description=f"TrustZone register - {key}",
        )
        reg._default_value = value_to_int(val)
        regs.add_register(reg)
        offset += 4
    regs.write_spec(output)

    click.echo(f"Output written to: {output}")


if __name__ == "__main__":
    sys.exit(main())  # pylint: disable=no-value-for-parameter
