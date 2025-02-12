#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Tool for converting C-code TrustZone data into YAML config file."""

import logging
import re
import sys
from datetime import datetime

import click
import yaml

regex = re.compile(r"\s+(?P<value>[x0-9a-fA-F]+).*// ?(?P<name>\w+);\s+/[!<\* ]+(?P<desc>[^\*]+).*")


def parse_c(code: str) -> dict[str, str]:
    """Extract TrustZone settings from the code."""
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
def main(c_file: str, output: str, debug: bool) -> None:
    """Extract TrustZone settings from the C code."""
    logging.basicConfig(level=logging.DEBUG if debug else logging.WARNING)
    with open(c_file, encoding="utf-8") as f:
        code = f.read()

    tz_data = parse_c(code=code)

    click.echo(f"Found {len(tz_data)} registers")

    with open(output, "w", encoding="utf-8") as f:
        f.writelines(
            [
                f"# Copyright {datetime.now().year} NXP\n",
                "\n",
                "# SPDX-License-Identifier: BSD-3-Clause\n",
                "\n",
            ]
        )
        yaml.safe_dump(tz_data, f, indent=4, sort_keys=False)
    click.echo(f"Output written to: {output}")


if __name__ == "__main__":
    sys.exit(main())  # pylint: disable=no-value-for-parameter
