#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Wrapper for all spsdk applications.

Its purpose is to provide easier discoverability.
New users may not be aware of all available apps.
"""

import sys

import click

from spsdk import __version__ as spsdk_version

from .blhost import main as blhost_main
from .pfr import main as pfr_main
from .sdphost import main as sdphost_main
from .nxpkeygen import main as nxpkeygen_main
from .nxpdebugmbox import main as nxpdebugmbox_main


@click.group()
@click.version_option(spsdk_version, '--version')
def main() -> int:
    """Main entry point for all SPSDK applications."""
    return 0


main.add_command(blhost_main, name='blhost')
main.add_command(sdphost_main, name='sdphost')
main.add_command(pfr_main, name='pfr')
main.add_command(nxpkeygen_main, name='nxpkeygen')
main.add_command(nxpdebugmbox_main, name='nxpdebugmbox')


if __name__ == "__main__":
    sys.exit(main())    # pragma: no cover  # pylint: disable=no-value-for-parameter
