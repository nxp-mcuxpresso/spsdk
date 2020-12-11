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
from typing import Any

import click

from spsdk import __version__ as spsdk_version
from .blhost import main as blhost_main
from .elftosb import main as elftosb_main
from .nxpdebugmbox import main as nxpdebugmbox_main
from .nxpkeygen import main as nxpkeygen_main
from .pfr import main as pfr_main
from .sdphost import main as sdphost_main
from .sdpshost import main as sdpshost_main
from .utils import catch_spsdk_error


@click.group()
@click.version_option(spsdk_version, '--version')
def main() -> int:
    """Main entry point for all SPSDK applications."""
    return 0


main.add_command(blhost_main, name='blhost')
main.add_command(sdphost_main, name='sdphost')
main.add_command(sdpshost_main, name='sdpshost')
main.add_command(pfr_main, name='pfr')
main.add_command(nxpkeygen_main, name='nxpkeygen')
main.add_command(nxpdebugmbox_main, name='nxpdebugmbox')
main.add_command(elftosb_main, name='elftosb')


@catch_spsdk_error
def safe_main() -> Any:
    """Call the main function."""
    sys.exit(main())


if __name__ == "__main__":
    safe_main()  # pragma: no cover   # pylint: disable=no-value-for-parameter
