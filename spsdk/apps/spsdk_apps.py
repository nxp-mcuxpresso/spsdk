#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
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
from spsdk.apps.utils.common_cli_options import CommandsTreeGroup
from spsdk.exceptions import SPSDKError

from .blhost import main as blhost_main
from .dk6prog import main as dk6prog_main
from .ifr import main as ifr_main
from .nxpcrypto import main as nxpcrypto_main
from .nxpdebugmbox import main as nxpdebugmbox_main
from .nxpdevhsm import main as nxpdevhsm_main
from .nxpdevscan import main as nxpdevscan_main
from .nxpele import main as nxpele_main
from .nxpimage import main as nxpimage_main
from .pfr import main as pfr_main
from .sdphost import main as sdphost_main
from .sdpshost import main as sdpshost_main
from .shadowregs import main as shadowregs_main

try:
    TP = True
    from .tpconfig import main as tpconfig_main
    from .tphost import main as tphost_main
except SPSDKError:
    TP = False
from .utils.utils import catch_spsdk_error


@click.group(name="spsdk", no_args_is_help=True, cls=CommandsTreeGroup)
@click.version_option(spsdk_version, "--version")
def main() -> int:
    """Main entry point for all SPSDK applications."""
    return 0


main.add_command(blhost_main, name="blhost")
main.add_command(ifr_main, name="ifr")
main.add_command(nxpcrypto_main, name="nxpcrypto")
main.add_command(nxpdebugmbox_main, name="nxpdebugmbox")
main.add_command(nxpdevscan_main, name="nxpdevscan")
main.add_command(nxpdevhsm_main, name="nxpdevhsm")
main.add_command(nxpele_main, name="nxpele")
main.add_command(nxpimage_main, name="nxpimage")
main.add_command(pfr_main, name="pfr")
main.add_command(sdphost_main, name="sdphost")
main.add_command(sdpshost_main, name="sdpshost")
main.add_command(shadowregs_main, name="shadowregs")
main.add_command(dk6prog_main, name="dk6prog")

if TP:
    main.add_command(tpconfig_main, name="tpconfig")
    main.add_command(tphost_main, name="tphost")
else:
    click.echo(
        "Please install SPSDK with pip install 'spsdk[tp]' in order to use tphost and tpconfig apps"
    )


@catch_spsdk_error
def safe_main() -> Any:
    """Call the main function."""
    sys.exit(main())


if __name__ == "__main__":
    safe_main()  # pylint: disable=no-value-for-parameter
