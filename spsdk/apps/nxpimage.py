#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""NXP MCU Image tool."""
import logging
import sys

import click

from spsdk.apps.nxpimage_apps.nxpimage_ahab import ahab_group
from spsdk.apps.nxpimage_apps.nxpimage_bca import bca_group
from spsdk.apps.nxpimage_apps.nxpimage_bee import bee_group
from spsdk.apps.nxpimage_apps.nxpimage_bimg import bootable_image_group
from spsdk.apps.nxpimage_apps.nxpimage_cert_block import cert_block_group
from spsdk.apps.nxpimage_apps.nxpimage_fcf import fcf_group
from spsdk.apps.nxpimage_apps.nxpimage_hab import hab_group
from spsdk.apps.nxpimage_apps.nxpimage_iee import iee_group
from spsdk.apps.nxpimage_apps.nxpimage_lpcprog import lpcprog_group
from spsdk.apps.nxpimage_apps.nxpimage_mbi import mbi_group
from spsdk.apps.nxpimage_apps.nxpimage_otfad import otfad_group
from spsdk.apps.nxpimage_apps.nxpimage_sb import sb21_group, sb31_group
from spsdk.apps.nxpimage_apps.nxpimage_signed_msg import signed_msg_group
from spsdk.apps.nxpimage_apps.nxpimage_trustzone import tz_group
from spsdk.apps.nxpimage_apps.nxpimage_utils import nxpimage_utils_group
from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import CommandsTreeGroup, spsdk_apps_common_options
from spsdk.apps.utils.utils import catch_spsdk_error

logger = logging.getLogger(__name__)


@click.group(name="nxpimage", cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> None:
    """NXP Image tool.

    Manage various kinds of images for NXP parts.
    """
    spsdk_logger.install(level=log_level)


main.add_command(ahab_group)
main.add_command(cert_block_group)
main.add_command(mbi_group)
main.add_command(sb21_group)
main.add_command(sb31_group)
main.add_command(hab_group)
main.add_command(bca_group)
main.add_command(fcf_group)
main.add_command(lpcprog_group)
main.add_command(bootable_image_group)
main.add_command(nxpimage_utils_group)
main.add_command(iee_group)
main.add_command(bee_group)
main.add_command(tz_group)
main.add_command(signed_msg_group)
main.add_command(otfad_group)


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
