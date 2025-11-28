#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK EdgeLock 2GO command-line interface.

This module provides the main entry point and command structure for the
EdgeLock 2GO application, enabling secure provisioning and device management
functionality through a unified CLI interface.
"""

import copy
import logging
import sys

import click

from spsdk.apps.el2go_apps.el2go_dev import dev_group
from spsdk.apps.el2go_apps.el2go_prod import prod_group
from spsdk.apps.el2go_apps.el2go_utils import utils_group
from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import CommandsTreeGroup, spsdk_apps_common_options
from spsdk.apps.utils.utils import catch_spsdk_error


@click.group(name="el2go-host", cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> int:
    """Use EdgeLock 2GO service to provision a device."""
    log_level = log_level or logging.WARNING
    spsdk_logger.install(level=log_level)
    return 0


def copy_command_to_group(cmd: click.Command) -> None:
    """Copy a command to a group, marking it deprecated and hidden."""
    cmd_copy = copy.deepcopy(cmd)
    cmd_copy.deprecated = True
    cmd_copy.hidden = True
    main.add_command(cmd_copy)


main.add_command(prod_group)

main.add_command(dev_group)
copy_command_to_group(cmd=dev_group.commands["bulk-so-download"])
copy_command_to_group(cmd=dev_group.commands["combine-uuid-db"])
copy_command_to_group(cmd=dev_group.commands["get-secure-objects"])
copy_command_to_group(cmd=dev_group.commands["get-template"])
copy_command_to_group(cmd=dev_group.commands["get-uuid"])
copy_command_to_group(cmd=dev_group.commands["parse-uuid-db"])
copy_command_to_group(cmd=dev_group.commands["prepare-device"])
copy_command_to_group(cmd=dev_group.commands["provision-device"])
copy_command_to_group(cmd=dev_group.commands["provision-objects"])
copy_command_to_group(cmd=dev_group.commands["run-provisioning"])
copy_command_to_group(cmd=dev_group.commands["unclaim"])

main.add_command(utils_group)
copy_command_to_group(cmd=utils_group.commands["get-fw-version"])
copy_command_to_group(cmd=utils_group.commands["get-otp-binary"])
copy_command_to_group(cmd=utils_group.commands["test-connection"])


@catch_spsdk_error
def safe_main() -> None:
    """Calls the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
