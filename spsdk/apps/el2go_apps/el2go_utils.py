#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK EL2GO utility commands for device provisioning and management.

This module provides command-line utilities for interacting with EL2GO (EdgeLock 2GO)
services, including connection testing, version retrieval, and OTP binary generation
for secure device provisioning.
"""

import click

from spsdk.apps.el2go_apps.common import el2go_fw_interface
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_config_option,
    spsdk_output_option,
)
from spsdk.el2go.api_utils import EL2GOTPClient, get_el2go_otp_binary
from spsdk.el2go.interface import EL2GOInterfaceHandler
from spsdk.fuses.fuses import Fuses
from spsdk.utils.config import Config
from spsdk.utils.misc import write_file


@click.group(name="utils", cls=CommandsTreeGroup)
def utils_group() -> None:
    """Group of sub-commands related to EdgeLock 2GO Product-based provisioning."""


@utils_group.command(name="test-connection", no_args_is_help=True)
@spsdk_config_option()
def test_connection_command(config: Config) -> None:
    """Test connection with EdgeLock 2GO."""
    test_connection(config=config)


def test_connection(config: Config) -> None:
    """Test connection with EdgeLock 2GO."""
    EL2GOTPClient.load_from_config(config).test_connection()
    click.echo("12NC and Device Group tested successfully")


@utils_group.command(name="get-fw-version", no_args_is_help=True)
@el2go_fw_interface
def get_version_command(interface: EL2GOInterfaceHandler) -> None:
    """Return EdgeLock 2GO NXP Provisioning Firmware's version."""
    click.echo(f"Firmware version: {interface.get_version()}")


@utils_group.command(name="get-otp-binary", no_args_is_help=True)
@spsdk_config_option(klass=Fuses)
@spsdk_output_option(force=True)
def get_otp_binary_command(config: Config, output: str) -> None:
    """Generate EL2GO OTP Binary from data in configuration file."""
    get_otp_binary(config=config, output=output)


def get_otp_binary(config: Config, output: str) -> None:
    """Generate EL2GO OTP Binary from data in configuration file."""
    data = get_el2go_otp_binary(config)
    write_file(data=data, path=output, mode="wb")
    click.echo(f"EL2GO OTP Binary stored into {output}")
