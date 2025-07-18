#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Common utilities for EdgeLock 2GO applications."""

from typing import Literal

import click

from spsdk.apps.utils.common_cli_options import spsdk_el2go_interface
from spsdk.el2go.api_utils import EL2GOTPClient
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import get_printable_path, write_file

# use the same set of interfaces for all commands
el2go_fw_interface = spsdk_el2go_interface(sdio=False, can=False, plugin=False)
el2go_optional_fw_interface = spsdk_el2go_interface(
    sdio=False, can=False, plugin=False, required=False
)


def get_template(
    family: FamilyRevision, output: str, mode: Literal["device", "product"] = "device"
) -> None:
    """Get template for the configuration file used in other command."""
    yaml_data = EL2GOTPClient.get_config_template(family=family, mode=mode)
    write_file(data=yaml_data, path=output)
    click.echo(
        f"The EL2GO template for {family} has been saved into {get_printable_path(output)} YAML file"
    )


def extract_device_id(uuid_list: list) -> str:
    """Format UID to be accepted by EdgeLock 2GO API."""
    response_uuid = ""
    for x in uuid_list:
        response_uuid += f"{(x >> 0) & 0xFF:02x}{(x >> 8) & 0xFF:02x}{(x >> 16) & 0xFF:02x}{(x >> 24) & 0xFF:02x}"
    response_uuid = str(int(response_uuid, 16))
    return response_uuid
