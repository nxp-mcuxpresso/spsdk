#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for el2go."""

import logging
import os
import sys

import click

from spsdk.apps.blhost_helper import display_output
from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_mboot_interface,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import INT, SPSDKAppError, catch_spsdk_error
from spsdk.el2go.api_utils import EL2GOTPClient, GenStatus
from spsdk.mboot.mcuboot import McuBoot, StatusCode
from spsdk.mboot.properties import PropertyTag
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.utils.misc import load_configuration, write_file

# use the same set of interfaces for all commands
el2go_fw_interface = spsdk_mboot_interface(lpcusbsio=False, sdio=False, can=False, plugin=False)


def extract_device_id(uuid_list: list) -> str:
    """Format UID to be accepted by EdgeLock 2GO API."""
    response_uuid = ""
    for x in uuid_list:
        response_uuid += f"{(x >> 0) & 0xFF:02x}{(x >> 8) & 0xFF:02x}{(x >> 16) & 0xFF:02x}{(x >> 24) & 0xFF:02x}"
    response_uuid = str(int(response_uuid, 16))
    return response_uuid


@click.group(name="el2go", cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> int:
    """Use EdgeLock 2GO service to provision a device."""
    log_level = log_level or logging.WARNING
    spsdk_logger.install(level=log_level)
    return 0


@main.command(name="get-fw-version", no_args_is_help=True)
@el2go_fw_interface
def get_version(interface: MbootProtocolBase) -> None:
    """Return EdgeLock 2GO NXP Provisioning Firmware's version."""
    with McuBoot(interface=interface) as mboot:
        version_list = mboot.el2go_get_version()
    if not version_list:
        raise SPSDKAppError(f"Unable to get FW version. Error: {mboot.status_string}")

    display_output(version_list, mboot.status_code)
    if mboot.status_code == StatusCode.SUCCESS:
        version = "{}".format(", ".join(hex(x) for x in version_list))
        version = "v" + version[2] + "." + version[3:5] + "." + version[5:7]
        click.echo(f"Firmware version: {version}")


@main.command(name="close-device", no_args_is_help=True)
@click.argument("address", type=INT(), required=True)
@click.option(
    "-d",
    "--dry-run",
    is_flag=True,
    default=False,
    help=("Enable Provisioning Firmware dry run, meaning that no fuses will be burned "),
)
@el2go_fw_interface
def close_device(
    interface: MbootProtocolBase,
    address: int,
    dry_run: bool,
) -> None:
    """Launch EdgeLock 2GO NXP Provisioning Firmware.

    By using EdgeLock 2GO Secure Object's stored
    in Flash memory:

    1. Device's lifecycle will be advanced to In-field/Closed or In-field Locked/Closed/Locked based on the lifecycle
    state associated with the Secure Objects downloaded from the EdgeLock 2GO server.

    2. Device will be moved to Secure state.

    3. OEM FW Authentication Key Hash will be provisioned.

    4. OEM FW Decryption Key will be provisioned.

    5. Desired OTP fuses will be provisioned using OTP Configuration Data.

    ADDRESS is the FLASH memory address where Secure Objects are stored.

    When -d/--dry-run flag is used, the device will not be provisioned
    and remain in the same status as before. Only, EdgeLock 2GO Secure Object's
    and correct setup will be verified.

    """
    with McuBoot(interface) as mboot:
        response = mboot.el2go_close_device(address, dry_run)
        display_output([response], mboot.status_code)
        if not response:
            raise SPSDKAppError("Closing the device failed.")
        if mboot.status_code == StatusCode.SUCCESS:
            if response == StatusCode.EL2GO_PROV_SUCCESS.tag:
                click.echo("Device has been successfully provisioned.")
            else:
                click.echo(f"Provision of device has failed with error code: {response:#x}.")


@main.command(name="get-secure-objects", no_args_is_help=True)
@spsdk_config_option()
@spsdk_output_option(force=True)
@el2go_fw_interface
def get_secure_objects(interface: MbootProtocolBase, config: str, output: str) -> None:
    """Download EdgeLock 2GO Secure objects generated for the device attached.

    To generate a template of the configuration file required as input,
    get-template command can be used.

    Inside configuration file the values below should be defined:

    - EdgeLock 2GO API key

    - Device Group id

    - Hardware's 12NC code
    """
    config_data = load_configuration(path=config)
    search_path = os.path.dirname(config)
    client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

    with McuBoot(interface) as mboot:
        uuid_list = mboot.get_property(PropertyTag.UNIQUE_DEVICE_IDENT)
        if not uuid_list:
            raise SPSDKAppError(f"Unable to get UUID. Error: {mboot.status_string}")

    device_id = extract_device_id(uuid_list=uuid_list)

    client.assign_device_to_devicegroup(device_id=device_id)
    data = client.download_secure_objects(device_id=device_id)
    if isinstance(data, GenStatus):
        raise SPSDKAppError(f"Secure objects download failed. Status: {data.value[0]}")
    write_file(data=data, path=output, mode="wb")
    click.echo(f"Secure Objects stored to {output}")


@main.command(name="get-template", no_args_is_help=True)
@spsdk_family_option(families=EL2GOTPClient.get_supported_families())
@spsdk_output_option(force=True)
def get_template(family: str, output: str) -> None:
    """Get template for the configuration file used in get-secure-objects command."""
    yaml_data = EL2GOTPClient.generate_config_template(family=family)
    write_file(data=yaml_data, path=output)
    click.echo(f"Creating {output} template file.")


@main.command(name="test-connection", no_args_is_help=True)
@spsdk_config_option()
def test_connection(config: str) -> None:
    """Test connection with EdgeLock 2GO."""
    config_data = load_configuration(path=config)
    search_path = os.path.dirname(config)
    client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

    client.test_connection()
    click.echo("Connection established successfully")


@catch_spsdk_error
def safe_main() -> None:
    """Calls the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
