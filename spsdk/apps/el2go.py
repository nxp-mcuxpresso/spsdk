#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for el2go."""

import json
import logging
import os
import sys
from typing import Optional

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
from spsdk.apps.utils.utils import SPSDKAppError, SPSDKError, catch_spsdk_error
from spsdk.el2go.api_utils import EL2GOTPClient, get_el2go_otp_binary
from spsdk.el2go.database import SecureObjectsDB
from spsdk.el2go.secure_objects import SecureObjects
from spsdk.mboot.mcuboot import McuBoot, StatusCode, stringify_status_code
from spsdk.mboot.properties import PropertyTag
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.utils.misc import load_binary, load_configuration, write_file

# use the same set of interfaces for all commands
el2go_fw_interface = spsdk_mboot_interface(sdio=False, can=False, plugin=False)


def extract_device_id(uuid_list: list) -> str:
    """Format UID to be accepted by EdgeLock 2GO API."""
    response_uuid = ""
    for x in uuid_list:
        response_uuid += f"{(x >> 0) & 0xFF:02x}{(x >> 8) & 0xFF:02x}{(x >> 16) & 0xFF:02x}{(x >> 24) & 0xFF:02x}"
    response_uuid = str(int(response_uuid, 16))
    return response_uuid


@click.group(name="el2go-host", cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> int:
    """Use EdgeLock 2GO service to provision a device."""
    log_level = log_level or logging.WARNING
    spsdk_logger.install(level=log_level)
    return 0


@main.command(name="get-fw-version", no_args_is_help=True)
@el2go_fw_interface
def get_version_command(interface: MbootProtocolBase) -> None:
    """Return EdgeLock 2GO NXP Provisioning Firmware's version."""
    get_version(interface=interface)


def get_version(interface: MbootProtocolBase) -> None:
    """Return EdgeLock 2GO NXP Provisioning Firmware's version."""
    with McuBoot(interface=interface, cmd_exception=True) as mboot:
        version_list = mboot.el2go_get_version()
    if not version_list:
        raise SPSDKAppError(f"Unable to get FW version. Error: {mboot.status_string}")

    display_output(version_list, mboot.status_code)
    if mboot.status_code == StatusCode.SUCCESS:
        version = "{}".format(", ".join(hex(x) for x in version_list))
        version = "v" + version[2] + "." + version[3:5] + "." + version[5:7]
        click.echo(f"Firmware version: {version}")


@main.command(name="prepare-device", no_args_is_help=True)
@el2go_fw_interface
@spsdk_config_option()
@click.option(
    "-sf",
    "--secure-objects-file",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    help="Path to Secure Objects file created via `get-secure-objects` command",
)
@click.option(
    "-db",
    "--database",
    type=click.Path(exists=True, dir_okay=False),
    help="Use Database of UUIDs and Secure Objects",
)
@click.option(
    "-rdb",
    "--remote-database",
    type=str,
    help="URL to the remote database",
)
@click.option(
    "--clean",
    is_flag=True,
    default=False,
    help="Clean deployed Secure objects from last run (if applicable for given device).",
)
def prepare_device_command(
    interface: MbootProtocolBase,
    config: str,
    secure_objects_file: str,
    database: str,
    remote_database: str,
    clean: bool,
) -> None:
    """Prepare device for Trust Provisioning.

    \b
    1) Get UUID from the target
    2) Download Secure Objects from EL2GO
    3) Upload Secure Objects to the target
    4) Upload OEM TP Firmware
    5) Reset the device which will start the TP FW

    Please note that the memory for Secure Objects and TP FW has to be configured.
    """
    prepare_device(
        interface=interface,
        config=config,
        secure_objects_file=secure_objects_file,
        database=database,
        remote_database=remote_database,
        clean=clean,
    )


def prepare_device(
    interface: MbootProtocolBase,
    config: str,
    secure_objects_file: Optional[str] = None,
    database: Optional[str] = None,
    remote_database: Optional[str] = None,
    clean: bool = False,
) -> None:
    """Prepare device for Trust Provisioning."""
    client = _create_client(config)
    prov_data = _retrieve_secure_objects(
        interface=interface,
        client=client,
        database=database,
        remote_database=remote_database,
        secure_objects_file=secure_objects_file,
    )

    _upload_data(client=client, interface=interface, secure_objects=prov_data, clean=clean)


@main.command(name="run-provisioning", no_args_is_help=True)
@el2go_fw_interface
@spsdk_config_option(required=False)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Do not perform the actual provisioning, just simulate it. Note: not all devices support this feature.",
)
def run_provisioning_command(
    interface: MbootProtocolBase,
    config: str,
    dry_run: bool,
) -> None:
    """Launch EdgeLock 2GO NXP Provisioning Firmware.

    \b
    When --dry-run flag is used, the device will not be provisioned
    and remain in the same status as before. Only, EdgeLock 2GO Secure Object's
    and correct setup will be verified.

    """
    client = _create_client(config)

    _run_provisioning(client=client, interface=interface, dry_run=dry_run)


@main.command(name="get-secure-objects", no_args_is_help=True)
@spsdk_mboot_interface(sdio=False, can=False, plugin=False, required=False)
@spsdk_config_option()
@click.option(
    "-e",
    "--encoding",
    type=click.Choice(["bin", "json"], case_sensitive=False),
    default="bin",
    help="Encoding of the Secure Objects file. Default: bin",
)
@spsdk_output_option(force=True, required=False)
@click.option(
    "-db",
    "--database",
    type=click.Path(exists=True, dir_okay=False),
    help="Use a database as source for UUIDs instead of connected device.",
)
@click.option(
    "-rdb",
    "--remote-database",
    type=str,
    help="URL to the remote database",
)
@click.option(
    "-r",
    "--re-download",
    is_flag=True,
    default=False,
    help="Re-download Secure Objects even if found in database.",
)
@click.option(
    "--re-assign",
    is_flag=True,
    default=False,
    help="Allow re-assignment if a Device is registered in a different Device Group.",
)
@click.option(
    "--continue-on-error",
    is_flag=True,
    default=False,
    help=(
        "Continue donwloading Secure Object in case of an error. "
        "This option has effect only when using a database with multiple UUIDs."
    ),
)
def get_secure_objects_command(
    config: str,
    interface: MbootProtocolBase,
    output: str,
    encoding: str,
    database: str,
    remote_database: str,
    re_download: bool,
    re_assign: bool,
    continue_on_error: bool,
) -> None:
    """Download EdgeLock 2GO Secure objects generated for the device attached.

    To generate a template of the configuration file required as input,
    `get-template` command can be used.
    """
    get_secure_objects(
        config=config,
        interface=interface,
        output=output,
        encoding=encoding,
        database=database,
        remote_database=remote_database,
        re_download=re_download,
        re_assign=re_assign,
        continue_on_error=continue_on_error,
    )


def get_secure_objects(
    config: str,
    interface: Optional[MbootProtocolBase] = None,
    output: Optional[str] = None,
    encoding: str = "bin",
    database: Optional[str] = None,
    remote_database: Optional[str] = None,
    re_download: bool = False,
    re_assign: bool = False,
    continue_on_error: bool = False,
) -> None:
    """Download EdgeLock 2GO Secure objects generated for the device attached."""
    client = _create_client(config)

    if database or remote_database:
        db = SecureObjectsDB.create(file_path=database, host=remote_database)
        total_count = db.get_count(not re_download)
        if total_count == 0:
            click.echo("There are no UUIDs in the database that need Secure Objects download.")
            return
        failures = []
        # exhaust the iterator so DB is ready for inserts below
        uuids = list(db.get_uuids(not re_download))
        click.echo(f"Found {len(uuids)} UUIDs out of {total_count} without Secure Objects")
        # TODO: figure out how to do this in parallel (using multiple UUIDs in one request)
        for uuid in uuids:
            try:
                click.echo(f"Downloading Secure Objects for UUID: {uuid}")
                client.assign_device_to_devicegroup(device_id=uuid, allow_reassignment=re_assign)
                provisionings = client.download_provisionings(device_id=uuid)
                bin_data = client.serialize_provisionings(provisionings)
                db.add_secure_object(uuid=uuid, so=bin_data)
            except SPSDKError as e:
                if not continue_on_error:
                    raise
                failures.append(uuid)
                click.secho(
                    f"Getting Secure Objects failed for UUID: {uuid}. Error: {e.description}",
                    fg="red",
                )
        click.echo(f"Database update completed {'successfully' if not failures else 'with errors'}")
        if failures:
            click.echo("There were problems with downloading Secure Objects for following UUIDs:")
            for uuid in failures:
                click.echo(uuid)
    else:
        if not interface:
            raise SPSDKAppError("Interface to a target must be defined when not using database")
        if not output:
            raise SPSDKAppError("Path to output file must be defined when not using database")
        uuid = _get_uuid(interface=interface)
        client.assign_device_to_devicegroup(device_id=uuid, allow_reassignment=re_assign)
        provisionings = client.download_provisionings(device_id=uuid)

        if encoding.lower() == "bin":
            bin_data = client.serialize_provisionings(provisionings=provisionings)
            write_file(data=bin_data, path=output, mode="wb")
        else:
            json_data = json.dumps(provisionings, indent=2)
            write_file(data=json_data, path=output, mode="w")
        click.echo(f"Secure Objects stored to {output}")


@main.command(name="get-uuid", no_args_is_help=True)
@el2go_fw_interface
@click.option(
    "-db",
    "--database",
    type=click.Path(dir_okay=False),
    help="Use Database of UUIDs and Secure Objects",
)
@click.option(
    "-rdb",
    "--remote-database",
    type=str,
    help="URL to the remote database",
)
def get_uuid_command(interface: MbootProtocolBase, database: str, remote_database: str) -> None:
    """Get UUID from the target and store it in a database."""
    get_uuid(interface=interface, database=database, remote_database=remote_database)


def get_uuid(interface: MbootProtocolBase, database: str, remote_database: str) -> None:
    """Get UUID from the target and store it in a database."""
    uuid = _get_uuid(interface=interface)
    db = SecureObjectsDB.create(file_path=database, host=remote_database)
    result = db.add_uuid(uuid=uuid)
    if result:
        click.echo(f"UUID {uuid} stored in the database")


def _get_uuid(interface: MbootProtocolBase) -> str:
    with McuBoot(interface) as mboot:
        uuid_list = mboot.get_property(PropertyTag.UNIQUE_DEVICE_IDENT)
        if not uuid_list:
            raise SPSDKAppError(f"Unable to get UUID. Error: {mboot.status_string}")
    uuid = extract_device_id(uuid_list=uuid_list)
    return uuid


@main.command(name="provision-objects", no_args_is_help=True)
@el2go_fw_interface
@spsdk_config_option()
@click.option(
    "-sf",
    "--secure-objects-file",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    help="Path to Secure Objects file created via `get-secure-objects` command",
)
@click.option(
    "-db",
    "--database",
    type=click.Path(exists=True, dir_okay=False),
    help="Use Database of UUIDs and Secure Objects",
)
@click.option(
    "-rdb",
    "--remote-database",
    type=str,
    help="URL to the remote database",
)
@click.option(
    "--clean",
    is_flag=True,
    default=False,
    help="Clean deployed Secure objects from last run (if applicable for given device).",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Do not perform the actual provisioning, just simulate it. (if applicable for given device).",
)
def provision_objects_commands(
    interface: MbootProtocolBase,
    config: str,
    secure_objects_file: str,
    database: str,
    remote_database: str,
    clean: bool,
    dry_run: bool,
) -> None:
    """Provision the device with Secure Object blob downloaded from EL2GO via `get-secure-objects` command."""
    provision_objects(
        interface=interface,
        config=config,
        secure_objects_file=secure_objects_file,
        database=database,
        remote_database=remote_database,
        clean=clean,
        dry_run=dry_run,
    )


def provision_objects(
    interface: MbootProtocolBase,
    config: str,
    secure_objects_file: Optional[str] = None,
    database: Optional[str] = None,
    remote_database: Optional[str] = None,
    clean: bool = False,
    dry_run: bool = False,
) -> None:
    """Provision the device with Secure Object blob downloaded from EL2GO via `get-secure-objects` command."""
    client = _create_client(config)

    prepare_device(
        interface=interface,
        config=config,
        secure_objects_file=secure_objects_file,
        database=database,
        remote_database=remote_database,
        clean=clean,
    )

    _run_provisioning(client=client, interface=interface, dry_run=dry_run)


@main.command(name="provision-device", no_args_is_help=True)
@el2go_fw_interface
@spsdk_config_option()
@click.option(
    "-w",
    "--workspace",
    type=click.Path(file_okay=False),
    help="Path to a folder for storing data used during provisioning for debugging purposes.",
)
@click.option(
    "--re-assign",
    is_flag=True,
    default=False,
    help="Allow re-assignment if a Device is registered in a different Device Group.",
)
@click.option(
    "--clean",
    is_flag=True,
    default=False,
    help="Clean deployed Secure objects from last run (if applicable for given device).",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Do not perform the actual provisioning, just simulate it. (if applicable for given device).",
)
def provision_device_command(
    interface: MbootProtocolBase,
    config: str,
    workspace: str,
    re_assign: bool,
    clean: bool,
    dry_run: bool,
) -> None:
    """Perform the full Trust Provisioning of a device in a single run.

    \b
    1) Read UUID from the device
    2) Download Secure Objects from EL2GO
    3) Upload Secure Objects to the target
    4) Upload OEM TP Firmware configuration blob
    5) Start provisioning process using a OEM TP Firmware
    """
    provision_device(
        interface=interface,
        config=config,
        workspace=workspace,
        re_assign=re_assign,
        clean=clean,
        dry_run=dry_run,
    )


def provision_device(
    interface: MbootProtocolBase,
    config: str,
    workspace: Optional[str] = None,
    re_assign: bool = False,
    clean: bool = False,
    dry_run: bool = False,
) -> None:
    """Perform the full Trust Provisioning of a device in a single run."""
    if workspace:
        os.makedirs(workspace, exist_ok=True)

    client = _create_client(config)
    uuid = _get_uuid(interface=interface)
    if workspace:
        write_file(uuid, os.path.join(workspace, "uuid.txt"), mode="w")
    client.assign_device_to_devicegroup(device_id=uuid, allow_reassignment=re_assign)
    provisionings = client.download_provisionings(device_id=uuid)
    if workspace:
        write_file(
            json.dumps(provisionings, indent=2),
            os.path.join(workspace, "provisionings.json"),
            mode="w",
        )
    secure_objects = client.serialize_provisionings(provisionings=provisionings)
    _upload_data(
        client=client,
        interface=interface,
        secure_objects=secure_objects,
        workspace=workspace,
        clean=clean,
    )

    _run_provisioning(client=client, interface=interface, dry_run=dry_run)


def _create_client(config: str) -> EL2GOTPClient:
    config_data = load_configuration(path=config)
    search_path = os.path.dirname(config)
    return EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])


def _retrieve_secure_objects(
    interface: MbootProtocolBase,
    client: EL2GOTPClient,
    database: Optional[str] = None,
    remote_database: Optional[str] = None,
    secure_objects_file: Optional[str] = None,
) -> bytes:
    if database or remote_database:
        db = SecureObjectsDB.create(file_path=database, host=remote_database)
        uuid = _get_uuid(interface=interface)
        prov_data = db.get_secure_object(uuid=uuid)
        if not prov_data:
            raise SPSDKAppError(f"There are no Secure Objects in database for UUID: {uuid}")
    else:
        if not secure_objects_file:
            raise SPSDKAppError("secure-objects-file must be defined when not using database.")
        prov_data = load_binary(path=secure_objects_file)
        try:
            json_data = json.loads(prov_data)
            prov_data = client.serialize_provisionings(provisionings=json_data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return prov_data


def _upload_data(
    client: EL2GOTPClient,
    interface: MbootProtocolBase,
    secure_objects: bytes,
    workspace: Optional[str] = None,
    clean: bool = False,
) -> None:
    if workspace:
        write_file(secure_objects, os.path.join(workspace, "secure_objects.bin"), mode="wb")

    user_config, fw_read_address, user_data_address = client.create_user_config()
    if workspace and user_config:
        write_file(user_config, os.path.join(workspace, "user_config.bin"), mode="wb")

    so_list = SecureObjects.parse(secure_objects)
    so_list.validate(family=client.family)

    with McuBoot(interface=interface, cmd_exception=True) as mboot:
        if clean:
            click.echo("Performing cleanup method")
            client.run_cleanup_method(mboot=mboot)
        if client.use_dispatch_fw:
            click.echo(f"Writing Secure Objects to: {hex(user_data_address)}")
            mboot.write_memory(address=user_data_address, data=secure_objects)
            click.echo("Uploading ProvFW")
            mboot.write_memory(address=client.fw_load_address, data=client.prov_fw)
            click.echo("Resetting the device (Starting Provisioning FW)")
            mboot.reset(reopen=False)
        elif client.use_user_config:
            click.echo(f"Writing User config data to: {hex(fw_read_address)}")
            mboot.write_memory(address=fw_read_address, data=user_config)
            click.echo(f"Writing Secure Objects to: {hex(user_data_address)}")
            mboot.write_memory(address=user_data_address, data=secure_objects)
        elif client.use_data_split:
            internal, external = so_list.split_int_ext()
            if internal:
                if workspace:
                    write_file(internal, os.path.join(workspace, "internal_so.bin"), mode="wb")
                click.echo(f"Writing Internal Secure Objects to: {hex(fw_read_address)}")
                mboot.write_memory(address=fw_read_address, data=internal)
            if external:
                if workspace:
                    write_file(external, os.path.join(workspace, "external_so.bin"), mode="wb")
                click.echo(f"Writing External Secure Objects to: {hex(user_data_address)}")
                mboot.write_memory(address=user_data_address, data=external)
        else:
            raise SPSDKAppError("Unsupported provisioning method")
    click.echo("Secure Objects uploaded successfully")


def _run_provisioning(
    client: EL2GOTPClient,
    interface: MbootProtocolBase,
    dry_run: bool = False,
) -> None:
    with McuBoot(interface=interface, cmd_exception=True) as mboot:
        if client.use_dispatch_fw:
            click.echo("Starting provisioning process")
            status = mboot.el2go_close_device(client.tp_data_address, dry_run=dry_run)
            if status is None:
                raise SPSDKAppError("Provisioning failed. No response from the firmware.")
            if status != StatusCode.EL2GO_PROV_SUCCESS.tag:
                raise SPSDKAppError(
                    f"Provisioning failed with status: {stringify_status_code(status)}"
                )
        else:
            click.echo("Uploading ProvFW (Starting provisioning process)")
            mboot.receive_sb_file(client.prov_fw)
    click.echo("Secure Objects provisioned successfully")


@main.command(name="get-template", no_args_is_help=True)
@spsdk_family_option(families=EL2GOTPClient.get_supported_families())
@spsdk_output_option(force=True)
def get_template_command(family: str, output: str) -> None:
    """Get template for the configuration file used in other command."""
    get_template(family=family, output=output)


def get_template(family: str, output: str) -> None:
    """Get template for the configuration file used in other command."""
    yaml_data = EL2GOTPClient.generate_config_template(family=family)
    write_file(data=yaml_data, path=output)
    click.echo(f"The EL2GO template for {family} has been saved into {output} YAML file")


@main.command(name="test-connection", no_args_is_help=True)
@spsdk_config_option()
def test_connection_command(config: str) -> None:
    """Test connection with EdgeLock 2GO."""
    test_connection(config=config)


def test_connection(config: str) -> None:
    """Test connection with EdgeLock 2GO."""
    config_data = load_configuration(path=config)
    search_path = os.path.dirname(config)
    client = EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])

    client.test_connection()
    click.echo("12NC and Device Group tested successfully")


@main.command(name="get-otp-binary", no_args_is_help=True)
@spsdk_family_option(
    families=EL2GOTPClient.get_supported_families(),
    required=False,
    help="Required only when using SEC Tool's JSON config file.",
)
@spsdk_config_option()
@spsdk_output_option(force=True)
def get_otp_binary_command(config: str, output: str, family: str) -> None:
    """Generate EL2GO OTP Binary from data in configuration file."""
    get_otp_binary(config=config, output=output, family=family)


def get_otp_binary(config: str, output: str, family: Optional[str] = None) -> None:
    """Generate EL2GO OTP Binary from data in configuration file."""
    config_data = load_configuration(path=config)
    data = get_el2go_otp_binary(config_data=config_data, family=family)
    write_file(data=data, path=output, mode="wb")
    click.echo(f"EL2GO OTP Binary stored into {output}")


@catch_spsdk_error
def safe_main() -> None:
    """Calls the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
