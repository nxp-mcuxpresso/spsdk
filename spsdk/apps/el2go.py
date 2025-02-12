#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for el2go."""

import json
import logging
import math
import os
import shlex
import sys
import time
from datetime import datetime, timedelta
from typing import Optional

import click

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_el2go_interface,
    spsdk_family_option,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import SPSDKAppError, SPSDKError, catch_spsdk_error
from spsdk.el2go.api_utils import EL2GOTPClient, get_el2go_otp_binary
from spsdk.el2go.bulk import ServiceDB
from spsdk.el2go.database import SecureObjectsDB
from spsdk.el2go.interface import EL2GOInterfaceHandler
from spsdk.el2go.secure_objects import SecureObjects
from spsdk.utils.misc import load_binary, load_configuration, load_text, write_file

# use the same set of interfaces for all commands
el2go_fw_interface = spsdk_el2go_interface(sdio=False, can=False, plugin=False)
el2go_optional_fw_interface = spsdk_el2go_interface(
    sdio=False, can=False, plugin=False, required=False
)


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
def get_version_command(interface: EL2GOInterfaceHandler) -> None:
    """Return EdgeLock 2GO NXP Provisioning Firmware's version."""
    click.echo(f"Firmware version: {interface.get_version()}")


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
    interface: EL2GOInterfaceHandler,
    config: str,
    secure_objects_file: str,
    database: str,
    remote_database: str,
    clean: bool,
) -> None:
    """Prepare device for Trust Provisioning.

    \b
    0) Execute optional interface preparation step
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
    interface: EL2GOInterfaceHandler,
    config: str,
    secure_objects_file: Optional[str] = None,
    database: Optional[str] = None,
    remote_database: Optional[str] = None,
    clean: bool = False,
) -> None:
    """Prepare device for Trust Provisioning."""
    client = _create_client(config)
    interface.prepare(client.loader)
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
    interface: EL2GOInterfaceHandler,
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

    interface.run_provisioning(
        tp_data_address=client.tp_data_address,
        use_dispatch_fw=client.use_dispatch_fw,
        prov_fw=client.prov_fw,
        dry_run=dry_run,
    )


@main.command(name="get-secure-objects", no_args_is_help=True)
@el2go_optional_fw_interface
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
    interface: EL2GOInterfaceHandler,
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
    interface: Optional[EL2GOInterfaceHandler] = None,
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
        with db:
            total_count = db.get_count(not re_download)
            if total_count == 0:
                click.echo("There are no UUIDs in the database that need Secure Objects download.")
                return
            failures = []
            # exhaust the iterator so DB is ready for inserts below
            uuids = list(db.get_uuids(not re_download))
            click.echo(f"Found {len(uuids)} UUIDs out of {total_count} without Secure Objects")
            for uuid in uuids:
                try:
                    click.echo(f"Downloading Secure Objects for UUID: {uuid}")
                    client.assign_device_to_devicegroup(
                        device_id=uuid, allow_reassignment=re_assign
                    )
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
        interface.prepare(client.loader)
        uuid = interface.get_uuid()
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
def get_uuid_command(interface: EL2GOInterfaceHandler, database: str, remote_database: str) -> None:
    """Get UUID from the target and store it in a database."""
    get_uuid(interface=interface, database=database, remote_database=remote_database)


def get_uuid(interface: EL2GOInterfaceHandler, database: str, remote_database: str) -> None:
    """Get UUID from the target and store it in a database."""
    uuid = interface.get_uuid()
    db = SecureObjectsDB.create(file_path=database, host=remote_database)
    with db:
        result = db.add_uuid(uuid=uuid)
    if result:
        click.echo(f"UUID {uuid} stored in the database")


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
    interface: EL2GOInterfaceHandler,
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
    interface: EL2GOInterfaceHandler,
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

    interface.run_provisioning(
        client.tp_data_address, client.use_dispatch_fw, client.prov_fw, dry_run
    )


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
    interface: EL2GOInterfaceHandler,
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
    interface: EL2GOInterfaceHandler,
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
    uuid = interface.get_uuid()
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

    interface.run_provisioning(
        tp_data_address=client.tp_data_address,
        use_dispatch_fw=client.use_dispatch_fw,
        prov_fw=client.prov_fw,
        dry_run=dry_run,
    )


def _create_client(config: str) -> EL2GOTPClient:
    config_data = load_configuration(path=config)
    search_path = os.path.dirname(config)
    return EL2GOTPClient.from_config(config_data=config_data, search_paths=[search_path])


def _retrieve_secure_objects(
    interface: EL2GOInterfaceHandler,
    client: EL2GOTPClient,
    database: Optional[str] = None,
    remote_database: Optional[str] = None,
    secure_objects_file: Optional[str] = None,
) -> bytes:
    if database or remote_database:
        db = SecureObjectsDB.create(file_path=database, host=remote_database)
        uuid = interface.get_uuid()
        with db:
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
    interface: EL2GOInterfaceHandler,
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

    if clean:
        click.echo("Performing cleanup method")
        client.run_cleanup_method(interface=interface)
    if client.use_dispatch_fw:
        click.echo(f"Writing Secure Objects to: {hex(user_data_address)}")
        interface.write_memory(address=user_data_address, data=secure_objects)
        if client.prov_fw:
            click.echo("Uploading ProvFW")
            interface.write_memory(address=client.fw_load_address, data=client.prov_fw)
            click.echo("Resetting the device (Starting Provisioning FW)")
            interface.reset()
    elif client.use_oem_app:
        click.echo(f"Writing Secure Objects to MMC/SD FAT: {client.fatwrite_filename}")
        interface.write_memory(address=user_data_address, data=secure_objects)
        output = interface.send_command(
            f"fatwrite {client.fatwrite_interface} {client.fatwrite_device_partition}"
            + f" {user_data_address:x} {client.fatwrite_filename} {len(secure_objects):x}"
        )
        click.echo(f"Data written {output}")
        if client.oem_provisioning_config_filename:
            interface.write_memory(
                address=user_data_address, data=client.oem_provisioning_config_bin
            )
            # Write also OEM APP config if provided
            click.echo(
                f"Writing OEM Provisioning Config to MMC/SD FAT: {client.oem_provisioning_config_filename}"
            )

            output = interface.send_command(
                f"fatwrite {client.fatwrite_interface} {client.fatwrite_device_partition}"
                + f" {user_data_address:x} {client.oem_provisioning_config_filename} "
                + f"{len(client.oem_provisioning_config_bin):x}"
            )

        click.echo(f"Data written {output}")

        if client.boot_linux:
            click.echo("Booting Linux")

            for command in client.linux_boot_sequence:
                # in case of last command set no_exit to true
                if command == client.linux_boot_sequence[-1]:
                    output = interface.send_command(command, no_exit=True)
                else:
                    output = interface.send_command(command)
                click.echo(f"  Command: {command} -> {output}")

    elif client.use_user_config:
        click.echo(f"Writing User config data to: {hex(fw_read_address)}")
        interface.write_memory(address=fw_read_address, data=user_config)
        click.echo(f"Writing Secure Objects to: {hex(user_data_address)}")
        interface.write_memory(address=user_data_address, data=secure_objects)
    elif client.use_data_split:
        internal, external = so_list.split_int_ext()
        if internal:
            if workspace:
                write_file(internal, os.path.join(workspace, "internal_so.bin"), mode="wb")
            click.echo(f"Writing Internal Secure Objects to: {hex(fw_read_address)}")
            interface.write_memory(address=fw_read_address, data=internal)
        if external:
            if workspace:
                write_file(external, os.path.join(workspace, "external_so.bin"), mode="wb")
            click.echo(f"Writing External Secure Objects to: {hex(user_data_address)}")
            interface.write_memory(address=user_data_address, data=external)
    else:
        raise SPSDKAppError("Unsupported provisioning method")
    click.echo("Secure Objects uploaded successfully")


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
@spsdk_config_option()
@spsdk_output_option(force=True)
def get_otp_binary_command(config: str, output: str) -> None:
    """Generate EL2GO OTP Binary from data in configuration file."""
    get_otp_binary(config=config, output=output)


def get_otp_binary(config: str, output: str) -> None:
    """Generate EL2GO OTP Binary from data in configuration file."""
    config_data = load_configuration(path=config)
    data = get_el2go_otp_binary(config_data=config_data)
    write_file(data=data, path=output, mode="wb")
    click.echo(f"EL2GO OTP Binary stored into {output}")


@main.command(name="combine-uuid-db", no_args_is_help=True)
@spsdk_output_option(force=True, help="Path to the output database file.")
@click.option(
    "-i",
    "--input",
    "input_sources",
    type=click.Path(exists=True, resolve_path=True),
    multiple=True,
    required=True,
    help=(
        "Path(s) to the input database file(s). "
        "Multiple inputs are allowed. You can use a folder containing the database files."
    ),
)
def combine_uuid_db_command(output: str, input_sources: list[str]) -> None:
    """Combine multiple UUID databases into one."""
    combine_uuid_db(output=output, input_sources=input_sources)


def combine_uuid_db(output: str, input_sources: list[str]) -> None:
    """Combine multiple UUID databases into one."""
    db = SecureObjectsDB.create(file_path=output)
    sources = []
    for s in input_sources:
        if os.path.isfile(s):
            sources.append(s)
        elif os.path.isdir(s):
            sources.extend([os.path.join(s, f) for f in os.listdir(s)])

    with db:
        for file in sources:
            click.echo(f"Processing {file}")
            try:
                db_source = SecureObjectsDB.create(file_path=file)
                with db_source:
                    for uuid in db_source.get_uuids():
                        db.add_uuid(uuid)
            except SPSDKError as e:
                click.secho(f"File {file}: {e.description}. Attempting text file parsing")
                text_data = load_text(file)
                uuids = shlex.split(text_data, comments=True)
                for uuid in uuids:
                    db.add_uuid(uuid=uuid)

    click.echo(f"UUID databases combined into {output}")


@main.command(name="parse-uuid-db")
@click.option(
    "-i",
    "--input",
    "input_db",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to DB file to parse",
)
@spsdk_output_option(
    required=False,
    directory=True,
    help="Path to directory where to extract Secure Objects.",
)
def parse_uuid_db_command(output: str, input_db: str) -> None:
    """Parse Information about DB file. Optionally extract Secure Objects."""
    parse_uuid_db(output=output, input_db=input_db)


def parse_uuid_db(output: str, input_db: str) -> None:
    """Parse Information about DB file. Optionally extract Secure Objects."""
    db = SecureObjectsDB.create(file_path=input_db)
    with db:
        empty = db.get_count(empty=True)
        total = db.get_count(empty=False)
        click.echo(f"Total records (UUIDs):          {total}")
        click.echo(f"Records with Secure Objects:    {total - empty}")
        click.echo(f"Records without Secure Objects: {empty}")
        if output:
            os.makedirs(output, exist_ok=True)
            for uuid in db.get_uuids(empty=False):
                data = db.get_secure_object(uuid=uuid)
                if not data:
                    continue
                write_file(data, os.path.join(output, f"{uuid}.bin"), mode="wb")
            click.echo(f"{total - empty} records(s) extracted to {output}")


@main.command(name="unclaim", no_args_is_help=True)
@spsdk_config_option()
@click.option(
    "-db",
    "--database",
    type=click.Path(exists=True, dir_okay=False),
    help="Unclaim devices only in this database",
)
def unclaim(config: str, database: str) -> None:
    """Unclaim devices: Remove UUIDs from Device Group.

    If a database is specified, unclaim only UUIDs in database and remove Secure Objects from database.
    """
    client = _create_client(config=config)
    click.echo(f"Loading UUIDs registered in Device Group: {client.device_group_id}")
    remote_uuids = client.get_uuids()
    click.echo(f"Found {len(remote_uuids)} UUIDs")
    if len(remote_uuids) == 0:
        return
    uuids = set(remote_uuids)

    if database:
        click.echo(f"Loading UUIDs from local database: {database}")
        db = SecureObjectsDB.create(file_path=database)
        with db:
            local_uuids = db.get_uuids(empty=False)
        click.echo(f"Found {len(local_uuids)} UUIDs")
        uuids = uuids & set(local_uuids)

    click.secho(
        f"You're about to remove {len(uuids)} UUIDs from Device Group: {client.device_group_id}",
        fg="yellow",
    )
    click.confirm("Are you sure you want to continue?", abort=True)

    client._unassign_device_from_group(device_id=list(uuids), wait_time=0)

    if database:
        db = SecureObjectsDB.create(file_path=database)
        click.echo(f"Removing {len(uuids)} Secure Objects from database.")
        with db:
            db.remove_secure_object(uuid=list(uuids))
    click.echo("Un-claim completed")


@main.command(name="bulk-so-download", no_args_is_help=True)
@spsdk_config_option()
@click.option(
    "-db",
    "--database",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Database of UUIDs and Secure Objects",
)
@click.option(
    "-l",
    "--limit",
    type=click.IntRange(0),
    default=0,
    help="Number of devices to download (default: 0 = all)",
)
@click.option(
    "-t",
    "--time-per-device",
    type=click.FloatRange(0),
    default=5,
    help="Time per device in seconds (default: 5)",
)
@click.option(
    "-s",
    "--max-job-size",
    type=click.IntRange(1, 500),
    default=500,
    help="Max chunk size for one job (default: 500)",
)
def bulk_so_download_command(
    config: str, database: str, limit: int, time_per_device: float, max_job_size: int
) -> None:
    """Download Secure Objects for all UUIDs in the database."""
    bulk_so_download(
        config=config,
        database=database,
        limit=limit,
        time_per_device=time_per_device,
        max_job_size=max_job_size,
    )


def bulk_so_download(
    config: str, database: str, limit: int, time_per_device: float, max_job_size: int
) -> None:
    """Download Secure Objects for all UUIDs in the database.

    Note: This command is only in alpha stage and may not work as expected.
    In case of any problems, please contact the SPSDK team.
    """
    client = _create_client(config)
    db = ServiceDB(file_path=database)

    # get UUIDs from the database
    def _get_uuid_jobs() -> Optional[list[list[str]]]:
        with db:
            uuids = db.get_uuids(empty=True, limit=limit)
        if not uuids:
            return None
        jobs = client.split_uuids_to_jobs(uuids, max_job_size)
        click.echo(f"Using {len(jobs)} parallel jobs with max chunk size {max_job_size}")
        return jobs

    # register devices
    def _submit_new_jobs(jobs: list[list[str]]) -> None:
        with db:
            for group_uuids in jobs:
                job_id, job_size = client.register_devices(group_uuids, remove_errors=True)
                if job_id and job_size:
                    click.echo(f"Job ID: {job_id} for {job_size} devices")
                    db.insert_job(job_id, job_size)

    # wait for all jobs to finish
    def _wait_for_jobs() -> None:
        with db:
            while True:
                incomplete_jobs = db.get_incomplete_jobs()
                if not incomplete_jobs:
                    break
                click.echo(f"Found {len(incomplete_jobs)} incomplete jobs")

                wait_times = [job.calc_wait_time(time_per_device) for job in incomplete_jobs]
                wt_filtered = [time for time in wait_times if time is not None]
                wait_time = min(wt_filtered) if wt_filtered else 0.0
                wait_time_delta = timedelta(seconds=math.ceil(wait_time))
                next_check = datetime.now() + wait_time_delta
                click.echo(
                    f"Next Jobs status check in {wait_time_delta} ({wait_time_delta.total_seconds():.0f} seconds) "
                    f"at {next_check.strftime('%H:%M:%S')}"
                )
                time.sleep(wait_time)

                for job in incomplete_jobs:
                    job_details = client.get_job_details(job.job_id)
                    if job_details is None:
                        click.echo(f"Job {job.job_id} not found")
                        continue
                    job.status = str(job_details["state"])
                    job.percentage = int(job_details["provisionedPercentage"])
                    db.update_job(job.job_id, job.status, job.percentage)
                    click.echo(
                        f"Job {job.job_id} updated with status {job.status} and percentage {job.percentage}"
                    )

    # download Secure Objects for successful jobs
    def _download_secure_objects() -> None:
        with db:
            jobs = db.get_jobs_to_download()
            for job in jobs:
                job_details = client.get_job_details(job.job_id)
                if job_details is None:
                    click.echo(f"Job {job.job_id} not found")
                    continue
                group_uuids = job_details["deviceIds"]
                provisionings = client._download_provisionings(device_id=group_uuids)
                for device_info in provisionings:
                    device_id = device_info["deviceId"]
                    secure_objects = client._serialize_single_provisioning(device_info)
                    db.add_secure_object(uuid=device_id, so=secure_objects)
                    click.echo(f"Secure object for {device_id} added to database")
                db.set_downloaded(job_id=job.job_id)

    click.echo("Checking for incomplete jobs from previous runs")
    _wait_for_jobs()
    _download_secure_objects()

    click.echo("Starting new jobs")
    jobs = _get_uuid_jobs()
    if not jobs:
        click.echo("No UUIDs without Secure Objects found.")
        return
    _submit_new_jobs(jobs)
    _wait_for_jobs()
    _download_secure_objects()

    failure = False
    with db:
        # check if there are some failed jobs
        failed_jobs = db.get_failed_jobs()
        if failed_jobs:
            failure = True
            click.echo(f"There were {len(failed_jobs)} failed job(s):")
            for job in failed_jobs:
                click.echo(f"Job {job.job_id} failed with status {job.status}")

        # check if there are some UUIDs without Secure Objects
        uuids = db.get_uuids(empty=True)
        if uuids:
            failure = True
            click.echo(
                f"There are {len(uuids)} UUIDs without Secure Objects. "
                "Either because already successfully registered in another device group, or "
                "the UUIDs were not found for given product, or UUIDs are invalid."
            )
            for uuid in uuids:
                click.echo(uuid)

    if failure:
        click.echo("There were some issues during the download process")
        raise SPSDKAppError()

    click.echo("Secure Objects downloaded for all UUIDs")


@catch_spsdk_error
def safe_main() -> None:
    """Calls the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
