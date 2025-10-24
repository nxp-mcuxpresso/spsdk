#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Sub-set of EL2GO-HOST commands related to Product-Based Provisioning."""

import time
from typing import Optional

import click
from click_option_group import RequiredMutuallyExclusiveOptionGroup, optgroup

from spsdk.apps.el2go_apps.common import el2go_fw_interface, get_template
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import SPSDKAppError
from spsdk.crypto.keys import PublicKeyEcc, SPSDKEncoding
from spsdk.el2go.api_utils import EL2GOTPClient
from spsdk.el2go.database import LocalProductBasedBatchDB, ProdDBStats, RemoteProductBasedBatchDB
from spsdk.el2go.interface import EL2GOInterfaceHandler
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary, write_file


@click.group(name="prod", cls=CommandsTreeGroup)
def prod_group() -> None:
    """Group of sub-commands related to EdgeLock 2GO Product-based provisioning."""


@prod_group.command(name="get-template", no_args_is_help=True)
@spsdk_family_option(families=EL2GOTPClient.get_supported_families())
@spsdk_output_option(force=True)
def get_template_command(family: FamilyRevision, output: str) -> None:
    """Get template for the configuration file used in other command."""
    get_template(family=family, output=output, mode="product")


@prod_group.command(name="get-secure-objects", no_args_is_help=True)
@spsdk_config_option()
@optgroup.group("Secure Object Batch Options", cls=RequiredMutuallyExclusiveOptionGroup)
@optgroup.option(
    "-d",
    "--devices",
    type=click.IntRange(min=1, max=1000),
    help="Create new batch with this many devices",
)
@optgroup.option(
    "-b",
    "--batch-id",
    type=click.UUID,
    help="Download already existing batch",
)
@spsdk_output_option(help="Path to database file.", force=True)
def prod_get_secure_objects_command(
    config: Config, devices: int, batch_id: str, output: str
) -> None:
    """Retrieve secure objects for EdgeLock 2GO product-based provisioning."""
    prod_get_secure_objects(config, devices, batch_id, output)


def prod_get_secure_objects(
    config: Config, devices: Optional[int], batch_id: Optional[str], output: str
) -> None:
    """Retrieve secure objects for EdgeLock 2GO product-based provisioning."""
    client = EL2GOTPClient.load_from_config(config)
    if devices:
        # Create a new batch of secure objects
        batch_id = client.create_secure_objects_batch(devices)
        if not batch_id:
            click.echo(f"Device group {client.device_group_id} doesn't have dynamic data.")
        else:
            click.echo(f"Created new batch with {devices}, ID: {batch_id}")
    data = client.download_secure_objects_batch(batch_id)
    db = LocalProductBasedBatchDB(file_path=output)
    with db:
        db.process(data=data)


@prod_group.command(name="get-next-so", no_args_is_help=True)
@optgroup.group("Secure Objects Source Options", cls=RequiredMutuallyExclusiveOptionGroup)
@optgroup.option(
    "-db",
    "--database",
    type=click.Path(exists=True),
    help="Path to existing database with secure objects",
)
@optgroup.option(
    "-rdb",
    "--remote-database",
    help="URL to remote database with secure objects",
)
@spsdk_output_option(help="Path to output file for secure objects", force=True)
def prod_get_next_so_command(database: str, remote_database: str, output: str) -> None:
    """Retrieve next available secure object from an existing batch."""
    data = _retrieve_secure_objects(database=database, remote_database=remote_database)
    write_file(data=data, path=output, mode="wb")
    click.echo(f"Retrieved next secure object to {output}")


@prod_group.command(name="store-report", no_args_is_help=True)
@optgroup.group("Report target Options", cls=RequiredMutuallyExclusiveOptionGroup)
@optgroup.option(
    "-db",
    "--database",
    type=click.Path(exists=True),
    help="Path to existing database with secure objects",
)
@optgroup.option(  # type: ignore[arg-type]
    "-rdb",
    "--remote-database",
    help="URL to remote database with secure objects",
)
@click.option(
    "-r",
    "--report",
    type=click.Path(exists=True),
    required=True,
    help="Path to provisioning report file",
)
def prod_store_report_command(database: str, remote_database: str, report: str) -> None:
    """Upload provisioning report for used secure objects."""
    report_data = load_binary(report)
    _store_report(report_data, database, remote_database)
    click.echo("Provisioning report uploaded successfully.")


@prod_group.command(name="provision-device", no_args_is_help=True)
@el2go_fw_interface
@optgroup.group("Secure Objects Source Options", cls=RequiredMutuallyExclusiveOptionGroup)
@optgroup.option(
    "-db",
    "--database",
    type=click.Path(exists=True),
    help="Path to existing database with secure objects",
)
@optgroup.option(
    "-rdb",
    "--remote-database",
    help="URL to remote database with secure objects",
)
@optgroup.option(
    "-sf",
    "--secure-objects-file",
    type=click.Path(exists=True),
    help="Path to file with secure object file for provisioning",
)
@spsdk_config_option()
@click.option("--dry-run", is_flag=True, help="Perform a dry run without actual provisioning")
@spsdk_output_option(required=False, help="Optional output path for provisioning report")
def prod_provision_device_command(
    interface: EL2GOInterfaceHandler,
    config: Config,
    database: str,
    remote_database: str,
    secure_objects_file: str,
    output: str,
    dry_run: bool = False,
) -> None:
    """Execute EdgeLock 2GO product provisioning process.

    \b
        1) Fetch secure objects from specified source
        2) Store the secure objects into the device's memory
        3) Run the provisioning process
        4) Store the provisioning report
    """
    prod_provision_device(
        interface, config, database, remote_database, secure_objects_file, output, dry_run
    )


def prod_provision_device(
    interface: EL2GOInterfaceHandler,
    config: Config,
    database: Optional[str],
    remote_database: Optional[str],
    secure_objects_file: Optional[str],
    output: Optional[str],
    dry_run: bool = False,
) -> None:
    """Execute EdgeLock 2GO product-based provisioning process."""
    client = EL2GOTPClient.load_from_config(config)
    secure_object = _retrieve_secure_objects(database, remote_database, secure_objects_file)
    interface.write_secure_objects_prod(client=client, secure_objects=secure_object)
    report = interface.run_batch_provisioning(
        client=client,
        dry_run=dry_run,
    )
    if not report:
        click.echo("No provisioning report available.")
        return

    _store_report(
        report=report, database=database, remote_database=remote_database, output_file=output
    )


@prod_group.command(name="prepare-device", no_args_is_help=True)
@el2go_fw_interface
@optgroup.group("Secure Objects Source Options", cls=RequiredMutuallyExclusiveOptionGroup)
@optgroup.option(
    "-db",
    "--database",
    type=click.Path(exists=True),
    help="Path to existing database with secure objects",
)
@optgroup.option(
    "-rdb",
    "--remote-database",
    help="URL to remote database with secure objects",
)
@optgroup.option(
    "-sf",
    "--secure-objects-file",
    type=click.Path(exists=True),
    help="Path to file with secure object file for provisioning",
)
@spsdk_config_option()
@click.option(
    "--check-fw",
    is_flag=True,
    help="Perform check after reset to validate Provisioning FW is running",
)
def prod_prepare_device_command(
    interface: EL2GOInterfaceHandler,
    config: Config,
    database: str,
    remote_database: str,
    secure_objects_file: str,
    check_fw: bool,
) -> None:
    """Prepare device for EdgeLock 2GO provisioning process.

    \b
    - Fetch the secure objects, load them into device memory
    - Load provisioning firmware if available
    - Reset the interface and optionally check firmware version
    """
    prod_prepare_device(
        interface=interface,
        config=config,
        database=database,
        remote_database=remote_database,
        secure_objects_file=secure_objects_file,
        check_fw=check_fw,
    )


def prod_prepare_device(
    interface: EL2GOInterfaceHandler,
    config: Config,
    database: str,
    remote_database: str,
    secure_objects_file: str,
    check_fw: bool = False,
) -> None:
    """Prepare device for EdgeLock 2GO provisioning process.

    Fetch the secure objects, load them into device memory
    Load provisioning firmware if available
    Reset the interface and optionally check firmware version
    """
    client = EL2GOTPClient.load_from_config(config)
    if not client.use_dispatch_fw:
        raise SPSDKAppError("This command is viable only for devices with dispatch firmware")
    secure_object = _retrieve_secure_objects(database, remote_database, secure_objects_file)
    interface.prepare_dispatch(secure_objects=secure_object, client=client)
    if check_fw:
        time.sleep(0.5)  # Allow a short delay for firmware initialization
        version = interface.get_version()
        click.echo(f"Provisioning firmware version: {version}")
    click.echo("Device is ready for provisioning")


@prod_group.command(name="run-provisioning")
@el2go_fw_interface
@spsdk_config_option()
@click.option("--dry-run", is_flag=True, help="Perform a dry run without actual provisioning")
@spsdk_output_option(required=False, help="Optional output path for provisioning report")
def prod_run_provisioning_command(
    interface: EL2GOInterfaceHandler,
    config: Config,
    output: str,
    dry_run: bool = False,
) -> None:
    """Execute provisioning process only."""
    prod_run_provisioning(interface=interface, config=config, output=output, dry_run=dry_run)


def prod_run_provisioning(
    interface: EL2GOInterfaceHandler,
    config: Config,
    output: str,
    dry_run: bool = False,
) -> None:
    """Execute provisioning process only."""
    client = EL2GOTPClient.load_from_config(config)
    report = interface.run_batch_provisioning(
        client=client,
        dry_run=dry_run,
    )
    if not report:
        click.echo("No provisioning report available.")
        return

    if output:
        write_file(data=report, path=output, mode="wb")
        click.echo(f"Provisioning report saved to {output}")


@prod_group.command(name="validate-reports", no_args_is_help=True)
@optgroup.group("Report Source Options", cls=RequiredMutuallyExclusiveOptionGroup)
@optgroup.option(
    "-db",
    "--database",
    type=click.Path(exists=True),
    help="Path to database file with reports",
)
@optgroup.option(  # type: ignore[arg-type]
    "-rdb",
    "--remote-database",
    help="URL to remote database with reports",
)
def prod_validate_reports_command(database: str, remote_database: str) -> None:
    """Validate provisioning reports from local or remote database."""
    raise SPSDKAppError("Not implemented")


@prod_group.command(name="db-stats", no_args_is_help=True)
@optgroup.group("Report Source Options", cls=RequiredMutuallyExclusiveOptionGroup)
@optgroup.option(
    "-db",
    "--database",
    type=click.Path(exists=True),
    help="Path to database file with reports",
)
@optgroup.option(  # type: ignore[arg-type]
    "-rdb",
    "--remote-database",
    help="URL to remote database with reports",
)
def prod_db_stats_command(database: str, remote_database: str) -> None:
    """Get database statistics for provisioning records and reports."""
    stats = prod_db_stats(database=database, remote_database=remote_database)
    click.echo("Database Statistics:")
    click.echo(stats)


def prod_db_stats(
    database: Optional[str] = None, remote_database: Optional[str] = None
) -> ProdDBStats:
    """Get database statistics for provisioning records and reports."""
    stats = None
    if database:
        db = LocalProductBasedBatchDB(file_path=database)
        with db:
            stats = db.get_stats()
    if remote_database:
        rdb = RemoteProductBasedBatchDB(host=remote_database)
        stats = rdb.get_stats()

    if not stats:
        raise SPSDKAppError("No database statistics could be retrieved.")

    return stats


def _store_report(
    report: bytes,
    database: Optional[str] = None,
    remote_database: Optional[str] = None,
    output_file: Optional[str] = None,
) -> None:
    """Store provisioning report to local or remote database."""
    if database:
        db = LocalProductBasedBatchDB(file_path=database)
        with db:
            db.insert_report(report)
        click.echo(f"Uploaded report to local database: {database}")

    if remote_database:
        rdb = RemoteProductBasedBatchDB(host=remote_database)
        rdb.insert_report(report)
        click.echo(f"Uploaded report to remote database: {remote_database}")

    if output_file:
        write_file(report, output_file, "wb")
        click.echo(f"Saved report to file: {output_file}")


def _retrieve_secure_objects(
    database: Optional[str] = None,
    remote_database: Optional[str] = None,
    secure_objects_file: Optional[str] = None,
) -> bytes:
    if database:
        db = LocalProductBasedBatchDB(file_path=database)
        with db:
            return db.get_next_secure_object()

    if remote_database:
        rdb = RemoteProductBasedBatchDB(host=remote_database)
        return rdb.get_next_secure_object()

    if secure_objects_file:
        return load_binary(secure_objects_file)
    raise SPSDKAppError("No secure object source provided")


####################################################################
# TBR - To Be Removed
# Following commands are only for early testing
####################################################################


@prod_group.command(name="tbr-reset-db", no_args_is_help=True)
@click.option(
    "-db",
    "--database",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to existing database to reset",
)
def prod_reset_database_command(database: str) -> None:
    """Reset/clear the local product-based batch database for testing purposes."""
    db = LocalProductBasedBatchDB(file_path=database)
    with db:
        cursor = db._sanitize_cursor()
        cursor.execute("DELETE FROM report")
        cursor.execute("UPDATE dynamic SET used = 0")
        cursor.execute("UPDATE dynamic SET uuid = null")
    click.echo(f"Reset database: {database}")


@prod_group.command(name="tbr-replace-puk", no_args_is_help=True)
@click.option(
    "-db",
    "--database",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to existing database with secure objects",
)
@click.option(
    "-puk",
    "--puk-file",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to file containing new PUK for replacement",
)
def prod_replace_puk_command(database: str, puk_file: str) -> None:
    """Replace PUK in the local product-based batch database for testing purposes."""
    db = LocalProductBasedBatchDB(file_path=database)
    puk = PublicKeyEcc.load(puk_file)
    with db:
        cursor = db._sanitize_cursor()
        cursor.execute("UPDATE dynamic SET attestation_key = ?", (puk.export(SPSDKEncoding.DER),))
    click.echo(f"PUK replaced in database: {database}")
