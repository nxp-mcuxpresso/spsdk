#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""NXP tool for working with SHE protocol."""

import logging
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
from spsdk.apps.utils.utils import SPSDKAppError, catch_spsdk_error
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.properties import PropertyTag
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.she.she import SHEBootMac, SHEDeriveKey, SHEMaxKeyCountCode, SHEUpdate
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import get_printable_path, load_binary, load_secret, write_file

logger = logging.getLogger(__name__)


@click.group(name="nxpshe", no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> None:
    """NXP tool for working with SHE (Secure Hardware Extension)."""
    spsdk_logger.install(level=log_level)


@main.command(name="get-template", no_args_is_help=True)
@spsdk_family_option(families=SHEUpdate.get_supported_families())
@spsdk_output_option(force=True)
def get_template_command(output: str, family: FamilyRevision) -> None:
    """Generate a template configuration for SHE protocol operations."""
    # Placeholder for template generation logic
    click.echo(f"Generating {get_printable_path(output)} template file.")
    write_file(SHEUpdate.get_config_template(family), output)


@main.command(name="update", no_args_is_help=True)
@spsdk_mboot_interface(required=False)
@spsdk_config_option(klass=SHEUpdate)
@spsdk_output_option(force=True, required=False)
def update(interface: MbootProtocolBase, config: Config, output: str) -> None:
    """Perform SHE update operation using provided configuration."""
    if not (output or interface):
        raise SPSDKAppError("Either output or interface must be specified.")
    she_update = SHEUpdate.load_from_config(config)
    data = she_update.get_messages()
    if output:
        click.echo(f"Generating update message: {get_printable_path(output)}.")
        write_file(b"".join(data), output, mode="wb")
    if interface:
        click.echo("Sending update message to device")
        with McuBoot(interface) as mboot:
            result = mboot.kp_set_user_key(she_update.new_key_id, key_data=b"".join(data))
        message = f"Updating key ID: {she_update.new_key_id} "
        message += "was successful." if result else "FAILED!"
        display_output([], mboot.status_code, extra_output=message)


@main.command(name="verify", no_args_is_help=True)
@spsdk_config_option(klass=SHEUpdate)
@click.option(
    "-m4", "--message4", required=True, type=click.Path(exists=True), help="Path to M4 message file"
)
@click.option(
    "-m5", "--message5", required=True, type=click.Path(exists=True), help="Path to M5 message file"
)
def verify(config: Config, message4: str, message5: str) -> None:
    """Verify SHE update messages."""
    she_update = SHEUpdate.load_from_config(config)
    m4_data = load_binary(message4)
    m5_data = load_binary(message5)
    she_update.verify_messages(m4_data, m5_data)
    click.echo("SHE update messages verified successfully.")


@main.command(name="calc-boot-mac", no_args_is_help=True)
@spsdk_mboot_interface(required=False)
@click.option(
    "-k",
    "--key",
    required=True,
    type=str,
    metavar="KEY|FILE",
    help=(
        "AES key used for MAC calculation (BOOT_MAC_KEY). "
        "The key is a hex-string either directly on command line or in a text file."
    ),
)
@click.option(
    "-d",
    "--data",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to data for MAC calculation.",
)
@click.option(
    "-b",
    "--boot-mode",
    type=click.Choice(["strict", "serial", "parallel", "unsecure"], case_sensitive=False),
    required=False,
    help="Boot mode [required if interface is defined]",
)
@spsdk_output_option(required=False, help="Output file for calculated boot MAC")
def calc_boot_mac(
    interface: MbootProtocolBase, key: str, data: str, output: str, boot_mode: str
) -> None:
    """Calculate Boot MAC using provided key and data."""
    key_data = bytes.fromhex(load_secret(key))
    input_data = load_binary(data)
    boot_mac = SHEBootMac.calculate(key_data, input_data)
    click.echo(f"Calculated Boot MAC: {boot_mac.hex()}")
    if output:
        write_file(boot_mac.hex(), output)
        click.echo(f"Boot MAC written to {get_printable_path(output)}")
    if interface:
        if not boot_mode:
            raise SPSDKAppError("Boot mode is required when using an interface.")
        boot_mode_mapping = {"strict": 0x00, "serial": 0x01, "parallel": 0x02, "unsecure": 0x03}
        input_data_len = len(input_data) * 8
        property_value = boot_mode_mapping[boot_mode] << 30 | input_data_len

        updater = SHEUpdate(new_key=boot_mac, new_key_id=3, auth_key=key_data, auth_key_id=1)
        updater_blob = updater.get_messages()
        with McuBoot(interface, cmd_exception=True) as mboot:
            click.echo("Updating BOOT_MAC")
            mboot.kp_set_user_key(3, key_data=b"".join(updater_blob))
            click.echo("Updating BOOT_MODE property")
            mboot.set_property(PropertyTag.SHE_BOOT_MODE, property_value)
            click.echo("Boot MAC and Boot Mode updated successfully.")


@main.command(name="derive-key", no_args_is_help=True)
@click.option(
    "-k",
    "--master-key",
    required=True,
    type=str,
    metavar="KEY|FILE",
    help="Master key for key derivation (hex string or file path)",
)
@click.option(
    "-t",
    "--type",
    "key_type",
    type=click.Choice(SHEDeriveKey.KeyType.labels(), case_sensitive=False),
    required=True,
    help="Type of derived key",
)
@spsdk_output_option(help="Output file for derived key", required=False)
def derive_key(master_key: str, key_type: str, output: str) -> None:
    """Derive a SHE key from master key."""
    key_data = load_secret(master_key)
    derived_key_type = SHEDeriveKey.KeyType.from_label(key_type.upper())
    derived_key = SHEDeriveKey.derive_key(bytes.fromhex(key_data), derived_key_type)
    click.echo(f"Derived {key_type.upper()} key: {derived_key.hex()}")
    if output:
        write_file(derived_key.hex(), output)
        click.echo(f"Derived key written to {get_printable_path(output)}")


@main.command(name="setup", no_args_is_help=True)
@spsdk_mboot_interface()
@click.option(
    "-k",
    "--max-key-count",
    type=click.Choice(SHEMaxKeyCountCode.labels(), case_sensitive=False),
    required=True,
    help="Maximum number of keys to setup",
)
def setup(interface: MbootProtocolBase, max_key_count: str) -> None:
    """Setup SHE key storage configuration."""
    click.echo(f"Configuring SHE key storage with max keys: {max_key_count}")
    key_code_enum = SHEMaxKeyCountCode.from_label(max_key_count.upper())
    key_code_tag = key_code_enum.tag
    flash_code_tag = 3 - key_code_tag

    property_value = key_code_tag | flash_code_tag << 8

    with McuBoot(interface, cmd_exception=True) as mboot:
        click.echo("Setting SHE flash partition property")
        mboot.set_property(PropertyTag.SHE_FLASH_PARTITION, property_value)
        click.echo("Enrolling SHE key storage")
        mboot.kp_enroll()
        click.echo("Resetting the device")
        mboot.reset(reopen=False)
        click.echo("SHE key storage configuration setup completed successfully.")


@main.command(name="reset", no_args_is_help=True)
@spsdk_mboot_interface()
@click.option(
    "-k",
    "--master-key",
    type=str,
    metavar="KEY|FILE",
    required=True,
    help="Master key for SHE key storage reset (hex string or file path)",
)
def reset(interface: MbootProtocolBase, master_key: str) -> None:
    """Reset SHE key storage configuration."""
    click.echo("Resetting SHE key storage configuration")
    master_key_data = bytes.fromhex(load_secret(master_key))
    debug_key = SHEDeriveKey.derive_debug_key(master_key_data)

    with McuBoot(interface) as mboot:
        result = mboot.kp_set_user_key(key_type=0xFF, key_data=debug_key)
    message = "Resetting SHE key storage configuration "
    message += "was successful." if result else "FAILED!"
    display_output([], mboot.status_code, extra_output=message)


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
