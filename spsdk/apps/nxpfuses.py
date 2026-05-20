#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK NXP fuses management command-line interface.

This module provides a comprehensive CLI tool for reading, writing, and managing
NXP MCU fuses. It supports fuse operations across NXP's MCU portfolio with
safety features and configuration templates.
"""

import logging
import sys
from typing import Optional

import click
import colorama

from spsdk.apps.nxpele import nxpele_options
from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
)
from spsdk.apps.utils.interface_helper import load_interface_config
from spsdk.apps.utils.utils import SPSDKAppError, catch_spsdk_error, progress_bar
from spsdk.ele.ele_comm import EleMessageHandler
from spsdk.exceptions import SPSDKError, SPSDKTypeError
from spsdk.fuses.fuse_registers import print_register_info
from spsdk.fuses.fuses import (
    BlhostFuseOperator,
    BlhostFuseOperatorLegacy,
    FuseOperator,
    Fuses,
    NxpeleFuseOperator,
    SPSDKFuseOperationFailure,
)
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import get_printable_path, value_to_int, write_file

logger = logging.getLogger(__name__)


def prompt_for_write_permission(skip: bool = False) -> bool:
    """Prompt user for permission.

    :return: True if permitted, False otherwise
    """
    if skip:
        return True
    yes = click.prompt(
        "Writing of fuses is irreversible operation. Type y/yes if you prefer to continue."
    )
    assert isinstance(yes, str)
    if yes.lower() not in ["y", "yes"]:
        click.echo("Operation is not permitted. Skipping the writing.")
        return False
    return True


def get_fuse_operator(
    family: FamilyRevision,
    port: Optional[str],
    usb: Optional[str],
    lpcusbsio: Optional[str],
    buspal: Optional[str],
    timeout: int,
    device: Optional[str],
    buffer_addr: Optional[int],
    buffer_size: Optional[int],
    fb_addr: Optional[int],
    fb_size: Optional[int],
    uboot_prompt: Optional[str],
) -> FuseOperator:
    """Get fuse operator."""
    operator_class = Fuses.get_fuse_operator_type(family)
    if operator_class == BlhostFuseOperator:
        iface_params = load_interface_config(
            {"port": port, "usb": usb, "buspal": buspal, "lpcusbsio": lpcusbsio}
        )
        interface_cls = MbootProtocolBase.get_interface_class(iface_params.IDENTIFIER)
        interface = interface_cls.scan_single(**iface_params.get_scan_args())
        return BlhostFuseOperator(McuBoot(interface, family=family))
    if operator_class == BlhostFuseOperatorLegacy:
        iface_params = load_interface_config(
            {"port": port, "usb": usb, "buspal": buspal, "lpcusbsio": lpcusbsio}
        )
        interface_cls = MbootProtocolBase.get_interface_class(iface_params.IDENTIFIER)
        interface = interface_cls.scan_single(**iface_params.get_scan_args())
        return BlhostFuseOperatorLegacy(McuBoot(interface, family=family))
    if operator_class == NxpeleFuseOperator:
        ele_message_handler = EleMessageHandler.get_message_handler(
            family=family,
            device=device,
            fb_addr=fb_addr,
            fb_size=fb_size,
            buffer_addr=buffer_addr,
            buffer_size=buffer_size,
            port=port,
            usb=usb,
            lpcusbsio=lpcusbsio,
            buspal=buspal,
            timeout=timeout,
            uboot_prompt=uboot_prompt,
        )
        return NxpeleFuseOperator(ele_message_handler)
    raise SPSDKTypeError(f"Unsupported fuse operator type: {operator_class.__name__}")


@click.group(name="nxpfuses", cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> None:
    """NXP Fuse Tool."""
    spsdk_logger.install(level=log_level)


@main.command(name="get-template", no_args_is_help=True)
@spsdk_family_option(families=Fuses.get_supported_families())
@spsdk_output_option(force=True)
def get_template(family: FamilyRevision, output: str) -> None:
    """Generate the template of Fuses YAML configuration file."""
    template = Fuses.get_config_template(family)
    write_file(template, output, encoding="utf-8")
    click.echo(
        f"The Fuses template for {family} has been saved into "
        f"{get_printable_path(output)} YAML file"
    )


@main.command(name="write", no_args_is_help=True)
@nxpele_options
@spsdk_config_option(klass=Fuses)
@click.option(
    "-y",
    "--yes",
    is_flag=True,
    default=False,
    help="I accept the risk of writing the fuses.",
)
def write(
    port: Optional[str],
    usb: Optional[str],
    lpcusbsio: Optional[str],
    buspal: Optional[str],
    timeout: int,
    device: Optional[str],
    buffer_addr: Optional[int],
    buffer_size: Optional[int],
    fb_addr: Optional[int],
    fb_size: Optional[int],
    config: Config,
    yes: bool,
    uboot_prompt: Optional[str],
) -> None:
    """Write fuses from configuration into device."""
    permitted = prompt_for_write_permission(yes)
    if not permitted:
        return
    fuses = Fuses.load_from_config(config)
    fuses.fuse_operator = get_fuse_operator(
        family=fuses.family,
        port=port,
        usb=usb,
        lpcusbsio=lpcusbsio,
        buspal=buspal,
        timeout=timeout,
        device=device,
        buffer_addr=buffer_addr,
        buffer_size=buffer_size,
        fb_addr=fb_addr,
        fb_size=fb_size,
        uboot_prompt=uboot_prompt,
    )
    try:
        fuses.write_loaded()
    except SPSDKError as e:
        click.echo(f"{colorama.Fore.RED}Error: {e}{colorama.Fore.RESET}")
        raise SPSDKAppError(str(e)) from e
    click.echo(f"The fuses has been loaded from configuration in {config.config_name} YAML file")


@main.command(name="write-single", no_args_is_help=True)
@nxpele_options
@spsdk_family_option(families=Fuses.get_supported_families())
@click.option(
    "-n", "--name", type=str, required=True, help="Fuse name/uid/otp_index to be written."
)
@click.option("-v", "--value", type=str, required=True, help="The new value of fuse in hex format.")
@click.option("--lock", is_flag=True, default=False, help="Lock the fuse after write.")
@click.option(
    "-y",
    "--yes",
    is_flag=True,
    default=False,
    help="Accept the risk of writing the fuses.",
)
def write_single(
    port: Optional[str],
    usb: Optional[str],
    lpcusbsio: Optional[str],
    buspal: Optional[str],
    timeout: int,
    device: Optional[str],
    buffer_addr: Optional[int],
    buffer_size: Optional[int],
    fb_addr: Optional[int],
    fb_size: Optional[int],
    family: FamilyRevision,
    name: str,
    value: str,
    lock: bool,
    yes: bool,
    uboot_prompt: Optional[str],
) -> None:
    """Write single fuse into device."""
    permitted = prompt_for_write_permission(yes)
    if not permitted:
        return
    fuse_operator = get_fuse_operator(
        family=family,
        port=port,
        usb=usb,
        lpcusbsio=lpcusbsio,
        buspal=buspal,
        timeout=timeout,
        device=device,
        buffer_addr=buffer_addr,
        buffer_size=buffer_size,
        fb_addr=fb_addr,
        fb_size=fb_size,
        uboot_prompt=uboot_prompt,
    )
    fuses = Fuses(family=family, fuse_operator=fuse_operator)
    try:
        otp_index = value_to_int(name)  # name is otp index
        name = fuses.registers.get_by_otp_index(otp_index).uid
    except SPSDKError:
        pass
    fuses.set_value(name, value)
    fuses.write_single(name, lock)
    msg = f"Writing value {value} to the fuse '{name}' succeeded."
    if lock:
        msg += "The fuse lock has been applied."
    click.echo(msg)


@main.command(name="print", no_args_is_help=True)
@nxpele_options
@spsdk_family_option(families=Fuses.get_supported_families())
@click.option(
    "-n",
    "--name",
    help="Fuse name/uid/otp_index to be printed.",
)
@click.option(
    "--rich",
    is_flag=True,
    default=False,
    help="Enables rich format of printed output.",
)
@click.option(
    "-ia",
    "--ignore-access-rights",
    is_flag=True,
    default=False,
    help="Force reading fuses even when access rights are set to WO (Write-Only).",
)
def print_fuses(
    port: Optional[str],
    usb: Optional[str],
    lpcusbsio: Optional[str],
    buspal: Optional[str],
    timeout: int,
    device: Optional[str],
    buffer_addr: Optional[int],
    buffer_size: Optional[int],
    fb_addr: Optional[int],
    fb_size: Optional[int],
    family: FamilyRevision,
    name: Optional[str],
    rich: bool,
    ignore_access_rights: bool,
    uboot_prompt: Optional[str],
) -> None:
    """Print the current state of fuses from device."""
    fuse_operator = get_fuse_operator(
        family=family,
        port=port,
        usb=usb,
        lpcusbsio=lpcusbsio,
        buspal=buspal,
        timeout=timeout,
        device=device,
        buffer_addr=buffer_addr,
        buffer_size=buffer_size,
        fb_addr=fb_addr,
        fb_size=fb_size,
        uboot_prompt=uboot_prompt,
    )
    fuses = Fuses(family=family, fuse_operator=fuse_operator)
    error_count = 0

    if name:
        try:
            otp_index = value_to_int(name)  # name is otp index
            name = fuses.registers.get_by_otp_index(otp_index).uid
            logger.debug(f"OTP index {otp_index} resolved to fuse '{name}'")
        except SPSDKError:
            logger.debug("Cannot resolve OTP index, using name as provided")
        try:
            fuses.read_single(name, force=ignore_access_rights)
            fuse = fuses.registers.find_reg(name, include_group_regs=True)
            print_register_info(
                fuse,
                rich,
            )
        except SPSDKFuseOperationFailure as e:
            logger.debug(f"Permission error, unable to read fuse {name}: {str(e)}")
            click.echo(f"Error: Unable to read fuse '{name}'. Check debug logs for details.")
            click.echo("Use -i option to ignore access rights.")
            error_count += 1
        except SPSDKError as e:
            logger.debug(f"Error occurred, unable to read the fuse {name}: {str(e)}")
            click.echo(f"Error: Unable to read fuse '{name}'. Check debug logs for details.")
            error_count += 1
    else:
        for reg in fuses.registers:
            try:
                fuses.read_single(reg.uid, force=ignore_access_rights)
                print_register_info(reg, rich)
                click.echo()
            except SPSDKFuseOperationFailure as e:
                logger.debug(f"Permission error, unable to read fuse {reg.name}: {str(e)}")
                error_count += 1
            except SPSDKError as e:
                logger.debug(f"Error occurred, unable to read the fuse {reg.name}: {str(e)}")
                error_count += 1

        if error_count > 0:
            click.echo(
                f"Warning: {error_count} fuse(s) could not be read. Check debug logs for details."
            )


@main.command(name="fuses-script", no_args_is_help=True)
@spsdk_config_option(klass=Fuses)
@click.option(
    "--non-default-only",
    is_flag=True,
    default=False,
    help="Filter only registers with non-default values.",
)
@spsdk_output_option(help="Path to a text file with blhost commands, where to store the output.")
def fuses_script(config: Config, output: str, non_default_only: bool) -> None:
    """The command generates blhost/nxpele script to burn fuses from configuration."""
    fuses = Fuses.load_from_config(config)
    fuse_script = fuses.create_fuse_script(loaded_only=True, non_default_only=non_default_only)
    write_file(fuse_script, output)
    click.echo(f"Fuse script for '{fuses.fuse_operator_type.NAME}' has been generated: {output}")


@main.command(name="get-config", no_args_is_help=True)
@nxpele_options
@spsdk_family_option(families=Fuses.get_supported_families())
@spsdk_output_option()
@click.option(
    "-do",
    "--diff-only",
    is_flag=True,
    default=False,
    help="Save differences compared to default values.",
)
@click.option(
    "-ia",
    "--ignore-access-rights",
    is_flag=True,
    default=False,
    help="Force reading fuses even when access rights are set to WO (Write-Only) or Reserved.",
)
def get_config(
    port: Optional[str],
    usb: Optional[str],
    lpcusbsio: Optional[str],
    buspal: Optional[str],
    timeout: int,
    device: Optional[str],
    buffer_addr: Optional[int],
    buffer_size: Optional[int],
    fb_addr: Optional[int],
    fb_size: Optional[int],
    family: FamilyRevision,
    output: str,
    diff_only: bool,
    ignore_access_rights: bool,
    uboot_prompt: Optional[str],
) -> None:
    """Save the current state of fuses to config file."""
    fuse_operator = get_fuse_operator(
        family=family,
        port=port,
        usb=usb,
        lpcusbsio=lpcusbsio,
        buspal=buspal,
        timeout=timeout,
        device=device,
        buffer_addr=buffer_addr,
        buffer_size=buffer_size,
        fb_addr=fb_addr,
        fb_size=fb_size,
        uboot_prompt=uboot_prompt,
    )
    fuses = Fuses(family=family, fuse_operator=fuse_operator)
    with progress_bar(label="Reading fuses") as progress_callback:
        try:
            fuses.read_all(
                force=ignore_access_rights,
                progress_callback=progress_callback,
            )
        except SPSDKFuseOperationFailure as e:
            click.echo(f"{e}. Check debug logs for details.")
        except SPSDKError as exc:
            raise SPSDKAppError(f"Reading the fuses failed: ({str(exc)})") from exc
        finally:
            write_file(fuses.get_config_yaml(diff=diff_only), output)
            click.echo(f"The fuses configuration has been saved into {output}")


@catch_spsdk_error
def safe_main() -> None:
    """Safe main method."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
