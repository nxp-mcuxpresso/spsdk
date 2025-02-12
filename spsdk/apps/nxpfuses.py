#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Fuse Tool CLI interface."""

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
    spsdk_revision_option,
)
from spsdk.apps.utils.interface_helper import load_interface_config
from spsdk.apps.utils.utils import SPSDKAppError, catch_spsdk_error, progress_bar
from spsdk.ele.ele_comm import EleMessageHandler
from spsdk.exceptions import SPSDKError, SPSDKTypeError
from spsdk.fuses.fuse_registers import FuseRegister
from spsdk.fuses.fuses import (
    BlhostFuseOperator,
    FuseOperator,
    Fuses,
    NxpeleFuseOperator,
    SPSDKFuseOperationFailure,
)
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.utils.misc import get_printable_path, load_configuration, value_to_int, write_file
from spsdk.utils.schema_validator import CommentedConfig

logger = logging.getLogger(__name__)


def print_register_info(fuse_register: FuseRegister, rich: bool = False) -> None:
    """Print info about a fuse register.

    :param fuse_register: Fuse register to be printed
    :param rich: Print additional information
    """
    click.echo(f"Fuse name:        {fuse_register.name}")
    if fuse_register.otp_index is not None:  # all non-grouped registers
        click.echo(f"Fuse OTP index:   {hex(fuse_register.otp_index)}")
    value = fuse_register.get_hex_value()
    click.echo(f"Fuse value:       {fuse_register.get_hex_value()}")
    click.echo(f"Fuse access:      {fuse_register.access.description}")
    locks = fuse_register.get_active_locks()
    click.echo(
        f"Fuse locks:       {','.join([lock.label for lock in locks]) if locks else 'No locks'}"
    )
    if value != fuse_register.get_hex_value(raw=True):
        click.echo(f"Fuse raw value:   {fuse_register.get_hex_value(raw=True)}")
    if rich:
        click.echo(f"Fuse description: {fuse_register.description}")
        click.echo(f"Fuse address:     0x{fuse_register.offset:08X}")
        click.echo(f"Fuse width:       {fuse_register.width} bits")


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
    family: str,
    revision: str,
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
) -> FuseOperator:
    """Get fuse operator."""
    operator_class = Fuses.get_fuse_operator_type(family, revision)
    if operator_class == BlhostFuseOperator:
        iface_params = load_interface_config(
            {"port": port, "usb": usb, "buspal": buspal, "lpcusbsio": lpcusbsio}
        )
        interface_cls = MbootProtocolBase.get_interface_class(iface_params.IDENTIFIER)
        interface = interface_cls.scan_single(**iface_params.get_scan_args())
        return BlhostFuseOperator(McuBoot(interface))
    if operator_class == NxpeleFuseOperator:
        ele_message_handler = EleMessageHandler.get_message_handler(
            family=family,
            revision=revision,
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
        )
        return NxpeleFuseOperator(ele_message_handler)
    raise SPSDKTypeError(f"Unsupported fuse operator type: {operator_class.__name__}")


@click.group(name="nxpfuses", no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_apps_common_options
def main(log_level: int) -> None:
    """NXP Fuse Tool."""
    spsdk_logger.install(level=log_level)


@main.command(name="get-template", no_args_is_help=True)
@spsdk_family_option(families=Fuses.get_supported_families())
@spsdk_revision_option
@spsdk_output_option(force=True)
def get_template(family: str, revision: str, output: str) -> None:
    """Generate the template of Fuses YAML configuration file."""
    template = Fuses.generate_config_template(family, revision)
    write_file(template, output, encoding="utf-8")
    click.echo(
        f"The Fuses template for {family} has been saved into "
        f"{get_printable_path(output)} YAML file"
    )


@main.command(name="write", no_args_is_help=True)
@nxpele_options
@spsdk_config_option()
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
    config: str,
    yes: bool,
) -> None:
    """Write fuses from configuration into device."""
    exit_code = 0

    def write_fuse(fuses: Fuses, name: str) -> int:
        """Handle writing the fuses into device.

        :return: Number of errors
        """
        try:
            fuses.write_single(name)
        except SPSDKFuseOperationFailure as exc:
            logger.error(f"Fuse '{name}' was not written as it is not writeable: {exc}")
            return 1
        except SPSDKError as exc:
            logger.error(f"Error when writing the fuse '{name}' to the device: {exc}")
            return 1
        return 0

    permitted = prompt_for_write_permission(yes)
    if not permitted:
        return
    config_data = load_configuration(config)
    fuses = Fuses.load_from_config(config_data)
    fuses.fuse_operator = get_fuse_operator(
        family=fuses.family,
        revision=fuses.revision,
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
    )
    # first we need to write non-lock fuses as they may lock other fuses to be written
    all_lock_fuses = fuses.fuse_regs.get_lock_fuses()
    lock_fuses: list[FuseRegister] = []
    for fuse in fuses.fuse_context:
        if fuse not in all_lock_fuses:
            exit_code += write_fuse(fuses, fuse.uid)
        else:
            lock_fuses.append(fuse)
    # now we can write lock fuses from the configuration
    for fuse in lock_fuses:
        exit_code += write_fuse(fuses, fuse.uid)
    if exit_code:
        raise SPSDKAppError(
            f"{colorama.Fore.RED}Writing the fuses failed with {exit_code} error(s){colorama.Fore.RESET}\n"
        )
    click.echo("Writing of fuses succeeded.")


@main.command(name="write-single", no_args_is_help=True)
@nxpele_options
@spsdk_family_option(families=Fuses.get_supported_families())
@spsdk_revision_option
@click.option(
    "-n", "--name", type=str, required=True, help="Fuse name/uid/otp_index to be written."
)
@click.option("-v", "--value", type=str, required=True, help="The new value of fuse in hex format.")
@click.option("-l", "--lock", is_flag=True, default=False, help="Lock the fuse after write.")
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
    family: str,
    revision: str,
    name: str,
    value: str,
    lock: bool,
    yes: bool,
) -> None:
    """Write single fuse into device."""
    permitted = prompt_for_write_permission(yes)
    if not permitted:
        return
    fuse_operator = get_fuse_operator(
        family=family,
        revision=revision,
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
    )
    fuses = Fuses(family=family, revision=revision, fuse_operator=fuse_operator)
    try:
        otp_index = value_to_int(name)  # name is otp index
        name = fuses.fuse_regs.get_by_otp_index(otp_index).uid
    except SPSDKError:
        pass
    fuse = fuses.fuse_regs.find_reg(name, include_group_regs=True)
    fuse.set_value(value)
    fuses.write_single(name, lock)
    msg = f"Writing value {value} to the fuse '{name}' succeeded."
    if lock:
        msg += "The fuse lock has been applied."
    click.echo(msg)


@main.command(name="print", no_args_is_help=True)
@nxpele_options
@spsdk_family_option(families=Fuses.get_supported_families())
@spsdk_revision_option
@click.option(
    "-n",
    "--name",
    help="Fuse name/uid/otp_index to be printed.",
)
@click.option(
    "-r",
    "--rich",
    is_flag=True,
    default=False,
    help="Enables rich format of printed output.",
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
    family: str,
    revision: str,
    name: Optional[str],
    rich: bool,
) -> None:
    """Print the current state of fuses from device."""
    fuse_operator = get_fuse_operator(
        family=family,
        revision=revision,
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
    )
    fuses = Fuses(family=family, revision=revision, fuse_operator=fuse_operator)
    if name:
        try:
            otp_index = value_to_int(name)  # name is otp index
            name = fuses.fuse_regs.get_by_otp_index(otp_index).uid
        except SPSDKError:
            pass
        fuses.read_single(name)
        fuse = fuses.fuse_regs.find_reg(name)
        print_register_info(fuse, rich)
    else:
        for reg in fuses.fuse_regs:
            try:
                fuses.read_single(reg.uid)
                print_register_info(reg, rich)
                click.echo()
            except SPSDKFuseOperationFailure as e:
                logger.warning(f"Permission error, unable to read fuse {reg.name}: {str(e)}")
            except SPSDKError as e:
                logger.warning(f"Error occurred, unable to read the fuse {reg.name}: {str(e)}")


@main.command(name="fuses-script", no_args_is_help=True)
@spsdk_config_option(required=True)
@spsdk_output_option(help="Path to a text file with blhost commands, where to store the output.")
def fuses_script(config: str, output: str) -> None:
    """The command generates blhost/nxpele script to burn fuses from configuration."""
    config_data = load_configuration(config)
    fuses = Fuses.load_from_config(config_data)
    fuse_script = fuses.create_fuse_script()
    write_file(fuse_script, output)
    click.echo(f"Fuse script for '{fuses.fuse_operator_type.NAME}' has been generated: {output}")


@main.command(name="get-config", no_args_is_help=True)
@nxpele_options
@spsdk_family_option(families=Fuses.get_supported_families())
@spsdk_revision_option
@spsdk_output_option()
@click.option(
    "-d",
    "--diff-only",
    is_flag=True,
    default=False,
    help="Save differences compared to default values.",
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
    family: str,
    revision: str,
    output: str,
    diff_only: bool,
) -> None:
    """Save the current state of fuses to config file."""
    fuse_operator = get_fuse_operator(
        family=family,
        revision=revision,
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
    )
    fuses = Fuses(family=family, revision=revision, fuse_operator=fuse_operator)
    try:
        total = 0
        with progress_bar(label="Reading fuses") as progress_callback:
            for reg in fuses.fuse_regs:
                try:
                    fuses.read_single(reg.uid)
                    progress_callback(total, len(fuses.fuse_regs))
                except SPSDKFuseOperationFailure as e:
                    logger.warning(f"Permission error, unable to read fuse {reg.name}: {str(e)}")
                except SPSDKError as e:
                    logger.warning(f"Error occurred, unable to read the fuse {reg.name}: {str(e)}")
                finally:
                    total += 1
    except SPSDKError as exc:
        raise SPSDKAppError(f"Reading the fuses failed: ({str(exc)})") from exc
    cfg = fuses.get_config(diff_only)
    schemas = fuses.get_validation_schemas(fuses.family, fuses.revision)
    ret = CommentedConfig(main_title="Fuses configuration", schemas=schemas).get_config(cfg)
    write_file(ret, output)
    click.echo(f"The fuses configuration has been saved into {output}")


@catch_spsdk_error
def safe_main() -> None:
    """Safe main method."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
