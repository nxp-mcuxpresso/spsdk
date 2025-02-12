#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Programmer for LPC8xx parts."""

import sys
from typing import Optional

import click

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    is_click_help,
    spsdk_apps_common_options,
    spsdk_family_option,
    spsdk_revision_option,
    timeout_option,
)
from spsdk.apps.utils.utils import (
    INT,
    catch_spsdk_error,
    format_raw_data,
    parse_file_and_size,
    parse_hex_data,
    progress_bar,
)
from spsdk.exceptions import SPSDKError
from spsdk.lpcprog.device import LPCDevice
from spsdk.lpcprog.interface import LPCProgInterface
from spsdk.lpcprog.protocol import LPCProgProtocol
from spsdk.utils.interfaces.device.serial_device import SerialDevice
from spsdk.utils.misc import load_binary


@click.group(name="lpcprog", no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_apps_common_options
@spsdk_family_option(families=LPCProgProtocol.get_supported_families(), required=False)
@spsdk_revision_option
@click.option("-p", "--port", help="Port/device for serial communication")
@timeout_option(timeout=1000)
@click.option(
    "-b",
    "--baudrate",
    help="baudrate",
    default="115200",
    type=click.Choice(choices=LPCProgProtocol.ALLOWED_BAUD_RATES_STR, case_sensitive=False),
)
@click.pass_context
def main(
    ctx: click.Context,
    port: str,
    timeout: int,
    baudrate: str,
    log_level: int,
    family: str,
    revision: str = "latest",
) -> int:
    """Utility for communication with the bootloader on target."""
    spsdk_logger.install(level=log_level)

    ctx.obj = None

    # if --help is provided anywhere on command line, skip interface lookup and display help message
    # Or the command doesn't need communication with target.
    if is_click_help(ctx, sys.argv):
        return 0

    if not port:
        raise SPSDKError("Port must be provided")

    device = SerialDevice(port, timeout, int(baudrate))
    interface = LPCProgInterface(device)
    lpc_device = None
    if family:
        lpc_device = LPCDevice(family, revision)
    protocol = LPCProgProtocol(interface, print_func=click.echo, device=lpc_device)

    ctx.obj = {"protocol": protocol}

    return 0


@click.argument("length", type=INT(), required=True)
@click.argument("address", type=INT(), required=True)
@click.option("-b", "--binary", help="Path to output binary file", type=str, required=False)
@click.option("-r", "--raw", is_flag=True, default=False, help="Do not use hexdump format")
@main.command(no_args_is_help=True)
@click.pass_context
def read_memory(
    ctx: click.Context, address: int, length: int, raw: bool, binary: Optional[str]
) -> None:
    """This command is used to read data from RAM or flash memory.

    This command is blocked when code read protection is enabled.
    """
    protocol: LPCProgProtocol = ctx.obj["protocol"]
    with progress_bar(label="Reading memory") as progress_callback:
        read_data = protocol.read_memory(address, length, binary, progress_callback)

    if not binary:
        click.echo(format_raw_data(read_data, use_hexdump=not raw))
    else:
        click.echo(f"Data read from memory has been saved to {binary}")


@click.argument("end", type=INT(), required=True)
@click.argument("start", type=INT(), required=True)
@main.command(no_args_is_help=True)
@click.pass_context
def erase_sector(ctx: click.Context, start: int, end: int) -> None:
    """Erase one or more sectors of on-chip memory."""
    protocol: LPCProgProtocol = ctx.obj["protocol"]
    protocol.unlock(print_status=False)
    protocol.prepare_sectors_for_write(start, end, print_status=False)
    protocol.erase_sector(start, end)


@click.argument("end", type=INT(), required=True, metavar="END_INDEX")
@click.argument("start", type=INT(), required=True, metavar="START_INDEX")
@main.command(no_args_is_help=True)
@click.pass_context
def erase_page(ctx: click.Context, start: int, end: int) -> None:
    """Erase one or more page(s) of on-chip flash memory.

    Start and end are page indices.
    """
    protocol: LPCProgProtocol = ctx.obj["protocol"]
    protocol.unlock(print_status=False)
    protocol.prepare_sectors_for_write(start // 16, end // 16 + 1, print_status=False)
    protocol.erase_page(start, end)


@main.command()
@click.pass_context
def unlock(ctx: click.Context) -> None:
    """This command is used to unlock Flash Write, Erase, and Go commands."""
    protocol: LPCProgProtocol = ctx.obj["protocol"]
    protocol.unlock()


@click.option(
    "-r",
    "--baud-rate",
    help="Baud rate",
    type=click.Choice(choices=LPCProgProtocol.ALLOWED_BAUD_RATES_STR, case_sensitive=False),
    required=True,
)
@click.option("-s", "--stop-bits", help="Stop bits", type=INT(), default="1", required=False)
@main.command(no_args_is_help=True)
@click.pass_context
def set_baud_rate(ctx: click.Context, baud_rate: str, stop_bits: int = 1) -> None:
    """This command is used to change the baud rate."""
    protocol: LPCProgProtocol = ctx.obj["protocol"]
    protocol.set_baud_rate(int(baud_rate), stop_bits)


@click.argument("echo", type=click.BOOL, required=True)
@main.command(no_args_is_help=True)
@click.pass_context
def set_echo(ctx: click.Context, echo: bool) -> None:
    """When ON the ISP command handler sends the received serial data back to the host."""
    protocol: LPCProgProtocol = ctx.obj["protocol"]
    protocol.set_echo(echo)


@click.option(
    "-b",
    "--binary",
    help="Binary file to program",
    metavar="FILE[,BYTE_COUNT] | {{HEX-DATA}}",
    type=str,
    required=True,
)
@click.option(
    "-a",
    "--address",
    type=INT(),
    help="RAM address where data bytes are to be written.",
)
@main.command(no_args_is_help=True)
@click.pass_context
def write_ram(ctx: click.Context, address: int, binary: str) -> None:
    """Download data to RAM."""
    try:
        data = parse_hex_data(binary)
    except SPSDKError:
        file_path, size = parse_file_and_size(binary)
        with open(file_path, "rb") as f:
            data = f.read(size)
    protocol: LPCProgProtocol = ctx.obj["protocol"]
    protocol.write_ram(address, data)
    click.echo("Data has been written to RAM")


@click.option("-f", "--frequency", help="Crystal frequency", default="12000", type=INT())
@click.option("-r", "--retries", help="Retries for synchronization", default="10", type=INT())
@main.command()
@click.pass_context
def sync(ctx: click.Context, frequency: int, retries: int) -> None:
    """Sync connection."""
    protocol: LPCProgProtocol = ctx.obj["protocol"]
    protocol.sync_connection(frequency, retries)


@main.command()
@click.pass_context
def get_info(ctx: click.Context) -> None:
    """Get information about the chip."""
    protocol: LPCProgProtocol = ctx.obj["protocol"]
    click.echo(protocol.get_info())


@click.argument("end", type=INT(), required=True, metavar="END_INDEX")
@click.argument("start", type=INT(), required=True, metavar="START_INDEX")
@main.command(no_args_is_help=True)
@click.pass_context
def prepare_sectors(ctx: click.Context, start: int, end: int) -> None:
    """Prepare one or more sector(s) of on-chip flash memory.

    Start and end are page indices.

    This command must be executed before executing
    "Copy RAM to flash" or "Erase Sector(s)", or “Erase Pages” command.
    """
    protocol: LPCProgProtocol = ctx.obj["protocol"]
    protocol.prepare_sectors_for_write(start, end)


@main.command(no_args_is_help=True)
@click.argument("address", type=INT(), required=True)
@click.option("-t", "--thumb", is_flag=True, default=False, help="Thumb mode")
@click.pass_context
def go(ctx: click.Context, address: int, thumb: bool) -> None:
    """Execute a program residing in RAM or flash memory.."""
    protocol: LPCProgProtocol = ctx.obj["protocol"]
    protocol.go(address, thumb)


@click.option("-b", "--binary", help="Binary file to program", required=True, metavar="FILE")
@click.option("-s", "--sector", type=INT(), default="0", help="Start sector, defaults to 0")
@click.option("-p", "--page", type=INT(), help="Start page, choose sector or page")
@click.option(
    "--verify/--no-verify", is_flag=True, default=True, help="Do not verify after programming"
)
@click.option(
    "--erase/--no-erase", is_flag=True, default=True, help="Do not erase before programming"
)
@main.command(no_args_is_help=True)
@click.pass_context
def program_flash(
    ctx: click.Context,
    binary: str,
    sector: int = 0,
    page: Optional[int] = None,
    verify: bool = True,
    erase: bool = True,
) -> None:
    """This command is used for programming the flash memory.

    Choose either sector or page.

    Before programming, the flash sector is erased.
    Data are aligned to page size and the copied to RAM before writing the sector.
    After programming, verification of data is performed.
    """
    protocol: LPCProgProtocol = ctx.obj["protocol"]
    bin_data = load_binary(binary)
    with progress_bar(label="Programming flash memory") as progress_callback:
        protocol.program_flash(
            bin_data, sector, page, progress_callback, erase=erase, verify=verify
        )


@click.argument("length", type=INT(), required=True)
@click.argument("destination", type=INT(), required=True)
@click.argument("source", type=INT(), required=True)
@main.command(no_args_is_help=True)
@click.pass_context
def compare(ctx: click.Context, source: int, destination: int, length: int) -> None:
    """This command is used to compare the memory contents at two locations."""
    protocol: LPCProgProtocol = ctx.obj["protocol"]
    protocol.compare(source, destination, length)


@click.argument("end", type=INT(), required=True)
@click.argument("start", type=INT(), required=True)
@main.command(no_args_is_help=True)
@click.pass_context
def blank_check_sectors(ctx: click.Context, start: int, end: int) -> None:
    """This command is used to blank check one or more sectors of on-chip flash memory."""
    protocol: LPCProgProtocol = ctx.obj["protocol"]
    protocol.blank_check_sectors(start, end)


@click.option("-w", "--wait-states", default=2, help="Number of wait states")
@click.option("-m", "--mode", default=0, help="Flash controller mode")
@click.argument("end", type=INT(), required=True)
@click.argument("start", type=INT(), required=True)
@main.command(no_args_is_help=True)
@click.pass_context
def read_flash_signature(
    ctx: click.Context, start: int, end: int, wait_states: int = 2, mode: int = 0
) -> None:
    """This command is used to read the flash signature generated by the flash controller."""
    protocol: LPCProgProtocol = ctx.obj["protocol"]
    signature = protocol.read_flash_signature(start, end, wait_states, mode)
    if signature:
        click.echo(f"Signature: {hex(signature)}")


@click.argument("length", type=INT(), required=True)
@click.argument("address", type=INT(), required=True)
@main.command(no_args_is_help=True)
@click.pass_context
def read_crc_checksum(ctx: click.Context, address: int, length: int) -> None:
    """This command is used to read the CRC checksum of a block of RAM or flash memory."""
    protocol: LPCProgProtocol = ctx.obj["protocol"]
    checksum = protocol.read_crc_checksum(address, length)
    if checksum:
        click.echo(f"Checksum: {hex(checksum)}")
    else:
        click.echo("Checksum cannot be read")


@catch_spsdk_error
def safe_main() -> None:
    """Calls the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
