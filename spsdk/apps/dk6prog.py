#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""DK6 Prog CLI interface."""
import logging
import os
import sys

import click
import colorama
import hexdump
import prettytable

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import CommandsTreeGroup, spsdk_apps_common_options
from spsdk.apps.utils.utils import (
    INT,
    WARNING_MSG,
    catch_spsdk_error,
    parse_file_and_size,
    parse_hex_data,
    progress_bar,
)
from spsdk.dk6.commands import MemoryId
from spsdk.dk6.dk6device import DK6Device, DK6Memory
from spsdk.dk6.driver import Backend, DriverInterface
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import value_to_int

MEMORY_IDS = {
    "flash": 0,
    "psect": 1,
    "pflash": 2,
    "config": 3,
    "efuse": 4,
    "rom": 5,
    "ram0": 6,
    "ram1": 7,
}

DEFAULT_BAUDRATE = 115200

logger = logging.getLogger(__name__)


def print_memory_table(memories: dict[int, DK6Memory]) -> str:
    """Prints the List of Interfaces to nice colored table."""
    if len(memories) == 0:
        return (
            colorama.Fore.RED
            + "Nothing to print - empty interface list!"
            + colorama.Style.RESET_ALL
        )

    header = [
        "Memory",
        "Memory ID",
        "Base Address",
        "Length",
        "Sector Size",
        "Memory Type",
        "Access",
    ]

    table = prettytable.PrettyTable(header)
    table.align = "l"
    table.header = True
    table.border = True
    table.hrules = prettytable.HRuleStyle.HEADER
    table.vrules = prettytable.VRuleStyle.NONE
    for memory_id, memory in memories.items():
        fields = [
            colorama.Fore.YELLOW + str(MemoryId.get_label(memory_id)),
            colorama.Fore.MAGENTA + str(memory.mem_id.tag),
            colorama.Fore.GREEN + hex(memory.base_address),
            colorama.Fore.RED + hex(memory.length),
            colorama.Fore.MAGENTA + hex(memory.sector_size),
            colorama.Fore.CYAN + str(memory.mem_type.label),
            colorama.Fore.BLUE + str(memory.access.label),
        ]

        table.add_row(fields)

    return table.get_string() + colorama.Style.RESET_ALL


def parse_memory_id(memory_id: str) -> MemoryId:
    """Convert the memory id as name or stringified number into integer.

    :param memory_id: Name or number of the property tag
    :return: memory id integer tag
    """
    try:
        value = value_to_int(memory_id)
        return MemoryId.from_tag(value) if value in MEMORY_IDS.values() else MemoryId.FLASH
    except SPSDKError:
        return MemoryId.from_tag(MEMORY_IDS.get(memory_id.lower(), 0))


def _split_string(string: str, length: int) -> list:
    """Split the string into chunks of same length."""
    return [string[i : i + length] for i in range(0, len(string), length)]


def format_raw_data(data: bytes, use_hexdump: bool = False, line_length: int = 16) -> str:
    """Format bytes data into human-readable form.

    :param data: Data to format
    :param use_hexdump: Use hexdump with addresses and ASCII, defaults to False
    :param line_length: bytes per line, defaults to 32
    :return: formatted string (multilined if necessary)
    """
    if use_hexdump:
        return hexdump.hexdump(data, result="return")
    data_string = data.hex()
    parts = [_split_string(line, 2) for line in _split_string(data_string, line_length * 2)]
    result = "\n".join(" ".join(line) for line in parts)
    return result


def get_dk6(ctx: click.Context) -> DK6Device:
    """Get initialized DK6 Device from click context.

    :param ctx: click Context
    :raises SPSDKError: if the device ID is not specified
    :return: DK6Device
    """
    dk6: DK6Device = ctx.obj["dk6"]
    if dk6 is None:
        raise SPSDKError("You have to specify DEVICE ID")
    dk6.init()

    return dk6


def get_default_backend() -> Backend:
    """Return default backend based on the operating system.

    :return: Backend
    """
    try:
        backend = {
            "win32": Backend.FTD2xx,
            "linux": Backend.PYFTDI,
            "darwin": Backend.PYFTDI,
        }[sys.platform]
    except KeyError:
        logger.warning(
            f"Platform {sys.platform} is not supported. Only Windows, Linux or Mac are supported."
        )
        backend = Backend.PYFTDI
    return backend


@click.group(name="dk6prog", chain=True, no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_apps_common_options
@click.option(
    "-d",
    "--device-id",
    help="DK6 Serial device ID, obtained by list command",
)
@click.option(
    "-r",
    "--baudrate",
    default=DEFAULT_BAUDRATE,
    help=f"Serial port baudrate. Default baud rate is {DEFAULT_BAUDRATE}.",
)
@click.option(
    "-b",
    "--backend",
    "backend",
    type=click.Choice(Backend.__members__, case_sensitive=False),  # type: ignore
    callback=lambda c, p, v: getattr(Backend, v) if v else None,
    help="PYFTDI backend, pure Python implementation of libFTDI.\n"
    + "PYLIBFTDI backend. Ctypes wrapper for libFTDI.\n"
    + "FTD2XX backend. Ctypes wrapper for D2XX.\n"
    + "PYSERIAL backend for simple UART",
)
@click.option(
    "-n",
    "--no-isp",
    "no_isp",
    is_flag=True,
    default=False,
    help="Do not send ISP sequence",
)
@click.pass_context
def main(
    ctx: click.Context,
    device_id: str,
    backend: Backend,
    baudrate: int,
    log_level: int,
    no_isp: bool,
) -> int:
    """Tool for reading and programming flash memory of DK6 target devices.

    This is an experimental utility. Use with caution!
    """
    spsdk_logger.install(level=log_level)
    click.echo(WARNING_MSG)
    backend = backend or get_default_backend()
    interface = DriverInterface(backend)
    if device_id is not None:
        if not no_isp:
            interface.go_to_isp(device_id)
        if baudrate != DEFAULT_BAUDRATE:
            interface.init_serial(device_id, DEFAULT_BAUDRATE)
            dk6 = DK6Device(interface.get_serial())
            dk6.set_baud_rate(baudrate)
            interface.set_baud_rate(baudrate)
        else:
            interface.init_serial(device_id, baudrate)
            dk6 = DK6Device(interface.get_serial())
        dk6.init()
    else:
        dk6 = None

    ctx.obj = {"backend": backend, "interface": interface, "dk6": dk6, "device_id": device_id}
    return 0


@main.command()
@click.pass_context
def listdev(ctx: click.Context) -> None:
    """Prints the information about the connected devices.

    DEVICE_ID identifier is a parameter used for identification of device in other commands.
    """
    interface: DriverInterface = ctx.obj["interface"]
    click.echo("List of available devices:")
    for device in interface.list_devices():
        click.echo(device)


@main.command()
@click.pass_context
def isp(ctx: click.Context) -> None:
    """Issues ISP sequence as defined in Driver interface."""
    interface: DriverInterface = ctx.obj["interface"]
    device_id: str = ctx.obj["device_id"]
    if not device_id:
        raise SPSDKError("You have to specify DEVICE ID")
    interface.go_to_isp(device_id)
    click.echo("Device switched to ISP mode")


@main.command()
@click.argument("address", type=INT(), required=True)
@click.argument("length", type=INT(), required=True)
@click.argument("memory_id", type=str, default="0", required=False)
@click.option(
    "-o",
    "--out-file",
    metavar="FILE",
    type=click.File("wb"),
    required=False,
    help="Save output to file",
)
@click.option("-h", "--use-hexdump", is_flag=True, default=False, help="Use hexdump format")
@click.option(
    "-r",
    "--relative",
    is_flag=True,
    default=False,
    help="Use address relative to memory base address",
)
@click.pass_context
def read(
    ctx: click.Context,
    address: int,
    length: int,
    memory_id: str,
    out_file: click.File,
    use_hexdump: bool,
    relative: bool,
) -> None:
    """Reads the memory and writes it to the file or stdout.

    Returns the contents of memory at the given <ADDRESS>, for a specified <BYTE_COUNT>.

    \b
    ADDRESS     - starting address
    BYTE_COUNT  - number of bytes to read
    FILE        - store result into this file, if not specified use stdout.
                 If needed specify MEMORY_ID argument, use '-' instead name of file
                 to print to stdout.
    MEMORY_ID   - id of memory to read from (default: 0)

    \b
    Available Memory IDs:
     0 or 'PFLASH'
     1 or 'pSECT'
     2 or 'pFlash'
     3 or 'Config'
     4 or 'EFUSE'
     5 or 'ROM'
     6 or 'RAM0'
     7 or 'RAM1'

    """
    dk6 = get_dk6(ctx)

    memory = parse_memory_id(memory_id)

    with progress_bar(label="Reading memory") as progress_callback:
        data = dk6.read_memory(
            memory,
            address,
            length,
            progress_callback=progress_callback,
            relative=relative,
        )

    click.echo(
        f"Read {len(data)}/{length} bytes from {hex(address)}:{hex(address+len(data))} Memory ID: {memory_id}"
    )
    if len(data) > 0:
        if out_file and out_file.name != "<stdout>":
            click.echo(f"Writing data to {out_file.name}")
            out_file.write(data)  # type: ignore
        else:
            click.echo(format_raw_data(data, use_hexdump=use_hexdump))


@main.command()
@click.argument("address", type=INT(), required=True)
@click.argument("data_source", metavar="FILE[,BYTE_COUNT] | {{HEX-DATA}}", type=str, required=True)
@click.argument("length", type=INT(), required=False)
@click.argument("memory_id", type=str, default="0", required=False)
@click.option(
    "-r",
    "--relative",
    is_flag=True,
    default=False,
    help="Use address relative to memory base address",
)
@click.pass_context
def write(
    ctx: click.Context,
    address: int,
    data_source: str,
    length: int,
    memory_id: str,
    relative: bool,
) -> None:
    """Write the memory.

    Writes the data to memory.

    \b
    ADDRESS     - starting address
    FILE        - write the content of this file
    LENGTH      - if specified, load only first LENGTH number of bytes from file
    HEX-DATA    - string of hex values: {{112233}}, {{11 22 33}}
    MEMORY_ID   - id of memory to read from (default: 0)

    \b
    Available Memory IDs:
     0 or 'PFLASH'
     1 or 'pSECT'
     2 or 'pFlash'
     3 or 'Config'
     4 or 'EFUSE'
     5 or 'ROM'
     6 or 'RAM0'
     7 or 'RAM1'

    """
    try:
        data = parse_hex_data(data_source)
    except SPSDKError:
        file_path, length = parse_file_and_size(data_source)
        with open(file_path, "rb") as f:
            data = f.read(length)

    if length == -1:
        length = os.stat(file_path).st_size

    dk6 = get_dk6(ctx)

    memory = parse_memory_id(memory_id)

    with progress_bar(label="Writing memory") as progress_callback:
        dk6.write_memory(
            memory,
            address,
            length,
            data,
            progress_callback=progress_callback,
            relative=relative,
        )

    click.echo(f"Written {length} bytes to memory ID {memory_id} at address {hex(address)}")

    dk6.reset()


@main.command()
@click.argument("address", type=INT(), required=True)
@click.argument("length", type=INT(), required=True)
@click.argument("memory_id", type=str, default="0", required=False)
@click.option(
    "-r",
    "--relative",
    is_flag=True,
    default=False,
    help="Use address relative to memory base address",
)
@click.option(
    "-v",
    "--verify",
    is_flag=True,
    default=False,
    help="Verify that the data were erase using blank check command",
)
@click.pass_context
def erase(
    ctx: click.Context,
    address: int,
    length: int,
    memory_id: str,
    relative: bool,
    verify: bool,
) -> None:
    """Erase the memory.

    Erase the content of memory at the given <ADDRESS>, for a specified <LENGTH>.

    \b
    ADDRESS     - starting address
    LENGTH      - count of bytes to be erased
    MEMORY_ID   - id of memory to erase (default: 0)

    \b
    Available Memory IDs:
     0 or 'PFLASH'
     1 or 'pSECT'
     2 or 'pFlash'
     3 or 'Config'
     4 or 'EFUSE'
     5 or 'ROM'
     6 or 'RAM0'
     7 or 'RAM1'

    """
    dk6 = get_dk6(ctx)

    memory = parse_memory_id(memory_id)

    with progress_bar(label="Erasing memory") as progress_callback:
        dk6.erase_memory(
            memory,
            address,
            length,
            relative=relative,
            verify=verify,
            progress_callback=progress_callback,
        )


@main.command()
@click.pass_context
def info(ctx: click.Context) -> None:
    """Prints the information about the connected device.

    :param ctx: click Context
    :raises SPSDKError: When the DEVICE ID is not specified
    """
    dk6: DK6Device = ctx.obj["dk6"]
    if dk6 is None:
        raise SPSDKError("You have to specify DEVICE ID")

    if dk6.chip_id:
        click.echo(
            f"Chip ID: {hex(dk6.chip_id.chip_id)}\nROM Version: {hex(dk6.chip_id.chip_version)}"
        )

    click.echo(f"MAC Address: {dk6.get_mac_str()}\n")
    if dk6.dev_type:
        click.echo(f"Detected DEVICE: {dk6.dev_type.label}\n")
    click.echo(print_memory_table(dk6.memories))


@catch_spsdk_error
def safe_main() -> None:
    """Calls the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
