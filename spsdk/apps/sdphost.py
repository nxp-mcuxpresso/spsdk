#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for SDP module aka SDPHost."""

import inspect
import json
import sys
from typing import Optional

import click

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_apps_common_options,
    spsdk_output_option,
    spsdk_sdp_interface,
    spsdk_use_json_option,
)
from spsdk.apps.utils.utils import INT, SPSDKAppError, catch_spsdk_error, format_raw_data
from spsdk.sdp.commands import ResponseValue
from spsdk.sdp.protocol.base import SDPProtocolBase
from spsdk.sdp.sdp import SDP
from spsdk.utils import misc


@click.group(name="sdphost", no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_sdp_interface()
@spsdk_use_json_option
@spsdk_apps_common_options
@click.pass_context
def main(
    ctx: click.Context,
    interface: SDPProtocolBase,
    use_json: bool,
    log_level: int,
) -> int:
    """Utility for communication with ROM on i.MX targets using SDP protocol."""
    spsdk_logger.install(level=log_level)
    ctx.obj = {
        "interface": interface,
        "use_json": use_json,
    }
    return 0


@main.command()
@click.pass_context
def error_status(ctx: click.Context) -> None:
    """Reads the error code from the device."""
    with SDP(ctx.obj["interface"]) as sdp:
        response = sdp.read_status()
    display_output(
        [response],
        sdp.hab_status,
        ctx.obj["use_json"],
        extra_output=f"Response status = {decode_status_code(response)}.",
    )


@main.command()
@click.argument("address", type=INT(), required=True)
@click.pass_context
def jump_address(ctx: click.Context, address: int) -> None:
    """Jumps to the entry point of the image at the given address.

    jump-address will result in the execution of the image once the ROM process
    the IVT and on successful authentication of the image.

    \b
    ADDRESS - starting address of the image
    """
    with SDP(ctx.obj["interface"]) as sdp:
        sdp.jump_and_run(address)
    display_output([], sdp.hab_status)


@main.command()
@click.argument("address", type=INT(), required=True)
@click.argument("bin_file", metavar="FILE", type=click.File("rb"), required=True)
@click.argument("count", type=INT(), required=False)
@click.pass_context
def write_file(ctx: click.Context, address: int, bin_file: click.File, count: int) -> None:
    """Writes file to the device's memory address.

    \b
    ADDRESS - starting address of the image
    FILE    - binary file to write
    COUNT   - Count is the size of data to write in bytes (default: whole file)
    """
    data = bin_file.read(count)  # type: ignore
    with SDP(ctx.obj["interface"]) as sdp:
        sdp.write_file(address, data)
    display_output(
        [],
        sdp.hab_status,
        extra_output=f"Response status = {decode_status_code(sdp.cmd_status)}.",
    )


@main.command()
@click.argument("address", type=INT(), required=True)
@click.argument("item_length", type=INT(), required=False, default="32", metavar="[FORMAT]")
@click.argument("count", type=INT(), required=False, default=None)
@spsdk_output_option(required=False)
@click.option("-h", "--use-hexdump", is_flag=True, default=False, help="Use hexdump format")
@click.pass_context
def read_register(
    ctx: click.Context,
    address: int,
    item_length: int,
    count: int,
    output: str,
    use_hexdump: bool,
) -> None:
    """Reads the contents of a memory location or register value.

    The address of the register or memory location should be passed in as the first argument.
    Optional arguments include the data format of the register value in the number of bits
    and number of bytes to read.

    \b
    ADDRESS - starting address where to read
    FORMAT  - bits per item: valid values: 8, 16, 32; default 32
    COUNT   - bytes to read; default size of FORMAT
    """
    with SDP(ctx.obj["interface"]) as sdp:
        response = sdp.read_safe(address, count, item_length)
    if not response:
        raise SPSDKAppError(
            f"Error: invalid sub-command or arguments 'read-register {address:#8X} {item_length} {count}'"
        )
    if output:
        misc.write_file(response, output, mode="wb")
        click.echo(f"{len(response)} bytes written to {output}")
    else:
        click.echo(format_raw_data(response, use_hexdump=use_hexdump))
    display_output([], sdp.hab_status, ctx.obj["use_json"])


@click.argument("baudrate", type=INT(), required=True)
@main.command()
@click.pass_context
def set_baudrate(ctx: click.Context, baudrate: int) -> None:
    """Configures UART baudrate.

    The SDP command SET_BAUDRATE is used by the host to configure the UART
    baudrate on the device side. The default baudrate is 115200.
    Please note that this command is not supported on all devices.

    \b
    BAUDRATE - baudrate to be set
    """
    with SDP(ctx.obj["interface"]) as sdp:
        response = sdp.set_baudrate(baudrate)
    display_output(
        [response],
        sdp.hab_status,
        ctx.obj["use_json"],
        extra_output=f"Response status = {decode_status_code(response)}.",
    )


def display_output(
    response: list, status_code: int, use_json: bool = False, extra_output: Optional[str] = None
) -> None:
    """Printout the response.

    :param response: Response list to display
    :param status_code: Response status
    :param use_json: use JSON output format
    :param extra_output: Extra string to display
    """
    if use_json:
        data = {
            # get the name of a caller function and replace _ with -
            "command": inspect.stack()[1].function.replace("_", "-"),
            # this is just a visualization thing
            "response": response or [],
            "status": {
                "description": decode_status_code(status_code),
                "value": status_code,
            },
        }
        print(json.dumps(data, indent=3))
    else:
        print(f"Status (HAB mode) = {decode_status_code(status_code)}.")
        if extra_output:
            print(extra_output)


def decode_status_code(status_code: Optional[int] = None) -> str:
    """Returns a stringified representation of status code.

    :param status_code: SDP status code
    :return: stringified representation
    """
    if not status_code:
        return "UNKNOWN ERROR"
    no_desc = "NO DESCRIPTION"
    desc = (
        ResponseValue.get_description(status_code, no_desc)
        if ResponseValue.contains(status_code)
        else no_desc
    )
    return f"{status_code} ({status_code:#x}) {desc}"


@catch_spsdk_error
def safe_main() -> None:
    """Calls the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
