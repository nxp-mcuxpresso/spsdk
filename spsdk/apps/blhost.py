#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for MBoot module aka BLHost."""

import inspect
import json
import logging
import sys

import click
from click_option_group import MutuallyExclusiveOptionGroup, optgroup

from spsdk import __version__ as spsdk_version
from spsdk.apps.utils import INT, get_interface, format_raw_data, catch_spsdk_error
from spsdk.mboot import McuBoot, StatusCode, parse_property_value


@click.group()
@optgroup.group('Interface configuration', cls=MutuallyExclusiveOptionGroup)
@optgroup.option('-p', '--port', metavar='COM[,speed]', help='Serial port')
@optgroup.option('-u', '--usb', metavar='PID,VID', help='USB device\'s PID:VID')
@click.option('-j', '--json', 'use_json', is_flag=True, help='Use JSON output')
@click.option('-v', '--verbose', 'log_level', flag_value=logging.INFO, help='Display more verbose output')
@click.option('-d', '--debug', 'log_level', flag_value=logging.DEBUG, help='Display debugging info')
@click.option('-t', '--timeout', metavar='<ms>', help='Set packet timeout in milliseconds', default=5000)
@click.version_option(spsdk_version, '--version')
@click.pass_context
def main(ctx: click.Context, port: str, usb: str, use_json: bool, log_level: int, timeout: int) -> int:
    """Utility for communication with bootloader on target."""
    logging.basicConfig(level=log_level or logging.WARNING)
    # if --help is provided anywhere on commandline, skip interface lookup and display help message
    if '--help' in sys.argv:
        port, usb = None, None  # type: ignore
    ctx.obj = {
        'interface': get_interface(
            module='mboot', port=port, usb=usb, timeout=timeout
        ) if port or usb else None,
        'use_json': use_json
    }
    return 0


@main.command()
@click.argument('memory_id', type=INT(), required=True)
@click.argument('address', type=INT(), required=True)
@click.pass_context
def configure_memory(ctx: click.Context, address: int, memory_id: int) -> None:
    """Apply configuration block at internal memory address <ADDRESS> to memory with ID <MEMORY_ID>.

    \b
    MEMORY_ID   - id of memory
    ADDRESS     - starting address
    """
    with McuBoot(ctx.obj['interface']) as mboot:
        mboot.configure_memory(address, memory_id)  # type: ignore
        display_output([], mboot.status_code, ctx.obj['use_json'])


@main.command()
@click.argument('address', type=INT(), required=True)
@click.argument('data', type=INT(base=16), required=True)
@click.pass_context
def efuse_program_once(ctx: click.Context, address: int, data: int) -> None:
    """Program one word of OCOTP Field.

    \b
    ADDRESS - address of OTP word, not the shadowed memory address.
    DATA    - hex digits without prefix '0x'.
    """
    with McuBoot(ctx.obj['interface']) as mboot:
        response = mboot.efuse_program_once(address, data)
        display_output([response], mboot.status_code, ctx.obj['use_json'])


@main.command()
@click.argument('address', type=INT(), required=True)
@click.pass_context
def efuse_read_once(ctx: click.Context, address: int) -> None:
    """Read one word of OCOTP Field.

    \b
    ADDRESS - is address of OTP word, not the shadowed memory address.
    """
    with McuBoot(ctx.obj['interface']) as mboot:
        response = mboot.efuse_read_once(address)
        display_output([4, response], mboot.status_code, ctx.obj['use_json'])


@main.command()
@click.argument('address', type=INT(), required=True)
@click.argument('byte_count', type=INT(), required=True)
@click.argument('memory_id', type=int, required=False, default=0)
@click.pass_context
def flash_erase_region(ctx: click.Context, address: int, byte_count: int, memory_id: int) -> None:
    """Erase region of the flash.

    \b
    ADDRESS     - starting address
    BYTE_COUNT  - number of bytes to erase
    MEMORY_ID   - id of memory to erase (default: 0)
    """
    with McuBoot(ctx.obj['interface']) as mboot:
        mboot.flash_erase_region(address, byte_count, memory_id)
        display_output([], mboot.status_code, ctx.obj['use_json'])


@main.command()
@click.argument('address', type=INT(), required=True)
@click.argument('byte_count', type=INT(), required=True)
@click.argument('pattern', type=INT(), required=True)
@click.argument('pattern_format', metavar='format', type=click.Choice(['word', 'short', 'byte']),
                required=False, default='word')
@click.pass_context
def fill_memory(ctx: click.Context, address: int, byte_count: int,
                pattern: int, pattern_format: str) -> None:
    """Fill memory with pattern.

    \b
    ADDRESS     - starting address
    BYTE_COUNT  - number of bytes to fill
    PATTERN     - pattern to fill
    FORMAT      - format of the pattern [word|short|byte] (default: word)
    """
    del pattern_format  # temporary workaround for not unused parameter
    with McuBoot(ctx.obj['interface']) as mboot:
        mboot.fill_memory(address, byte_count, pattern)
        display_output([], mboot.status_code, ctx.obj['use_json'])


@main.command()
@click.argument('property_tag', type=int, default=1, required=True)
@click.argument('index', type=int, default=0)
@click.pass_context
def get_property(ctx: click.Context, property_tag: int, index: int) -> None:
    """Get bootloader-specific property.

    \b
    PROPERTY_TAG - number represeting the requested property
    MEMORY_ID    - id/index of the memory (default: 0)
    """
    with McuBoot(ctx.obj['interface']) as mboot:
        response = mboot.get_property(property_tag, index=index)  # type: ignore
        assert response, f"Error reading property {property_tag}"
        display_output(
            response, mboot.status_code, ctx.obj['use_json'],
            parse_property_value(property_tag, response)
        )


@main.command()
@click.argument('address', type=INT(), required=True)
@click.argument('byte_count', type=INT(), required=True)
@click.argument('out_file', metavar='FILE', type=click.File('wb'), required=False)
@click.argument('memory_id', type=int, default=0, required=False)
@click.option('-h', '--use-hexdump', is_flag=True, default=False, help='Use hexdump format')
@click.pass_context
def read_memory(ctx: click.Context, address: int, byte_count: int,
                out_file: click.File, memory_id: int, use_hexdump: bool) -> None:
    """Read memory.

    \b
    ADDRESS     - starting address
    BYTE_COUNT  - number of bytes to read
    FILE        - store result into this file, if not specified use stdout
    MEMORY_ID   - id of memory to read from (default: 0)
    """
    with McuBoot(ctx.obj['interface']) as mboot:
        response = mboot.read_memory(address, byte_count, memory_id)
    assert response, "Error reading memory"
    if out_file:
        out_file.write(response)  # type: ignore
    else:
        click.echo(format_raw_data(response, use_hexdump=use_hexdump))

    display_output(
        [len(response)], mboot.status_code, ctx.obj['use_json'],
        f"Read {len(response)} of {byte_count} bytes."
    )


@main.command()
@click.pass_context
def reset(ctx: click.Context) -> None:
    """Reset the device."""
    with McuBoot(ctx.obj['interface']) as mboot:
        mboot.reset(reopen=False)
    display_output([], mboot.status_code, ctx.obj['use_json'])


@main.command()
@click.argument('address', type=INT(), required=True)
@click.argument('in_file', metavar='FILE', type=click.File('rb'), required=True)
@click.argument('memory_id', type=int, required=False, default=0)
@click.pass_context
def write_memory(ctx: click.Context, address: int, in_file: click.File, memory_id: int) -> None:
    """Write memory.

    \b
    ADDRESS     - starting address
    FILE        - write content of this file
    MEMORY_ID   - id of memory to read from (default: 0)
    """
    with McuBoot(ctx.obj['interface']) as mboot:
        data = in_file.read()  # type: ignore
        write_response = mboot.write_memory(address, data, memory_id)
        assert write_response, f"Error writing memory addr={address:#0x} memory_id={memory_id}"
        display_output([write_response], mboot.status_code, ctx.obj['use_json'])


@main.command()
@click.argument('dek_file', type=click.File('rb'), required=True)
@click.argument('blob_file', type=click.File('wb'), required=True)
@click.pass_context
def generate_key_blob(ctx: click.Context, dek_file: click.File, blob_file: click.File) -> None:
    """Generate the Key Blob for a given DEK.

    \b
    DEK_FILE     - the file with the binary DEK key
    BLOB_FILE    - the generated file with binary key blob
    """
    with McuBoot(ctx.obj['interface']) as mboot:
        data = dek_file.read()  # type: ignore
        write_response = mboot.generate_key_blob(data)
        if not write_response:
            raise ValueError(f"Error generating key blob")
        blob_file.write(write_response)  # type: ignore
        display_output([mboot.status_code, len(write_response)], mboot.status_code, ctx.obj['use_json'])


def display_output(response: list, status_code: int, use_json: bool = False,
                   extra_output: str = None) -> None:
    """Display response and status code.

    :param response: Response from the MBoot function
    :type response: list
    :param status_code: MBoot status code
    :type status_code: int
    :param use_json: Format the output in JSON format, defaults to False
    :type use_json: bool, optional
    :param extra_output: Extra string to print out, defaults to None
    :type extra_output: str, optional
    """
    if use_json:
        data = {
            # get the name of a caller function and replace _ with -
            'command': inspect.stack()[1].function.replace('_', '-'),
            # this is just a visualization thing
            'response': response or [],
            'status': {
                'description': decode_status_code(status_code),
                'value': status_code
            }
        }
        print(json.dumps(data, indent=3))
    else:
        print(f'Response status = {decode_status_code(status_code)}')
        if status_code != 0:
            return
        for i, word in enumerate(response):
            print(f'Response word {i + 1} = {word} ({word:#x})')
        if extra_output:
            print(extra_output)


def decode_status_code(status_code: int) -> str:
    """Stringify the MBoot status code.

    :param status_code: MBoot status code
    :type status_code: int
    :return: String representation
    :rtype: str
    """
    return f"{status_code} ({status_code:#x}) {StatusCode.desc(status_code)}."


@catch_spsdk_error
def safe_main() -> int:
    """Call the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
