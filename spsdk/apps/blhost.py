#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for MBoot module aka BLHost."""

import inspect
import json
import logging
import sys

import click
from click_option_group import MutuallyExclusiveOptionGroup, optgroup

from spsdk import __version__ as spsdk_version, SPSDKError
from spsdk.apps.blhost_helper import parse_property_tag
from spsdk.apps.utils import (
    INT, get_interface, format_raw_data, catch_spsdk_error,
    parse_file_and_size, parse_hex_data
)
from spsdk.mboot import McuBoot, StatusCode, parse_property_value, GenerateKeyBlobSelect


@click.group()
@optgroup.group('Interface configuration', cls=MutuallyExclusiveOptionGroup)
@optgroup.option('-p', '--port', metavar='COM[,speed]', help='Serial port')
@optgroup.option('-u', '--usb', metavar='PID,VID', help="""
USB device identifier. Following formats are supported:
<vid>, <vid:pid> or <vid,pid>, device/instance path, device name.
vid: hex or dec string; e.g. 0x0AB12, 43794.

vid/pid: hex or dec string; e.g. 0x0AB12:0x123, 1:3451

device name: use 'dscan' utility to list supported device names.

path - OS specific string.
Windows:
'device instance path' in device manager under Windows OS.

Linux specific:
Use 'Bus' and 'Device' ID observed using 'lsusb' in <bus>#<device>' form; e.g. '3#2'.

Mac specific:
Use device name and location ID from 'System report' in '<device_name> <location id>'
form. e.g. 'SE Blank RT Family @14100000'
""")
@click.option('-j', '--json', 'use_json', is_flag=True, help='Use JSON output')
@click.option('-v', '--verbose', 'log_level', flag_value=logging.INFO, help='Display more verbose output')
@click.option('-d', '--debug', 'log_level', flag_value=logging.DEBUG, help='Display debugging info')
@click.option('-t', '--timeout', metavar='<ms>', help='Set packet timeout in milliseconds', default=5000)
@click.version_option(spsdk_version, '--version')
@click.help_option('--help')
@click.pass_context
def main(ctx: click.Context, port: str, usb: str, use_json: bool, log_level: int, timeout: int) -> int:
    """Utility for communication with bootloader on target."""
    logging.basicConfig(level=log_level or logging.WARNING)

    # print help for get-property if property tag is 0 or 'list-properties'
    if ctx.invoked_subcommand == 'get-property':
        args = click.get_os_args()
        # running this via pytest changes the args to a single arg, in that case skip
        if len(args) > 1 and 'get-property' in args:
            tag_str = args[args.index('get-property') + 1]
            if parse_property_tag(tag_str) == 0:
                click.echo(ctx.command.commands['get-property'].help)   # type: ignore
                ctx.exit(0)

    # if --help is provided anywhere on commandline, skip interface lookup and display help message
    if not '--help' in click.get_os_args():
        ctx.obj = {
            'interface': get_interface(
                module='mboot', port=port, usb=usb, timeout=timeout
            ),
            'use_json': use_json
        }
    return 0


@main.command()
@click.argument('address', type=INT(), required=True)
@click.argument('argument', type=INT(), required=True)
@click.pass_context
def call(ctx: click.Context, address: int, argument: int) -> None:
    """Invoke code that the ADDRESS, passing single ARGUMENT to it.

    \b
    ADDRESS     - function code address
    ARGUMENT    - argument for the function
    """
    with McuBoot(ctx.obj['interface']) as mboot:
        mboot.call(address, argument)
        display_output([], mboot.status_code, ctx.obj['use_json'])


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
@click.argument('lock', metavar='[nolock/lock]', type=click.Choice(['nolock', 'lock']), default='nolock')
@click.pass_context
def efuse_program_once(ctx: click.Context, address: int, data: int, lock: str) -> None:
    """Program one word of OCOTP Field.

    \b
    ADDRESS - address of OTP word, not the shadowed memory address.
    DATA    - hex digits without prefix '0x'.
    """
    if lock == 'lock':
        address = address | (1 << 24)
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
        display_output(
            None if response is None else [4, response],
            mboot.status_code, ctx.obj['use_json']
        )


@main.command()
@click.argument('address', type=INT(), required=True)
@click.argument('argument', type=INT(), required=True)
@click.argument('stackpointer', type=INT(), required=True)
@click.pass_context
def execute(ctx: click.Context, address: int, argument: int, stackpointer: int) -> None:
    """Execute application at address with arg and stack pointer.

    \b
    ADDRESS      - Address of the application to run
    ARGUMENT     - Argument passed to the application
    STACKPOINTER - Stack pointer for the application
    """
    with McuBoot(ctx.obj['interface']) as mboot:
        response = mboot.execute(address, argument, stackpointer)
        display_output([], mboot.status_code, ctx.obj['use_json'])


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
@click.argument('memory_id', type=int, required=False, default=0)
@click.pass_context
def flash_erase_all(ctx: click.Context, memory_id: int) -> None:
    """Erase all flash according to [memory_id], excluding protected regions.

    \b
    MEMORY_ID   - id of memory to erase (default: 0)
    """
    with McuBoot(ctx.obj['interface']) as mboot:
        mboot.flash_erase_all(memory_id)
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
@click.argument('boot_file', metavar='FILE', type=click.File('rb'))
@click.pass_context
def load_image(ctx: click.Context, boot_file: click.File) -> None:
    """Load a boot image to the device.

    \b
    FILE  - boot file to load
    """
    data = boot_file.read()  # type: ignore
    with McuBoot(ctx.obj['interface']) as mboot:
        mboot.load_image(data)
        display_output([], mboot.status_code, ctx.obj['use_json'])


@main.command()
@click.argument('property_tag', type=str, required=True)
@click.argument('index', type=int, default=0)
@click.pass_context
def get_property(ctx: click.Context, property_tag: str, index: int) -> None:
    """Get bootloader-specific property.

    \b
    PROPERTY_TAG - number or name represeting the requested property
    MEMORY_ID    - id/index of the memory (default: 0)
    \b
    Available properties:
     0 or 'list-properties'             List all properties
     1 or 'current-version'             Bootloader version
     2 or 'available-peripherals'       Available peripherals
     3 or 'flash-start-address'         Start of program flash, <index> is required
     4 or 'flash-size-in-bytes'         Size of program flash, <index> is required
     5 or 'flash-sector-size'           Size of flash sector, <index> is required
     6 or 'flash-block-count'           Blocks in flash array, <index> is required
     7 or 'available-commands'          Available commands
     8 or 'check-status'                Check Status, <status id> is required
     9 or 'reserved'
    10 or 'verify-writes'               Verify Writes flag
    11 or 'max-packet-size'             Max supported packet size
    12 or 'reserved-regions'            Reserved regions
    13 or 'reserved'
    14 or 'ram-start-address'           Start of RAM, <index> is required
    15 or 'ram-size-in-bytes'           Size of RAM, <index> is required
    16 or 'system-device-id'            System device identification
    17 or 'security-state'              Flash security state
    18 or 'unique-device-id'            Unique device identification
    19 or 'flash-fac-support'           FAC support flag
    20 or 'flash-access-segment-size'   FAC segment size
    21 or 'flash-access-segment-count'  FAC segment count
    22 or 'flash-read-margin'           Read margin level of program flash
    23 or 'qspi/otfad-init-status'      QuadSpi initialization status
    24 or 'target-version'              Target version
    25 or 'external-memory-attributes'  External memory attributes, <memoryId> is required
    26 or 'reliable-update-status'      Reliable update status
    27 or 'flash-page-size'             Flash page size, <index> is required
    28 or 'irq-notify-pin'              Interrupt notifier pin
    29 or 'ffr-keystore_update-opt'     FFR key store update option

    Note: Not all properties are available for all devices.
    """
    property_tag_int = parse_property_tag(property_tag)
    with McuBoot(ctx.obj['interface']) as mboot:
        response = mboot.get_property(property_tag_int, index=index)  # type: ignore
        property_text = str(parse_property_value(property_tag_int, response)) if response else None
        display_output(
            response, mboot.status_code, ctx.obj['use_json'],
            property_text
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

    if response:
        if out_file:
            out_file.write(response)  # type: ignore
        else:
            click.echo(format_raw_data(response, use_hexdump=use_hexdump))

    display_output(
        [len(response) if response else 0],
        mboot.status_code, ctx.obj['use_json'],
        f"Read {len(response) if response else 0} of {byte_count} bytes."
    )



@main.command()
@click.argument('sb_file', metavar='FILE', type=click.File('rb'), required=True)
@click.pass_context
def receive_sb_file(ctx: click.Context, sb_file: click.File) -> None:
    """Receive SB file.

    \b
    FILE    - SB file to send to target
    """
    with McuBoot(ctx.obj['interface']) as mboot:
        data = sb_file.read()  # type: ignore
        mboot.receive_sb_file(data)
        display_output([], mboot.status_code, ctx.obj['use_json'])


@main.command()
@click.pass_context
def reset(ctx: click.Context) -> None:
    """Reset the device."""
    with McuBoot(ctx.obj['interface']) as mboot:
        mboot.reset(reopen=False)
    display_output([], mboot.status_code, ctx.obj['use_json'])


@main.command()
@click.argument('address', type=INT(), required=True)
@click.argument('data_source', metavar='FILE[,BYTE_COUNT] | {{HEX-DATA}}', type=str, required=True)
@click.argument('memory_id', type=int, required=False, default=0)
@click.pass_context
def write_memory(ctx: click.Context, address: int, data_source: str, memory_id: int) -> None:
    """Write memory.

    \b
    ADDRESS     - starting address
    FILE        - write content of this file
    BYTE_COUNT  - if specified, load only first BYTE_COUNT number of bytes from file
    HEX-DATA    - string of hex values: {{112233}}, {{11 22 33}}
    MEMORY_ID   - id of memory to read from (default: 0)
    """
    try:
        data = parse_hex_data(data_source)
    except SPSDKError:
        file_path, size = parse_file_and_size(data_source)
        with open(file_path, 'rb') as f:
            data = f.read(size)

    with McuBoot(ctx.obj['interface']) as mboot:
        response = mboot.write_memory(address, data, memory_id)
        display_output([len(data)] if response else None, mboot.status_code, ctx.obj['use_json'])


@main.command()
@click.argument('dek_file', type=click.File('rb'), required=True)
@click.argument('blob_file', type=click.File('wb'), required=True)
@click.argument('key_sel', metavar='[KEY_SEL]',
                type=click.Choice(['0', '1', '2', '3', 'OPTMK', 'ZMK', 'CMK']), default='0')
@click.pass_context
def generate_key_blob(ctx: click.Context, dek_file: click.File, blob_file: click.File, key_sel: str) -> None:
    """Generate the Key Blob for a given DEK.

    \b
    DEK_FILE     - the file with the binary DEK key
    BLOB_FILE    - the generated file with binary key blob
    KEY_SEL      - select the BKEK used to wrap  the BK and generate the blob.
                   For devices with SNVS, valid options of [key_sel] are
                        0, 1 or OTPMK: OTPMK from FUSE or OTP(default),
                        2 or ZMK: ZMK from SNVS,
                        3 or CMK: CMK from SNVS,
                   For devices without SNVS, this option will be ignored.
    """
    with McuBoot(ctx.obj['interface']) as mboot:
        data = dek_file.read()  # type: ignore
        key_sel_int = int(key_sel) if key_sel.isnumeric() else GenerateKeyBlobSelect.get(key_sel)
        assert isinstance(key_sel_int, int)
        write_response = mboot.generate_key_blob(data, key_sel=key_sel_int)
        display_output(
            [mboot.status_code, len(write_response)] if write_response else None,
            mboot.status_code, ctx.obj['use_json']
        )
        if write_response:
            blob_file.write(write_response)  # type: ignore



@main.group()
@click.pass_context
def key_provisioning(ctx: click.Context) -> None:
    """Group of commands related to key provisioning."""


@key_provisioning.command()
@click.pass_context
def enroll(ctx: click.Context) -> None:
    """Key provisioning enroll."""
    with McuBoot(ctx.obj['interface']) as mboot:
        response = mboot.kp_enroll()
        display_output([], mboot.status_code, ctx.obj['use_json'])


@key_provisioning.command(name='set_user_key')
@click.argument('key_type', metavar='TYPE', type=INT(), required=True)
@click.argument('file_and_size', metavar='FILE[,SIZE]', type=str, required=True)
@click.pass_context
def set_user_key(ctx: click.Context, key_type: int, file_and_size: str) -> None:
    """Send the user key specified by <type> to bootloader.

    \b
    TYPE  - Type of user key
    FILE  - Binary file containing user key plaintext
    SIZE  - If not specified, the entire <file> will be sent. Otherwise, only send
            the first <size> bytes. The valid options of <type> and
            corresponding <size> are documented in the target's Reference
            Manual or User Manual.
    """
    file_path, size = parse_file_and_size(file_and_size)

    with open(file_path, 'rb') as key_file:
        key_data = key_file.read(size)

    with McuBoot(ctx.obj['interface']) as mboot:
        response = mboot.kp_set_user_key(key_type=key_type, key_data=key_data)  # type: ignore
        display_output([], mboot.status_code, ctx.obj['use_json'])


@key_provisioning.command(name='set_key')
@click.argument('key_type', metavar='TYPE', type=int, required=True)
@click.argument('key_size', metavar='SIZE', type=int, required=True)
@click.pass_context
def set_key(ctx: click.Context, key_type: int, key_size: int) -> None:
    """Generate <size> bytes of the key specified by <type>.

    \b
    TYPE  - type of key to generate
    SIZE  - size of key to generate
    """
    with McuBoot(ctx.obj['interface']) as mboot:
        response = mboot.kp_set_intrinsic_key(key_type, key_size)
        display_output([], mboot.status_code, ctx.obj['use_json'])


@key_provisioning.command(name='write_key_nonvolatile')
@click.argument('memory_id', metavar='memoryID', type=int, default=0)
@click.pass_context
def write_key_nonvolatile(ctx: click.Context, memory_id: int) -> None:
    """Write the key to a nonvolatile memory.

    \b
    memoryID  - ID of the non-volatile memory, default: 0
    """
    with McuBoot(ctx.obj['interface']) as mboot:
        response = mboot.kp_write_nonvolatile(memory_id)
        display_output([], mboot.status_code, ctx.obj['use_json'])


@key_provisioning.command(name='read_key_nonvolatile')
@click.argument('memory_id', metavar='memoryID', type=int, default=0)
@click.pass_context
def read_key_nonvolatile(ctx: click.Context, memory_id: int) -> None:
    """Load the key from a nonvolatile memory to bootloader.

    \b
    memoryID  - ID of the non-volatile memory, default: 0
    """
    with McuBoot(ctx.obj['interface']) as mboot:
        response = mboot.kp_read_nonvolatile(memory_id)
        display_output([], mboot.status_code, ctx.obj['use_json'])


@key_provisioning.command(name='write_key_store')
@click.argument('file_and_size', metavar='FILE[,SIZE]', type=str, required=True)
@click.pass_context
def write_key_store(ctx: click.Context, file_and_size: str) -> None:
    """Send the key store to bootloader..

    \b
    FILE  - Binary file containing key store.
    SIZE  - If not specified, the entire <file> will be sent. Otherwise, only send
            the first <size> bytes.
    """
    file_path, size = parse_file_and_size(file_and_size)

    with open(file_path, 'rb') as key_file:
        key_data = key_file.read(size)

    with McuBoot(ctx.obj['interface']) as mboot:
        response = mboot.kp_write_key_store(key_data)
        display_output([], mboot.status_code, ctx.obj['use_json'])


@key_provisioning.command(name='read_key_store')
@click.argument('key_store_file', metavar='FILE', type=click.File('wb'), required=True)
@click.pass_context
def read_key_store(ctx: click.Context, key_store_file: click.File) -> None:
    """Read the key store from bootloader to host(PC).

    \b
    FILE  - Binary file to save the key store.
    """
    with McuBoot(ctx.obj['interface']) as mboot:
        response = mboot.kp_read_key_store()
        display_output(
            [len(response)] if response else None,
            mboot.status_code, ctx.obj['use_json']
        )
        if response:
            key_store_file.write(response)  # type: ignore


def display_output(response: list = None, status_code: int = 0, use_json: bool = False,
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
        if isinstance(response, list):
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
    return (f"{status_code} ({status_code:#x}) "
            f"{StatusCode.desc(status_code, f'Unknown error code ({status_code})')}.")


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
