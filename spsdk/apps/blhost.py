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
import os
import sys

import click
from click_option_group import MutuallyExclusiveOptionGroup, optgroup

from spsdk import SPSDKError
from spsdk import __version__ as spsdk_version
from spsdk.apps.blhost_helper import parse_image_file, parse_key_prov_key_type, parse_property_tag
from spsdk.apps.utils import (
    INT,
    catch_spsdk_error,
    format_raw_data,
    get_interface,
    parse_file_and_size,
    parse_hex_data,
)
from spsdk.mboot import GenerateKeyBlobSelect, McuBoot, StatusCode, parse_property_value


@click.group()
@optgroup.group("Interface configuration", cls=MutuallyExclusiveOptionGroup)
@optgroup.option(
    "-p", "--port",
    metavar="COM[,speed]",
    help="""Serial port configuration. Use 'nxpdevscan' utility to list devices on serial port.""",
)
@optgroup.option(
    "-u",
    "--usb",
    metavar="VID,PID",
    help="""USB device identifier.
    Following formats are supported: <vid>, <vid:pid> or <vid,pid>, device/instance path, device name.
    <vid>: hex or dec string; e.g. 0x0AB12, 43794.
    <vid/pid>: hex or dec string; e.g. 0x0AB12:0x123, 1:3451.
    Use 'nxpdevscan' utility to list connected device names.
""",
)
@click.option("-j",
    "--json",
    "use_json",
    is_flag=True,
    help="Prints output in JSON format."
)
@click.option("-v",
    "--verbose",
    "log_level",
    flag_value=logging.INFO,
    help="Prints more detailed information.",
)
@click.option("-d",
    "--debug",
    "log_level",
    flag_value=logging.DEBUG,
    help="Display more debugging info.",
)
@click.option("-t",
    "--timeout",
    metavar="<ms>",
    help="""Sets timeout when waiting on data over a serial line. The default is 5000 milliseconds.""",
    default=5000,
)
@click.version_option(spsdk_version, "--version")
@click.help_option("--help")
@click.pass_context
def main(
    ctx: click.Context,
    port: str,
    usb: str,
    use_json: bool,
    log_level: int,
    timeout: int,
) -> int:
    """Utility for communication with the bootloader on target."""
    logging.basicConfig(level=log_level or logging.WARNING)

    # print help for get-property if property tag is 0 or 'list-properties'
    if ctx.invoked_subcommand == "get-property":
        args = click.get_os_args()
        # running this via pytest changes the args to a single arg, in that case skip
        if len(args) > 1 and "get-property" in args:
            tag_str = args[args.index("get-property") + 1]
            if parse_property_tag(tag_str) == 0:
                click.echo(ctx.command.commands["get-property"].help)  # type: ignore
                ctx.exit(0)

    # if --help is provided anywhere on commandline, skip interface lookup and display help message
    if "--help" not in click.get_os_args():
        ctx.obj = {
            "interface": get_interface(module="mboot", port=port, usb=usb, timeout=timeout),
            "use_json": use_json,
        }
    return 0


@main.command()
@click.argument("address", type=INT(), required=True)
@click.argument("argument", type=INT(), required=True)
@click.pass_context
def call(ctx: click.Context, address: int, argument: int) -> None:
    """Invokes code at an address, passing an argument to it.

    \b
    ADDRESS     - function code address
    ARGUMENT    - argument for the function
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.call(address, argument)
        display_output([], mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.argument("memory_id", type=INT(), required=True)
@click.argument("address", type=INT(), required=True)
@click.pass_context
def configure_memory(ctx: click.Context, address: int, memory_id: int) -> None:
    """Sets a config at internal memory to memory with ID.

    The specified configuration block must have been previously written to memory using the write-memory command.

    \b
    MEMORY_ID   - id of memory
    ADDRESS     - starting address
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.configure_memory(address, memory_id)  # type: ignore
        display_output([], mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.argument("address", type=INT(), required=True)
@click.argument("data", type=INT(base=16), required=True)
@click.argument(
    "lock",
    metavar="[nolock/lock]",
    type=click.Choice(["nolock", "lock"]),
    default="nolock",
)
@click.pass_context
def efuse_program_once(ctx: click.Context, address: int, data: int, lock: str) -> None:
    """Writes data to a specific efuse word.

    Each efuse bit can only be programmed once.

    \b
    ADDRESS - address of OTP word, not the shadowed memory address.
    DATA    - hex digits without prefix '0x'.
    """
    if lock == "lock":
        address = address | (1 << 24)
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.efuse_program_once(address, data)
        display_output([response], mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.argument("address", type=INT(), required=True)
@click.pass_context
def efuse_read_once(ctx: click.Context, address: int) -> None:
    """Returns the contents of a specific efuse word.

    \b
    ADDRESS - is the address of OTP word, not the shadowed memory address.
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.efuse_read_once(address)
        display_output(
            None if response is None else [4, response],
            mboot.status_code,
            ctx.obj["use_json"],
        )


@main.command()
@click.argument("address", type=INT(), required=True)
@click.argument("argument", type=INT(), required=True)
@click.argument("stackpointer", type=INT(), required=True)
@click.pass_context
def execute(ctx: click.Context, address: int, argument: int, stackpointer: int) -> None:
    """Jumps to code at the provided address.

    The system is returned to a reset state before the jump.
    The function <ARGUMENT> parameter is passed in R0 to the called code.

    The main stack pointer and process stack pointer registers are set to the <STACKPOINTER> parameter.
    If set to zero, the code being called should set the stack pointer before using the stack.

    \b
    ADDRESS      - Address of the application to run
    ARGUMENT     - Argument passed to the application
    STACKPOINTER - Stack pointer for the application
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.execute(address, argument, stackpointer)
        display_output([], mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.argument("address", type=INT(), required=True)
@click.argument("byte_count", type=INT(), required=True)
@click.argument("memory_id", type=int, required=False, default=0)
@click.pass_context
def flash_erase_region(ctx: click.Context, address: int, byte_count: int, memory_id: int) -> None:
    """Erases one or more sectors of the flash memory.

    The start <ADDRESS> and <BYTE_COUNT> must be a multiple of the word size.
    The entire sector(s) containing the start and end address is erased.

    \b
    ADDRESS     - starting address
    BYTE_COUNT  - number of bytes to erase
    MEMORY_ID   - id of memory to erase (default: 0)
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.flash_erase_region(address, byte_count, memory_id)
        display_output([], mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.argument("memory_id", type=int, required=False, default=0)
@click.pass_context
def flash_erase_all(ctx: click.Context, memory_id: int) -> None:
    """Performs an erase of the entire flash memory.

    \b
    MEMORY_ID   - id of memory to erase (default: 0)

    \b
    Note: excluding protected regions.
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.flash_erase_all(memory_id)
        display_output([], mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.pass_context
def flash_erase_all_unsecure(ctx: click.Context) -> None:
    """Erase complete flash memory and recover flash security section."""
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.flash_erase_all_unsecure()
        display_output([], mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.argument("image_file_path", metavar="FILE", type=str, required=True)
@click.argument("erase", type=str, required=False, default="none")
@click.argument("memory_id", type=INT(), required=False, default='0')
@click.pass_context
def flash_image(ctx: click.Context, image_file_path: str, erase: str, memory_id: int) -> None:
    """Write the formatted image in <FILE> to the memory specified by memoryID.

    \b
    FILE       - path to image file
    ERASE      - string 'erase' determines if flash is erased before writing
    MEMORY_ID  - id of memory to erase (default: 0)
    """
    if not os.path.isfile(image_file_path):
        raise SPSDKError("The image file does not exist")
    mem_id = 0
    if erase not in ["erase", "none"]:
        try:
            mem_id = int(erase, 0)
        except ValueError as e:
            raise SPSDKError("The option for erasing was not declared properly. Choose from 'erase' or 'none'.") from e
    if memory_id:
        mem_id = memory_id
    segments = parse_image_file(image_file_path)
    with McuBoot(ctx.obj["interface"]) as mboot:
        if erase == "erase":
            for segment in segments:
                mboot.flash_erase_region(
                    address=segment.aligned_start, length=segment.aligned_length, mem_id=mem_id
                )
                if mboot.status_code != StatusCode.SUCCESS:
                    display_output([], mboot.status_code, ctx.obj["use_json"])
                    exit(1)
        for segment in segments:
            mboot.write_memory(address=segment.start, data=segment.data_bin, mem_id=mem_id)
            display_output([], mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.argument("index", type=int, required=True)
@click.argument("byte_count", type=click.Choice(["4", "8"]), required=True)
@click.argument("data", type=INT(base=16), required=True)
@click.argument(
    "endianess",
    metavar="[LSB|MSB]",
    type=click.Choice(["LSB", "MSB"]),
    default="LSB", required=False
)
@click.pass_context
def flash_program_once(
    ctx: click.Context, index: int, byte_count: str, data: int, endianess: str
) -> None:
    """Writes provided data to a specific program once field.

    \b
    INDEX       - fuse word index
    BYTE_COUNT  - width in bits (acceptable only 4 or 8-byte long data)
    DATA        - 4 or 8-byte-hex according to <byte_count>
    ENDIANESS   - output sequence is specified by LSB (Default) or MSB
    """
    byte_order = "big" if endianess == "MSB" else "little"
    input_data = data.to_bytes(int(byte_count), byteorder=byte_order)
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.flash_program_once(index=index, data=input_data)
        display_output([], mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.argument("index", type=int, required=True)
@click.argument("byte_count", type=click.Choice(["4", "8"]), required=True, default=4)
@click.pass_context
def flash_read_once(ctx: click.Context, index: int, byte_count: str) -> None:
    """Returns the contents of a specific program once field.

    \b
    INDEX        - fuse word index
    BYTE_COUNT   - width in bits (acceptable only 4 or 8-byte long data)
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.flash_read_once(index=index, count=int(byte_count))
        display_output(
            None if response is None else [len(response), int.from_bytes(response, "little")],
            mboot.status_code,
            ctx.obj["use_json"],
        )


@main.command()
@click.argument("key", type=str, required=True)
@click.pass_context
def flash_security_disable(ctx: click.Context, key: str) -> None:
    """Disable flash security by using of backdoor key.

    \b
    KEY        - key value as hex-string (8 bytes long)
    """
    if len(key) != 16:
        raise SPSDKError("Key length must be 8 bytes")
    try:
        key_bytes = bytes.fromhex(key)
    except ValueError as e:
        raise SPSDKError("Key is not a valid hex-string [A-Fa-f0-9]") from e
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.flash_security_disable(backdoor_key=key_bytes)
        display_output([], mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.argument("address", type=INT(), required=True)
@click.argument("length", type=int, required=True)
@click.argument("option", type=click.Choice(["0", "1"]), required=True)
@click.argument("out_file", metavar="FILE", type=click.File("wb"), required=False)
@click.option("-h", "--use-hexdump", is_flag=True, default=False, help="Use hexdump format")
@click.pass_context
def flash_read_resource(
    ctx: click.Context, address: int, length: int, option: str, out_file: click.File, use_hexdump: bool
) -> None:
    """Read resource of flash module.

    Reads the contents of Flash IFR or Flash Firmware ID as specified by option and
    writes result to file or stdout if file is not specified.

    \b
    ADDRESS      - Start address
    LENGTH       - Number of bytes to read. Must be 4-byte aligned.
    OPTION       - Area to be read. 0 means Flash IFR, 1 means Flash Firmware ID.
    OUT_FILE     - Path to file, where the output will be stored
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.flash_read_resource(address=address, length=length, option=int(option))

        if response:
            if out_file:
                out_file.write(response)  # type: ignore
            else:
                click.echo(format_raw_data(response, use_hexdump=use_hexdump))

        display_output(
            [len(response) if response else 0],
            mboot.status_code,
            ctx.obj["use_json"],
            f"Read {len(response) if response else 0} of {length} bytes."
        )


@main.command()
@click.argument("address", type=INT(), required=True)
@click.argument("byte_count", type=INT(), required=True)
@click.argument("pattern", type=INT(), required=True)
@click.argument(
    "pattern_format",
    metavar="format",
    type=click.Choice(["word", "short", "byte"]),
    required=False,
    default="word",
)
@click.pass_context
def fill_memory(
    ctx: click.Context, address: int, byte_count: int, pattern: int, pattern_format: str
) -> None:
    """Fills the memory with a pattern.

    \b
    ADDRESS     - starting address
    BYTE_COUNT  - number of bytes to fill
    PATTERN     - pattern to fill
    FORMAT      - format of the pattern [word|short|byte] (default: word)
    """
    del pattern_format  # temporary workaround for not unused parameter
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.fill_memory(address, byte_count, pattern)
        display_output([], mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.argument("address", type=INT(), required=True)
@click.argument("data_source", metavar="FILE[,BYTE_COUNT] | {{HEX-DATA}}", type=str, required=True)
@click.argument("memory_id", type=int, required=False, default=0)
@click.pass_context
def fuse_program(ctx: click.Context, address: int, data_source: str, memory_id: int) -> None:
    """Program fuse.

    \b
    ADDRESS     - starting address
    FILE        - write the content of this file
    BYTE_COUNT  - if specified, load only first BYTE_COUNT number of bytes from file
    HEX-DATA    - string of hex values: {{112233}}, {{11 22 33}}
    MEMORY_ID   - id of memory to read from (default: 0)
    """
    try:
        data = parse_hex_data(data_source)
    except SPSDKError:
        file_path, size = parse_file_and_size(data_source)
        with open(file_path, "rb") as f:
            data = f.read(size)

    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.fuse_program(address, data, memory_id)
        display_output([len(data)] if response else None, mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.argument("address", type=INT(), required=True)
@click.argument("byte_count", type=INT(), required=True)
@click.argument("out_file", metavar="FILE", type=click.File("wb"), required=False)
@click.argument("memory_id", type=int, default=0, required=False)
@click.option("-h", "--use-hexdump", is_flag=True, default=False, help="Use hexdump format")
@click.pass_context
def fuse_read(
    ctx: click.Context,
    address: int,
    byte_count: int,
    out_file: click.File,
    memory_id: int,
    use_hexdump: bool,
) -> None:
    """Reads the fuse and writes it to the file or stdout.

    Returns the contents of memory at the given <ADDRESS>, for a specified <BYTE_COUNT>.

    \b
    ADDRESS     - starting address
    BYTE_COUNT  - number of bytes to read
    FILE        - store result into this file, if not specified use stdout
    MEMORY_ID   - id of memory to read from (default: 0)
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.fuse_read(address, byte_count, memory_id)

    if response:
        if out_file:
            out_file.write(response)  # type: ignore
        else:
            click.echo(format_raw_data(response, use_hexdump=use_hexdump))

    display_output(
        [len(response) if response else 0],
        mboot.status_code,
        ctx.obj["use_json"],
        f"Read {len(response) if response else 0} of {byte_count} bytes.",
    )


@main.command()
@click.pass_context
def list_memory(ctx: click.Context) -> None:
    """Lists all memories, supported by the current device."""
    with McuBoot(ctx.obj["interface"]) as mboot:
        print("Internal Flash:")
        int_flash = mboot._get_internal_flash()
        for i in range(len(int_flash)):
            print(f"    {int_flash[i]}")
        print("Internal RAM:")
        int_ram = mboot._get_internal_ram()
        for i in range(len(int_ram)):
            print(f"    {int_ram[i]}")
        print("External Memories:")
        ext_mem = mboot._get_ext_memories()
        for i in range(len(ext_mem)):
            print(f"{(ext_mem[i].name)}:\n  {ext_mem[i]}")


@main.command()
@click.argument("boot_file", metavar="FILE", type=click.File("rb"))
@click.pass_context
def load_image(ctx: click.Context, boot_file: click.File) -> None:
    """Sends a boot image file to the device.

    Only binary file is supported.
    The <FILE> must be a bootable image which contains the boot image header supported by MCU bootloader.

    \b
    FILE  - boot file to load
    """
    data = boot_file.read()  # type: ignore
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.load_image(data)
        display_output([], mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.argument("property_tag", type=str, required=True)
@click.argument("index", type=int, default=0)
@click.pass_context
def get_property(ctx: click.Context, property_tag: str, index: int) -> None:
    """Queries various bootloader properties and settings.

    Each supported property has a unique <PROPERTY_TAG>.

    \b
    PROPERTY_TAG - number or name representing the requested property
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
    29 or 'pfr-keystore_update-opt'     PFR key store update option

    \b
    Note: Not all the properties are available for all devices.
    """
    property_tag_int = parse_property_tag(property_tag)
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.get_property(property_tag_int, index=index)  # type: ignore
        property_text = str(parse_property_value(property_tag_int, response)) if response else None
        display_output(response, mboot.status_code, ctx.obj["use_json"], property_text)


@main.command()
@click.argument("property_tag", type=str, required=True)
@click.argument("value", type=INT(), required=True)
@click.pass_context
def set_property(ctx: click.Context, property_tag: str, value: int) -> None:
    """Changes properties and options in the bootloader.

    Accepts the same <PROPERTY_TAG> used with the get-property sub-command;
    however, only some properties are writable.

    \b
    PROPERTY_TAG - number or name representing the requested property
    VALUE        - value to set

    \b
    Available properties to set:
    10 or 'verify-writes'               Verify Writes flag
    22 or 'flash-read-margin'           Read margin level of program flash
    28 or 'irq-notify-pin'              Interrupt notifier pin
    29 or 'pfr-keystore_update-opt'     PFR key store update option

    \b
    Note: Not all properties can be set on all devices.
    """
    property_tag_int = parse_property_tag(property_tag)
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.set_property(prop_tag=property_tag_int, value=value)  # type: ignore
        display_output([], mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.argument("address", type=INT(), required=True)
@click.argument("byte_count", type=INT(), required=True)
@click.argument("out_file", metavar="FILE", type=click.File("wb"), required=False)
@click.argument("memory_id", type=int, default=0, required=False)
@click.option("-h", "--use-hexdump", is_flag=True, default=False, help="Use hexdump format")
@click.pass_context
def read_memory(
    ctx: click.Context,
    address: int,
    byte_count: int,
    out_file: click.File,
    memory_id: int,
    use_hexdump: bool,
) -> None:
    """Reads the memory and writes it to the file or stdout.

    Returns the contents of memory at the given <ADDRESS>, for a specified <BYTE_COUNT>.

    \b
    ADDRESS     - starting address
    BYTE_COUNT  - number of bytes to read
    FILE        - store result into this file, if not specified use stdout
    MEMORY_ID   - id of memory to read from (default: 0)
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.read_memory(address, byte_count, memory_id)

    if response:
        if out_file:
            out_file.write(response)  # type: ignore
        else:
            click.echo(format_raw_data(response, use_hexdump=use_hexdump))

    display_output(
        [len(response) if response else 0],
        mboot.status_code,
        ctx.obj["use_json"],
        f"Read {len(response) if response else 0} of {byte_count} bytes.",
    )


@main.command()
@click.argument("sb_file", metavar="FILE", type=click.File("rb"), required=True)
@click.pass_context
def receive_sb_file(ctx: click.Context, sb_file: click.File) -> None:
    """Receives a file in a Secure Binary (SB) format.

    An SB file is an encapsulated, binary stream of bootloader commands that can be optionally encrypted.

    \b
    FILE    - SB file to send to the target
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        data = sb_file.read()  # type: ignore
        mboot.receive_sb_file(data)
        display_output([], mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.argument("address", type=INT(), required=True)
@click.pass_context
def reliable_update(
    ctx: click.Context, address: int) -> None:
    """Reliable Update.

    \b
    ADDRESS     - starting address
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.reliable_update(address)
        display_output([], mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.pass_context
def reset(ctx: click.Context) -> None:
    """Resets the device.

    A response packet is sent before resetting the device.
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.reset(reopen=False)
    display_output([], mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.argument("address", type=INT(), required=True)
@click.argument("data_source", metavar="FILE[,BYTE_COUNT] | {{HEX-DATA}}", type=str, required=True)
@click.argument("memory_id", type=int, required=False, default=0)
@click.pass_context
def write_memory(ctx: click.Context, address: int, data_source: str, memory_id: int) -> None:
    """Writes memory from a file or a hex-data.

    Writes memory specified by <MEMORY_ID> at <ADDRESS> from <FILE> or <HEX-DATA>
    Writes a provided buffer to a specified <BYTE_COUNT> in memory.

    \b
    ADDRESS     - starting address
    FILE        - write the content of this file
    BYTE_COUNT  - if specified, load only first BYTE_COUNT number of bytes from file
    HEX-DATA    - string of hex values: {{112233}}, {{11 22 33}}
    MEMORY_ID   - id of memory to read from (default: 0)
    """
    try:
        data = parse_hex_data(data_source)
    except SPSDKError:
        file_path, size = parse_file_and_size(data_source)
        with open(file_path, "rb") as f:
            data = f.read(size)

    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.write_memory(address, data, memory_id)
        display_output([len(data)] if response else None, mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.argument("dek_file", type=click.File("rb"), required=True)
@click.argument("blob_file", type=click.File("wb"), required=True)
@click.argument(
    "key_sel",
    metavar="[KEY_SEL]",
    type=click.Choice(["0", "1", "2", "3", "OPTMK", "ZMK", "CMK"]),
    default="0",
)
@click.pass_context
def generate_key_blob(
    ctx: click.Context, dek_file: click.File, blob_file: click.File, key_sel: str
) -> None:
    """Generates the Key Blob, and writes it to the file.

    <KEY_SEL> selects the blob key encryption key(BKEK) used to generate the key blob.

    \b
    DEK_FILE     - the file with the binary DEK key
    BLOB_FILE    - the generated file with a binary key blob
    KEY_SEL      - select the BKEK used to wrap the BK and generate the blob.
                   For devices with SNVS, valid options of [key_sel] are
                        0, 1 or OTPMK: OTPMK from FUSE or OTP(default),
                        2 or ZMK: ZMK from SNVS,
                        3 or CMK: CMK from SNVS,
                   For devices without SNVS, this option will be ignored.
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        data = dek_file.read()  # type: ignore
        key_sel_int = int(key_sel) if key_sel.isnumeric() else GenerateKeyBlobSelect.get(key_sel)
        assert isinstance(key_sel_int, int)
        write_response = mboot.generate_key_blob(data, key_sel=key_sel_int)
        display_output(
            [mboot.status_code, len(write_response)] if write_response else None,
            mboot.status_code,
            ctx.obj["use_json"],
        )
        if write_response:
            blob_file.write(write_response)  # type: ignore


@main.group()
@click.pass_context
def key_provisioning(ctx: click.Context) -> None:
    """Group of sub-commands related to key provisioning."""


@key_provisioning.command()
@click.pass_context
def enroll(ctx: click.Context) -> None:
    """Enrolls key provisioning feature. No argument for this operation."""
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.kp_enroll()
        display_output([], mboot.status_code, ctx.obj["use_json"])


@main.command()
@click.argument("file", metavar="FILE", type=click.File("rb"), required=True)
@click.pass_context
def program_aeskey(ctx: click.Context, file: click.File) -> None:
    """Sends raw binary, which contains an aes key, to the devices and program it to the OTP field.

    \b
    FILE    - file, which contains an aes key
    """
    data = file.read()  # type: ignore
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.write_memory(address=0x0, data=data, mem_id=0x200)
        display_output([], mboot.status_code, ctx.obj["use_json"])


@key_provisioning.command(name="set_user_key")
@click.argument("key_type", metavar="TYPE", type=str, required=True)
@click.argument("file_and_size", metavar="FILE[,SIZE]", type=str, required=True)
@click.pass_context
def set_user_key(ctx: click.Context, key_type: str, file_and_size: str) -> None:
    """Sends the user key specified by type to the bootloader.

    <FILE> is the binary file containing user key plain text.
    If <SIZE> is not specified, the entire <FILE> will be sent.
    Otherwise, blhost only sends the first <SIZE> bytes.

    \b
    TYPE  - Type of user key
    FILE  - Binary file containing user key plaintext
    SIZE  - If not specified, the entire <file> will be sent. Otherwise, only send
            the first <size> bytes.

    \b
    Available KEY TYPES:
     2 or 'OTFADKEK'    OTFAD key
     3 or 'SBKEK'       SB file encryption key
     7 or 'PRINCE0'     Prince region 0 encryption key
     8 or 'PRINCE1'     Prince region 1 encryption key
     9 or 'PRINCE2'     Prince region 2 encryption key
    11 or 'USERKEK'     User/Boot-image encryption key
    12 or 'UDS'         Universal Device Secret for DICE

    \b
    Note: The valid options of <type> and corresponding <size> are documented
          in the target's Reference Manual or User Manual.
    Note: Names are case insensitive
    """
    file_path, size = parse_file_and_size(file_and_size)
    key_type_int = parse_key_prov_key_type(key_type)
    with open(file_path, "rb") as key_file:
        key_data = key_file.read(size)

    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.kp_set_user_key(key_type=key_type_int, key_data=key_data)  # type: ignore
        display_output([], mboot.status_code, ctx.obj["use_json"])


@key_provisioning.command(name="set_key")
@click.argument("key_type", metavar="TYPE", type=str, required=True)
@click.argument("key_size", metavar="SIZE", type=int, required=True)
@click.pass_context
def set_key(ctx: click.Context, key_type: str, key_size: int) -> None:
    """Generates a size bytes of the key specified by the type.

    \b
    TYPE  - type of key to generate,
    SIZE  - size of key to generate

    \b
    Available KEY TYPES:
     2 or 'OTFADKEK'    OTFAD key
     3 or 'SBKEK'       SB file encryption key
     7 or 'PRINCE0'     Prince region 0 encryption key
     8 or 'PRINCE1'     Prince region 1 encryption key
     9 or 'PRINCE2'     Prince region 2 encryption key
    11 or 'USERKEK'     User/Boot-image encryption key
    12 or 'UDS'         Universal Device Secret for DICE

    \b
    Note: The valid options of <type> and corresponding <size> are documented
          in the target's Reference Manual or User Manual.
    Note: Names are case insensitive
    """
    key_type_int = parse_key_prov_key_type(key_type)
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.kp_set_intrinsic_key(key_type_int, key_size)
        display_output([], mboot.status_code, ctx.obj["use_json"])


@key_provisioning.command(name="write_key_nonvolatile")
@click.argument("memory_id", metavar="memoryID", type=int, default=0)
@click.pass_context
def write_key_nonvolatile(ctx: click.Context, memory_id: int) -> None:
    """Writes the key to nonvolatile memory.

    \b
    memoryID  - ID of the non-volatile memory, default: 0
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.kp_write_nonvolatile(memory_id)
        display_output([], mboot.status_code, ctx.obj["use_json"])


@key_provisioning.command(name="read_key_nonvolatile")
@click.argument("memory_id", metavar="memoryID", type=int, default=0)
@click.pass_context
def read_key_nonvolatile(ctx: click.Context, memory_id: int) -> None:
    """Loads the key from nonvolatile memory to bootloader.

    \b
    memoryID  - ID of the non-volatile memory, default: 0
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.kp_read_nonvolatile(memory_id)
        display_output([], mboot.status_code, ctx.obj["use_json"])


@key_provisioning.command(name="write_key_store")
@click.argument("file_and_size", metavar="FILE[,SIZE]", type=str, required=True)
@click.pass_context
def write_key_store(ctx: click.Context, file_and_size: str) -> None:
    """Sends the key store to the bootloader.

    <FILE> is the binary file containing key store.
    If <SIZE> is not specified, the entire <FILE> will be sent.
    Otherwise, only send the first <SIZE> bytes.

    \b
    FILE  - Binary file containing key store.
    SIZE  - If not specified, the entire <file> will be sent. Otherwise, only send
            the first <size> bytes.
    """
    file_path, size = parse_file_and_size(file_and_size)

    with open(file_path, "rb") as key_file:
        key_data = key_file.read(size)

    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.kp_write_key_store(key_data)
        display_output([], mboot.status_code, ctx.obj["use_json"])


@key_provisioning.command(name="read_key_store")
@click.argument("key_store_file", metavar="FILE", type=click.File("wb"), required=True)
@click.pass_context
def read_key_store(ctx: click.Context, key_store_file: click.File) -> None:
    """Reads the key store from the bootloader to host(PC).

    <FILE> is the binary file to store the key store.

    \b
    FILE  - Binary file to save the key store.
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.kp_read_key_store()
        display_output(
            [len(response)] if response else None,
            mboot.status_code,
            ctx.obj["use_json"],
        )
        if response:
            key_store_file.write(response)  # type: ignore


def display_output(
    response: list = None,
    status_code: int = 0,
    use_json: bool = False,
    extra_output: str = None,
) -> None:
    """Displays response and status code.

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
        print(f"Response status = {decode_status_code(status_code)}")
        if isinstance(response, list):
            for i, word in enumerate(response):
                print(f"Response word {i + 1} = {word} ({word:#x})")
        if extra_output:
            print(extra_output)


def decode_status_code(status_code: int) -> str:
    """Stringifies the MBoot status code.

    :param status_code: MBoot status code
    :type status_code: int
    :return: String representation
    """
    return (
        f"{status_code} ({status_code:#x}) "
        f"{StatusCode.desc(status_code, f'Unknown error code ({status_code})')}."
    )


@catch_spsdk_error
def safe_main() -> None:
    """Calls the main function."""
    sys.exit(main())  # pragma: no cover  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()  # pragma: no cover
