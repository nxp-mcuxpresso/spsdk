#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Console script for MBoot module aka BLHost."""

import logging
import os
import shlex
import sys

import click

from spsdk.apps.blhost_helper import (
    OemGenMasterShareHelp,
    OemSetMasterShareHelp,
    display_output,
    parse_key_prov_key_type,
    parse_property_tag,
    parse_trust_prov_key_type,
    parse_trust_prov_oem_key_type,
)
from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    SpsdkClickGroup,
    spsdk_apps_common_options,
    spsdk_family_option,
    spsdk_mboot_interface,
    spsdk_use_json_option,
)
from spsdk.apps.utils.utils import (
    INT,
    SPSDKAppError,
    catch_spsdk_error,
    format_raw_data,
    parse_file_and_size,
    parse_hex_data,
    progress_bar,
)
from spsdk.exceptions import SPSDKError
from spsdk.mboot.mcuboot import GenerateKeyBlobSelect, McuBoot, StatusCode, parse_property_value
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.utils.database import DatabaseManager, get_families
from spsdk.utils.misc import Endianness, load_hex_string


@click.group(name="blhost", no_args_is_help=True, cls=CommandsTreeGroup)
@spsdk_mboot_interface()
@spsdk_use_json_option
@spsdk_apps_common_options
@click.option(
    "-s",
    "--silent",
    is_flag=True,
    help="Silent mode suppresses progress bar and status response",
)
@click.pass_context
def main(
    ctx: click.Context,
    interface: MbootProtocolBase,
    use_json: bool,
    log_level: int,
    silent: bool,
) -> int:
    """Utility for communication with the bootloader on target."""
    log_level = log_level or logging.WARNING
    spsdk_logger.install(level=log_level)

    # print help for get-property if property tag is 0 or 'list-properties'
    if ctx.invoked_subcommand == "get-property":
        args = sys.argv[1:]
        # running this via pytest changes the args to a single arg, in that case skip
        if len(args) > 1 and "get-property" in args:
            try:
                tag_str = args[args.index("get-property") + 1]
                if parse_property_tag(tag_str) == 0:
                    click.echo(ctx.command.commands["get-property"].help)  # type: ignore
                    ctx.exit(0)
            except IndexError:
                click.echo("Invalid index for get-property", err=True)
                ctx.exit(1)

    ctx.obj = {
        "interface": interface,
        "use_json": use_json,
        "suppress_progress_bar": use_json or silent or log_level < logging.WARNING,
        "silent": silent,
    }
    return 0


@main.command(no_args_is_help=True)
@click.argument("command_file", type=click.Path(file_okay=True))
@click.pass_context
def batch(ctx: click.Context, command_file: str) -> None:
    """Invoke blhost commands defined in command file.

    Command file contains one blhost command per line.
    example: "read-memory 0 4096 memory.bin"
    example: "get-property 24 # read target version"

    Comments are supported. Everything after '#' is a comment (just like in Python/Shell)

    Note: This is an early experimental format, it may change at any time.

    \b
    COMMAND_FILE    - path to blhost command file
    """
    with open(command_file, encoding="utf-8") as f:
        for line in f.readlines():
            tokes = shlex.split(line, comments=True)
            if len(tokes) < 1:
                continue

            command_name, *command_args = tokes
            ctx.params = {}
            assert isinstance(ctx.parent, click.Context)
            assert isinstance(ctx.parent.command, click.Group)
            cmd_obj = ctx.parent.command.commands.get(command_name)
            if not cmd_obj:
                raise SPSDKError(f"Unknown command: {command_name}")
            cmd_obj.parse_args(ctx, command_args)
            ctx.invoke(cmd_obj, **ctx.params)


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
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command(no_args_is_help=True)
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
        mboot.configure_memory(address, memory_id)
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command(no_args_is_help=True)
@click.argument("address", type=INT(), required=True)
@click.argument("data", type=INT(base=16), required=True)
@click.argument(
    "lock",
    metavar="[nolock/lock]",
    type=click.Choice(["nolock", "lock"], case_sensitive=False),
    default="nolock",
)
@click.option(
    "-v / ",
    "--verify/--no-verify",
    is_flag=True,
    default=False,
    help="Verify write operation (don't verify by default)",
)
@click.pass_context
def efuse_program_once(
    ctx: click.Context, address: int, data: int, lock: str, verify: bool
) -> None:
    """Writes data to a specific efuse word.

    Each efuse bit can only be programmed once.

    \b
    ADDRESS - address of OTP word, not the shadowed memory address.
    DATA    - hex digits without prefix '0x'.
    """
    if lock == "lock":
        address = address | (1 << 24)
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.efuse_program_once(address, data, verify=verify)
        display_output([response], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command(no_args_is_help=True)
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
            ctx.obj["silent"],
        )


@main.command(no_args_is_help=True)
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
        mboot.execute(address, argument, stackpointer)
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command(no_args_is_help=True)
@click.argument("address", type=INT(), required=True)
@click.argument("byte_count", type=INT(), required=True)
@click.argument("memory_id", type=INT(), required=False, default="0")
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
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command()
@click.argument("memory_id", type=INT(), required=False, default="0")
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
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command()
@click.pass_context
def flash_erase_all_unsecure(ctx: click.Context) -> None:
    """Erase complete flash memory and recover flash security section."""
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.flash_erase_all_unsecure()
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command(no_args_is_help=True)
@click.argument("image_file_path", metavar="FILE", type=str, required=True)
@click.argument("erase", type=str, required=False, default="none")
@click.argument("memory_id", type=INT(), required=False, default="0")
@click.pass_context
def flash_image(ctx: click.Context, image_file_path: str, erase: str, memory_id: int) -> None:
    """Write the formatted image in <FILE> to the memory specified by memoryID.

    \b
    FILE       - path to image file
    ERASE      - string 'erase' determines if flash is erased before writing
    MEMORY_ID  - id of memory to erase (default: 0)
    """
    from spsdk.utils.images import BinaryImage

    ALIGNMENT = 1024

    if not os.path.isfile(image_file_path):
        raise SPSDKError("The image file does not exist")
    mem_id = 0
    if erase not in ["erase", "none"]:
        try:
            mem_id = int(erase, 0)
        except ValueError as e:
            raise SPSDKError(
                "The option for erasing was not declared properly. Choose from 'erase' or 'none'."
            ) from e
    if memory_id:
        mem_id = memory_id
    bin_image = BinaryImage.load_binary_image(image_file_path)
    with McuBoot(ctx.obj["interface"]) as mboot:
        if erase == "erase":
            for segment in bin_image.sub_images:
                mboot.flash_erase_region(
                    address=segment.aligned_start(ALIGNMENT),
                    length=segment.aligned_length(ALIGNMENT),
                    mem_id=mem_id,
                )
                if mboot.status_code != StatusCode.SUCCESS:
                    display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])
                    raise SPSDKAppError()
        for i, segment in enumerate(bin_image.sub_images, start=1):
            with progress_bar(
                suppress=ctx.obj["suppress_progress_bar"], label=f"Writing segment #{i}"
            ) as progress_callback:
                mboot.write_memory(
                    address=segment.absolute_address,
                    data=segment.export(),
                    mem_id=mem_id,
                    progress_callback=progress_callback,
                )
            display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command(no_args_is_help=True)
@click.argument("index", type=INT(), required=True)
@click.argument("byte_count", type=click.Choice(["4", "8"], case_sensitive=False), required=True)
@click.argument("data", type=INT(base=16), required=True)
@click.argument(
    "endianness",
    metavar="[LSB|MSB]",
    type=click.Choice(["LSB", "MSB"], case_sensitive=False),
    default="LSB",
    required=False,
)
@click.pass_context
def flash_program_once(
    ctx: click.Context, index: int, byte_count: str, data: int, endianness: str
) -> None:
    """Writes provided data to a specific program once field.

    \b
    INDEX       - fuse word index
    BYTE_COUNT  - width in bits (acceptable only 4 or 8-byte long data)
    DATA        - 4 or 8-byte-hex according to <byte_count>
    ENDIANNESS   - output sequence is specified by LSB (Default) or MSB
    """
    byte_order = Endianness.BIG if endianness == "MSB" else Endianness.LITTLE
    input_data = data.to_bytes(int(byte_count), byteorder=byte_order.value)
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.flash_program_once(index=index, data=input_data)
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command(no_args_is_help=True)
@click.argument("index", type=INT(), required=True)
@click.argument(
    "byte_count", type=click.Choice(["4", "8"], case_sensitive=False), required=True, default="4"
)
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
            (
                None
                if response is None
                else [len(response), int.from_bytes(response, Endianness.LITTLE.value)]
            ),
            mboot.status_code,
            ctx.obj["use_json"],
            ctx.obj["silent"],
        )


@main.command(no_args_is_help=True)
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
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command(no_args_is_help=True)
@click.argument("address", type=INT(), required=True)
@click.argument("length", type=INT(), required=True)
@click.argument("option", type=click.Choice(["0", "1"], case_sensitive=False), required=True)
@click.argument("out_file", metavar="FILE", type=click.File("wb"), required=False)
@click.option("-h", "--use-hexdump", is_flag=True, default=False, help="Use hexdump format")
@click.pass_context
def flash_read_resource(
    ctx: click.Context,
    address: int,
    length: int,
    option: str,
    out_file: click.File,
    use_hexdump: bool,
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
            ctx.obj["silent"],
            f"Read {len(response) if response else 0} of {length} bytes.",
        )


@main.command(no_args_is_help=True)
@click.argument("address", type=INT(), required=True)
@click.argument("byte_count", type=INT(), required=True)
@click.argument("pattern", type=INT(), required=True)
@click.argument(
    "pattern_format",
    metavar="format",
    type=click.Choice(["word", "short", "byte"], case_sensitive=False),
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
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command(no_args_is_help=True)
@click.argument("address", type=INT(), required=True)
@click.argument("data_source", metavar="FILE[,BYTE_COUNT] | {{HEX-DATA}}", type=str, required=True)
@click.argument("memory_id", type=INT(), required=False, default="0")
@click.pass_context
def fuse_program(ctx: click.Context, address: int, data_source: str, memory_id: int) -> None:
    """Program fuse.

    \b
    ADDRESS     - starting address
    FILE        - write the content of this file
    BYTE_COUNT  - if specified, load only first BYTE_COUNT number of bytes from file
    HEX-DATA    - string of hex values: {{112233}}, {{11 22 33}}
                - when using Jupyter notebook, use [[ ]] instead of {{ }}: eg. [[11 22 33]]
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
        display_output(
            [len(data)] if response else None,
            mboot.status_code,
            ctx.obj["use_json"],
            ctx.obj["silent"],
        )


@main.command(no_args_is_help=True)
@click.argument("address", type=INT(), required=True)
@click.argument("byte_count", type=INT(), required=True)
@click.argument("out_file", metavar="FILE", type=click.File("wb"), required=False)
@click.argument("memory_id", type=INT(), default="0", required=False)
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
        ctx.obj["silent"],
        f"Read {len(response) if response else 0} of {byte_count} bytes.",
    )


@main.command()
@click.pass_context
def list_memory(ctx: click.Context) -> None:
    """Lists all memories, supported by the current device."""
    with McuBoot(ctx.obj["interface"]) as mboot:
        print("Internal Flash:")
        int_flash = mboot._get_internal_flash()  # pylint: disable=protected-access
        for flash in int_flash:
            print(f"    {flash}")
        print("Internal RAM:")
        int_ram = mboot._get_internal_ram()  # pylint: disable=protected-access
        for ram in int_ram:
            print(f"    {ram}")
        print("External Memories:")
        ext_mem = mboot._get_ext_memories()  # pylint: disable=protected-access
        for mem in ext_mem:
            print(f"{(mem.name)}:\n  {mem}")


@main.command(no_args_is_help=True)
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
        with progress_bar(
            suppress=ctx.obj["suppress_progress_bar"], label="Loading image"
        ) as progress_callback:
            mboot.load_image(data, progress_callback)
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command(no_args_is_help=True)
@click.argument("property_tag", type=str, required=True)
@click.argument("index", type=INT(), default="0")
@spsdk_family_option(
    families=get_families(DatabaseManager.BLHOST, "overridden_properties"), required=False
)
@click.pass_context
def get_property(
    ctx: click.Context,
    property_tag: str,
    index: int,
    family: str,
) -> None:
    """Queries various bootloader properties and settings.

    Each supported property has a unique <PROPERTY_TAG>.

    \b
    PROPERTY_TAG - number or name representing the requested property
    INDEX        - id/index of the memory (default: 0)

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
    30 or 'byte-write-timeout-ms'       Byte write timeout in ms
    31 or 'fuse-locked-status'          Fuse Locked Status
    32 or 'boot status'                 Value of Boot Status Register
    33 or 'loadable-fw-version'         LoadableFWVersion

    \b
    for kw45xx/k32w1xx devices:
    10 or 'verify-erases'               Verify Erases flag
    20 or 'boot status'                 Value of Boot Status Register
    21 or 'loadable-fw-version'         LoadableFWVersion
    22 or 'fuse-program-voltage'        Fuse Program Voltage

    \b
    for kw47xx devices:
    10 or 'verify-erases'               Verify Erases flag
    20 or 'boot status'                 Value of Boot Status Register
    21 or 'loadable-fw-version'         LoadableFWVersion
    34 or 'fuse-program-voltage'        Fuse Program Voltage

    \b
    for mcxa1xx devices:
    17 or 'life-cycle'                  Life Cycle

    \b
    Note: Not all the properties are available for all devices.
    """
    property_tag_int = parse_property_tag(property_tag, family)
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.get_property(property_tag_int, index=index)
        property_text = (
            str(parse_property_value(property_tag_int, response, None, family))
            if response
            else None
        )
        display_output(
            response, mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"], property_text
        )


@main.command(no_args_is_help=True)
@click.argument("property_tag", type=str, required=True)
@click.argument("value", type=INT(), required=True)
@spsdk_family_option(
    families=get_families(DatabaseManager.BLHOST, "overridden_properties"), required=False
)
@click.pass_context
def set_property(
    ctx: click.Context,
    property_tag: str,
    value: int,
    family: str,
) -> None:
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
    30 or 'byte-write-timeout-ms'       Byte write timeout in ms

    \b
    for kw45xx/k32w1xx devices:
    10 or 'verify-erases'               Verify Erases flag
    22 or 'fuse-program-voltage'        Fuse Program Voltage

    \b
    for kw47xx devices:
    10 or 'verify-erases'               Verify Erases flag
    34 or 'fuse-program-voltage'        Fuse Program Voltage

    \b
    Note: Not all properties can be set on all devices.
    """
    property_tag_int = parse_property_tag(property_tag, family)
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.set_property(prop_tag=property_tag_int, value=value)
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command(no_args_is_help=True)
@click.argument("address", type=INT(), required=True)
@click.argument("byte_count", type=INT(), required=True)
@click.argument("out_file", metavar="FILE", type=click.File("wb"), required=False)
@click.argument("memory_id", type=INT(), default="0", required=False)
@click.option("-h", "--use-hexdump", is_flag=True, default=False, help="Use hexdump format")
@click.option(
    "-f",
    "--fast-mode",
    is_flag=True,
    default=False,
    help="Fast mode for USB-HID data transfer, not reliable !!!",
)
@click.pass_context
def read_memory(
    ctx: click.Context,
    address: int,
    byte_count: int,
    out_file: click.File,
    memory_id: int,
    use_hexdump: bool,
    fast_mode: bool,
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
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        with progress_bar(
            suppress=ctx.obj["suppress_progress_bar"], label="Reading memory"
        ) as progress_callback:
            response = mboot.read_memory(
                address, byte_count, memory_id, progress_callback, fast_mode
            )

    if response:
        if out_file and out_file.name != "<stdout>":
            out_file.write(response)  # type: ignore
        else:
            click.echo(format_raw_data(response, use_hexdump=use_hexdump))

    display_output(
        [len(response) if response else 0],
        mboot.status_code,
        ctx.obj["use_json"],
        ctx.obj["silent"],
        f"Read {len(response) if response else 0} of {byte_count} bytes.",
    )


@main.command(no_args_is_help=True)
@click.argument("sb_file", metavar="FILE", type=click.File("rb"), required=True)
@click.option(
    "-c",
    "--check-errors",
    is_flag=True,
    default=False,
    help=(
        "This flag should be used when the `receive-sb-file` operation fails using USB interface. "
        "Without this flag USB transfer is significantly faster (roughly 20x) "
        "However, the status code might be misleading in case of an error. "
        "In case of an error using USB interface, "
        "rerun `receive-sb-file` with this setting for clearer error message. "
        "This setting has no effect interfaces other than USB."
    ),
)
@click.pass_context
def receive_sb_file(ctx: click.Context, sb_file: click.File, check_errors: bool) -> None:
    """Receives a file in a Secure Binary (SB) format.

    An SB file is an encapsulated, binary stream of bootloader commands that can be optionally encrypted.

    \b
    FILE    - SB file to send to the target
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        with progress_bar(
            suppress=ctx.obj["suppress_progress_bar"], label="Sending SB file"
        ) as progress_callback:
            data = sb_file.read()  # type: ignore
            mboot.receive_sb_file(data, progress_callback, check_errors)
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command(no_args_is_help=True)
@click.argument("address", type=INT(), required=True)
@click.pass_context
def reliable_update(ctx: click.Context, address: int) -> None:
    """Reliable Update.

    \b
    ADDRESS     - starting address
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.reliable_update(address)
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command()
@click.pass_context
def reset(ctx: click.Context) -> None:
    """Resets the device.

    A response packet is sent before resetting the device.
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.reset(reopen=False)
    display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command(no_args_is_help=True)
@click.argument("address", type=INT(), required=True)
@click.argument("data_source", metavar="FILE[,BYTE_COUNT] | {{HEX-DATA}}", type=str, required=True)
@click.argument("memory_id", type=INT(), required=False, default="0")
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
                - when using Jupyter notebook, use [[ ]] instead of {{ }}: eg. [[11 22 33]]
    MEMORY_ID   - id of memory to read from (default: 0)
    """
    try:
        data = parse_hex_data(data_source)
    except SPSDKError:
        file_path, size = parse_file_and_size(data_source)
        with open(file_path, "rb") as f:
            data = f.read(size)

    with McuBoot(ctx.obj["interface"]) as mboot:
        with progress_bar(
            suppress=ctx.obj["suppress_progress_bar"], label="Writing memory"
        ) as progress_callback:
            response = mboot.write_memory(address, data, memory_id, progress_callback)
        display_output(
            [len(data)] if response else None,
            mboot.status_code,
            ctx.obj["use_json"],
            ctx.obj["silent"],
        )


@main.command(no_args_is_help=True)
@click.argument("dek_file", type=click.File("rb"), required=True)
@click.argument("blob_file", type=click.File("wb"), required=True)
@click.argument(
    "key_sel",
    metavar="[KEY_SEL]",
    type=click.Choice(["0", "1", "2", "3", "OPTMK", "ZMK", "CMK"], case_sensitive=False),
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
        key_sel_int = (
            int(key_sel) if key_sel.isnumeric() else GenerateKeyBlobSelect.get_tag(key_sel)
        )
        assert isinstance(key_sel_int, int)
        write_response = mboot.generate_key_blob(data, key_sel=key_sel_int)
        if write_response:
            blob_file.write(write_response)  # type: ignore
        display_output(
            [mboot.status_code, len(write_response)] if write_response else None,
            mboot.status_code,
            ctx.obj["use_json"],
            ctx.obj["silent"],
        )


@main.group(cls=SpsdkClickGroup)
@click.pass_context
def key_provisioning(ctx: click.Context) -> None:  # pylint: disable=unused-argument
    """Group of sub-commands related to key provisioning."""


@key_provisioning.command(no_args_is_help=False)
@click.pass_context
def enroll(ctx: click.Context) -> None:
    """Enrolls key provisioning feature. No argument for this operation."""
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.kp_enroll()
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command(no_args_is_help=True)
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
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@key_provisioning.command(name="set_user_key", no_args_is_help=True)
@click.option(
    "-s",
    "--key-size",
    type=INT(),
    required=False,
    help=(
        "Key size in bits. If this field is defined,"
        " the command could load as text as binary form of key."
    ),
)
@click.argument("key_type", metavar="TYPE", type=str, required=True)
@click.argument("file_and_size", metavar="FILE[,SIZE]", type=str, required=True)
@click.pass_context
def set_user_key(ctx: click.Context, key_type: str, file_and_size: str, key_size: int) -> None:
    """Sends the user key specified by type to the bootloader.

    <FILE> is the binary file containing user key plain text.
    If <SIZE> is not specified, the entire <FILE> will be sent.
    Otherwise, blhost only sends the first <SIZE> bytes.

    \b
    If the '--key-size' option is defined, the argument 'file_and_size' accepts those formats:
     - filename to binary file
     - filename to text file
     - string with key
    The size part is ignored in this case.

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

    if not key_size:
        key_size = (size if size > 0 else os.path.getsize(file_path)) * 8

    key_data = load_hex_string(file_path, expected_size=key_size // 8)

    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.kp_set_user_key(key_type=key_type_int, key_data=key_data)
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@key_provisioning.command(name="set_key", no_args_is_help=True)
@click.argument("key_type", metavar="TYPE", type=str, required=True)
@click.argument("key_size", metavar="SIZE", type=INT(), required=True)
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
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@key_provisioning.command(name="write_key_nonvolatile")
@click.argument("memory_id", metavar="memoryID", type=INT(), default="0")
@click.pass_context
def write_key_nonvolatile(ctx: click.Context, memory_id: int) -> None:
    """Writes the key to nonvolatile memory.

    \b
    memoryID  - ID of the non-volatile memory, default: 0
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.kp_write_nonvolatile(memory_id)
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@key_provisioning.command(name="read_key_nonvolatile")
@click.argument("memory_id", metavar="memoryID", type=INT(), default="0")
@click.pass_context
def read_key_nonvolatile(ctx: click.Context, memory_id: int) -> None:
    """Loads the key from nonvolatile memory to bootloader.

    \b
    memoryID  - ID of the non-volatile memory, default: 0
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.kp_read_nonvolatile(memory_id)
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@key_provisioning.command(name="write_key_store", no_args_is_help=True)
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
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@key_provisioning.command(name="read_key_store", no_args_is_help=True)
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
        if response:
            key_store_file.write(response)  # type: ignore
        display_output(
            [len(response)] if response else None,
            mboot.status_code,
            ctx.obj["use_json"],
            ctx.obj["silent"],
        )


@main.group(cls=SpsdkClickGroup)
@click.pass_context
def trust_provisioning(ctx: click.Context) -> None:  # pylint: disable=unused-argument
    """Group of sub-commands related to trust provisioning."""


@trust_provisioning.command(name="hsm_store_key", no_args_is_help=True)
@click.argument("key_type", metavar="KEY_TYPE", type=str, required=True)
@click.argument("key_property", metavar="KEY_PROPERTY", type=INT(), required=True)
@click.argument("key_input_addr", metavar="KEY_INPUT_ADDR", type=INT(), required=True)
@click.argument("key_input_size", metavar="KEY_INPUT_SIZE", type=INT(), required=True)
@click.argument("key_blob_output_addr", metavar="KEY_BLOB_OUTPUT_ADDR", type=INT(), required=True)
@click.argument("key_blob_output_size", metavar="KEY_BLOB_OUTPUT_SIZE", type=INT(), required=True)
@click.pass_context
def hsm_store_key(
    ctx: click.Context,
    key_type: str,
    key_property: int,
    key_input_addr: int,
    key_input_size: int,
    key_blob_output_addr: int,
    key_blob_output_size: int,
) -> None:
    """Stores known keys, and generate the corresponding key blob.

    It wraps the known key, which is given by the customer,
    using NXP_CUST_KEK_EXT_SK, and output the RFC3396 key blob.

    \b
    KEY_TYPE              - Type of key to generate (CKDFK, HKDFK, HMACK, CMACK, AESK, KUOK)
    KEY_PROPERTY          - Bit 0: Key Size, 0 for 128bit, 1 for 256bit. Bits 30-31: set key protection CSS mode
    KEY_INPUT_ADDR        - The input buffer address where the key locates at
    KEY_INPUT_SIZE        - The byte count of the key
    KEY_BLOB_OUTPUT_ADDR  - The output buffer address where ROM writes the key blob to
    KEY_BLOB_OUTPUT_SIZE  - The output buffer size in byte
    """
    key_type_int = parse_trust_prov_key_type(key_type)
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.tp_hsm_store_key(
            key_type_int,
            key_property,
            key_input_addr,
            key_input_size,
            key_blob_output_addr,
            key_blob_output_size,
        )

        extra_output = ""
        if response:
            key_header = response[0]
            key_blob_size = response[1]
            if mboot.status_code == StatusCode.SUCCESS:
                extra_output = "Output data size/value(s) is(are):\n"
                extra_output += (
                    f"\tKey Header: {key_header} ({hex(key_header)})\n"
                    f"\tKey Blob size: {key_blob_size} ({hex(key_blob_size)})"
                )
        display_output(
            response, mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"], extra_output
        )


@trust_provisioning.command(name="hsm_gen_key", no_args_is_help=True)
@click.argument("key_type", metavar="KEY_TYPE", type=str, required=True)
@click.argument("reserved", metavar="RESERVED", type=INT(), required=True)
@click.argument("key_blob_output_addr", metavar="KEY_BLOB_OUTPUT_ADDR", type=INT(), required=True)
@click.argument("key_blob_output_size", metavar="KEY_BLOB_OUTPUT_SIZE", type=INT(), required=True)
@click.argument("ecdsa_puk_output_addr", metavar="ECDSA_PUK_OUTPUT_ADDR", type=INT(), required=True)
@click.argument("ecdsa_puk_output_size", metavar="ECDSA_PUK_OUTPUT_SIZE", type=INT(), required=True)
@click.pass_context
def hsm_gen_key(
    ctx: click.Context,
    key_type: str,
    reserved: int,
    key_blob_output_addr: int,
    key_blob_output_size: int,
    ecdsa_puk_output_addr: int,
    ecdsa_puk_output_size: int,
) -> None:
    """Creates OEM common keys, including encryption keys and signing keys.

    It outputs the key blob, which is wrapped by NXP_CUST_KEK_IN_SK
    and the public portion of the signing key.

    \b
    KEY_TYPE              - Type of key to generate (MFWISK, MFWENCK, GENSIGNK, GETCUSTMKSK)
    RESERVED              - Reserved must be 0
    KEY_BLOB_OUTPUT_ADDR  - Output buffer address where ROM writes the key blob to
    KEY_BLOB_OUTPUT_SIZE  - Output buffer size in bytes
    ECDSA_PUK_OUTPUT_ADDR - Output buffer address where ROM writes the public key to
    ECDSA_PUK_OUTPUT_SIZE - Output buffer size in bytes
    """
    key_type_int = parse_trust_prov_oem_key_type(key_type)
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.tp_hsm_gen_key(
            key_type_int,
            reserved,
            key_blob_output_addr,
            key_blob_output_size,
            ecdsa_puk_output_addr,
            ecdsa_puk_output_size,
        )

        extra_output = ""
        if response:
            keyblob_size = response[0]
            ecdsa_puk_size = response[1]
            if mboot.status_code == StatusCode.SUCCESS:
                extra_output = "Output data size/value(s) is(are):\n"
            else:
                extra_output = (
                    "Output buffer(s) is(are) smaller than the minimum requested which is(are):\n"
                )
            extra_output += (
                f"\tKey Blob size: {keyblob_size} ({hex(keyblob_size)})\n"
                f"\tECDSA Puk size: {ecdsa_puk_size} ({hex(ecdsa_puk_size)})"
            )
        display_output(
            response, mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"], extra_output
        )


@trust_provisioning.command(name="hsm_enc_blk", no_args_is_help=True)
@click.argument(
    "mfg_cust_mk_sk_0_blob_input_addr",
    metavar="MFG_CUST_MK_SK_0_BLOB_INPUT_ADDR",
    type=INT(),
    required=True,
)
@click.argument(
    "mfg_cust_mk_sk_0_blob_input_size",
    metavar="MFG_CUST_MK_SK_0_BLOB_INPUT_SIZE",
    type=INT(),
    required=True,
)
@click.argument("kek_id", metavar="KEK_ID", type=str, required=True)
@click.argument("sb3_header_input_addr", metavar="SB3_HEADER_INPUT_ADDR", type=INT(), required=True)
@click.argument("sb3_header_input_size", metavar="SB3_HEADER_INPUT_SIZE", type=INT(), required=True)
@click.argument("block_num", metavar="BLOCK_NUM", type=INT(), required=True)
@click.argument("block_data_addr", metavar="BLOCK_DATA_ADDR", type=INT(), required=True)
@click.argument("block_data_size", metavar="BLOCK_DATA_SIZE", type=INT(), required=True)
@click.pass_context
def hsm_enc_blk(
    ctx: click.Context,
    mfg_cust_mk_sk_0_blob_input_addr: int,
    mfg_cust_mk_sk_0_blob_input_size: int,
    kek_id: str,
    sb3_header_input_addr: int,
    sb3_header_input_size: int,
    block_num: int,
    block_data_addr: int,
    block_data_size: int,
) -> None:
    """Encrypts the given SB3 data block.

    \b
    MFG_CUST_MK_SK_0_BLOB_INPUT_ADDR - The input buffer address where the CKDF Master Key Blob locates at
    MFG_CUST_MK_SK_0_BLOB_INPUT_SIZE - The byte count of the CKDF Master Key Blob
    KEK_ID                           - The CKDF Master Key Encryption Key ID
    (0x10: NXP_CUST_KEK_INT_SK, 0x11: NXP_CUST_KEK_EXT_SK)
    SB3_HEADER_INPUT_ADDR            - The input buffer address where the SB3 Header(block0) locates at
    SB3_HEADER_INPUT_SIZE            - The byte count of the SB3 Header
    BLOCK_NUM                        - The index of the block. Due to SB3 Header(block 0) is always unencrypted,
    the index starts from block1
    BLOCK_DATA_ADDR                  - The buffer address where the SB3 data block locates at
    BLOCK_DATA_SIZE                  - The byte count of the SB3 data block
    """
    kek_id_int = parse_trust_prov_key_type(kek_id)
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.tp_hsm_enc_blk(
            mfg_cust_mk_sk_0_blob_input_addr,
            mfg_cust_mk_sk_0_blob_input_size,
            kek_id_int,
            sb3_header_input_addr,
            sb3_header_input_size,
            block_num,
            block_data_addr,
            block_data_size,
        )
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@trust_provisioning.command(name="hsm_enc_sign", no_args_is_help=True)
@click.argument("key_blob_input_addr", metavar="KEY_BLOB_INPUT_ADDR", type=INT(), required=True)
@click.argument("key_blob_input_size", metavar="KEY_BLOB_INPUT_SIZE", type=INT(), required=True)
@click.argument("block_data_input_addr", metavar="BLOCK_DATA_INPUT_ADDR", type=INT(), required=True)
@click.argument("block_data_input_size", metavar="BLOCK_DATA_INPUT_SIZE", type=INT(), required=True)
@click.argument("signature_output_addr", metavar="SIGNATURE_OUTPUT_ADDR", type=INT(), required=True)
@click.argument("signature_output_size", metavar="SIGNATURE_OUTPUT_SIZE", type=INT(), required=True)
@click.pass_context
def hsm_enc_sign(
    ctx: click.Context,
    key_blob_input_addr: int,
    key_blob_input_size: int,
    block_data_input_addr: int,
    block_data_input_size: int,
    signature_output_addr: int,
    signature_output_size: int,
) -> None:
    """Signs the given data.

    It uses the private key in the given key blob, which is generated by HSM_GEN_KEY.

    \b
    KEY_BLOB_INPUT_ADDR   - The input buffer address where signing key blob locates at
    KEY_BLOB_INPUT_SIZE   - The byte count of the signing key blob
    BLOCK_DATA_INPUT_ADDR - The input buffer address where the data locates at
    BLOCK_DATA_INPUT_SIZE - The byte count of the data
    SIGNATURE_OUTPUT_ADDR - The output buffer address where ROM writes the signature to
    SIGNATURE_OUTPUT_SIZE - The output buffer size in byte
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.tp_hsm_enc_sign(
            key_blob_input_addr,
            key_blob_input_size,
            block_data_input_addr,
            block_data_input_size,
            signature_output_addr,
            signature_output_size,
        )

        extra_output = ""
        if response:
            output_signature_size = response
            if mboot.status_code == StatusCode.SUCCESS:
                extra_output = "Output data size/value(s) is(are):\n"
            else:
                extra_output = (
                    "Output buffer(s) is(are) smaller than the minimum requested which is(are):\n"
                )
            extra_output += (
                f"\tSignature size: {output_signature_size} ({hex(output_signature_size)})"
            )
        display_output(
            [response], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"], extra_output
        )


@trust_provisioning.command(
    name="oem_gen_master_share",
    cls=OemGenMasterShareHelp,
    no_args_is_help=True,
)
@click.argument("oem_share_input_addr", type=INT(), required=True)
@click.argument("oem_share_input_size", type=INT(), required=True)
@click.argument("oem_enc_share_output_addr", type=INT(), required=True)
@click.argument("oem_enc_share_output_size", type=INT(), required=True)
@click.argument("oem_enc_master_share_output_addr", type=INT(), required=True)
@click.argument("oem_enc_master_share_output_size", type=INT(), required=True)
@click.argument("oem_cust_cert_puk_output_addr", type=INT(), required=True)
@click.argument("oem_cust_cert_puk_output_size", type=INT(), required=True)
@click.pass_context
def oem_gen_master_share(
    ctx: click.Context,
    oem_share_input_addr: int,
    oem_share_input_size: int,
    oem_enc_share_output_addr: int,
    oem_enc_share_output_size: int,
    oem_enc_master_share_output_addr: int,
    oem_enc_master_share_output_size: int,
    oem_cust_cert_puk_output_addr: int,
    oem_cust_cert_puk_output_size: int,
) -> None:
    """Creates shares for initial trust provisioning keys.

    \b
    OEM_SHARE_INPUT_ADDR            - The input buffer address where the OEM Share(entropy seed) locates at
    OEM_SHARE_INPUT_SIZE             - The byte count of the OEM Share
    OEM_ENC_SHARE_OUTPUT_ADDR        - The output buffer address where ROM writes the Encrypted OEM Share to
    OEM_ENC_SHARE_OUTPUT_SIZE        - The output buffer size in byte
    OEM_ENC_MASTER_SHARE_OUTPUT_ADDR - The output buffer address where ROM writes the Encrypted OEM Master Share to
    OEM_ENC_MASTER_SHARE_OUTPUT_SIZE - The output buffer size in byte.
    OEM_CUST_CERT_PUK_OUTPUT_ADDR    - The output buffer address where ROM writes
                                       the OEM Customer Certificate Public Key to
    OEM_CUST_CERT_PUK_OUTPUT_SIZE    - The output buffer size in byte
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.tp_oem_gen_master_share(
            oem_share_input_addr,
            oem_share_input_size,
            oem_enc_share_output_addr,
            oem_enc_share_output_size,
            oem_enc_master_share_output_addr,
            oem_enc_master_share_output_size,
            oem_cust_cert_puk_output_addr,
            oem_cust_cert_puk_output_size,
        )
        extra_output = ""
        if response:
            oem_enc_share_size = response[0]
            oem_enc_master_share_size = response[1]
            oem_cust_cert_puk_size = response[2]
            if mboot.status_code == StatusCode.SUCCESS:
                extra_output = "Output data size/value(s) is(are):\n"
            else:
                extra_output = (
                    "Output buffer(s) is(are) smaller than the minimum requested which is(are):\n"
                )
            extra_output += (
                f"\tOEM Share size: {oem_enc_share_size} ({hex(oem_enc_share_size)})\n"
                f"\tOEM Master Share size: {oem_enc_master_share_size} ({hex(oem_enc_master_share_size)})\n"
                f"\tCust Cert Puk size: {oem_cust_cert_puk_size} ({hex(oem_cust_cert_puk_size)})"
            )
        display_output(
            response, mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"], extra_output
        )


@trust_provisioning.command(
    name="oem_set_master_share", cls=OemSetMasterShareHelp, no_args_is_help=True
)
@click.argument("oem_share_input_addr", type=INT(), required=True)
@click.argument("oem_share_input_size", type=INT(), required=True)
@click.argument("oem_enc_master_share_input_addr", type=INT(), required=True)
@click.argument("oem_enc_master_share_input_size", type=INT(), required=True)
@click.pass_context
def oem_set_master_share(
    ctx: click.Context,
    oem_share_input_addr: int,
    oem_share_input_size: int,
    oem_enc_master_share_input_addr: int,
    oem_enc_master_share_input_size: int,
) -> None:
    """Takes the entropy seed and the Encrypted OEM Master Share."""
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.tp_oem_set_master_share(
            oem_share_input_addr,
            oem_share_input_size,
            oem_enc_master_share_input_addr,
            oem_enc_master_share_input_size,
        )
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@trust_provisioning.command(name="oem_get_cust_cert_dice_puk", no_args_is_help=True)
@click.argument("oem_rkth_input_addr", type=INT(), required=True)
@click.argument("oem_rkth_input_size", type=INT(), required=True)
@click.argument("oem_cust_cert_dice_puk_output_addr", type=INT(), required=True)
@click.argument("oem_cust_cert_dice_puk_output_size", type=INT(), required=True)
@click.pass_context
def oem_get_cust_cert_dice_puk(
    ctx: click.Context,
    oem_rkth_input_addr: int,
    oem_rkth_input_size: int,
    oem_cust_cert_dice_puk_output_addr: int,
    oem_cust_cert_dice_puk_output_size: int,
) -> None:
    """Creates the initial trust provisioning keys.

    \b
    OEM_RKTH_INPUT_ADDR                - The input buffer address where the OEM RKTH locates at
    OEM_RKTH_INPUT_SIZE                - The byte count of the OEM RKTH
    OEM_CUST_CERT_DICE_PUK_OUTPUT_ADDR - The output buffer address where ROM writes the OEM Customer
                                         Certificate Public Key for DICE to
    OEM_CUST_CERT_DICE_PUK_OUTPUT_SIZE - The output buffer size in byte
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.tp_oem_get_cust_cert_dice_puk(
            oem_rkth_input_addr,
            oem_rkth_input_size,
            oem_cust_cert_dice_puk_output_addr,
            oem_cust_cert_dice_puk_output_size,
        )
    extra_output = ""
    if response:
        output_size = response
        if mboot.status_code == StatusCode.SUCCESS:
            extra_output = "Output data size/value(s) is(are):\n"
        else:
            extra_output = (
                "Output buffer(s) is(are) smaller than the minimum requested which is(are):"
            )
        extra_output += f"\tCust Cert Dice Puk size: {output_size} ({hex(output_size)})"
    display_output(
        [response], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"], extra_output
    )


@trust_provisioning.command(name="wpc_get_id", no_args_is_help=True)
@click.argument("wpc_id_blob_addr", type=INT(), required=True)
@click.argument("wpc_id_blob_size", type=INT(), required=True)
@click.pass_context
def wpc_get_id(
    ctx: click.Context,
    wpc_id_blob_addr: int,
    wpc_id_blob_size: int,
) -> None:
    """Command used for harvesting device ID blob.

    \b
    WPC_ID_BLOB_ADDR - Buffer address
    WPC_ID_BLOB_SIZE - Buffer size
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.wpc_get_id(
            wpc_id_blob_addr,
            wpc_id_blob_size,
        )
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@trust_provisioning.command(name="nxp_get_id", no_args_is_help=True)
@click.argument("id_blob_addr", type=INT(), required=True)
@click.argument("id_blob_size", type=INT(), required=True)
@click.pass_context
def nxp_get_id(
    ctx: click.Context,
    id_blob_addr: int,
    id_blob_size: int,
) -> None:
    """Command used for harvesting device ID blob during wafer test as part of RTS flow.

    This command is allowed only when LC_STATE < 0x3.

    \b
    ID_BLOB_ADDR            - address of ID blob defined by Round-trip trust provisioning specification.
    ID_BLOB_SIZE            - length of buffer in bytes
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.nxp_get_id(
            id_blob_addr,
            id_blob_size,
        )
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@trust_provisioning.command(name="wpc_insert_cert", no_args_is_help=True)
@click.argument("wpc_cert_addr", type=INT(), required=True)
@click.argument("wpc_cert_len", type=INT(), required=True)
@click.argument("ec_id_offset", type=INT(), required=True)
@click.argument("wpc_puk_offset", type=INT(), required=True)
@click.pass_context
def wpc_insert_cert(
    ctx: click.Context,
    wpc_cert_addr: int,
    wpc_cert_len: int,
    ec_id_offset: int,
    wpc_puk_offset: int,
) -> None:
    """Command used for certificate validation before it is written into flash.

    This command does following things:
        Extracts ECID and WPC PUK from certificate
        Validates ECID and WPC PUK. If both are OK it returns success. Otherwise returns fail

    \b
    WPC_CERT_ADDR   - address of inserted certificate
    WPC_CERT_LEN    - length in bytes of inserted certificate
    EC_ID_OFFSET    - offset to 72-bit ECID
    WPC_PUK_OFFSET  - WPC PUK offset from beginning of inserted certificate
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.wpc_insert_cert(
            wpc_cert_addr,
            wpc_cert_len,
            ec_id_offset,
            wpc_puk_offset,
        )
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@trust_provisioning.command(name="wpc_sign_csr", no_args_is_help=True)
@click.argument("csr_tbs_addr", type=INT(), required=True)
@click.argument("csr_tbs_len", type=INT(), required=True)
@click.argument("signature_addr", type=INT(), required=True)
@click.argument("signature_len", type=INT(), required=True)
@click.pass_context
def wpc_sign_csr(
    ctx: click.Context,
    csr_tbs_addr: int,
    csr_tbs_len: int,
    signature_addr: int,
    signature_len: int,
) -> None:
    """Command used for signing CSR data (TBS portion).

    \b
    CSR_TBS_ADDR   - address of CSR-TBS data
    CSR_TBS_LEN    - length in bytes of CSR-TBS data
    SIGNATURE_ADDR - address where to store signature
    SIGNATURE_LEN  - expected length of signature
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.wpc_sign_csr(
            csr_tbs_addr,
            csr_tbs_len,
            signature_addr,
            signature_len,
        )
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@trust_provisioning.command(name="dsc_hsm_create_session", no_args_is_help=True)
@click.argument("oem_seed_input_addr", type=INT(), required=True)
@click.argument("oem_seed_input_size", type=INT(), required=True)
@click.argument("oem_share_output_addr", type=INT(), required=True)
@click.argument("oem_share_output_size", type=INT(), required=True)
@click.pass_context
def dsc_hsm_create_session(
    ctx: click.Context,
    oem_seed_input_addr: int,
    oem_seed_input_size: int,
    oem_share_output_addr: int,
    oem_share_output_size: int,
) -> None:
    """Command used by OEM to provide it share to create the initial trust provisioning keys.

    \b
    OEM_SEED_INPUT_ADDR     - address of 128-bit entropy seed value provided by the OEM.
    OEM_SEED_INPUT_SIZE     - OEM seed size in bytes
    OEM_SHARE_OUTPUT_ADDR   - A 128-bit encrypted token.
    OEM_SHARE_OUTPUT_SIZE   - size in bytes
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.dsc_hsm_create_session(
            oem_seed_input_addr,
            oem_seed_input_size,
            oem_share_output_addr,
            oem_share_output_size,
        )
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@trust_provisioning.command(name="dsc_hsm_enc_blk", no_args_is_help=True)
@click.argument("sbx_header_input_addr", type=INT(), required=True)
@click.argument("sbx_header_input_size", type=INT(), required=True)
@click.argument("block_num", type=INT(), required=True)
@click.argument("block_data_addr", type=INT(), required=True)
@click.argument("block_data_size", type=INT(), required=True)
@click.pass_context
def dsc_hsm_enc_blk(
    ctx: click.Context,
    sbx_header_input_addr: int,
    sbx_header_input_size: int,
    block_num: int,
    block_data_addr: int,
    block_data_size: int,
) -> None:
    """Command used to encrypt the given block sliced by the nxpimage.

    This command is only supported after issuance of dsc_hsm_create_session.

    \b
    SBX_HEADER_INPUT_ADDR - SBx header containing file size, Firmware version and Timestamp data.
         Except for hash digest of block 0, all other fields should be valid.
    SBX_HEADER_INPUT_SIZE - size of the header in bytes
    BLOCK_NUM             - Number of block
    BLOCK_DATA_ADDR       - Address of data block
    BLOCK_DATA_SIZE       - Size of data block
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.dsc_hsm_enc_blk(
            sbx_header_input_addr,
            sbx_header_input_size,
            block_num,
            block_data_addr,
            block_data_size,
        )
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@trust_provisioning.command(name="dsc_hsm_enc_sign", no_args_is_help=True)
@click.argument("block_data_input_addr", type=INT(), required=True)
@click.argument("block_data_input_size", type=INT(), required=True)
@click.argument("signature_output_addr", type=INT(), required=True)
@click.argument("block_data_addr", type=INT(), required=True)
@click.pass_context
def dsc_hsm_enc_sign(
    ctx: click.Context,
    block_data_input_addr: int,
    block_data_input_size: int,
    signature_output_addr: int,
    signature_output_size: int,
) -> None:
    """Command used for signing the data buffer provided.

    This command is only supported after issuance of dsc_hsm_create_session.

    \b
    BLOCK_DATA_INPUT_ADDR - Address of data buffer to be signed
    BLOCK_DATA_INPUT_SIZE - Size of data buffer in bytes
    SIGNATURE_OUTPUT_ADDR - Address to output signature data
    SIGNATURE_OUTPUT_SIZE - Size of the output signature data in bytes
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.dsc_hsm_enc_sign(
            block_data_input_addr,
            block_data_input_size,
            signature_output_addr,
            signature_output_size,
        )
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


# @main.command(no_args_is_help=True)
@trust_provisioning.command(name="oem_get_cust_dice_response")
@click.argument("challenge_addr", type=INT(), required=True)
@click.argument("challenge_size", type=INT(), required=True)
@click.argument("response_addr", type=INT(), required=True)
@click.argument("response_size", type=INT(), required=True)
@click.pass_context
def oem_get_cust_dice_response(
    ctx: click.Context,
    challenge_addr: int,
    challenge_size: int,
    response_addr: int,
    response_size: int,
) -> None:
    """Creates DICE response for given challenge.

    \b
    CHALLENGE_ADDR - The input buffer address where the challenge is located
    CHALLENGE_SIZE - The byte count of the challenge
    RESPONSE_ADDR  - The output buffer address where ROM writes DICE response
    RESPONSE_SIZE  - The byte count of the response
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.tp_oem_get_cust_dice_response(
            challenge_addr, challenge_size, response_addr, response_size
        )
    extra_output = ""
    if response:
        if mboot.status_code == StatusCode.SUCCESS:
            extra_output = f"Response size: {response} ({hex(response)})\n"
        else:
            extra_output = "Output buffer is smaller than the minimum requested size"
    display_output(
        [response], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"], extra_output
    )


@main.command()
@click.argument("life-cycle", metavar="LIFE CYCLE", type=INT(), required=True)
@click.pass_context
def update_life_cycle(ctx: click.Context, life_cycle: int) -> None:
    """Update life cycle of device.

    \b
    LIFE CYCLE    - Device life cycle to be device move to.
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.update_life_cycle(life_cycle)
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@main.command(no_args_is_help=True)
@click.argument("cmd-msg-addr", metavar="COMMAND MESSAGE ADDRESS", type=INT(), required=True)
@click.argument("cmd-msg-cnt", metavar="COMMAND MESSAGE COUNT", type=INT(), required=True)
@click.argument("resp-msg-addr", metavar="RESPONSE MESSAGE ADDRESS", type=INT(), required=True)
@click.argument("resp-msg-cnt", metavar="RESPONSE MESSAGE COUNT", type=INT(), required=True)
@click.pass_context
def ele_message(
    ctx: click.Context, cmd_msg_addr: int, cmd_msg_cnt: int, resp_msg_addr: int, resp_msg_cnt: int
) -> None:
    """Send message to EdgeLock Enclave.

    This command is designed to be, as general, as is possible to work with EdgeLock Enclave.
    EdgeLock Enclave message is prepared in PC and stored in target RAM (for example by 'blhost write-memory').
    The response of ELE command is stored also in target memory on place that is defined by 'resp-msg-addr
    and could be read back (for example by 'blhost read-memory').


    Size of command message and response is in count of 32-bit words.

    \b
    COMMAND MESSAGE ADDRESS     - Address in target where is stored the command words.
    COMMAND MESSAGE COUNT       - Count of the stored command words.
    RESPONSE MESSAGE ADDRESS    - Address in target memory space where the ELE store response.
    RESPONSE MESSAGE COUNT      - Maximal count of words reserved for response.
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.ele_message(
            cmdMsgAddr=cmd_msg_addr,
            cmdMsgCnt=cmd_msg_cnt,
            respMsgAddr=resp_msg_addr,
            respMsgCnt=resp_msg_cnt,
        )
        display_output([], mboot.status_code, ctx.obj["use_json"], ctx.obj["silent"])


@trust_provisioning.command(name="prove_genuinity", no_args_is_help=True)
@click.argument("address", type=INT())
@click.argument("buffer_size", type=INT())
@click.pass_context
def prove_genuinity(ctx: click.Context, address: int, buffer_size: int) -> None:
    """Start the process of proving genuinity.

    \b
    ADDRESS     - Address where is the prove_genuinity request stored
    BUFFER_SIZE - Maximal size of the generated prove_genuinity response
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        tp_response_length = mboot.tp_prove_genuinity(address=address, buffer_size=buffer_size)
        display_output(
            [tp_response_length],
            mboot.status_code,
            use_json=ctx.obj["use_json"],
            extra_output=(
                f"TP response will be {tp_response_length} bytes long."
                if tp_response_length
                else None
            ),
        )


@trust_provisioning.command(name="isp_set_wrap_data", no_args_is_help=True)
@click.argument("address", type=INT())
@click.argument("control", type=INT(), required=False, default=0x1)
@click.argument("stage", type=INT(), required=False, default=0x4B)
@click.pass_context
def set_wrap_data(ctx: click.Context, address: int, control: int, stage: int) -> None:
    """Start the process of setting wrapped OEM data.

    \b
    ADDRESS - Address of the Wrapped data package in target
    CONTROL - Controls location of the Wrapped data package (1 - by address /default/, 2 - in firmware)
    STAGE   - Stage of the OEM TrustProvisioning process
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        mboot.tp_set_wrapped_data(address=address, control=control, stage=stage)
        display_output(None, mboot.status_code, use_json=ctx.obj["use_json"])


@trust_provisioning.command(name="el2go_close_device", no_args_is_help=True)
@click.argument("address", type=INT())
@click.option("-d", "--dry-run", is_flag=True, default=False, help="Dry run mode")
@click.pass_context
def el2go_close_device(ctx: click.Context, address: int, dry_run: bool) -> None:
    """Close the device using EdgeLock2Go TP Firmware.

    \b
    ADDRESS - Address of the Secure Objects in target to provision
    """
    with McuBoot(ctx.obj["interface"]) as mboot:
        response = mboot.el2go_close_device(address=address, dry_run=dry_run)
        display_output([response], mboot.status_code, use_json=ctx.obj["use_json"])


@catch_spsdk_error
def safe_main() -> None:
    """Calls the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
