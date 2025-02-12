#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK NXPELE application."""

import logging
import os
import shlex
import sys
from struct import pack
from typing import Any, Callable, Optional, TypeVar, Union

import click
from click_option_group import RequiredMutuallyExclusiveOptionGroup, optgroup

from spsdk.apps.utils import spsdk_logger
from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    SpsdkClickGroup,
    buspal_option,
    is_click_help,
    lpcusbsio_option,
    port_option,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
    spsdk_revision_option,
    timeout_option,
    usb_option,
)
from spsdk.apps.utils.utils import INT, SPSDKAppError, catch_spsdk_error
from spsdk.ele import ele_message
from spsdk.ele.ele_comm import EleMessageHandler
from spsdk.ele.ele_constants import (
    EleInfo2Commit,
    KeyBlobEncryptionAlgorithm,
    KeyBlobEncryptionIeeCtrModes,
    LifeCycleToSwitch,
)
from spsdk.exceptions import SPSDKError
from spsdk.mboot.exceptions import McuBootCommandError
from spsdk.utils.crypto.iee import IeeKeyBlobLockAttributes, IeeKeyBlobModeAttributes, IeeNxp
from spsdk.utils.crypto.otfad import KeyBlob, OtfadNxp
from spsdk.utils.database import DatabaseManager
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import (
    BinaryPattern,
    load_binary,
    load_configuration,
    load_hex_string,
    write_file,
)
from spsdk.utils.schema_validator import check_config

logger = logging.getLogger(__name__)


FC = TypeVar("FC", bound=Union[Callable[..., Any], click.Command])


def nxpele_options(options: FC) -> Callable:
    """Click decorator handling Mboot interface.

    Provides: `interface: str` an instance of MbootInterface class.

    :return: Click decorator.
    """
    options = click.option(
        "--fb-size",
        type=INT(),
        required=False,
        help="Override default buffer size for fastboot",
    )(options)
    options = click.option(
        "--fb-addr",
        type=INT(),
        required=False,
        help="Override default buffer address for fastboot",
    )(options)
    options = click.option(
        "--buffer-size",
        type=INT(),
        required=False,
        help="Override default buffer size for ELE communication",
    )(options)
    options = click.option(
        "--buffer-addr",
        type=INT(),
        required=False,
        help="Override default buffer address for ELE communication",
    )(options)
    options = click.option(
        "-d",
        "--device",
        type=click.Choice(
            EleMessageHandler.get_supported_ele_devices(),
            case_sensitive=False,
        ),
        required=False,
        help="Select connection method for ELE communication, otherwise default from DB will be used",
    )(options)
    options = buspal_option()(options)
    options = lpcusbsio_option()(options)
    options = usb_option()(options)
    options = port_option()(options)
    options = timeout_option(timeout=5000)(options)
    return options


@click.group(name="nxpele", no_args_is_help=True, cls=CommandsTreeGroup)
@nxpele_options
@spsdk_apps_common_options
@spsdk_family_option(families=EleMessageHandler.get_supported_families(), required=True)
@spsdk_revision_option
@click.pass_context
def main(
    ctx: click.Context,
    port: Optional[str],
    usb: Optional[str],
    lpcusbsio: Optional[str],
    buspal: Optional[str],
    log_level: int,
    timeout: int,
    family: str,
    revision: str,
    device: Optional[str],
    buffer_addr: Optional[int],
    buffer_size: Optional[int],
    fb_addr: Optional[int],
    fb_size: Optional[int],
) -> int:
    """Utility for communication with the EdgeLock Enclave on target over BLHOST or UBOOT."""
    log_level = log_level or logging.WARNING
    spsdk_logger.install(level=log_level)

    # if --help is provided anywhere on command line, skip interface lookup and display help message
    # Or the command doesn't need communication with target.
    if is_click_help(ctx, sys.argv):
        return 0

    ctx.obj = EleMessageHandler.get_message_handler(
        family=family,
        revision=revision,
        device=device,
        fb_addr=fb_addr,
        fb_size=fb_size,
        buffer_addr=buffer_addr,
        buffer_size=buffer_size,
        port=port,
        buspal=buspal,
        usb=usb,
        lpcusbsio=lpcusbsio,
        timeout=timeout,
    )
    return 0


@main.command(no_args_is_help=True)
@click.argument("command_file", type=click.Path(file_okay=True))
@click.pass_context
def batch(ctx: click.Context, command_file: str) -> None:
    """Invoke nxpele commands defined in command file.

    Command file contains one nxpele command per line.
    example: "write-fuse --index=129 --data=0x7021b4a5"

    Comments are supported. Everything after '#' is a comment (just like in Python/Shell)

    Note: This is an early experimental format, it may change at any time.

    \b
    COMMAND_FILE    - path to nxpele command file
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


@main.command(name="ping", no_args_is_help=False)
@click.pass_obj
def cmd_ping(
    handler: EleMessageHandler,
) -> None:
    """Send general EdgeLock Enclave PING message."""
    ele_ping(handler)


def ele_ping(ele_handler: EleMessageHandler) -> None:
    """ELE Ping command.

    :param ele_handler: ELE handler class
    """
    ping = ele_message.EleMessagePing()
    with ele_handler:
        ele_handler.send_message(ping)
    click.echo("ELE Ping ends successfully")


@main.command(name="enable-apc", no_args_is_help=False)
@click.pass_obj
def cmd_enable_apc(
    handler: EleMessageHandler,
) -> None:
    """Send request to enable APC to EdgeLock Enclave."""
    ele_enable_apc(handler)


def ele_enable_apc(ele_handler: EleMessageHandler) -> None:
    """ELE Enable APC Request  command.

    :param ele_handler: ELE handler class
    """
    enable_apc = ele_message.EleMessageEnableApc()
    with ele_handler:
        ele_handler.send_message(enable_apc)
    click.echo("ELE Enable APC request ends successfully")


@main.command(name="enable-rtc", no_args_is_help=False)
@click.pass_obj
def cmd_enable_rtc(
    handler: EleMessageHandler,
) -> None:
    """Send request to enable RTC to EdgeLock Enclave."""
    ele_enable_rtc(handler)


def ele_enable_rtc(ele_handler: EleMessageHandler) -> None:
    """ELE Enable RTC Request  command.

    :param ele_handler: ELE handler class
    """
    enable_rtc = ele_message.EleMessageEnableRtc()
    with ele_handler:
        ele_handler.send_message(enable_rtc)
    click.echo("ELE Enable RTC request ends successfully")


@main.command(name="reset-apc-context", no_args_is_help=False)
@click.pass_obj
def cmd_reset_apc_context(
    handler: EleMessageHandler,
) -> None:
    """Send request to reset APC context in EdgeLock Enclave."""
    ele_reset_apc_context(handler)


def ele_reset_apc_context(ele_handler: EleMessageHandler) -> None:
    """Send request to reset APC context in EdgeLock Enclave.

    :param ele_handler: ELE handler class
    """
    reset_apc_context = ele_message.EleMessageResetApcContext()
    with ele_handler:
        ele_handler.send_message(reset_apc_context)
    click.echo("ELE Reset APC context ends successfully")


@main.command(name="reset", no_args_is_help=False)
@click.pass_obj
def cmd_reset(
    handler: EleMessageHandler,
) -> None:
    """Send general EdgeLock Enclave RESET message."""
    ele_reset(handler)


def ele_reset(ele_handler: EleMessageHandler) -> None:
    """ELE Reset command.

    :param ele_handler: ELE handler class
    """
    reset = ele_message.EleMessageReset()
    with ele_handler:
        try:
            ele_handler.send_message(reset)
        except (McuBootCommandError, SPSDKError) as exc:
            logger.debug(f"Reset by ELE failed: {str(exc)}")
    click.echo("ELE Reset ends successfully")


@main.command(name="get-ele-fw-status", no_args_is_help=False)
@click.pass_obj
def cmd_get_ele_fw_status(
    handler: EleMessageHandler,
) -> None:
    """Get status of EdgeLock Enclave firmware."""
    ele_get_ele_fw_status(handler)


def ele_get_ele_fw_status(ele_handler: EleMessageHandler) -> None:
    """ELE Get ELE FW STATUS command.

    :param ele_handler: ELE handler class
    """
    get_ele_fw_status = ele_message.EleMessageGetFwStatus()
    with ele_handler:
        ele_handler.send_message(get_ele_fw_status)
    click.echo(f"Get ELE firmware status ends successfully:\n{get_ele_fw_status.response_info()}")


@main.command(name="get-ele-trng-state", no_args_is_help=False)
@click.pass_obj
def cmd_get_ele_trng_state(
    handler: EleMessageHandler,
) -> None:
    """Get status of EdgeLock Enclave TRNG."""
    ele_get_ele_trng_state(handler)


def ele_get_ele_trng_state(ele_handler: EleMessageHandler) -> None:
    """ELE Get ELE TRNG STATE command.

    :param ele_handler: ELE handler class
    """
    get_ele_trng_state = ele_message.EleMessageGetTrngState()
    with ele_handler:
        ele_handler.send_message(get_ele_trng_state)
    click.echo(f"Get ELE trng state ends successfully:\n{get_ele_trng_state.response_info()}")


@main.command(name="get-ele-fw-version", no_args_is_help=False)
@click.pass_obj
def cmd_get_ele_fw_version(
    handler: EleMessageHandler,
) -> None:
    """Get version of EdgeLock Enclave firmware."""
    ele_get_ele_fw_version(handler)


def ele_get_ele_fw_version(ele_handler: EleMessageHandler) -> None:
    """ELE Get ELE FW version command.

    :param ele_handler: ELE handler class
    """
    get_ele_fw_version = ele_message.EleMessageGetFwVersion()
    with ele_handler:
        ele_handler.send_message(get_ele_fw_version)
    click.echo(f"Get ELE firmware version ends successfully:\n{get_ele_fw_version.response_info()}")


@main.command(name="get-info", no_args_is_help=False)
@click.pass_obj
def cmd_get_info(
    handler: EleMessageHandler,
) -> None:
    """Get information from EdgeLock Enclave."""
    ele_get_info(handler)


def ele_get_info(ele_handler: EleMessageHandler) -> None:
    """ELE Get Info command.

    :param ele_handler: ELE handler class
    """
    get_info = ele_message.EleMessageGetInfo()
    with ele_handler:
        ele_handler.send_message(get_info)
    click.echo(f"ELE get info ends successfully:\n{get_info.response_info()}")


@main.command(name="ele-fw-auth", no_args_is_help=True)
@optgroup("EdgeLock Enclave firmware Source", cls=RequiredMutuallyExclusiveOptionGroup)
@optgroup.option(
    "-a",
    "--address",
    type=INT(),
    help="Address of EdgeLock Enclave firmware container in target memory.",
)
@optgroup.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, resolve_path=True),
    help="File name with binary of EdgeLock Enclave firmware.",
)
@click.pass_obj
def cmd_ele_fw_auth(
    handler: EleMessageHandler, address: Optional[int], binary: Optional[str]
) -> None:
    """Authenticate and execute EdgeLock Enclave firmware.

    Firmware should be placed in any memory accessible by ROM code if '-a' is used, otherwise
    the correct address will be used.
    """
    ele_ele_fw_auth(handler, address, binary)


def ele_ele_fw_auth(
    ele_handler: EleMessageHandler, address: Optional[int], binary: Optional[str]
) -> None:
    """Authenticate and execute EdgeLock Enclave firmware command.

    :param ele_handler: ELE handler class
    :param address: Address of ele firmware container, this is optionally to binary
    :param binary: File path to binary file with ELE FW, this is optionally to address
    """
    if binary:
        # Create temporary message just to get space where to load FW
        msg = ele_message.EleMessageEleFwAuthenticate(0)
        msg.set_buffer_params(ele_handler.comm_buff_addr, ele_handler.comm_buff_size)
        address = msg.free_space_address
        max_size = msg.free_space_size
        ele_fw = load_binary(binary)
        if len(ele_fw) > max_size:
            raise SPSDKAppError(
                f"ELE firmware size doesn't fit into communication buffer: {len(ele_fw)} > {max_size}"
            )
        logger.info(
            f"The download ELE FW address: 0x{address:08X}, size: {len(ele_fw)}B. Max size for ELE FW is {max_size}B"
        )
        with ele_handler:
            ele_handler.device.write_memory(address, ele_fw)

    assert isinstance(address, int)
    ele_fw_auth_msg = ele_message.EleMessageEleFwAuthenticate(address)
    with ele_handler:
        ele_handler.send_message(ele_fw_auth_msg)
    click.echo("ELE firmware authentication and execution ends successfully.")


@main.command(name="dump-debug-data", no_args_is_help=False)
@click.pass_obj
def cmd_dump_debug_data(
    handler: EleMessageHandler,
) -> None:
    """Dump ELE debug buffer data of EdgeLock Enclave firmware."""
    ele_dump_debug_data(handler)


def ele_dump_debug_data(ele_handler: EleMessageHandler) -> None:
    """Dump ELE debug buffer data command.

    :param ele_handler: ELE handler class
    """
    dump_debug_data = ele_message.EleMessageDumpDebugBuffer()
    with ele_handler:
        ele_handler.send_message(dump_debug_data)
    click.echo(f"Dump debug buffer ends successfully:\n{dump_debug_data.response_info()}")


@main.command(name="read-common-fuse", no_args_is_help=True)
@click.option(
    "-i",
    "--index",
    type=INT(),
    required=True,
    help="Fuse index.",
)
@click.pass_obj
def cmd_read_common_fuse(handler: EleMessageHandler, index: int) -> None:
    """Read common fuse from EdgeLock Enclave.

    Not all fuses could be read by this command, just some of them are supported.
    """
    ele_read_common_fuse(handler, index)


def ele_read_common_fuse(ele_handler: EleMessageHandler, index: int) -> None:
    """Read common fuse from EdgeLock Enclave.

    Not all fuses could be read by this command, just some of them are supported.

    :param ele_handler: ELE handler class
    :param index: Fuse Id
    """
    read_common_fuse_msg = ele_message.EleMessageReadCommonFuse(index)
    with ele_handler:
        ele_handler.send_message(read_common_fuse_msg)
    click.echo(f"Read common fuse ends successfully.\n{read_common_fuse_msg.response_info()}")


@main.command(name="read-shadow-fuse", no_args_is_help=True)
@click.option(
    "-i",
    "--index",
    type=INT(),
    required=True,
    help="Fuse index.",
)
@click.pass_obj
def cmd_read_shadow_fuse(handler: EleMessageHandler, index: int) -> None:
    """Read shadow fuse from EdgeLock Enclave.

    Not all fuses could be read by this command, just some of them are supported.
    """
    ele_read_shadow_fuse(handler, index)


def ele_read_shadow_fuse(ele_handler: EleMessageHandler, index: int) -> None:
    """Read shadow fuse from EdgeLock Enclave.

    Not all fuses could be read by this command, just some of them are supported.

    :param ele_handler: ELE handler class
    :param index: Fuse Id
    """
    read_shadow_fuse_msg = ele_message.EleMessageReadShadowFuse(index)
    with ele_handler:
        ele_handler.send_message(read_shadow_fuse_msg)
    click.echo(f"Read shadow fuse ends successfully.\n{read_shadow_fuse_msg.response_info()}")


@main.command(name="oem-cntn-auth", no_args_is_help=True)
@click.option(
    "-a",
    "--address",
    type=INT(),
    help="Address of OEM container in target memory.",
)
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, readable=True),
    help=(
        "Alternative to defining address, this option get the "
        "binary file, load it into device and run authentication."
    ),
)
@click.pass_obj
def cmd_oem_cntn_auth(handler: EleMessageHandler, address: int, binary: str) -> None:
    """Authenticate OEM container.

    Container should be placed in any memory accessible by ROM code
    """
    ele_oem_cntn_auth(handler, address, binary)


def ele_oem_cntn_auth(
    ele_handler: EleMessageHandler, address: Optional[int], binary: Optional[str]
) -> None:
    """Authenticate OEM container.

    :param ele_handler: ELE handler class
    :param address: Address of OEM container to be authenticated
    :param binary: Path to binary file that should be loaded to device and authenticated
    """
    if binary:
        data = load_binary(binary)
        if address is None:
            address = ele_handler.database.get_int(DatabaseManager.COMM_BUFFER, "address")
            size = ele_handler.database.get_int(DatabaseManager.COMM_BUFFER, "size")
            if len(data) > size:
                raise SPSDKAppError(
                    f"The SPSDK validation size of OEM binary file exceeded supported size: {len(data)}B > {size}B"
                )
            ele_handler.device.write_memory(address, data)

    if address is None:
        raise SPSDKAppError("Address has to be defined, option '-a'. Check the help.")

    oem_cntn_auth_msg = ele_message.EleMessageOemContainerAuthenticate(address)
    with ele_handler:
        ele_handler.send_message(oem_cntn_auth_msg)
    click.echo("OEM container authentication ends successfully.")
    click.echo(
        "Be aware that 'release-container' must be called to allow another OEM container authentication."
    )


@main.command(name="commit", no_args_is_help=True)
@click.option(
    "-i",
    "--commit-info",
    type=click.Choice(EleInfo2Commit.labels(), case_sensitive=False),
    help="Info to be committed. It could be used multiple",
    required=True,
    multiple=True,
)
@click.pass_obj
def cmd_commit(handler: EleMessageHandler, commit_info: list[str]) -> None:
    """Commit information."""
    ele_commit(handler, [EleInfo2Commit.from_label(i) for i in commit_info])
    click.echo("Commit ends successfully.")


def ele_commit(ele_handler: EleMessageHandler, commit_info: list[EleInfo2Commit]) -> None:
    """Commit info.

    :param ele_handler: ELE handler class
    :param commit_info: List of information to be committed
    """
    commit_msg = ele_message.EleMessageCommit(commit_info)
    with ele_handler:
        ele_handler.send_message(commit_msg)


@main.command(name="derive-key", no_args_is_help=True)
@click.option(
    "-s",
    "--size",
    type=click.Choice(["16", "32"], case_sensitive=False),
    help="Size of output key",
    default=16,
)
@click.option(
    "-c",
    "--key-diversification-context",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    help="File path to Key diversification context binary file",
)
@spsdk_output_option(required=False, help="Derived key output file.")
@click.pass_obj
def cmd_derive_key(
    handler: EleMessageHandler,
    size: str,
    key_diversification_context: Optional[str],
    output: Optional[str],
) -> None:
    """Derive key.

    Allowed sizes are 16 and 32 bytes.
    """
    context = None
    if key_diversification_context:
        context = load_binary(key_diversification_context)
    derived_key = ele_derive_key(handler, int(size), context)

    if output:
        write_file(derived_key, output, "wb")

    click.echo("Key derivation ends successfully.")
    click.echo(f"Key: {derived_key.hex()}")


def ele_derive_key(
    ele_handler: EleMessageHandler, size: int, key_diversification_context: Optional[bytes]
) -> bytes:
    """Derive key.

    :param ele_handler: ELE handler class
    :param size: Size of derived key [16,32]
    :param key_diversification_context: Key diversification context if used
    :returns: Derived key
    """
    derive_key_msg = ele_message.EleMessageDeriveKey(size, key_diversification_context)
    with ele_handler:
        ele_handler.send_message(derive_key_msg)

    return derive_key_msg.get_key()


@main.command(name="verify-image", no_args_is_help=False)
@click.option(
    "-m",
    "--mask",
    type=INT(),
    help=(
        "Used to indicate which images are to be checked. There must be at least one image."
        " If not defined Image_0 will be checked."
    ),
    default="0x0000_0001",
)
@click.pass_obj
def cmd_verify_image(handler: EleMessageHandler, mask: int) -> None:
    """Verify OEM image.

    The Verify Image message is sent to the ELE after a container has been loaded into memory
    and processed with an Authenticate Container message. This commands the ELE to check the hash
    on one or more images.
    """
    ele_verify_image(handler, mask)


def ele_verify_image(ele_handler: EleMessageHandler, mask: int = 0x0000_0001) -> None:
    """Verify OEM image.

    :param ele_handler: ELE handler class
    :param mask: Used to indicate which images are to be checked. There must be at least one image.
        If not defined Image_0 will be checked
    """
    verify_image_msg = ele_message.EleMessageVerifyImage(mask)
    with ele_handler:
        ele_handler.send_message(verify_image_msg)
    click.echo(f"Verify image ends successfully.\n{verify_image_msg.response_info()}")


@main.command(name="release-container", no_args_is_help=False)
@click.pass_obj
def cmd_release_container(
    handler: EleMessageHandler,
) -> None:
    """Release EdgeLock Enclave firmware message."""
    ele_release_container(handler)


def ele_release_container(ele_handler: EleMessageHandler) -> None:
    """Release EdgeLock Enclave firmware message.

    :param ele_handler: ELE handler class
    """
    release_container = ele_message.EleMessageReleaseContainer()
    with ele_handler:
        ele_handler.send_message(release_container)
    click.echo("ELE Release container ends successfully")


@main.command(name="forward-lifecycle-update", no_args_is_help=False)
@click.option(
    "-l",
    "--lifecycle",
    type=click.Choice(LifeCycleToSwitch.labels(), case_sensitive=False),
    required=True,
    help="Lifecycle to switch to value",
)
@click.pass_obj
def cmd_fwd_lc_update(handler: EleMessageHandler, lifecycle: str) -> None:
    """Forward Lifecycle update to Closed or Locked state.

    The Forward Lifecycle update message is used to change the chip lifecycle.
    It is used for updating the lifecycle state to OEM Closed or OEM Locked.
    """
    ele_fwd_lc_update(handler, LifeCycleToSwitch.from_label(lifecycle))


def ele_fwd_lc_update(ele_handler: EleMessageHandler, lifecycle: LifeCycleToSwitch) -> None:
    """Forward Lifecycle update to Closed or Locked state.

    The Forward Lifecycle update message is used to change the chip lifecycle.
    It is used for updating the lifecycle state to OEM Closed or OEM Locked.

    :param ele_handler: ELE handler class
    :param lifecycle: Life cycle new value
    """
    fwd_lc_update_msg = ele_message.EleMessageForwardLifeCycleUpdate(lifecycle)
    with ele_handler:
        ele_handler.send_message(fwd_lc_update_msg)
    click.echo("Forward Lifecycle update ends successfully.")


@main.command(name="signed-message", no_args_is_help=True)
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, file_okay=True, resolve_path=True),
    required=True,
    help="Binary file with signed message container.",
)
@click.pass_obj
def cmd_signed_message(handler: EleMessageHandler, binary: str) -> None:
    """Send signed message to EdgeLock Enclave.

    Signed message could be created by 'nxpimage signed-msg' tool.
    """
    ele_signed_message(handler, binary)


def ele_signed_message(ele_handler: EleMessageHandler, signed_msg_path: str) -> None:
    """ELE Get Info command.

    :param ele_handler: ELE handler class
    :param signed_msg_path: Path to signed message binary file
    """
    signed_msg = ele_message.EleMessageSigned(
        signed_msg=load_binary(signed_msg_path),
        family=ele_handler.family,
        revision=ele_handler.revision,
    )
    with ele_handler:
        ele_handler.send_message(signed_msg)
    click.echo(f"ELE signed message ends successfully:\n{signed_msg.info()}")


@main.command(name="get-events", no_args_is_help=False)
@click.pass_obj
def cmd_get_events(
    handler: EleMessageHandler,
) -> None:
    """Get stored events in EdgeLock Enclave."""
    ele_get_events(handler)


def ele_get_events(ele_handler: EleMessageHandler) -> None:
    """Get events command.

    :param ele_handler: ELE handler class
    """
    get_events = ele_message.EleMessageGetEvents()
    with ele_handler:
        ele_handler.send_message(get_events)
    click.echo(f"ELE get events ends successfully.\n{get_events.response_info()}")


@main.command(name="start-trng", no_args_is_help=False)
@click.pass_obj
def cmd_start_trng(
    handler: EleMessageHandler,
) -> None:
    """Start True Random Number Generator in EdgeLock Enclave message."""
    ele_start_trng(handler)


def ele_start_trng(ele_handler: EleMessageHandler) -> None:
    """ELE Ping command.

    :param ele_handler: ELE handler class
    """
    start_trng = ele_message.EleMessageStartTrng()
    with ele_handler:
        ele_handler.send_message(start_trng)
    click.echo("ELE starts TRNG successfully")


@main.command(name="load-keyblob", no_args_is_help=True)
@click.option(
    "-i",
    "--key-id",
    type=INT(),
    required=True,
    help=(
        "Key ID (know also as Key Identifier), the same value has to be "
        "provided again when decrypting the generated blob."
    ),
)
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, file_okay=True, resolve_path=True),
    required=True,
    help="Binary file with EdgeLock Enclave keyblob to be loaded to HW.",
)
@click.pass_obj
def cmd_ele_load_keyblob(handler: EleMessageHandler, key_id: int, binary: str) -> None:
    """Load EdgeLock Enclave keyblob to hardware.

    The command 'Load key blob' is used to inject some keys in specific HW blocks.
    The expected blob must have been previously created by using the 'Generate Key Blob' command.
    """
    ele_load_keyblob(handler, key_id, load_binary(binary))


def ele_load_keyblob(ele_handler: EleMessageHandler, key_id: int, binary: bytes) -> None:
    """Authenticate and execute EdgeLock Enclave firmware command.

    :param ele_handler: ELE handler class
    :param key_id: Key Identifier
    :param binary: Binary form of the keyblob
    """
    ele_load_keyblob_msg = ele_message.EleMessageLoadKeyBLob(key_identifier=key_id, keyblob=binary)
    with ele_handler:
        ele_handler.send_message(ele_load_keyblob_msg)
    click.echo("ELE load keyblob ends successfully.")


@main.group(name="generate-keyblob", no_args_is_help=True, cls=SpsdkClickGroup)
def gen_keyblob_group() -> None:
    """Group of sub-commands related to generate Keyblob."""


@gen_keyblob_group.command(name="DEK", no_args_is_help=True)
@click.option(
    "-a",
    "--algorithm",
    type=click.Choice(
        ele_message.EleMessageGenerateKeyBlobDek.get_supported_algorithms(),
        case_sensitive=False,
    ),
    required=True,
    help="Encryption algorithm to wrap key.",
)
@click.option(
    "-i",
    "--key-id",
    type=INT(),
    required=True,
    help=(
        "Key ID (know also as Key Identifier), the same value has to be "
        "provided again when decrypting the generated blob."
    ),
)
@click.option(
    "-k",
    "--key",
    type=str,
    required=True,
    help="Key as hexadecimal string or path to file containing key in plain text or in binary",
)
@click.option(
    "-s",
    "--key-size",
    type=INT(),
    required=True,
    help="Key size in bits. Table with allowed combination:\n"
    + ele_message.EleMessageGenerateKeyBlobDek.get_supported_key_sizes(),
)
@spsdk_output_option(
    required=False,
    help="Store DEK keyblob into a file. If not used, then value is just printed to console.",
)
@click.pass_obj
def cmd_gen_keyblob_dek(
    handler: EleMessageHandler,
    algorithm: str,
    key_id: int,
    key: str,
    key_size: int,
    output: str,
) -> None:
    """Generate DEK keyblob on EdgeLock Enclave."""
    ele_gen_keyblob_dek(handler, algorithm, key_id, key, key_size, output)


def ele_gen_keyblob_dek(
    ele_handler: EleMessageHandler,
    algorithm: str,
    key_id: int,
    key: str,
    key_size: int,
    output: str,
) -> None:
    """Generate DEK keyblob on EdgeLock Enclave.

    :param ele_handler: ELE handler class
    :param algorithm: Encryption algorithm to wrap key
    :param key_id: Key Identifier
    :param key: Key as hexadecimal string or path to file containing key in plain text or in binary
    :param key_size: Size of key in bits
    :param output: Output keyblob file name
    :raises SPSDKAppError: Invalid input key size.
    """
    enum_algorithm = KeyBlobEncryptionAlgorithm.from_label(algorithm)
    if (
        key_size
        not in ele_message.EleMessageGenerateKeyBlobDek.SUPPORTED_ALGORITHMS[enum_algorithm]
    ):
        raise SPSDKAppError("Invalid key size")

    gen_keyblob_dek_msg = ele_message.EleMessageGenerateKeyBlobDek(
        key_id, enum_algorithm, load_hex_string(key, key_size // 8)
    )
    with ele_handler:
        ele_handler.send_message(gen_keyblob_dek_msg)
    click.echo(
        f"ELE generate DEK key blob ends successfully:\n{gen_keyblob_dek_msg.key_blob.hex()}"
    )
    if output:
        write_file(gen_keyblob_dek_msg.key_blob, output, mode="wb")


@gen_keyblob_group.command(name="OTFAD", no_args_is_help=True)
@click.option(
    "-i",
    "--key-id",
    type=INT(),
    required=True,
    help="""
    Key ID (know also as Key Identifier):
    Byte 0: Index of the OTFAD key struct (0 .. 3). Important when the key scrambling is enabled.
    Byte 1: 0x1 - FlexSPI 1, 0x2 - FlexSPI 2.
    Bytes 2-3: reserved
    """,
)
@click.option(
    "-k",
    "--key",
    type=str,
    required=True,
    help="AES 128 key as hexadecimal string or path to file containing key in plain text or in binary",
)
@click.option(
    "-c",
    "--counter",
    type=str,
    required=True,
    help="AES 64 bit counter as hexadecimal string or path to file containing key in plain text or in binary",
)
@click.option(
    "-s",
    "--start-address",
    type=INT(),
    required=True,
    help="Start address of OTFAD. Address must be aligned to 1KB block",
)
@click.option(
    "-e",
    "--end-address",
    type=INT(),
    required=True,
    help="End address of OTFAD. Address must be aligned to 1KB block",
)
@click.option(
    "-r",
    "--read-only",
    type=bool,
    is_flag=True,
    default=False,
    help="Configuration is read only",
)
@click.option(
    "-d",
    "--decryption_enabled",
    type=bool,
    is_flag=True,
    default=False,
    help="Decryption is enabled",
)
@click.option(
    "-v",
    "--valid",
    type=bool,
    is_flag=True,
    default=False,
    help="Configuration is valid",
)
@spsdk_output_option(
    required=False,
    help="Store OTFAD keyblob into a file. If not used, value is just printed to console.",
)
@click.pass_obj
def cmd_gen_keyblob_otfad(
    handler: EleMessageHandler,
    key_id: int,
    key: str,
    counter: str,
    start_address: int,
    end_address: int,
    read_only: bool,
    decryption_enabled: bool,
    valid: bool,
    output: str,
) -> None:
    """Generate OTFAD keyblob atomic command on EdgeLock Enclave.

    This commands send just return raw format of one quarter of whole OTFAD DUK keyblob.
    For experts only!
    To get whole working keyblob use OTFAD-KEYBLOB command.
    """
    otfad_keyblob = ele_gen_keyblob_otfad(
        handler,
        key_id,
        load_hex_string(key, 16),
        load_hex_string(counter, 8),
        start_address,
        end_address,
        read_only,
        decryption_enabled,
        valid,
    )
    click.echo(f"ELE generate OTFAD key blob ends successfully:\n{otfad_keyblob.hex()}")
    if output:
        write_file(otfad_keyblob, output, mode="wb")


def ele_gen_keyblob_otfad(
    ele_handler: EleMessageHandler,
    key_id: int,
    key: bytes,
    counter: bytes,
    start_address: int,
    end_address: int,
    read_only: bool,
    decryption_enabled: bool,
    valid: bool,
) -> bytes:
    """Generate OTFAD keyblob on EdgeLock Enclave.

    :param ele_handler: ELE handler class
    :param key_id: Key Identifier
    :param key: AES 128 Key as hexadecimal string or path to file containing key in plain text or in binary
    :param counter: AES Counter 64 bits
    :param start_address: Start address, aligned to 1KB
    :param end_address: End address, aligned to 1KB
    :param read_only: Read only configuration
    :param decryption_enabled: Decryption enabled
    :param valid: Configuration is valid
    :return: OTFAD KeyBlob value
    """
    gen_keyblob_otfad_msg = ele_message.EleMessageGenerateKeyBLobOtfad(
        key_identifier=key_id,
        key=key,
        aes_counter=counter,
        start_address=start_address,
        end_address=end_address,
        read_only=read_only,
        decryption_enabled=decryption_enabled,
        configuration_valid=valid,
    )
    with ele_handler:
        ele_handler.send_message(gen_keyblob_otfad_msg)

    return gen_keyblob_otfad_msg.key_blob


@gen_keyblob_group.command(name="OTFAD-KEYBLOB", no_args_is_help=True)
@click.option(
    "-i",
    "--flexspi-index",
    type=INT(),
    default="1",
    help="Index of used FlexSPI peripheral. Typically 1 or 2.",
)
@spsdk_config_option(
    help="Configuration file from NXPIMAGE OTFAD tool. From the config, all needed values has been loaded."
)
@spsdk_output_option(
    required=False,
    help="Store OTFAD keyblob into a file. If not used, value is just printed to console.",
)
@click.pass_obj
def cmd_gen_keyblob_otfad_full(
    handler: EleMessageHandler, flexspi_index: int, config: str, output: str
) -> None:
    """Generate OTFAD keyblob on EdgeLock Enclave."""
    ele_gen_keyblob_otfad_whole_keyblob(handler, flexspi_index, config, output)


def ele_gen_keyblob_otfad_whole_keyblob(
    ele_handler: EleMessageHandler, flexspi_index: int, config: str, output: str
) -> None:
    """Generate OTFAD keyblob on EdgeLock Enclave.

    :param ele_handler: ELE handler class
    :param flexspi_index: Index of used FlexSPI peripheral
    :param config: Configuration of OTFAD from NXPIMAGE OTFAD tool
    :param output: Output keyblob file name
    """
    config_data = load_configuration(config)
    config_dir = os.path.dirname(config)
    check_config(config_data, OtfadNxp.get_validation_schemas_family(), search_paths=[config_dir])
    family = config_data["family"]
    schemas = OtfadNxp.get_validation_schemas(family)
    check_config(config_data, schemas, search_paths=[config_dir])
    # Input configuration is OK
    otfad = OtfadNxp.load_from_config(config_data, config_dir, search_paths=[config_dir])
    otfad_keyblobs = BinaryImage(
        name="OTFAD Keyblobs",
        description=ele_handler.family,
        size=256,
        pattern=BinaryPattern("zeros"),
    )
    for i in range(4):
        if len(otfad) > i:
            keyblob = otfad[i]
            description = str(keyblob)
        else:
            keyblob = KeyBlob(
                start_addr=0,
                end_addr=0,
                key=bytes(16),
                counter_iv=bytes(8),
                key_flags=0,
                zero_fill=bytes(4),
            )
            description = "Unused keyblob"

        keyblob_data = ele_gen_keyblob_otfad(
            ele_handler=ele_handler,
            key_id=flexspi_index * 256 + i,
            key=keyblob.key,
            counter=keyblob.ctr_init_vector,
            start_address=keyblob.start_addr,
            end_address=keyblob.end_addr,
            read_only=bool(keyblob.key_flags & keyblob.KEY_FLAG_READ_ONLY),
            decryption_enabled=bool(keyblob.key_flags & keyblob.KEY_FLAG_ADE),
            valid=bool(keyblob.key_flags & keyblob.KEY_FLAG_VLD),
        )
        # Concatenate the final keyblob - remove the headers
        logger.debug(f"Keyblob data: {keyblob_data.hex()}")
        logger.debug(f"Keyblob length: {len(keyblob_data)} bytes")
        otfad_keyblobs.add_image(
            BinaryImage(
                name=f"Keyblob {i}",
                offset=i * 64,
                description=description,
                size=64,
                binary=keyblob_data[8:],
            )
        )
    logger.info(otfad_keyblobs.draw())

    click.echo(f"ELE generate OTFAD key blobs ends successfully:\n{otfad_keyblobs.export().hex()}")
    if output:
        write_file(otfad_keyblobs.export(), output, mode="wb")


@gen_keyblob_group.command(name="IEE", no_args_is_help=True)
@click.option(
    "-i",
    "--key-id",
    type=INT(),
    required=True,
    help=(
        "Key ID (know also as Key Identifier),the same value has to be "
        "provided again when decrypting the generated blob."
    ),
)
@click.option(
    "-a",
    "--algorithm",
    type=click.Choice(
        ele_message.EleMessageGenerateKeyBlobIee.get_supported_algorithms(),
        case_sensitive=False,
    ),
    required=True,
    help="Encryption algorithm to wrap key.",
)
@click.option(
    "-k",
    "--key",
    type=str,
    required=True,
    help="AES Key as hexadecimal string or path to file containing key in plain text or in binary",
)
@click.option(
    "-s",
    "--key-size",
    type=INT(),
    required=True,
    help="Key size in bits. Table with allowed combination:\n"
    + ele_message.EleMessageGenerateKeyBlobIee.get_supported_key_sizes(),
)
@click.option(
    "-c",
    "--counter",
    type=str,
    required=False,
    help="AES 64 bit counter as hexadecimal string or path to file containing key in plain text or in binary",
)
@click.option(
    "-m",
    "--ctr-mode",
    type=click.Choice(KeyBlobEncryptionIeeCtrModes.labels(), case_sensitive=False),
    required=False,
    default="CTR_WITH_ADDRESS",
    help="AES CTR mode in case that is used",
)
@click.option(
    "-p",
    "--page-offset",
    type=INT(),
    required=False,
    default="0",
    help="IEE page offset, default is 0",
)
@click.option(
    "-r",
    "--region-number",
    type=INT(),
    required=True,
    help="Region number",
)
@click.option(
    "-b",
    "--bypass",
    type=bool,
    is_flag=True,
    default=False,
    help="Bypass Encryption",
)
@click.option(
    "-l",
    "--locked",
    type=bool,
    is_flag=True,
    default=False,
    help="Lock configuration",
)
@spsdk_output_option(
    required=False,
    help="Store IEE keyblob into a file. If not used, then value is just printed to console.",
)
@click.pass_obj
def cmd_gen_keyblob_iee(
    handler: EleMessageHandler,
    key_id: int,
    algorithm: str,
    key: str,
    key_size: int,
    counter: str,
    ctr_mode: str,
    page_offset: int,
    region_number: int,
    bypass: bool,
    locked: bool,
    output: str,
) -> None:
    """Generate IEE keyblob atomic command on EdgeLock Enclave."""
    enum_algorithm = KeyBlobEncryptionAlgorithm.from_label(algorithm)
    enum_ctr_mode = KeyBlobEncryptionIeeCtrModes.from_label(ctr_mode)
    if (
        key_size
        not in ele_message.EleMessageGenerateKeyBlobIee.SUPPORTED_ALGORITHMS[enum_algorithm]
    ):
        raise SPSDKAppError("Invalid key size")

    key_blob = ele_gen_keyblob_iee(
        handler,
        key_id,
        enum_algorithm,
        key=load_hex_string(key, key_size // 8),
        counter=load_hex_string(counter, 16) if counter else b"",
        ctr_mode=enum_ctr_mode,
        page_offset=page_offset,
        region_number=region_number,
        bypass=bypass,
        locked=locked,
    )

    click.echo(f"ELE generate IEE key blob ends successfully:\n{key_blob.hex()}")
    if output:
        write_file(key_blob, output, mode="wb")


def ele_gen_keyblob_iee(
    ele_handler: EleMessageHandler,
    key_id: int,
    algorithm: KeyBlobEncryptionAlgorithm,
    key: bytes,
    counter: bytes,
    ctr_mode: KeyBlobEncryptionIeeCtrModes,
    page_offset: int,
    region_number: int,
    bypass: bool,
    locked: bool,
) -> bytes:
    """Generate IEE keyblob on EdgeLock Enclave.

    :param ele_handler: ELE handler class
    :param key_id: Key Identifier
    :param algorithm: Encryption algorithm to wrap key
    :param key: AES Key as bytes
    :param counter: AES Counter 64 bits, 16 bytes
    :param ctr_mode: CTR mode, of IEE encryption
    :param page_offset: IEE page offset
    :param region_number: Region number
    :param bypass: Bypass encryption
    :param locked:Lock configuration
    :raises SPSDKAppError: Invalid input key length
    :returns: Wrapped IEE keyblob
    """
    gen_keyblob_iee_msg = ele_message.EleMessageGenerateKeyBlobIee(
        key_identifier=key_id,
        algorithm=algorithm,
        key=key,
        aes_counter=counter,
        ctr_mode=ctr_mode,
        page_offset=page_offset,
        region_number=region_number,
        bypass=bypass,
        locked=locked,
    )
    with ele_handler:
        ele_handler.send_message(gen_keyblob_iee_msg)

    return gen_keyblob_iee_msg.key_blob


@gen_keyblob_group.command(name="IEE-KEYBLOB", no_args_is_help=True)
@click.option(
    "-r",
    "--region-number",
    type=INT(),
    required=True,
    help="Region number",
)
@spsdk_config_option(
    help="Configuration file from NXPIMAGE IEE tool. From the config, all needed values has been loaded."
)
@spsdk_output_option(
    required=False,
    help="Store IEE keyblob into a file. If not used, value is just printed to console.",
)
@click.pass_obj
def cmd_gen_keyblob_iee_full(
    handler: EleMessageHandler, region_number: int, config: str, output: str
) -> None:
    """Generate IEE keyblob on EdgeLock Enclave."""
    ele_gen_keyblob_iee_whole_keyblob(handler, region_number, config, output)


def ele_gen_keyblob_iee_whole_keyblob(
    ele_handler: EleMessageHandler, region_number: int, config: str, output: str
) -> None:
    """Generate OTFAD keyblob on EdgeLock Enclave.

    :param ele_handler: ELE handler class
    :param region_number: Region number
    :param config: Configuration of IEE from NXPIMAGE IEE tool
    :param output: Output keyblob file name
    """
    IEE_KEYBLOB_ID = 0x49454542
    config_data = load_configuration(config)
    config_dir = os.path.dirname(config)
    check_config(config_data, IeeNxp.get_validation_schemas_family(), search_paths=[config_dir])
    family = config_data["family"]
    schemas = IeeNxp.get_validation_schemas(family)
    check_config(config_data, schemas, search_paths=[config_dir])
    iee = IeeNxp.load_from_config(config_data, config_dir, search_paths=[config_dir])

    bypass = bool(iee[0].attributes.aes_mode == IeeKeyBlobModeAttributes.Bypass)
    encryption_algorithm = (
        KeyBlobEncryptionAlgorithm.AES_XTS
        if iee[0].attributes.aes_mode == IeeKeyBlobModeAttributes.AesXTS
        else KeyBlobEncryptionAlgorithm.AES_CTR
    )
    key = iee[0].key1
    if iee[0].attributes.ctr_mode:
        key = iee[0].key1
        counter = iee[0].key2
        counter_mode = {
            IeeKeyBlobModeAttributes.AesCTRWAddress: KeyBlobEncryptionIeeCtrModes.AesCTRWAddress,
            IeeKeyBlobModeAttributes.AesCTRWOAddress: KeyBlobEncryptionIeeCtrModes.AesCTRWOAddress,
            IeeKeyBlobModeAttributes.AesCTRkeystream: KeyBlobEncryptionIeeCtrModes.AesCTRkeystream,
        }[iee[0].attributes.aes_mode]
    else:
        key = iee[0].key1 + iee[0].key2
        counter = b""
        counter_mode = KeyBlobEncryptionIeeCtrModes.AesCTRWAddress
    iee_keyblob = ele_gen_keyblob_iee(
        ele_handler=ele_handler,
        key_id=IEE_KEYBLOB_ID,
        algorithm=encryption_algorithm,
        key=key,
        counter=counter,
        ctr_mode=counter_mode,
        page_offset=iee[0].page_offset,
        region_number=region_number,
        bypass=bypass,
        locked=bool(iee[0].attributes.lock == IeeKeyBlobLockAttributes.LOCK),
    )
    header_xor = iee[0].HEADER_TAG ^ iee[0].start_addr ^ iee[0].end_addr
    logger.debug(
        "Header IEE:\n"
        f"TAG:        {iee[0].HEADER_TAG:08X}\n"
        f"START ADDR: {iee[0].start_addr:08X}\n"
        f"END ADDR:   {iee[0].end_addr:08X}\n"
        f"EXOR:       {header_xor:08X}"
    )
    iee_keyblob_header = pack(
        "<4I", iee[0].HEADER_TAG, iee[0].start_addr, iee[0].end_addr, header_xor
    )

    iee_keyblobs = BinaryImage(
        name="IEE Keyblobs",
        description=ele_handler.family,
        size=0,
        pattern=BinaryPattern("zeros"),
    )
    iee_keyblobs.add_image(
        BinaryImage(
            name="IEE Keyblob header",
            offset=0,
            description=str(iee[0]),
            size=16,
            binary=iee_keyblob_header,
        )
    )
    iee_keyblobs.add_image(
        BinaryImage(
            name="IEE wrapped keyblob",
            offset=16,
            description="Wrapped IEE keyblob by ELE",
            binary=iee_keyblob,
        )
    )

    logger.info(iee_keyblobs.draw())

    click.echo(f"ELE generate IEE key blobs ends successfully:\n{iee_keyblobs.export().hex()}")
    if output:
        write_file(iee_keyblobs.export(), output, mode="wb")


@main.command(name="write-fuse", no_args_is_help=True)
@click.option(
    "-d",
    "--data",
    type=INT(base=16),
    required=True,
    help="Data to be written",
)
@click.option(
    "-i",
    "--index",
    type=INT(),
    required=True,
    help="Index of the fuse to be written",
)
@click.option(
    "--lock",
    is_flag=True,
    help="Write lock fuse",
)
@click.pass_obj
def cmd_write_fuse(handler: EleMessageHandler, data: int, index: int, lock: bool) -> None:
    """Write one fuse by specifying index and data to be written."""
    write_fuse(handler, data, index, lock)


def write_fuse(ele_handler: EleMessageHandler, data: int, index: int, lock: bool) -> None:
    """Write one fuse by specifying index and data to be written.

    :param ele_handler: ELE handler class
    :param data: Data to be written in fuse (32 bit)
    :param index: Index of the fuse to be written (32 bit)
    :param lock: If true, fuse will be write locked
    """
    bit_position = index * 32
    bit_length = 32

    ele_fw_write_fuse_msg = ele_message.EleMessageWriteFuse(bit_position, bit_length, lock, data)
    with ele_handler:
        ele_handler.send_message(ele_fw_write_fuse_msg)
    click.echo("ELE write fuse ends successfully.")


@main.command(name="write-shadow-fuse", no_args_is_help=True)
@click.option(
    "-d",
    "--data",
    type=INT(base=16),
    required=True,
    help="Data to be written",
)
@click.option(
    "-i",
    "--index",
    type=INT(),
    required=True,
    help="Index of the fuse to be written",
)
@click.pass_obj
def cmd_write_shadow_fuse(handler: EleMessageHandler, data: int, index: int) -> None:
    """Write one shadow fuse by specifying index and data to be written."""
    write_shadow_fuse(handler, data, index)


def write_shadow_fuse(ele_handler: EleMessageHandler, data: int, index: int) -> None:
    """Write one shadow fuse by specifying index and data to be written.

    :param ele_handler: ELE handler class
    :param data: Data to be written in fuse (32 bit)
    :param index: Index of the fuse to be written (32 bit)
    """
    ele_fw_write_fuse_msg = ele_message.EleMessageWriteShadowFuse(index, data)
    with ele_handler:
        ele_handler.send_message(ele_fw_write_fuse_msg)
    click.echo("ELE write shadow fuse ends successfully.")


@catch_spsdk_error
def safe_main() -> None:
    """Call the main function."""
    sys.exit(main())  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    safe_main()
