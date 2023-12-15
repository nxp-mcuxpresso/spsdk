#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK NXPELE application."""

import logging
import os
import sys
from struct import pack

import click

from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    is_click_help,
    isp_interfaces,
    spsdk_apps_common_options,
    spsdk_config_option,
    spsdk_family_option,
    spsdk_output_option,
)
from spsdk.apps.utils.utils import INT, SPSDKAppError, catch_spsdk_error, get_key
from spsdk.ele import ele_message
from spsdk.ele.ele_comm import EleMessageHandler
from spsdk.ele.ele_constants import KeyBlobEncryptionAlgorithm, KeyBlobEncryptionIeeCtrModes
from spsdk.exceptions import SPSDKError
from spsdk.mboot.exceptions import McuBootCommandError
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.mboot.scanner import get_mboot_interface
from spsdk.utils.crypto.iee import IeeKeyBlobLockAttributes, IeeKeyBlobModeAttributes, IeeNxp
from spsdk.utils.crypto.otfad import KeyBlob, OtfadNxp
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import BinaryPattern, load_binary, load_configuration, write_file
from spsdk.utils.schema_validator import check_config

logger = logging.getLogger(__name__)


@click.group(name="nxpele", no_args_is_help=True, cls=CommandsTreeGroup)
@isp_interfaces(uart=True, usb=True, lpcusbsio=True, buspal=True, json_option=False)
@spsdk_apps_common_options
@spsdk_family_option(families=EleMessageHandler.get_supported_families(), required=False)
@click.option(
    "-r",
    "--revision",
    default="latest",
    help="Chip revision; if not specified, most recent one will be used",
)
@click.pass_context
def main(
    ctx: click.Context,
    port: str,
    usb: str,
    buspal: str,
    lpcusbsio: str,
    log_level: int,
    timeout: int,
    family: str,
    revision: str,
) -> int:
    """Utility for communication with the EdgeLock Enclave on target over BLHOST."""
    log_level = log_level or logging.WARNING
    logging.basicConfig(level=log_level)

    ctx.obj = None

    # if --help is provided anywhere on command line, skip interface lookup and display help message
    # Or the command doesn't need communication with target.
    if not is_click_help(ctx, sys.argv):
        if not family:
            click.echo("Missing family option !")
            ctx.exit(-1)
        mboot_interface = get_mboot_interface(
            port=port, usb=usb, timeout=timeout, buspal=buspal, lpcusbsio=lpcusbsio
        )
        assert isinstance(mboot_interface, MbootProtocolBase)
        mboot = McuBoot(mboot_interface, cmd_exception=True)
        ele_handler = EleMessageHandler(mboot=mboot, family=family, revision=revision)
        ctx.obj = ele_handler

    return 0


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
@click.option(
    "-a",
    "--address",
    type=INT(),
    required=True,
    help="Address of EdgeLock Enclave firmware container.",
)
@click.pass_obj
def cmd_ele_fw_auth(handler: EleMessageHandler, address: int) -> None:
    """Authenticate and execute EdgeLock Enclave firmware.

    Firmware could be placed in any memory accessible by ROM code.
    """
    ele_ele_fw_auth(handler, address)


def ele_ele_fw_auth(ele_handler: EleMessageHandler, address: int) -> None:
    """Authenticate and execute EdgeLock Enclave firmware command.

    :param ele_handler: ELE handler class
    :param address: Address of ele firmware container
    """
    ele_fw_auth_msg = ele_message.EleMessageEleFwAuthenticate(address)
    with ele_handler:
        ele_handler.send_message(ele_fw_auth_msg)
    click.echo("ELE firmware authentication and execution ends successfully.")


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
    signed_msg = ele_message.EleMessageSigned(load_binary(signed_msg_path))
    with ele_handler:
        ele_handler.send_message(signed_msg)
    click.echo(f"ELE signed message ends successfully:\n{signed_msg.info()}")


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
    Currently only the IEE HW is supported. The expected blob must have been previously
    created by using the 'Generate Key Blob' command.
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


@main.group(name="generate-keyblob", no_args_is_help=True)
def gen_keyblob_group() -> None:
    """Group of sub-commands related to generate Keyblob."""


@gen_keyblob_group.command(name="DEK", no_args_is_help=True)
@click.option(
    "-a",
    "--algorithm",
    type=click.Choice(ele_message.EleMessageGenerateKeyBLobDek.get_supported_algorithms()),
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
    + ele_message.EleMessageGenerateKeyBLobDek.get_supported_key_sizes(),
)
@spsdk_output_option(
    required=False,
    help="Store DEK keyblob into a file. If not used, then value is just printed to console.",
)
@click.pass_obj
def cmd_gen_keyblob_dek(
    handler: EleMessageHandler, algorithm: str, key_id: int, key: str, key_size: int, output: str
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
    enum_algorithm = KeyBlobEncryptionAlgorithm.get(algorithm)
    assert isinstance(enum_algorithm, int)
    if (
        key_size
        not in ele_message.EleMessageGenerateKeyBLobDek.SUPPORTED_ALGORITHMS[enum_algorithm]
    ):
        raise SPSDKAppError("Invalid key size")

    gen_keyblob_dek_msg = ele_message.EleMessageGenerateKeyBLobDek(
        key_id, enum_algorithm, get_key(key, key_size // 8)
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
        get_key(key, 16),
        get_key(counter, 8),
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
        logger.debug(f"Keyblog length: {len(keyblob_data)} bytes")
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
    type=click.Choice(ele_message.EleMessageGenerateKeyBLobIee.get_supported_algorithms()),
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
    + ele_message.EleMessageGenerateKeyBLobIee.get_supported_key_sizes(),
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
    type=click.Choice(
        [KeyBlobEncryptionIeeCtrModes.name(x) for x in KeyBlobEncryptionIeeCtrModes.tags()]
    ),
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
    algorithm: KeyBlobEncryptionAlgorithm,
    key: str,
    key_size: int,
    counter: str,
    ctr_mode: KeyBlobEncryptionIeeCtrModes,
    page_offset: int,
    region_number: int,
    bypass: bool,
    locked: bool,
    output: str,
) -> None:
    """Generate IEE keyblob atomic command on EdgeLock Enclave."""
    enum_algorithm = KeyBlobEncryptionAlgorithm.get(algorithm)
    assert isinstance(enum_algorithm, int)
    enum_ctr_mode = KeyBlobEncryptionIeeCtrModes.get(ctr_mode)
    assert isinstance(enum_ctr_mode, int)

    if (
        key_size
        not in ele_message.EleMessageGenerateKeyBLobIee.SUPPORTED_ALGORITHMS[enum_algorithm]
    ):
        raise SPSDKAppError("Invalid key size")

    key_blob = ele_gen_keyblob_iee(
        handler,
        key_id,
        enum_algorithm,
        key=get_key(key, key_size // 8),
        counter=get_key(counter, 16) if counter else b"",
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
    algorithm: int,
    key: bytes,
    counter: bytes,
    ctr_mode: int,
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
    gen_keyblob_iee_msg = ele_message.EleMessageGenerateKeyBLobIee(
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
    "-p",
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
