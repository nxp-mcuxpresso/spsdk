#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK NXP EdgeLock Enclave Hardware Security Engine command-line interface.

This module provides CLI commands for interacting with HSE (Hardware Security Engine)
functionality through NXP EdgeLock Enclave, including key management, firmware updates,
image signing and verification, and attribute retrieval operations.
"""

from typing import Optional

import click

import spsdk.ele.ele_message_hse
from spsdk.apps.utils.common_cli_options import CommandsTreeGroup, spsdk_output_option
from spsdk.apps.utils.utils import INT
from spsdk.ele.ele_comm import EleMessageHandler
from spsdk.ele.ele_constants import ResponseStatus
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import load_binary, write_file


@click.group(name="hse", cls=CommandsTreeGroup)
def hse_group() -> None:
    """Hardware Security Engine commands."""


@hse_group.command(name="get-key-info", no_args_is_help=True)
@click.pass_obj
@click.option(
    "-c",
    "--catalog-id",
    type=INT(),
    required=True,
    help="Key catalog ID (byte 2 of key handle).",
)
@click.option(
    "-g",
    "--group-idx",
    type=INT(),
    required=True,
    help="Group index in catalog (byte 1 of key handle, between 0 and n-1).",
)
@click.option(
    "-s",
    "--slot-idx",
    type=INT(),
    required=True,
    help="Key slot index within the group (byte 0 of key handle, between 0 and p-1).",
)
def get_key_info(
    ele_handler: EleMessageHandler, catalog_id: int, group_idx: int, slot_idx: int
) -> None:
    """Get HSE key information.

    This command retrieves detailed information about a key using its handle.
    The information includes key flags, bit length, counter, SMR flags, and key type.
    """
    key_handle = ((catalog_id & 0xFF) << 16) | ((group_idx & 0xFF) << 8) | (slot_idx & 0xFF)
    cmd = spsdk.ele.ele_message_hse.EleMessageHseGetKeyInfo(key_handle)
    with ele_handler:
        ele_handler.send_message(cmd)

    if cmd.status == ResponseStatus.ELE_SUCCESS_IND.tag:
        click.echo("HSE Get Key Info successful:")
        click.echo(cmd.response_info())
    else:
        click.echo(f"HSE Get Key Info failed: {cmd.response_status()}")


@hse_group.command(name="fw-update", no_args_is_help=True)
@click.pass_obj
@click.option(
    "-m",
    "--mode",
    type=click.Choice(
        spsdk.ele.ele_message_hse.EleMessageHseFirmwareUpdate.HseAccessMode.labels(),
        case_sensitive=False,
    ),
    required=True,
    help="Access mode for firmware update (ONE_PASS, START, UPDATE, FINISH).",
)
@click.option(
    "-a",
    "--fw-addr",
    type=INT(),
    required=True,
    help="Address of the HSE firmware file or chunk in target memory.",
)
@click.option(
    "-l",
    "--length",
    type=INT(),
    required=False,
    default=0,
    help="Length of firmware chunk in bytes (required for START and UPDATE modes, must be multiple of 64 bytes).",
)
@click.option(
    "-b",
    "--binary",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, resolve_path=True),
    required=False,
    help="Binary file with HSE firmware to load to target memory before update (optional).",
)
def fw_update(
    ele_handler: EleMessageHandler, mode: str, fw_addr: int, length: int, binary: Optional[str]
) -> None:
    """Update HSE firmware.

    This service is used to update the HSE firmware into the HSE internal flash memory.
    Supports both one-pass and streaming modes (START, UPDATE, FINISH).

    For streaming mode:
    1. First use mode=START with the first chunk
    2. Use mode=UPDATE for intermediate chunks
    3. Finally use mode=FINISH for the last chunk

    For one-pass mode:
    - Use mode=ONE_PASS to update the entire firmware in one operation

    If --binary is provided, the firmware will be loaded to the specified address
    before performing the update operation.
    """
    access_mode = spsdk.ele.ele_message_hse.EleMessageHseFirmwareUpdate.HseAccessMode.from_label(
        mode
    )

    # If binary file is provided, load it to target memory
    if binary:
        fw_data = load_binary(binary)
        # For streaming modes, use the specified length or the file size
        length = length or len(fw_data)
        # Write firmware to target memory
        with ele_handler:
            ele_handler.device.write_memory(fw_addr, fw_data)
        click.echo(f"Loaded {len(fw_data)} bytes of firmware to address 0x{fw_addr:08X}")

    # Create and send firmware update command
    try:
        cmd = spsdk.ele.ele_message_hse.EleMessageHseFirmwareUpdate(
            access_mode=access_mode, fw_file_addr=fw_addr, stream_length=length
        )
        with ele_handler:
            ele_handler.send_message(cmd)

        click.echo(cmd.response_info())

    except SPSDKError as e:
        click.echo(f"Error: {str(e)}")


@hse_group.command(name="img-verify", no_args_is_help=True)
@click.pass_obj
@click.option(
    "-a",
    "--img-addr",
    type=INT(),
    required=True,
    help="The address of the Boot Data Image to verify (includes authentication TAG).",
)
def img_verify(ele_handler: EleMessageHandler, img_addr: int) -> None:
    """Verify Boot Data Image.

    Verifies the GMAC tag of a Boot Data Image that was previously signed using the img-sign command.
    For HSE_H/M, verifies IVT/DCD/ST/LPDDR4(S32Z/E devices)/AppBSB image.
    For HSE_B, verifies IVT/AppBSB image.
    """
    cmd = spsdk.ele.ele_message_hse.EleMessageHseBootDataImageVerify(img_addr)
    with ele_handler:
        ele_handler.send_message(cmd)
    click.echo(cmd.response_info())


@hse_group.command(name="img-sign", no_args_is_help=True)
@click.pass_obj
@click.option(
    "-a",
    "--img-addr",
    type=INT(),
    required=True,
    help="The address of the Boot Data Image.",
)
@click.option(
    "-l",
    "--tag-length",
    type=INT(),
    required=False,
    default="28",
    help="The address of the Boot Data Image.",
)
@spsdk_output_option(
    required=False,
    help="Store the signature into output file.",
)
def img_sign(ele_handler: EleMessageHandler, img_addr: int, tag_length: int, output: str) -> None:
    """Boot Data image sign."""
    cmd = spsdk.ele.ele_message_hse.EleMessageHseBootDataImageSign(img_addr, tag_length)
    with ele_handler:
        ele_handler.send_message(cmd)
    click.echo(str(cmd.response_info()))
    if output:
        write_file(cmd.signature, output, mode="wb")


@hse_group.command(name="get-attr", no_args_is_help=True)
@click.pass_obj
@click.option(
    "-id",
    "--attr-id",
    type=click.Choice(spsdk.ele.ele_message_hse.HseAttributeId.labels(), case_sensitive=False),
    required=True,
    help="Attribute identifier to retrieve",
)
def get_attr(ele_handler: EleMessageHandler, attr_id: str) -> None:
    """Get HSE attribute."""
    cmd = spsdk.ele.ele_message_hse.EleMessageHseGetAttr(
        spsdk.ele.ele_message_hse.HseAttributeId.from_label(attr_id)
    )
    with ele_handler:
        ele_handler.send_message(cmd)
    click.echo(str(cmd.attr_handler))
