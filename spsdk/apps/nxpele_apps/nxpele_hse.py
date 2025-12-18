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

import json
from typing import Optional

import click

from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_output_option,
    spsdk_use_json_option,
)
from spsdk.apps.utils.utils import INT
from spsdk.crypto.keys import PrivateKey, PublicKey
from spsdk.ele.ele_comm import EleMessageHandler
from spsdk.ele.ele_constants import ResponseStatus
from spsdk.ele.ele_message_hse import (
    EleMessageHseBootDataImageSign,
    EleMessageHseBootDataImageVerify,
    EleMessageHseFirmwareUpdate,
    EleMessageHseFormatKeyCatalogs,
    EleMessageHseGetAttr,
    EleMessageHseGetKeyInfo,
    EleMessageHseImportKey,
    EleMessageHseSetAttr,
    KeyImportPayload,
)
from spsdk.ele.hse_attrs import (
    EnablePublishKeyStoreRamToFlashAttributeHandler,
    HseAttributeHandler,
    HseAttributeId,
    SecureLifecycle,
    SecureLifecycleAttributeHandler,
)
from spsdk.exceptions import SPSDKError
from spsdk.image.hse.key_catalog import KeyCatalogCfg
from spsdk.image.hse.key_info import KeyCatalogId, KeyFormat, KeyHandle, KeyInfo
from spsdk.utils.config import Config
from spsdk.utils.misc import load_binary, write_file


@click.group(name="hse", cls=CommandsTreeGroup)
def hse_group() -> None:
    """Hardware Security Engine commands."""


@hse_group.command(name="get-key-info", no_args_is_help=True)
@click.pass_obj
@click.option(
    "-c",
    "--catalog-id",
    type=click.Choice(KeyCatalogId.labels(), case_sensitive=False),
    required=True,
    callback=lambda ctx, param, value: KeyCatalogId.from_label(value.lower()),
    help="Key catalog ID.",
)
@click.option(
    "-g",
    "--group-idx",
    type=INT(),
    required=True,
    help="Group index in catalog.",
)
@click.option(
    "-s",
    "--slot-idx",
    type=INT(),
    required=True,
    help="Key slot index within the group.",
)
def get_key_info(
    ele_handler: EleMessageHandler, catalog_id: KeyCatalogId, group_idx: int, slot_idx: int
) -> None:
    """Get HSE key information.

    This command retrieves detailed information about a key using its handle.
    The information includes key flags, bit length, counter, SMR flags, and key type.
    """
    cmd = EleMessageHseGetKeyInfo(
        KeyHandle(catalog_id=catalog_id, group_idx=group_idx, slot_idx=slot_idx)
    )
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
        EleMessageHseFirmwareUpdate.HseAccessMode.labels(),
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
    access_mode = EleMessageHseFirmwareUpdate.HseAccessMode.from_label(mode)

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
        cmd = EleMessageHseFirmwareUpdate(
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
    cmd = EleMessageHseBootDataImageVerify(img_addr)
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
    help="Length of the final signature with IV.",
)
@spsdk_output_option(
    required=False,
    help="Store the signature into output file.",
)
def img_sign(ele_handler: EleMessageHandler, img_addr: int, tag_length: int, output: str) -> None:
    """Boot Data image sign."""
    cmd = EleMessageHseBootDataImageSign(img_addr, tag_length)
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
    type=click.Choice(
        [
            id.label
            for id in HseAttributeId
            if HseAttributeHandler.get_attr_handler_cls(id).is_readable()
        ],
        case_sensitive=False,
    ),
    callback=lambda ctx, param, value: HseAttributeId.from_label(value.lower()),
    required=True,
    help="Attribute identifier to retrieve",
)
@spsdk_use_json_option
def get_attr(ele_handler: EleMessageHandler, attr_id: HseAttributeId, use_json: bool) -> None:
    """Get HSE attribute."""
    cmd = EleMessageHseGetAttr(attr_id)
    with ele_handler:
        ele_handler.send_message(cmd)
    if use_json:
        attr_dict = cmd.attr_value.to_dict() if cmd.attr_value else {}
        click.echo(json.dumps(attr_dict, indent=3))
    else:
        click.echo(cmd.info())


@hse_group.group(name="set-attr", cls=CommandsTreeGroup)
def set_attribute_group() -> None:
    """Attribute related commands."""


@set_attribute_group.command(name="enable-publish-keystore-ram-to-flash", no_args_is_help=True)
@click.option(
    "-v",
    "--value",
    type=click.Choice(
        EnablePublishKeyStoreRamToFlashAttributeHandler.ConfigValue.labels(), case_sensitive=False
    ),
    callback=lambda ctx, param, value: EnablePublishKeyStoreRamToFlashAttributeHandler.ConfigValue.from_label(
        value.lower()
    ),
    required=True,
    help="Config value to be set",
)
@click.pass_obj
def enable_publish_keystore_ram_to_flash(
    ele_handler: EleMessageHandler,
    value: EnablePublishKeyStoreRamToFlashAttributeHandler.ConfigValue,
) -> None:
    """Enable publish keystore RAM To Flash Attribute Handler."""
    attr_handler = EnablePublishKeyStoreRamToFlashAttributeHandler(value)
    cmd: EleMessageHseSetAttr = set_attr(ele_handler, attr_handler)
    click.echo(
        f"Setting up the attribute '{attr_handler.ATTR_ID.label}' finished: {cmd.status_string}."
    )


@set_attribute_group.command(name="secure_lifecycle", no_args_is_help=True)
@click.option(
    "-v",
    "--value",
    type=click.Choice(SecureLifecycle.labels(), case_sensitive=False),
    callback=lambda ctx, param, value: SecureLifecycle.from_label(value.lower()),
    required=True,
    help="Config value to be set",
)
@click.pass_obj
def secure_lifecycle(
    ele_handler: EleMessageHandler,
    value: SecureLifecycle,
) -> None:
    """Advance the secure lifecycle."""
    attr_handler = SecureLifecycleAttributeHandler(value)
    cmd: EleMessageHseSetAttr = set_attr(ele_handler, attr_handler)
    click.echo(
        f"Setting up the attribute '{attr_handler.ATTR_ID.label}' finished: {cmd.status_string}."
    )


def set_attr(
    ele_handler: EleMessageHandler, attr_handler: HseAttributeHandler
) -> EleMessageHseSetAttr:
    """Set attribute helper function."""
    cmd = EleMessageHseSetAttr(attr_handler.ATTR_ID)
    cmd.set_buffer_params(ele_handler.comm_buff_addr, ele_handler.comm_buff_size)
    with ele_handler:
        ele_handler.device.write_memory(cmd.free_space_address, attr_handler.export())
        cmd.value_addr = cmd.free_space_address
        ele_handler.send_message(cmd)
    return cmd


@hse_group.command(name="format-key-catalog", no_args_is_help=True)
@click.option(
    "--key-catalog",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, resolve_path=True),
    required=True,
    help="Path to key catalog binary or configuration file. Key catalog configuration can be created using 'nxpimage hse key-catalog' commands.",
)
@click.pass_obj
def format_key_catalog(ele_handler: EleMessageHandler, key_catalog: str) -> None:
    """Format key catalog."""
    try:
        key_catalog_cfg = KeyCatalogCfg.load_from_config(Config.create_from_file(key_catalog))
    except SPSDKError:
        key_catalog_cfg = KeyCatalogCfg.parse(load_binary(key_catalog))
    cmd = EleMessageHseFormatKeyCatalogs()
    cmd.set_buffer_params(ele_handler.comm_buff_addr, ele_handler.comm_buff_size)
    with ele_handler:
        ele_handler.device.write_memory(cmd.free_space_address, key_catalog_cfg.export())
        cmd.nvm_catalog_addr = cmd.free_space_address
        cmd.ram_catalog_addr = cmd.free_space_address + key_catalog_cfg.nvm_catalog_cfg_size
        ele_handler.send_message(cmd)


@hse_group.command(name="key-import", no_args_is_help=True)
@click.pass_obj
@click.option(
    "--catalog-id",
    type=click.Choice(KeyCatalogId.labels(), case_sensitive=False),
    required=True,
    callback=lambda ctx, param, value: KeyCatalogId.from_label(value.lower()),
    help="Key catalog ID.",
)
@click.option(
    "--group-idx",
    type=INT(),
    required=True,
    help="Group index in catalog.",
)
@click.option(
    "--slot-idx",
    type=INT(),
    required=True,
    help="Key slot index within the group.",
)
@click.option(
    "--key-info",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, resolve_path=True),
    required=True,
    help="Path to key info binary or configuration file.",
)
@click.option(
    "--key-path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, resolve_path=True),
    required=True,
    help="Path to a key to be loaded.",
)
@click.option(
    "--key-format",
    type=click.Choice(KeyFormat.labels(), case_sensitive=False),
    required=False,
    callback=lambda ctx, param, value: (
        KeyCatalogId.from_label(value.lower()) if value is not None else None
    ),
    help="Key format of the imported key. Applicable only for ECC keys.",
)
def key_import(
    ele_handler: EleMessageHandler,
    catalog_id: KeyCatalogId,
    group_idx: int,
    slot_idx: int,
    key_info: str,
    key_path: str,
    key_format: Optional[KeyFormat],
) -> None:
    """Import key in HSE key catalog."""
    key = None
    for parser in [
        lambda k: PrivateKey.load(k),
        lambda k: PublicKey.load(k),
        lambda k: load_binary(k),
    ]:
        try:
            key = parser(key_path)
        except SPSDKError:
            continue
    if key is None:
        raise SPSDKError(f"Unable to load key from path {key_path}")
    assert isinstance(key, (PrivateKey, PublicKey, bytes))
    try:
        key_info_obj = KeyInfo.load_from_config(Config.create_from_file(key_info))
    except SPSDKError:
        key_info_obj = KeyInfo.parse(load_binary(key_info))
    payload = KeyImportPayload(key_info=key_info_obj, key=key)
    key_handle = KeyHandle(catalog_id, group_idx, slot_idx)
    cmd = EleMessageHseImportKey(key_handle=key_handle, payload=payload, key_format=key_format)
    cmd.set_buffer_params(ele_handler.comm_buff_addr, ele_handler.comm_buff_size)
    if cmd.free_space_size < payload.size:
        raise SPSDKError(
            f"Insufficient free space at address {cmd.free_space_address}: Required {payload.size}, Available {cmd.free_space_size}"
        )
    cmd.payload_address = cmd.free_space_address
    with ele_handler:
        ele_handler.device.write_memory(cmd.free_space_address, payload.export())
        ele_handler.send_message(cmd)
    click.echo(str(cmd.response_info()))
