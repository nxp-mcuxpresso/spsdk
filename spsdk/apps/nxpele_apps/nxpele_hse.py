#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK NXP EdgeLock Enclave Hardware Security Engine command-line interface.

This module provides CLI commands for interacting with HSE (Hardware Security Engine)
functionality through NXP EdgeLock Enclave, including key management, firmware updates,
image signing and verification, and attribute retrieval operations.
"""

import json
import logging
from typing import Optional

import click

from spsdk.apps.utils.common_cli_options import (
    CommandsTreeGroup,
    spsdk_output_option,
    spsdk_use_json_option,
)
from spsdk.apps.utils.utils import INT
from spsdk.crypto.keys import load_key
from spsdk.ele.ele_comm import EleMessageHandler
from spsdk.ele.ele_constants import ResponseStatus
from spsdk.ele.ele_message_hse import (
    EleMessageHseActivatePassiveBlock,
    EleMessageHseBootDataImageSign,
    EleMessageHseBootDataImageVerify,
    EleMessageHseCoreResetEntryErase,
    EleMessageHseCoreResetEntryInstall,
    EleMessageHseEraseFirmware,
    EleMessageHseFirmwareIntegrityCheck,
    EleMessageHseFirmwareUpdate,
    EleMessageHseFormatKeyCatalogs,
    EleMessageHseGetAttr,
    EleMessageHseGetKeyInfo,
    EleMessageHseImportKey,
    EleMessageHseSetAttr,
    EleMessageHseSmrEntryErase,
    EleMessageHseSmrEntryInstall,
    EleMessageHseSmrVerify,
    HseAccessMode,
    HseSmrVerificationOptions,
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
from spsdk.image.hse.common import KeyCatalogId, KeyHandle
from spsdk.image.hse.core_reset import CoreResetEntry
from spsdk.image.hse.key_catalog import KeyCatalogCfg
from spsdk.image.hse.key_info import KeyFormat, KeyInfo
from spsdk.image.hse.smr import SmrEntry
from spsdk.mboot.mcuboot import McuBoot
from spsdk.utils.config import Config
from spsdk.utils.misc import load_binary, write_file

logger = logging.getLogger(__name__)


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
@spsdk_use_json_option
def get_key_info(
    ele_handler: EleMessageHandler,
    catalog_id: KeyCatalogId,
    group_idx: int,
    slot_idx: int,
    use_json: bool,
) -> None:
    """Get HSE key information.

    This command retrieves detailed information about a key using its handle.
    The information includes key flags, bit length, counter, SMR flags, and key type.
    """
    cmd = EleMessageHseGetKeyInfo(
        KeyHandle.from_attributes(catalog_id=catalog_id, group_idx=group_idx, slot_idx=slot_idx)
    )
    with ele_handler:
        ele_handler.send_message(cmd)
    assert cmd.key_info  # key info is set at this point
    cmd.key_info.family = ele_handler.family
    if use_json:
        key_info = cmd.key_info.get_config()
        click.echo(json.dumps(key_info, indent=3))
    else:
        click.echo(cmd.response_info())


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
    cmd = EleMessageHseFirmwareUpdate(
        access_mode=access_mode, fw_file_addr=fw_addr, stream_length=length
    )
    with ele_handler:
        ele_handler.send_message(cmd)

    click.echo(cmd.response_info())


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
    key_catalog_cfg.verify().validate()
    cmd = EleMessageHseFormatKeyCatalogs()
    cmd.set_buffer_params(ele_handler.comm_buff_addr, ele_handler.comm_buff_size)
    with ele_handler:
        ele_handler.device.write_memory(cmd.free_space_address, key_catalog_cfg.export())
        cmd.nvm_catalog_addr = cmd.free_space_address
        cmd.ram_catalog_addr = cmd.free_space_address + key_catalog_cfg.nvm_catalog_cfg_size
        ele_handler.send_message(cmd)
    click.echo("Formatting of key catalog succeeded.")


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
        KeyFormat.from_label(value.lower()) if value is not None else None
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
    key = load_key(key_path)
    try:
        key_info_obj = KeyInfo.load_from_config(Config.create_from_file(key_info))
    except SPSDKError:
        key_info_obj = KeyInfo.parse(load_binary(key_info))
    payload = KeyImportPayload(key_info=key_info_obj, key=key)
    key_handle = KeyHandle.from_attributes(catalog_id, group_idx, slot_idx)
    cmd = EleMessageHseImportKey(key_handle=key_handle, payload=payload, key_format=key_format)
    cmd.set_buffer_params(ele_handler.comm_buff_addr, ele_handler.comm_buff_size)
    if cmd.free_space_size < payload.size:
        raise SPSDKError(
            f"Insufficient free space at address {cmd.free_space_address}: Required {payload.size}, Available {cmd.free_space_size}"
        )
    cmd.payload.address = cmd.free_space_address
    with ele_handler:
        ele_handler.device.write_memory(cmd.free_space_address, payload.export())
        ele_handler.send_message(cmd)
    click.echo(str(cmd.response_info()))


@hse_group.command(name="smr-entry-install", no_args_is_help=True)
@click.pass_obj
@click.option(
    "-i",
    "--entry-idx",
    type=click.IntRange(0, 7),
    required=True,
    help="SMR entry index in the SMR table to be added/updated.",
)
@click.option(
    "-e",
    "--smr-entry",
    "smr_entry_path",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to SMR entry binary data or config file.",
)
@click.option(
    "-t",
    "--auth-tag",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to SMR authentication tag as a binary file.",
    callback=lambda ctx, param, value: load_binary(value),
)
@click.option(
    "-a",
    "--auth-tag-addr",
    type=INT(),
    required=True,
    help="The location in flash of the initial proof of authenticity over SMR.",
)
@click.option(
    "-ef",
    "--erase-flash",
    is_flag=True,
    default=False,
    help="Erase flash before writing the authentication tag.",
)
def smr_entry_install(
    ele_handler: EleMessageHandler,
    entry_idx: int,
    smr_entry_path: str,
    auth_tag: bytes,
    auth_tag_addr: int,
    erase_flash: bool,
) -> None:
    """Install SMR (Secure Memory Region)."""
    try:
        smr_entry = SmrEntry.load_from_config(Config.create_from_file(smr_entry_path))
    except SPSDKError:
        smr_entry = SmrEntry.parse(load_binary(smr_entry_path), ele_handler.family)
    smr_entry.verify().validate()
    auth_tag_lengths = smr_entry.get_auth_tag_lengths(auth_tag)
    smr_entry.update_auth_tag_addrs(auth_tag, auth_tag_addr)
    # currently only ONE_PASS access mode is supported
    cmd = EleMessageHseSmrEntryInstall(
        access_mode=HseAccessMode.ONE_PASS,
        entry_index=entry_idx,
        smr_data_addr=smr_entry.smr_src_addr,
        smr_data_length=smr_entry.smr_size,
        auth_tag_addrs=smr_entry.inst_auth_tag_addrs,
        auth_tag_lengths=auth_tag_lengths,
    )
    cmd.set_buffer_params(ele_handler.comm_buff_addr, ele_handler.comm_buff_size)
    cmd.smr_entry_addr = cmd.free_space_address
    with ele_handler:
        if erase_flash:
            if isinstance(ele_handler.device, McuBoot):
                ele_handler.device.flash_erase_region(
                    smr_entry.inst_auth_tag_addrs[0], len(auth_tag)
                )
            else:
                logger.warning("Device does not support flash erase operation")
        ele_handler.device.write_memory(smr_entry.inst_auth_tag_addrs[0], auth_tag)
        logger.info(f"The authentication tag has been loaded to address {smr_entry}")
        ele_handler.device.write_memory(cmd.free_space_address, smr_entry.export())
        ele_handler.send_message(cmd)
    click.echo(str(cmd.response_info()))


# Add the SMR verify command
@hse_group.command(name="smr-verify", no_args_is_help=True)
@click.pass_obj
@click.option(
    "-i",
    "--entry-idx",
    type=click.IntRange(0, 7),
    required=True,
    help="SMR entry index in the SMR table to be verified.",
)
@click.option(
    "--options",
    type=click.Choice(HseSmrVerificationOptions.labels(), case_sensitive=False),
    default="NONE",
    callback=lambda ctx, param, value: HseSmrVerificationOptions.from_label(value.upper()),
    help="Verification options for customizing the on-demand SMR verification.",
)
def smr_verify(
    ele_handler: EleMessageHandler,
    entry_idx: int,
    options: HseSmrVerificationOptions,
) -> None:
    """Verify SMR (Secure Memory Region) on-demand.

    This service starts the on-demand verification of a secure memory region by specifying
    the index in the SMR table. The service loads and verifies an SMR entry in SRAM based
    on the specified verification options.

    Options:
    - NONE: Default verification of the SMR at run-time
    - NO_LOAD: SMR is verified from external flash without loading to SRAM
    - RELOAD: SMR is loaded from external flash and verified even if already loaded
    - PASSIVE_MEM: Verifies SMR from passive block with address translation (HSE_B only)
    """
    # Validate entry index range
    if entry_idx < 0 or entry_idx > 31:
        raise SPSDKError(f"Invalid SMR entry index: {entry_idx}. Must be between 0 and 31.")

    # Create SMR verify command
    cmd = EleMessageHseSmrVerify(entry_index=entry_idx, options=options)

    # Send command to HSE
    with ele_handler:
        try:
            ele_handler.send_message(cmd)
        except SPSDKError as e:
            if options == HseSmrVerificationOptions.NO_LOAD:
                click.echo(
                    "Hint: NO_LOAD option requires SMR to be in memory-mapped external flash (not SD/eMMC) and cannot be encrypted."
                )
            elif options == HseSmrVerificationOptions.RELOAD:
                click.echo(
                    "Hint: RELOAD option requires SMR to be in memory-mapped external flash (not SD/eMMC)."
                )
            elif options == HseSmrVerificationOptions.PASSIVE_MEM:
                click.echo(
                    "Hint: PASSIVE_MEM option is only available for HSE_B with A/B Swap Configuration."
                )
            raise e
    click.echo(cmd.response_info())


@hse_group.command(name="smr-entry-erase", no_args_is_help=True)
@click.pass_obj
@click.option(
    "-i",
    "--entry-idx",
    type=click.IntRange(0, 7),
    required=True,
    help="SMR entry index in the SMR table to be erased.",
)
@click.confirmation_option(
    prompt="This will permanently erase the SMR entry and all associated secure memory configurations. "
    "This operation cannot be undone. Are you sure you want to continue?"
)
def smr_entry_erase(
    ele_handler: EleMessageHandler,
    entry_idx: int,
) -> None:
    """Erase SMR (Secure Memory Region) entry.

    This service erases one SMR entry from the internal HSE memory.
    The service removes the specified entry from the SMR table, effectively
    disabling the secure memory region configuration for that entry index.

    Requirements:

    - SuperUser (SU) access rights with privileges over HSE_SYS_AUTH_NVM_CONFIG data
      are required to perform this service
    - Erasing an SMR entry will remove all associated secure memory configurations
    - The operation is irreversible - the entry must be reinstalled if needed again
    - Ensure no Core Reset entries reference this SMR entry before erasing
    - Consider the impact on secure boot flow before erasing
    """
    # Create SMR entry erase command
    cmd = EleMessageHseSmrEntryErase(entry_index=entry_idx)

    # Send command to HSE
    with ele_handler:
        ele_handler.send_message(cmd)
    click.echo(cmd.response_info())


@hse_group.command(name="fw-erase")
@click.pass_obj
@click.confirmation_option(
    prompt="This will permanently erase the HSE firmware, SYS-IMG, and backup images. "
    "This operation cannot be undone. Are you sure you want to continue?"
)
def fw_erase(ele_handler: EleMessageHandler) -> None:
    """Erase HSE firmware from the device.

    This service erases the HSE Firmware, SYS-IMG, and backup (if present)
    from the secure flash on the device.

    Requirements:
    - Available for flash-based devices only (HSE_B variant)
    - Can only be performed in CUST_DEL life cycle
    - This is a DESTRUCTIVE operation that cannot be undone

    The command will return an error if attempted in any life cycle other than CUST_DEL.
    """
    cmd = EleMessageHseEraseFirmware()

    with ele_handler:
        ele_handler.send_message(cmd)

    click.echo(cmd.response_info())

    if cmd.status != ResponseStatus.ELE_SUCCESS_IND.tag:
        click.echo(cmd.response_status())


@hse_group.command(name="fw-integrity-check")
@click.pass_obj
def fw_integrity_check(ele_handler: EleMessageHandler) -> None:
    """Check HSE firmware integrity.

    This service performs an integrity check of the HSE Firmware and SYS-IMG
    inside HSE to verify they have not been corrupted or tampered with.

    Notes:
    - Available for HSE_B variant only
    - Non-destructive operation - only checks integrity
    - Returns success if firmware integrity is valid, failure otherwise
    """
    cmd = EleMessageHseFirmwareIntegrityCheck()

    with ele_handler:
        ele_handler.send_message(cmd)

    click.echo(cmd.response_info())

    if cmd.status != ResponseStatus.ELE_SUCCESS_IND.tag:
        click.echo(cmd.response_status())


@hse_group.command(name="cr-entry-install", no_args_is_help=True)
@click.pass_obj
@click.option(
    "-i",
    "--entry-idx",
    type=click.IntRange(0, 3),
    required=True,
    help="Core Reset entry index in the CR table to be added/updated.",
)
@click.option(
    "-e",
    "--cr-entry",
    "cr_entry_path",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to Core Reset entry binary data or config file.",
)
def core_reset_install(
    ele_handler: EleMessageHandler,
    entry_idx: int,
    cr_entry_path: str,
) -> None:
    """Install Core Reset entry.

    This service updates an existing or adds a new entry in the Core Reset table.
    The Core Reset table manages the boot sequence and SMR verification for different
    processor cores in the system.

    Requirements:

    - SMR entries linked with the CR entry (via preBoot/altPreBoot/postBoot SMR maps)
      must be installed in HSE prior to the CR installation
    - SuperUser rights (for NVM Configuration) are needed to perform this service
    - Updating an existing CR entry requires all preBoot and postBoot SMR(s) linked
      with the previous entry to be verified successfully (applicable only in
      OEM_PROD/IN_FIELD life cycles)
    """
    try:
        cr_entry = CoreResetEntry.load_from_config(Config.create_from_file(cr_entry_path))
    except SPSDKError:
        cr_entry = CoreResetEntry.parse(load_binary(cr_entry_path), ele_handler.family)
    cr_entry.verify().validate()

    cmd = EleMessageHseCoreResetEntryInstall(
        entry_index=entry_idx,
        entry_addr=0,  # Will be set after loading to target memory
    )

    cmd.set_buffer_params(ele_handler.comm_buff_addr, ele_handler.comm_buff_size)
    cr_entry_data = cr_entry.export()
    cmd.entry_addr = cmd.free_space_address
    with ele_handler:
        # Write CR entry data to target memory
        ele_handler.device.write_memory(cmd.free_space_address, cr_entry_data)
        logger.info(f"Core Reset entry loaded to address 0x{cmd.free_space_address:08X}")
        ele_handler.send_message(cmd)
    click.echo(cmd.response_info())


@hse_group.command(name="cr-entry-erase", no_args_is_help=True)
@click.pass_obj
@click.option(
    "-i",
    "--entry-idx",
    type=click.IntRange(0, 3),
    required=True,
    help="Core Reset entry index in the CR table to be erased.",
)
@click.confirmation_option(
    prompt="This will permanently erase the Core Reset entry and all associated boot configurations. "
    "This operation cannot be undone. Are you sure you want to continue?"
)
def core_reset_erase(
    ele_handler: EleMessageHandler,
    entry_idx: int,
) -> None:
    """Erase Core Reset entry.

    This service erases one Core Reset entry from the internal HSE memory.
    The service removes the specified entry from the Core Reset table, effectively
    disabling the core reset configuration for that entry index.

    Notes:
    - Ensure no critical boot sequences depend on this Core Reset entry
    - Consider the impact on system boot flow before erasing
    - SMR entries referenced by this CR entry may become orphaned
    """
    cmd = EleMessageHseCoreResetEntryErase(entry_index=entry_idx)
    with ele_handler:
        ele_handler.send_message(cmd)
    click.echo(cmd.response_info())


@hse_group.command(name="activate-passive-block")
@click.pass_obj
def activate_passive_block(ele_handler: EleMessageHandler) -> None:
    """Activate passive flash block.

    This service switches the passive flash block area to become the active block.
    It enables A/B swap functionality in dual-bank flash configurations.

    Notes:
    - Available for HSE_B variant only
    - Used for A/B update scenarios and dual-bank flash configurations
    """
    cmd = EleMessageHseActivatePassiveBlock()
    with ele_handler:
        ele_handler.send_message(cmd)
    click.echo(cmd.response_info())
