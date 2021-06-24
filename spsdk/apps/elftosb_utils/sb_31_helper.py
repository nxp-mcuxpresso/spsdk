#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for parsing original elf2sb configuration files."""
# pylint: disable=too-few-public-methods,too-many-instance-attributes

import struct
from typing import List

from spsdk import SPSDKError
from spsdk.sbfile.sb31 import commands
from spsdk.utils.misc import load_binary


class RootOfTrustInfo:
    """Filters out Root Of Trust information given to elf2sb application."""

    def __init__(self, data: dict) -> None:
        """Create object out of data loaded from elf2sb configuration file."""
        self.config_data = data
        self.private_key = data["mainCertPrivateKeyFile"]
        self.public_keys = [data.get(f"rootCertificate{idx}File") for idx in range(4)]
        # filter out None and empty values
        self.public_keys = list(filter(None, self.public_keys))
        self.public_key_index = self.config_data["mainCertChainId"]


class TrustZoneConfig:
    """Configuration object specific for TrustZone."""

    def __init__(self, config_data: dict) -> None:
        """Initialize TrustZoneConfig from json config data."""
        self.family = config_data["family"]
        self.revision = config_data.get("revision")
        self.output_file = config_data["tzpOutputFile"]
        self.presets = config_data["trustZonePreset"]


class CertificateBlockConfig:
    """Configuration object for Certificate block."""

    def __init__(self, config_data: dict) -> None:
        """Initialize CertificateBlockConfig from json config data."""
        self.root_certificate_0_file = config_data.get("rootCertificate0File")
        self.root_certificate_1_file = config_data.get("rootCertificate1File")
        self.root_certificate_2_file = config_data.get("rootCertificate2File")
        self.root_certificate_3_file = config_data.get("rootCertificate3File")
        self.root_certs = [
            self.root_certificate_0_file,
            self.root_certificate_1_file,
            self.root_certificate_2_file,
            self.root_certificate_3_file,
        ]
        self.root_certs = [item for item in self.root_certs if item]
        self.root_certificate_curve = config_data.get("rootCertificateEllipticCurve")
        self.main_root_cert_id = config_data.get("mainRootCertId", 0)
        self.main_root_private_key_file = config_data.get("mainRootCertPrivateKeyFile")
        self.use_isk = config_data.get("useIsk", False)
        self.isk_certificate = config_data.get("signingCertificateFile")
        self.isk_private_key_file = config_data.get("signingCertificatePrivateKeyFile")
        self.isk_constraint = int(config_data.get("signingCertificateConstraint", "0"), 0)
        self.isk_certificate_curve = config_data.get("iskCertificateEllipticCurve")
        self.isk_sign_data_path = config_data.get("signCertData")

        self.main_signing_key = self.main_root_private_key_file
        self.main_curve_name = self.root_certificate_curve
        if self.use_isk:
            self.main_signing_key = self.isk_private_key_file
            self.main_curve_name = self.isk_certificate_curve


class MasterBootImageConfig(CertificateBlockConfig):
    """Configuration object for MasterBootImage."""

    def __init__(self, config_data: dict) -> None:
        """Initialize MasterBootImageConfig from json config data."""
        super().__init__(config_data)
        self.family = config_data["family"]
        self.revision = config_data.get("revision")
        self.input_image_file = config_data["inputImageFile"]
        self.output_image_exec_address = int(config_data["outputImageExecutionAddress"], 0)
        self.output_image_exec_target = config_data.get("outputImageExecutionTarget")
        self.output_image_auth_type = config_data.get("outputImageAuthenticationType")
        self.output_image_subtype = config_data.get("outputImageSubtype", "default")
        self.trustzone_preset_file = config_data.get("trustZonePresetFile")
        self.is_dual_boot = config_data.get("isDualBootImageVersion", False)
        self.dual_boot_version = config_data.get("dualBootImageVersion")
        if self.is_dual_boot:
            assert self.dual_boot_version
            self.dual_boot_version = int(self.dual_boot_version, 0)
        self.firmware_version = int(config_data.get("firmwareVersion", "1"), 0)
        self.master_boot_output_file = config_data["masterBootOutputFile"]


class SB31Config(CertificateBlockConfig):
    """Configuration object for SecureBinary image."""

    def __init__(self, config_data: dict) -> None:
        """Initialize SB31Config from json config data."""
        super().__init__(config_data)
        self.family = config_data["family"]
        self.revision = config_data.get("revision")
        self.container_keyblob_enc_key_path = config_data.get("containerKeyBlobEncryptionKey")
        self.is_nxp_container = config_data.get("isNxpContainer", False)
        self.description = config_data.get("description")
        self.kdk_access_rights = config_data.get("kdkAccessRights", 0)
        self.container_configuration_word = config_data.get("containerConfigurationWord", 0)
        self.firmware_version = int(config_data.get("firmwareVersion", "1"), 0)
        self.sb3_block_output = config_data.get("sb3BlockOutput", False)
        self.commands = config_data["commands"]
        self.container_output = config_data["containerOutputFile"]
        self.is_encrypted = config_data.get("isEncrypted", True)
        self.timestamp = config_data.get("timestamp")


def _erase_cmd_handler(cmd_args: dict) -> commands.CmdErase:
    address = int(cmd_args["address"], 0)
    length = int(cmd_args["size"], 0)
    memory_id = int(cmd_args.get("memoryId", "0"), 0)
    return commands.CmdErase(address=address, length=length, memory_id=memory_id)


def _load_key_blob_handler(cmd_args: dict) -> commands.CmdLoadKeyBlob:
    data = load_binary(cmd_args["file"])
    offset = int(cmd_args["offset"], 0)
    key_wrap_name = cmd_args["wrappingKeyId"]
    key_wrap_id = commands.CmdLoadKeyBlob.KeyWraps[key_wrap_name]
    return commands.CmdLoadKeyBlob(offset=offset, data=data, key_wrap_id=key_wrap_id)


def _program_fuses(cmd_args: dict) -> commands.CmdProgFuses:
    address = int(cmd_args["address"], 0)
    fuses = [int(fuse, 0) for fuse in cmd_args["values"].split(",")]
    data = struct.pack(f"<{len(fuses)}L", *fuses)
    return commands.CmdProgFuses(address=address, data=data)


def _program_ifr(cmd_args: dict) -> commands.CmdProgIfr:
    address = int(cmd_args["address"], 0)
    data = load_binary(cmd_args["file"])
    return commands.CmdProgIfr(address=address, data=data)


def _call(cmd_args: dict) -> commands.CmdCall:
    address = int(cmd_args["address"], 0)
    return commands.CmdCall(address=address)


def _execute(cmd_args: dict) -> commands.CmdExecute:
    address = int(cmd_args["address"], 0)
    return commands.CmdExecute(address=address)


def _configure_memory(cmd_args: dict) -> commands.CmdConfigureMemory:
    memory_id = int(cmd_args["memoryId"], 0)
    return commands.CmdConfigureMemory(
        address=int(cmd_args["configAddress"], 0), memory_id=memory_id
    )


def _fill_memory(cmd_args: dict) -> commands.CmdFillMemory:
    address = int(cmd_args["address"], 0)
    length = int(cmd_args["size"], 0)
    pattern = int(cmd_args["pattern"], 0)
    return commands.CmdFillMemory(address=address, length=length, pattern=pattern)


def _copy(cmd_args: dict) -> commands.CmdCopy:
    address = int(cmd_args["addressFrom"], 0)
    length = int(cmd_args["size"], 0)
    destination_address = int(cmd_args["addressTo"], 0)
    memory_id_from = int(cmd_args["memoryIdFrom"], 0)
    memory_id_to = int(cmd_args["memoryIdTo"], 0)
    return commands.CmdCopy(
        address=address,
        length=length,
        destination_address=destination_address,
        memory_id_from=memory_id_from,
        memory_id_to=memory_id_to,
    )


def _check_fw_version(cmd_args: dict) -> commands.CmdFwVersionCheck:
    value = int(cmd_args["value"], 0)
    counter_id_str = cmd_args["counterId"]
    counter_id = commands.CmdFwVersionCheck.COUNTER_ID[counter_id_str]
    return commands.CmdFwVersionCheck(value=value, counter_id=counter_id)


def _load(cmd_args: dict) -> commands.CmdLoadBase:
    authentication = cmd_args.get("authentication")
    address = int(cmd_args["address"], 0)
    memory_id = int(cmd_args.get("memoryId", "0"), 0)
    if authentication == "hashlocking":
        data = load_binary(cmd_args["file"])
        return commands.CmdLoadHashLocking(address=address, data=data, memory_id=memory_id)
    if authentication == "cmac":
        data = load_binary(cmd_args["file"])
        return commands.CmdLoadCmac(address=address, data=data, memory_id=memory_id)
    # general non-authenticated load command
    if cmd_args.get("file"):
        data = load_binary(cmd_args["file"])
        return commands.CmdLoad(address=address, data=data, memory_id=memory_id)
    if cmd_args.get("values"):
        values = [int(s, 0) for s in cmd_args["values"].split(",")]
        data = struct.pack(f"<{len(values)}L", *values)
        return commands.CmdLoad(address=address, data=data, memory_id=memory_id)
    raise SPSDKError(f"Unsupported LOAD command args: {cmd_args}")


_CMD_PARSER_HANDLERS = {
    "erase": _erase_cmd_handler,
    "load": _load,
    "execute": _execute,
    "call": _call,
    "programFuses": _program_fuses,
    "programIFR": _program_ifr,
    "copy": _copy,
    "loadKeyBlob": _load_key_blob_handler,
    "configureMemory": _configure_memory,
    "fillMemory": _fill_memory,
    "checkFwVersion": _check_fw_version,
}


def get_cmd_from_dict(cmd_dict: dict) -> commands.BaseCmd:
    """Process command description into a command object.

    :param cmd_dict: Command description from json config file
    :return: Command object
    :raises SPSDKError: Unknown command
    """
    cmd_dict_copy = cmd_dict.copy()
    cmd_name, cmd_args = cmd_dict_copy.popitem()
    try:
        parse_handler = _CMD_PARSER_HANDLERS[cmd_name]
        command = parse_handler(cmd_args)
        return command
    except KeyError:
        raise SPSDKError(f"Unknown command name: {cmd_name}")


def get_cmd_from_json(config: SB31Config) -> List[commands.BaseCmd]:
    """Parse commands from config files.

    :param config: Config file object
    :return: List of command objects
    """
    results = []
    for command in config.commands:
        results.append(get_cmd_from_dict(command))
    return results
