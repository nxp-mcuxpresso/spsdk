#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for parsing original elf2sb configuration files."""
# pylint: disable=too-few-public-methods,too-many-instance-attributes

import abc
import re
import struct
from typing import Iterable, List, Union

from spsdk import SPSDKError
from spsdk.image.mbimg import MasterBootImageType
from spsdk.sbfile.sb31 import commands
from spsdk.utils.misc import load_binary


class RootOfTrustInfo:
    """Filters out Root Of Trust information given to elf2sb application."""

    def __init__(self, data: dict) -> None:
        """Create object out of data loaded from elf2sb configuration file."""
        self.config_data = data
        self.private_key = data.get("mainCertPrivateKeyFile") or data.get(
            "mainRootCertPrivateKeyFile"
        )
        if not self.private_key:
            raise SPSDKError(
                "Private key not specified (mainCertPrivateKeyFile or mainRootCertPrivateKeyFile)"
            )
        self.public_keys = [data.get(f"rootCertificate{idx}File") for idx in range(4)]
        # filter out None and empty values
        self.public_keys = list(filter(None, self.public_keys))
        # look for keyID; can't use "or" because 0 is a valid number although it's a "falsy" value
        self.public_key_index = data.get("mainCertChainId")
        if self.public_key_index is None:
            self.public_key_index = data.get("mainRootCertId")
        if self.public_key_index is None:
            raise SPSDKError("Main Cert ID not specified (mainCertChainId or mainRootCertId)")


class TrustZoneConfig:
    """Configuration object specific for TrustZone."""

    def __init__(self, config_data: dict) -> None:
        """Initialize TrustZoneConfig from json config data."""
        self.family = config_data["family"]
        self.revision = config_data.get("revision")
        self.output_file = config_data["tzpOutputFile"]
        self.presets = config_data["trustZonePreset"]


class CertificateBlockConfig(abc.ABC):
    """Abstract class for certificate block configurations.

    This class serves as an interface class for it's children. At the moment
    there is no special functionality required, but this may change in the future.
    """

    pass


class CertificateBlockConfigGroup3(CertificateBlockConfig):
    """Certificate block configuration options for LPC55xx (LPC552x, LPC55S2x & LPC55S6x), LPC55S1x, RT5xx & RT6xx."""

    def __init__(self, config: dict) -> None:
        """Initialize the options based on `config`.

        Consult the configuration data with master boot image configuration
        options as defined in elftosb used guide.

        :param config: group 3 devices configuration options from json file.
        """
        self.image_build_number = int(config.get("imageBuildNumber", 0), 0)
        self.root_certificates: List[List[str]] = [[] for _ in range(4)]
        # TODO we need to read the whole chain from the dict for a given
        # selection based on mainCertPrivateKeyFile!!!
        self.root_certificates[0].append(config.get("rootCertificate0File", None))
        self.root_certificates[1].append(config.get("rootCertificate1File", None))
        self.root_certificates[2].append(config.get("rootCertificate2File", None))
        self.root_certificates[3].append(config.get("rootCertificate3File", None))
        self.main_cert_chain_id = config.get("mainCertChainId", 0)

        # get all certificate chain related keys from config
        pattern = f"chainCertificate{self.main_cert_chain_id}File[0-3]"
        keys = [key for key in config.keys() if re.fullmatch(pattern, key)]
        # just in case, sort the chain certificate keys in order
        keys.sort()
        for key in keys:
            self.root_certificates[self.main_cert_chain_id].append(config[key])

        self.main_cert_private_key_file = config.get("mainCertPrivateKeyFile", "")


class CertificateBlockConfigGroup4(CertificateBlockConfig):
    """Certificate block configuration options for LPC55S3x."""

    def __init__(self, config: dict) -> None:
        """Initialize options based on `config`.

        Consult the configuration data with master boot image configuration
        options as defined in elftosb used guide.

        :param config: group 4 devices configuration options from json file.
        """
        self.root_certificate_0_file = config.get("rootCertificate0File")
        self.root_certificate_1_file = config.get("rootCertificate1File")
        self.root_certificate_2_file = config.get("rootCertificate2File")
        self.root_certificate_3_file = config.get("rootCertificate3File")
        self.root_certs = [
            self.root_certificate_0_file,
            self.root_certificate_1_file,
            self.root_certificate_2_file,
            self.root_certificate_3_file,
        ]
        self.root_certs = [item for item in self.root_certs if item]
        self.root_certificate_curve = config.get("rootCertificateEllipticCurve")
        self.main_root_cert_id = config.get("mainRootCertId", 0)
        self.main_root_private_key_file = config.get("mainRootCertPrivateKeyFile")
        self.use_isk = config.get("useIsk", False)
        self.isk_certificate = config.get("signingCertificateFile")
        self.isk_private_key_file = config.get("signingCertificatePrivateKeyFile")
        self.isk_constraint = int(config.get("signingCertificateConstraint", "0"), 0)
        self.isk_certificate_curve = config.get("iskCertificateEllipticCurve")
        self.isk_sign_data_path = config.get("signCertData")


class MasterBootImageConfig(abc.ABC):
    """Abstract class for master boot image configuration options.

    This class defines the interface required by every child.
    """

    @staticmethod
    @abc.abstractmethod
    def _validate(config: dict) -> None:
        """Device group specific validation method.

        :param config: configuration to be validated.
        :raises SPSDKError: If the validation method has not been re-implemented.
        """
        raise SPSDKError("Configuration validation is not implemented.")

    def _validate_post_init(self) -> None:
        """Device group specific validation post __init__."""

    @staticmethod
    def _validate_item(
        item_name: str, item_value: Union[bool, int, str], valid_values: Iterable
    ) -> None:
        if item_value not in valid_values:
            raise SPSDKError(
                f"Invalid {item_name}. " + f"Got: {item_value}, expected one of {valid_values}"
            )

    @property
    def image_type(self) -> MasterBootImageType:
        """Image type.

        :raises SPSDKError: If the image_type method has not been re-implemented.
        """
        raise SPSDKError("image_type not implemented!")


class MasterBootImageConfigGroup3(MasterBootImageConfig):
    """Configuration object for MasterBootImage."""

    VALID_EXEC_TARGETS = ["ram", "xip"]
    VALID_AUTH_TYPES = ["crc", "signed", "encrypted"]

    def __init__(self, config: dict) -> None:
        """Initializes the object.

        :param config: master boot image configuration data. Consult the content with elftosb user guide.
        """
        self._validate(config)
        self.family = config["family"]
        self.input_image_file = config["inputImageFile"]
        execution_address = int(
            config.get("imageLinkAddress") or config["outputImageExecutionAddress"], 0
        )
        self.output_image_exec_address = execution_address
        self.output_image_exec_target = config["outputImageExecutionTarget"].lower()
        if "xip" in self.output_image_exec_target:
            self.output_image_exec_target = "xip"
        self.output_image_auth_type = config["outputImageAuthenticationType"].lower()
        authentication_type = self.output_image_auth_type
        if "signed" in self.output_image_auth_type:
            authentication_type = "signed"
        if "encrypted" in self.output_image_auth_type:
            authentication_type = "encrypted"
        self.output_image_auth_type = authentication_type
        self.output_image_encryption_key_file = config.get("outputImageEncryptionKeyFile", None)
        self.enable_trustzone = config.get("enableTrustZone", False)
        self.trustzone_preset_file = config.get("trustZonePresetFile", "")
        self.device_key_source = config.get("deviceKeySource", "")
        self.use_key_store = config.get("useKeyStore", False)
        self.key_store_file = config.get("keyStoreFile", "")
        self.enable_hw_user_mode_keys = config.get("enableHwUserModeKeys", None)
        self.master_boot_output_file = config["masterBootOutputFile"]
        self.certificate_block_config = CertificateBlockConfigGroup3(config)
        self._validate_post_init()

    def _validate_post_init(self) -> None:
        self._validate_item(
            "outputImageExecutionTarget", self.output_image_exec_target, self.VALID_EXEC_TARGETS
        )
        self._validate_item(
            "outputImageAuthenticationType", self.output_image_auth_type, self.VALID_AUTH_TYPES
        )

    @staticmethod
    def _validate(config: dict) -> None:
        """Validates the json configuration file for group 3 devices.

        :param config: configuration dictionary for group 3 devices.
        :raises SPSDKError: if invalid MCU family identifier provided
        :raises SPSDKError: if execution target is RAM, but should be XIP
        :raises SPSDKError: if `deviceKeySource` option is set for devices other then RT5xx/RT6xx
        :raises SPSDKError: if `useKeyStore` is set for devices other then RT5xx/RT6xx
        :raises SPSDKError: if `enableHwUserModeKeys` set to true on lpc55xx, lpc552x, lpc55s2x, lpc55s6x
        """
        family = config.get("family", "NA").lower()
        families = [
            "lpc55xx",
            "lpc55s0x",
            "lpc55s1x",
            "lpc552x",
            "lpc55s2x",
            "lpc55s6x",
            "rt5xx",
            "rt6xx",
        ]
        if family not in families:
            raise SPSDKError(
                f'Invalid family. Expected one of "{", ".join(families)}", got {family}'
            )

        output_image_exec_target = config["outputImageExecutionTarget"].lower()
        if family in ["lpc55xx", "lpc55s0x", "lpc55s1x", "lpc552x", "lpc55s2x", "lpc55s6x"]:
            if "ram" == output_image_exec_target:
                raise SPSDKError(
                    desc=(
                        f'Unsupported value "{output_image_exec_target}" of '
                        f'"outputImageExecutionTarget" for selected family "{family}".'
                        f'Expected values for "{family}" ["XIP"].'
                    )
                )

            # It would be convenient to handle this in the Master Boot Image generation,
            # however, this would lead to validating the json parameters at different places,
            # which is a bit unconvenient. I would like to have the validation at one place.
            if config.get("deviceKeySource", None):
                raise SPSDKError(
                    '"deviceKeySource" option is allowed only for RT5xx & RT6xx devices.'
                )
            if config.get("useKeyStore", None):
                raise SPSDKError('"useKeyStore" option is allowed only for RT5xx & RT6xx devices.')

        enable_hw_user_mode_keys = config["enableHwUserModeKeys"]
        if family in ["lpc55xx", "lpc552x", "lpc55s2x", "lpc55s6x"]:
            if True == enable_hw_user_mode_keys:
                raise SPSDKError(
                    desc=(
                        f'Unsupported value "{enable_hw_user_mode_keys}" of '
                        f'"enableHwUserModeKeys" for selected family "{family}".'
                        f'Expected values for "{family}" ["False"].'
                    )
                )

        # If the image is signed, we need to provide up to 4 Root of Turst
        # certificates (certificate chains), where one out of these will be
        # used for signing the image. The used certificate chain is selected
        # with the "mainCertChainId" parameter. The rest of RoT certificates
        # are used to compute a hash, which is stored in the device for
        # future use.
        # From this perspective we don't need to define all certificate chains
        # just the one used for signing and it's corresponding private key.
        # This is defined by the "mainCertPrivateKeyFile" parameter.
        # If multiple certificate chains are used, only the signing certificate
        # chain is read, the rest is not taken into consideration (except the
        # root certificate for hash computation).
        # It seems that multiple certificate chains are useless, but this
        # provides convenience when switching to different signing chain, as
        # it's sufficient to change the private key and set different number.
        # The number of certificates in a chain is unlimited, but as the whole
        # certificate chain is stored into memory, the memory limits the
        # number of certificates.
        # TODO validate configurations expecting signed image, that they provide
        # certificates etc.???

    @property
    def image_type(self) -> MasterBootImageType:
        """Image type.

        The image type is encoded by the way how images are authenticated together
        with from where the image is executed. Not all configurations of
        authentication and storage are however valid.

        :raises SPSDKError: invalid authentication & execution target.

        :return: image type.
        """
        image_types = {
            "plain-ram": MasterBootImageType.PLAIN_IMAGE,
            "plain-xip": MasterBootImageType.PLAIN_IMAGE,
            "crc-ram": MasterBootImageType.CRC_RAM_IMAGE,
            "crc-xip": MasterBootImageType.CRC_XIP_IMAGE,
            "signed-ram": MasterBootImageType.SIGNED_RAM_IMAGE,
            "signed-xip": MasterBootImageType.SIGNED_XIP_IMAGE,
            "encrypted-ram": MasterBootImageType.ENCRYPTED_RAM_IMAGE,
        }
        image_type = f"{self.output_image_auth_type}-{self.output_image_exec_target}"

        try:
            retval = image_types[image_type.lower()]
        except KeyError as e:
            raise SPSDKError(
                (
                    f"Unsupported combination of inputs: \n"
                    f"outputImageAuthenticationType: {self.output_image_auth_type}, "
                    f"outputImageExecutionTarget: {self.output_image_exec_target}"
                )
            ) from e

        return retval


class MasterBootImageConfigGroup4(MasterBootImageConfig):
    """Configuration object for MasterBootImage."""

    VALID_EXEC_TARGETS = ["ram", "xip"]
    VALID_AUTH_TYPES = ["crc", "signed", "encrypted"]

    def __init__(self, config: dict) -> None:
        """Initializes the object.

        :param config: master boot image configuration data. Consult the content with elftosb user guide.
        """
        self._validate(config)
        self.family = config["family"]
        self.revision = config.get("revision")
        self.input_image_file = config["inputImageFile"]
        self.output_image_exec_address = int(config["outputImageExecutionAddress"], 0)
        self.output_image_exec_target = config["outputImageExecutionTarget"].lower()
        if "xip" in self.output_image_exec_target:
            self.output_image_exec_target = "xip"
        self.output_image_auth_type = config["outputImageAuthenticationType"].lower()
        authentication_type = self.output_image_auth_type
        if "signed" in self.output_image_auth_type:
            authentication_type = "signed"
        if "encrypted" in self.output_image_auth_type:
            authentication_type = "encrypted"
        self.output_image_auth_type = authentication_type
        self.output_image_subtype = config.get("outputImageSubtype", "default")
        self.trustzone_preset_file = config.get("trustZonePresetFile", "")
        self.firmware_version = int(config.get("firmwareVersion", "0"), 0)
        self.master_boot_output_file = config["masterBootOutputFile"]
        self.certificate_block_config = CertificateBlockConfigGroup4(config)
        self._validate_post_init()

    def _validate_post_init(self) -> None:
        self._validate_item(
            "outputImageExecutionTarget", self.output_image_exec_target, self.VALID_EXEC_TARGETS
        )
        self._validate_item(
            "outputImageAuthenticationType", self.output_image_auth_type, self.VALID_AUTH_TYPES
        )

    @staticmethod
    def _validate(config: dict) -> None:
        """Verifies the Master Boot Image parameters validity."""
        pass

    @property
    def image_type(self) -> MasterBootImageType:
        """Image type.

        The image type is encoded by the way how images are authenticated together
        with from where the image is executed. Not all configurations of
        authentication and storage are however valid.

        :raises SPSDKError:

        :return: image type.
        """
        image_types = {
            "plain-ram": MasterBootImageType.PLAIN_IMAGE,
            "plain-xip": MasterBootImageType.PLAIN_IMAGE,
            "crc-ram": MasterBootImageType.CRC_RAM_IMAGE,
            "crc-xip": MasterBootImageType.CRC_XIP_IMAGE,
            "signed-ram": MasterBootImageType.SIGNED_RAM_IMAGE,
            "signed-xip": MasterBootImageType.SIGNED_XIP_IMAGE,
            "encrypted-ram": MasterBootImageType.ENCRYPTED_RAM_IMAGE,
        }
        image_type = f"{self.output_image_auth_type}-{self.output_image_exec_target}"

        try:
            retval = image_types[image_type]
        except KeyError as e:
            raise SPSDKError(
                (
                    f"Unsupported combination of inputs: \n"
                    f"outputImageAuthenticationType: {self.output_image_auth_type}, "
                    f"outputImageExecutionTarget: {self.output_image_exec_target}"
                )
            ) from e
        return retval


class SB31Config:
    """Configuration object for SecureBinary image."""

    def __init__(self, config_data: dict) -> None:
        """Initialize SB31Config from json config data."""
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

        self.certificate_block_config = CertificateBlockConfigGroup4(config_data)

        self.main_signing_key = self.certificate_block_config.main_root_private_key_file
        self.main_curve_name = self.certificate_block_config.root_certificate_curve
        # if use_isk is set, we use for signing the ISK certificate instead of root
        if self.certificate_block_config.use_isk:
            self.main_signing_key = self.certificate_block_config.isk_private_key_file
            self.main_curve_name = self.certificate_block_config.isk_certificate_curve


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
