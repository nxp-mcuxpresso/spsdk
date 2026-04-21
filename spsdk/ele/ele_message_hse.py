#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK ELE HSE message implementation for Hardware Security Engine operations.

This module provides specialized ELE message classes for HSE (Hardware Security Engine)
operations including attribute management, firmware updates, boot data signing and
verification, and key information handling.
"""

import math
from abc import abstractmethod
from dataclasses import dataclass
from struct import calcsize, pack
from typing import Optional, Type, Union, cast

from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.keys import (
    PrivateKey,
    PrivateKeyEcc,
    PrivateKeyRsa,
    PublicKey,
    PublicKeyEcc,
    PublicKeyRsa,
)
from spsdk.ele.ele_constants import HseMessageIDs, HseResponseStatus, MessageIDs, ResponseStatus
from spsdk.ele.ele_message import EleMessage
from spsdk.ele.hse_attrs import HseAttributeHandler, HseAttributeId
from spsdk.exceptions import SPSDKValueError
from spsdk.image.hse.common import HseAeadScheme, HseCipherSchemeBase, KeyContainer, KeyHandle
from spsdk.image.hse.key_info import KeyFormat, KeyInfo, KeyType
from spsdk.utils.database import DatabaseManager
from spsdk.utils.misc import LITTLE_ENDIAN, UINT8, UINT16, UINT32, Endianness
from spsdk.utils.spsdk_enum import SpsdkEnum

RESERVED = 0


class MuChannel(SpsdkEnum):
    """HSE service message unit channel."""

    CHANNEL_0 = (0, "channel0", "MU channel 0")
    CHANNEL_1 = (1, "channel1", "MU channel 1")
    CHANNEL_2 = (2, "channel2", "MU channel 2")
    CHANNEL_3 = (3, "channel3", "MU channel 3")


class EleMessageHse(EleMessage):
    """Base class for HSE-specific ELE messages.

    This class extends the EleMessage base class with HSE-specific functionality
    for command formatting, response handling, and service identification. It provides
    the foundation for implementing HSE (Hardware Security Engine) communication
    protocols within the SPSDK framework.

    :cvar CMD_ID_FORMAT: Format string for HSE command ID structure.
    :cvar CMD_DESCRIPTOR_FORMAT: Format string for HSE descriptor structure.
    :cvar RESPONSE_HEADER_WORDS_COUNT: Number of words in HSE response header.
    :cvar MSG_IDS: HSE-specific message ID enumeration.
    """

    CMD_HEADER_FORMAT: str = LITTLE_ENDIAN + UINT32 + UINT8 + UINT8 + UINT8 + UINT8
    CMD_DESCRIPTOR_FORMAT: str
    MSG_IDS = cast(Type[MessageIDs], HseMessageIDs)

    class ServiceVersion(SpsdkEnum):
        """HSE service version enumeration.

        Defines the available HSE service versions that can be used when
        constructing HSE messages for EdgeLock Enclave operations.
        """

        VERSION_0 = (0, "ver0", "Hse service version 0")
        VERSION_1 = (1, "ver1", "Hse service version 1")

    def __init__(
        self,
        srv_version: ServiceVersion = ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_0,
    ) -> None:
        """Initialize the HSE message with the specified service version.

        :param srv_version: Service version to use for this message, defaults to VERSION_0.
        """
        super().__init__()
        self.srv_version = srv_version
        self.mu_channel = mu_channel

    def decode_response(self, response: bytes) -> None:
        """Decode the HSE response data.

        Extracts the response status from the HSE response data and sets the
        appropriate status and indication values based on the HSE response.

        :param response: Response data bytes to decode containing HSE status information.
        """
        response_word = 4 * self.mu_channel.tag
        response_cmd = response[response_word : response_word + 4]
        hse_response = HseResponseStatus.from_tag(
            int.from_bytes(response_cmd, byteorder=Endianness.LITTLE.value)
        )
        if hse_response == HseResponseStatus.OK:
            self.status = ResponseStatus.ELE_SUCCESS_IND.tag
        else:
            self.status = ResponseStatus.ELE_FAILURE_IND.tag
        self.indication = hse_response.tag

    def response_status(self) -> str:
        """Get response status information as formatted string.

        The method formats the response status and optionally includes HSE response
        indication details when the status indicates ELE failure.

        :return: Formatted string containing response status and indication details.
        """
        ret = f"Response status: {ResponseStatus.get_label(self.status)}\n"
        if self.status == ResponseStatus.ELE_FAILURE_IND:
            ret += (
                f"   Response indication: {HseResponseStatus.get_label(self.indication)}"
                f" - ({hex(self.indication)})\n"
            )
        return ret

    def export(self) -> bytes:
        """Export command data as bytes for target memory loading.

        Converts the command data address to a 4-byte little-endian byte sequence
        that can be loaded into the target memory space.

        :return: Command data address as 4-byte little-endian bytes.
        """
        ret = bytes()
        cmd_addr = self.command_data_address
        for _ in range(self.mu_channel.tag):
            ret += cmd_addr.to_bytes(4, byteorder=Endianness.LITTLE.value)
            dummy_cmd_len = len(self._get_dummy_command())
            cmd_addr += dummy_cmd_len
        ret += cmd_addr.to_bytes(4, byteorder=Endianness.LITTLE.value)
        return ret

    def _get_dummy_command(self) -> "EleMessageHse":
        """Get dummy command bytes for initialization.

        :return: Dummy command as bytes.
        """
        return EleMessageHseGetAttr(HseAttributeId.FW_VERSION)

    @property
    def response_header_words_count(self) -> int:
        """Get the number of words if the response header.

        :return: The number of 32-bit words in the response header.
        """
        # when sending the command to non-zero channel, dummy commands are sent before the actual command
        return 1 + self.mu_channel.tag

    @property
    def command_words_count(self) -> int:
        """Get the count of command words.

        :return: Number of command words, always returns 1.
        """
        # when sending the command to non-zero channel, dummy commands are sent before the actual command
        return 1 + self.mu_channel.tag

    @abstractmethod
    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor.

        Retrieves the service descriptor as a byte sequence for HSE message processing.

        :return: Service descriptor in bytes format.
        """

    @property
    def command_data_size(self) -> int:
        """Get the size of command data in bytes.

        Calculates the total size by combining the command ID format size and command descriptor format
        size using struct.calcsize().

        :return: Size of command data in bytes.
        """
        dummy_len = len(self._get_dummy_command())
        return dummy_len * self.mu_channel.tag + len(self)

    @property
    def command_data(self) -> bytes:
        """Get the complete command data.

        Combines the command header and service descriptor into the complete command data.
        The header is packed using CMD_ID_FORMAT with service_id and zero padding, then
        concatenated with the service descriptor bytes.

        :return: Complete command data as bytes.
        """
        ret = bytes()
        for _ in range(self.mu_channel.tag):
            ret += self._get_dummy_command().export_command()
        ret += self.export_command()
        return ret

    def export_command(self) -> bytes:
        """Export the HSE command message as bytes.

        This method serializes the HSE (Hardware Security Engine) command message
        into a byte representation suitable for transmission to the ELE.

        :return:  The serialized command message as bytes.
        """
        header = pack(
            self.CMD_HEADER_FORMAT, self.service_id, RESERVED, RESERVED, RESERVED, RESERVED
        )
        descriptor = self.get_srv_descriptor()
        return header + descriptor

    @property
    def service_id(self) -> int:
        """Get the service ID for this message.

        Combines the command ID and service version into a single service ID value.

        :return: Service ID as an integer.
        """
        return self.CMD | (self.srv_version.tag << 24)

    @property
    def service_index(self) -> int:
        """Get the service index from service_id.

        Extracts the first byte (byte 0) from the service_id when converted to
        little-endian byte representation.

        :return: Service index value in range 0-255.
        """
        return self.service_id.to_bytes(4, Endianness.LITTLE.value)[0]

    @property
    def service_class_index(self) -> int:
        """Get the service class index from service_id.

        Extracts the service class index from byte 1 of the service_id when converted
        to little-endian 4-byte representation.

        :return: Service class index value in range 0-255.
        """
        return self.service_id.to_bytes(4, Endianness.LITTLE.value)[1]

    @property
    def service_cancelable(self) -> bool:
        """Check if the service can be canceled based on service_id byte 2.

        The method examines the third byte (index 2) of the service_id when converted to
        little-endian format to determine if the service supports cancellation.

        :return: True if service can be canceled (byte 2 == 0x00), False if not
                 cancelable (byte 2 == 0xA5).
        """
        return self.service_id.to_bytes(4, Endianness.LITTLE.value)[2] != 0xA5

    @property
    def service_version(self) -> int:
        """Get the service version from service_id.

        The method extracts the service version from byte 3 of the service_id when
        converted to little-endian byte representation.

        :return: Service version value in range 0-255.
        """
        return self.service_id.to_bytes(4, Endianness.LITTLE.value)[3]

    @property
    def descriptor_size(self) -> int:
        """The size of service descriptor."""
        return calcsize(self.CMD_DESCRIPTOR_FORMAT)

    def __len__(self) -> int:
        """Get the length of exported data.

        :return: Number of bytes in the exported data.
        """
        return calcsize(self.CMD_HEADER_FORMAT) + self.descriptor_size


class EleMessageHseAttr(EleMessageHse):
    """Base class for HSE attribute operations.

    Provides common functionality for getting and setting HSE attributes,
    including attribute handler management and response processing.

    :cvar CMD_DESCRIPTOR_FORMAT: Binary format specification for command descriptor.
    """

    CMD_DESCRIPTOR_FORMAT = LITTLE_ENDIAN + UINT16 + UINT8 + UINT8 + UINT32 + UINT32

    def __init__(
        self,
        attr_id: HseAttributeId,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_0,
    ):
        """Initialize the HSE attribute message.

        :param attr_id: The attribute ID to operate on.
        :param srv_version: Service version to use for this message.
        """
        super().__init__(srv_version, mu_channel)
        self.attr_handler_cls = HseAttributeHandler.get_attr_handler_cls(attr_id)

    @abstractmethod
    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor.

        Retrieves the service descriptor as a byte sequence for HSE message processing.

        :return: Service descriptor in bytes format.
        """


class EleMessageHseGetAttr(EleMessageHseAttr):
    """ELE message for retrieving HSE (Hardware Security Engine) attributes.

    This class implements the GET_ATTR command to request and decode specific HSE
    attribute values from the EdgeLock Enclave. It handles the service descriptor
    creation, response data decoding, and provides formatted output of the retrieved
    attribute information.

    :cvar CMD: HSE message command identifier for GET_ATTR operation.
    """

    CMD = HseMessageIDs.GET_ATTR.tag

    def __init__(
        self,
        attr_id: HseAttributeId,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_0,
    ) -> None:
        """Initialize HSE attribute get message.

        Creates a new HSE attribute get message with the specified attribute ID and service version.
        The attribute value is initially set to None and will be populated when the response is received.

        :param attr_id: HSE attribute identifier to retrieve.
        :param srv_version: Service version for the HSE message, defaults to VERSION_0.
        """
        super().__init__(attr_id, srv_version, mu_channel)
        self.attr_value: Optional[HseAttributeHandler] = None
        self.response_data_size = self.attr_handler_cls.get_size()

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor.

        Creates and returns a packed binary service descriptor containing the attribute handler
        information, including attribute ID, size, and response data address.

        :return: Packed binary service descriptor as bytes.
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.attr_handler_cls.ATTR_ID.tag,
            RESERVED,
            RESERVED,
            self.attr_handler_cls.get_size(),
            self.response_data_address,
        )

    def decode_response_data(self, response: bytes) -> None:
        """Decode the response data for this attribute.

        Sets the response data in the attribute handler and triggers decoding.

        :param response: Response data to decode.
        """
        self.attr_value = self.attr_handler_cls.parse(response)

    def info(self) -> str:
        """Get formatted information about the response.

        :return: String representation of the attribute data or message if no attribute retrieved.
        """
        if not self.attr_value:
            return "No attribute has been retrieved"
        return str(self.attr_value)


class EleMessageHseSetAttr(EleMessageHseAttr):
    """ELE message for setting HSE (Hardware Security Engine) attributes.

    This class handles the SET_ATTR command to modify HSE attribute values on the target
    device. It extends the base HSE attribute message functionality with specific
    support for setting attribute data through memory addresses.

    :cvar CMD: Command identifier for the SET_ATTR operation.
    """

    CMD = HseMessageIDs.SET_ATTR.tag

    def __init__(
        self,
        attr_id: HseAttributeId,
        value_addr: Optional[int] = None,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_0,
    ) -> None:
        """Initialize HSE attribute message for getting attribute value.

        Creates a new HSE message instance for retrieving the value of a specified
        HSE attribute. The message can optionally specify a memory address where
        the attribute value should be stored.

        :param attr_id: HSE attribute identifier to get value for.
        :param value_addr: Optional memory address where attribute value will be stored.
        :param srv_version: Service version for the HSE message.
        """
        super().__init__(attr_id, srv_version, mu_channel)
        self.response_data_size = 0
        self.value_addr = value_addr

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor.

        Creates and returns a packed binary service descriptor containing the attribute ID,
        reserved fields, size, and value address according to the command descriptor format.

        :return: Packed binary service descriptor as bytes.
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.attr_handler_cls.ATTR_ID.tag,
            RESERVED,
            RESERVED,
            self.attr_handler_cls.get_size(),
            self.value_addr,
        )

    def decode_response_data(self, response: bytes) -> None:
        """Decode the response data for this attribute.

        Sets the response data in the attribute handler and triggers decoding.

        :param response: Response data to decode.
        """


class EleMessageHseBootDataImageSign(EleMessageHse):
    """ELE message for HSE boot data image signing operations.

    Handles cryptographic signing of boot data images for different HSE variants.
    For HSE_H/M devices, supports IVT/DCD/ST/LPDDR4(S32Z/E devices)/AppBSB images.
    For HSE_B devices, supports IVT/AppBSB images. The class manages the signing
    process and extracts authentication tags from the HSE response.
    """

    CMD = HseMessageIDs.BOOT_DATA_IMAGE_SIGN.tag
    CMD_DESCRIPTOR_FORMAT = LITTLE_ENDIAN + UINT32 + UINT32 + UINT32

    def __init__(
        self,
        img_addr: int,
        tag_len: int = 28,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_0,
    ):
        """Initialize the boot data image sign message.

        :param img_addr: Address of the image to sign.
        :param tag_len: Length of the tag (must be 16 or 28).
        :param srv_version: Service version to use for this message.
        :raises SPSDKValueError: If tag_len is not 16 or 28.
        """
        super().__init__(srv_version, mu_channel)
        self.img_addr = img_addr
        if tag_len not in [16, 28]:
            raise SPSDKValueError(f"Invalid tag length: {tag_len}. Must be 16 or 28.")
        self.tag_len = tag_len
        self.response_data_size = tag_len
        self.initial_vector: Optional[bytes] = None
        self.gmac_value: bytes = bytes()

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor for HSE message.

        Packs the image address, tag length, and response data address into a binary
        service descriptor format using the predefined CMD_DESCRIPTOR_FORMAT.

        :return: Binary service descriptor containing packed message parameters.
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.img_addr,
            self.tag_len,
            self.response_data_address,
        )

    def decode_response_data(self, response: bytes) -> None:
        """Decode the response data for the boot data image sign operation.

        Extracts the initial vector (if present) and GMAC value from the response based on tag length.
        For tag_len=16, only GMAC value is extracted. For tag_len=28, both initial vector (12 bytes)
        and GMAC value (16 bytes) are extracted.

        :param response: Response data bytes to decode containing IV and/or GMAC
        :raises SPSDKValueError: If tag_len is not supported (must be 16 or 28)
        """
        if self.tag_len == 16:
            self.initial_vector = None
            self.gmac_value = response
        elif self.tag_len == 28:
            self.initial_vector = response[:12]
            self.gmac_value = response[12:28]
        else:
            raise SPSDKValueError(f"Unsupported tag length: {self.tag_len}")

    def response_info(self) -> str:
        """Get formatted information about the response.

        Returns a string containing the image signature data including the initial vector
        (if present) and GMAC value in hexadecimal format.

        :return: String representation of the image signature data.
        """
        ret = "Image Signature:\n"
        if self.initial_vector:
            ret += f"Initial Vector: {self.initial_vector.hex()}\n"
        ret += f"GMAC: {self.gmac_value.hex()}\n"
        return ret

    @property
    def signature(self) -> bytes:
        """Get the complete signature bytes.

        Combines the initial vector (if present) and GMAC value to form the complete signature.

        :return: Complete signature bytes containing optional initial vector followed by GMAC value.
        """
        ret = bytes()
        if self.initial_vector:
            ret += self.initial_vector
        ret += self.gmac_value
        return ret


class EleMessageHseFirmwareUpdate(EleMessageHse):
    """HSE Firmware Update command.

    This service is used to update the HSE firmware into the HSE internal flash memory.
    Supports both one-pass and streaming modes (START, UPDATE, FINISH).

    :cvar CMD: Command identifier for HSE firmware update operations.
    :cvar CMD_DESCRIPTOR_FORMAT: Binary format specification for command descriptor.
    """

    CMD = HseMessageIDs.FIRMWARE_UPDATE.tag
    CMD_DESCRIPTOR_FORMAT = LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8 + UINT32 + UINT32

    class HseAccessMode(SpsdkEnum):
        """HSE firmware update access mode enumeration.

        Defines the available access modes for HSE (Hardware Security Engine) firmware
        update operations, supporting both single-pass and streaming update workflows.
        """

        ONE_PASS = (0, "ONE_PASS", "One-pass mode - complete firmware update in one operation")
        START = (1, "START", "Start mode - begin streaming firmware update")
        UPDATE = (2, "UPDATE", "Update mode - continue streaming firmware update")
        FINISH = (3, "FINISH", "Finish mode - complete streaming firmware update")

    def __init__(
        self,
        access_mode: HseAccessMode,
        fw_file_addr: int,
        stream_length: int = 0,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_0,
    ):
        """Initialize the HSE firmware update message.

        Creates a new HSE firmware update message with specified access mode and firmware parameters.
        Validates stream length requirements for streaming modes (START/UPDATE).

        :param access_mode: The access mode for firmware update (ONE_PASS, START, UPDATE, FINISH)
        :param fw_file_addr: Address of the firmware file or chunk
        :param stream_length: Length of the firmware chunk in streaming mode (must be multiple of 64 bytes)
        :param srv_version: Service version to use for this message
        :raises SPSDKValueError: If stream_length is invalid for the specified access mode
        """
        super().__init__(srv_version, mu_channel)
        self.access_mode = access_mode
        self.fw_file_addr = fw_file_addr
        self.stream_length = stream_length

        # Validate stream_length based on access mode
        if access_mode in [self.HseAccessMode.START, self.HseAccessMode.UPDATE]:
            if stream_length < 64 or stream_length % 64 != 0:
                raise SPSDKValueError(
                    f"Stream length must be at least 64 bytes and multiple of 64 bytes for {access_mode.label} mode"
                )

        # No response data expected for this command
        self.response_data_size = 0

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor for the firmware update command.

        Creates a packed binary service descriptor containing access mode, stream length,
        and firmware file address for HSE firmware update operations.

        :return: Packed service descriptor bytes containing command parameters.
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.access_mode.tag,  # accessMode
            RESERVED,
            RESERVED,
            RESERVED,  # reserved[3]
            self.stream_length,  # streamLength
            self.fw_file_addr,  # pInFwFile
        )

    def response_info(self) -> str:
        """Get formatted information about the response.

        Returns a human-readable string describing the status of the firmware update operation,
        indicating whether it was successful or failed.

        :return: String representation of the firmware update status.
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return f"Firmware update {self.access_mode.label.lower()} operation successful"
        return "Firmware update failed"


class EleMessageHseBootDataImageVerify(EleMessageHse):
    """HSE Boot Data Image Verification Message.

    Handles verification of boot data images including IVT, DCD, ST, LPDDR4 (S32Z/E devices),
    and AppBSB components. For HSE_H/M devices, verifies all image types. For HSE_B devices,
    verifies IVT and AppBSB images only.
    This message verifies GMAC tags generated by the EleMessageHseBootDataImageSign service,
    ensuring boot data integrity and authenticity during secure boot process.
    """

    CMD = HseMessageIDs.BOOT_DATA_IMAGE_VERIFY.tag
    CMD_DESCRIPTOR_FORMAT = LITTLE_ENDIAN + UINT32

    def __init__(
        self,
        img_addr: int,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_0,
    ):
        """Initialize the boot data image verify message.

        :param img_addr: Address of the image to verify (includes the authentication TAG).
        :param srv_version: Service version to use for this message.
        """
        super().__init__(srv_version, mu_channel)
        self.img_addr = img_addr
        # No response data expected for this command beyond status
        self.response_data_size = 0

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor.

        Packs the image address into a service descriptor format for HSE communication.

        :return: Packed service descriptor bytes containing the image address.
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.img_addr,  # pInImage
        )

    def response_info(self) -> str:
        """Get formatted information about the response.

        Returns a human-readable string indicating whether the Boot Data Image verification
        was successful or failed based on the response status.

        :return: String representation of the image verification result.
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return "Boot Data Image verification successful"
        return "Boot Data Image verification failed"


class EleMessageHseGetKeyInfo(EleMessageHse):
    """HSE Get Key Info command message.

    This class represents an ELE HSE service message for retrieving key information
    and properties using a key handle as input parameter. It handles the command
    formatting, response parsing, and provides access to the retrieved key data.
    """

    CMD = HseMessageIDs.GET_KEY_INFO.tag
    CMD_DESCRIPTOR_FORMAT = LITTLE_ENDIAN + UINT32 + UINT32

    def __init__(
        self,
        key_handle: KeyHandle,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_1,
    ):
        """Initialize the HSE Get Key Info message.

        :param key_handle: The key handle to get information for.
        :param srv_version: Service version to use for this message.
        """
        super().__init__(srv_version, mu_channel)
        self.key_handle = key_handle
        self.key_info: Optional[KeyInfo] = None
        self.response_data_size = KeyInfo.get_size()

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor for the Get Key Info command.

        :return: Packed service descriptor bytes.
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.key_handle.handle,
            self.response_data_address,
        )

    def decode_response_data(self, response: bytes) -> None:
        """Decode the response data for the Get Key Info operation.

        Extracts the key information from the response and stores it in the key_info attribute.

        :param response: Response data bytes to decode containing key information.
        :raises SPSDKError: If response data cannot be parsed or is invalid.
        """
        self.key_info = KeyInfo.parse(response)

    def response_info(self) -> str:
        """Get formatted information about the response.

        Returns string representation of key information if the response status indicates success,
        otherwise returns an error message indicating failure to retrieve key information.

        :return: String representation of the key information or error message.
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return str(self.key_info)
        return "Failed to retrieve key information"


class HseAccessMode(SpsdkEnum):
    """HSE access mode enumeration for streaming operations.

    Defines the available access modes that control how HSE (Hardware Security Engine)
    operations are executed, supporting both single-pass and multi-step streaming workflows.
    """

    ONE_PASS = (0, "ONE_PASS", "One-pass mode - complete operation in one step")
    START = (1, "START", "Start mode - begin streaming operation")
    UPDATE = (2, "UPDATE", "Update mode - continue streaming operation")
    FINISH = (3, "FINISH", "Finish mode - complete streaming operation")


@dataclass
class HseSmrCipherParams:
    """HSE SMR cipher parameters container.

    This class encapsulates the cryptographic parameters required for installing and
    decrypting encrypted Secure Memory Regions (SMRs) in HSE operations, including
    initialization vectors, GMAC authentication tags, and additional authenticated data.
    """

    iv_addr: int = 0
    """Address of Initialization Vector/Nonce. The length of the IV is 16 bytes."""

    gmac_tag_addr: int = 0
    """Optional - Address of tag used for AEAD. The length for the GMAC tag is 16 bytes."""

    aad_addr: int = 0
    """Optional - Address of the AAD used for AEAD."""


class EleMessageHseSmrEntryInstall(EleMessageHse):
    """HSE Secure Memory Region Installation service.

    This service installs or updates a Secure Memory Region (SMR) entry which needs
    to be verified during boot or runtime phase. The installation can be done in
    one-pass or streaming mode.

    :cvar CMD: Command identifier for SMR entry installation service.
    :cvar CMD_DESCRIPTOR_FORMAT: Binary format descriptor for the command structure.
    """

    CMD = HseMessageIDs.SMR_ENTRY_INSTALL.tag
    CMD_DESCRIPTOR_FORMAT = (
        LITTLE_ENDIAN
        + UINT8
        + UINT8
        + UINT8
        + UINT8
        + UINT32
        + UINT32
        + UINT32
        + UINT32
        + UINT32
        + UINT16
        + UINT16
        + UINT32
        + UINT32
        + UINT32
    )

    def __init__(
        self,
        access_mode: HseAccessMode,
        entry_index: int,
        smr_entry_addr: Optional[int] = None,
        smr_data_addr: Optional[int] = None,
        smr_data_length: Optional[int] = None,
        auth_tag_addrs: tuple[int, int] = (0, 0),
        auth_tag_lengths: tuple[int, int] = (0, 0),
        cipher_params: Optional[HseSmrCipherParams] = None,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_1,
    ):
        """Initialize the SMR Entry Install message.

        Creates a new SMR (Secure Memory Region) Entry Install message for HSE communication.
        This message is used to install or update SMR entries in the HSE SMR table with
        specified access modes and optional encryption parameters.

        :param access_mode: The access mode for SMR installation (ONE_PASS, START, UPDATE, FINISH).
        :param entry_index: Index of SMR entry in the SMR table to be installed/updated.
        :param smr_entry_addr: Address of SMR entry structure containing configuration properties.
        :param smr_data_addr: Address where SMR data to be installed is located.
        :param smr_data_length: Length of the SMR data in bytes.
        :param auth_tag_addr: Tuple of addresses where SMR authentication tags are located.
        :param auth_tag_length: Tuple of lengths for the authentication tags.
        :param cipher_params: Cipher parameters for encrypted SMR installation, defaults to None.
        :param srv_version: Service version to use for this message.
        """
        super().__init__(srv_version, mu_channel)
        self.access_mode = access_mode
        self.entry_index = entry_index
        self.smr_entry_addr = smr_entry_addr
        self.smr_data_addr = smr_data_addr
        self.smr_data_length = smr_data_length or 0
        self.auth_tag_addrs = auth_tag_addrs
        self.auth_tag_lengths = auth_tag_lengths
        self.cipher_params = cipher_params or HseSmrCipherParams()

        # No response data expected for this command beyond status
        self.response_data_size = 0

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor for the SMR Entry Install command.

        Packs all the service descriptor fields into a binary format according to the
        CMD_DESCRIPTOR_FORMAT specification for HSE SMR entry installation.

        :return: Packed service descriptor bytes containing access mode, entry index,
                 SMR entry/data addresses, authentication tags, and cipher parameters.
        """
        if self.smr_entry_addr is None:
            raise SPSDKValueError("SMR entry address must be provided")
        if self.smr_data_addr is None:
            raise SPSDKValueError("SMR data address must be provided")
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.access_mode.tag,  # accessMode
            self.entry_index,  # entryIndex
            RESERVED,
            RESERVED,  # reserved[2]
            self.smr_entry_addr,  # pSmrEntry
            self.smr_data_addr,  # pSmrData
            self.smr_data_length,  # smrDataLength
            self.auth_tag_addrs[0],  # pAuthTag[0]
            self.auth_tag_addrs[1],  # pAuthTag[1]
            self.auth_tag_lengths[0],  # authTagLength[0]
            self.auth_tag_lengths[1],  # authTagLength[1]
            self.cipher_params.iv_addr,  # cipher.pIV
            self.cipher_params.gmac_tag_addr,  # cipher.pGmacTag
            self.cipher_params.aad_addr,  # cipher.pAAD
        )

    def response_info(self) -> str:
        """Get formatted information about the response.

        Returns a human-readable string describing the SMR (Secure Memory Region) installation
        result based on the response status and entry details.

        :return: String representation of the SMR installation result including entry index,
                 access mode, and success/failure status.
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return f"SMR entry {self.entry_index} installation ({self.access_mode.label.lower()}) successful"
        return f"SMR entry {self.entry_index} installation failed"


class HseSmrVerificationOptions(SpsdkEnum):
    """HSE SMR verification options enumeration.

    Defines the available options for customizing on-demand SMR verification behavior.
    """

    NONE = (0, "NONE", "Default verification of the SMR at run-time")
    NO_LOAD = (3, "NO_LOAD", "SMR is verified from external flash without loading to SRAM")
    RELOAD = (
        3 << 2,
        "RELOAD",
        "SMR is loaded from external flash and verified even if already loaded",
    )
    PASSIVE_MEM = (
        3 << 4,
        "PASSIVE_MEM",
        "Verifies SMR from passive block with address translation (HSE_B only)",
    )


class EleMessageHseSmrVerify(EleMessageHse):
    """HSE Secure Memory Region Verification service.

    This service starts the on-demand verification of a secure memory region by specifying
    the index in the SMR table. The service loads and verifies an SMR entry in SRAM based
    on the specified verification options.

    Important notes for HSE_H/M:

    - SMRs used in CORE RESET table can be verified on-demand only if they were loaded
      before in SRAM or BOOT_SEQ = 0. Otherwise, NOT_ALLOWED error will be reported.
    - SMRs not part of CORE RESET table can be loaded and verified at run time.
    - On second call, HSE will only perform verification in SRAM.
    - SMRs cannot be loaded and verified from SD/MMC memory using this service.

    :cvar CMD: Command identifier for SMR verification service.
    :cvar CMD_DESCRIPTOR_FORMAT: Binary format descriptor for the command structure.
    """

    CMD = HseMessageIDs.SMR_VERIFY.tag
    CMD_DESCRIPTOR_FORMAT = LITTLE_ENDIAN + UINT8 + UINT8 + UINT16

    def __init__(
        self,
        entry_index: int,
        options: HseSmrVerificationOptions = HseSmrVerificationOptions.NONE,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_1,
    ):
        """Initialize the SMR Verify message.

        Creates a new SMR (Secure Memory Region) verification message for HSE communication.
        This message is used to trigger on-demand verification of SMR entries in the SMR table.

        :param entry_index: Index of SMR entry in the SMR table to be verified
                           (max HSE_NUM_OF_SMR_ENTRIES)
        :param options: Verification options for customizing the on-demand SMR verification
        :param srv_version: Service version to use for this message
        :raises SPSDKValueError: If entry_index is invalid
        """
        super().__init__(srv_version, mu_channel)

        # Validate entry index (assuming max 32 SMR entries based on typical HSE limits)
        if not isinstance(entry_index, int) or entry_index < 0 or entry_index > 7:
            raise SPSDKValueError(f"Invalid SMR entry index: {entry_index}. Must be 0-7.")

        self.entry_index = entry_index
        self.options = options

        # No response data expected for this command beyond status
        self.response_data_size = 0

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor for the SMR Verify command.

        Packs the service descriptor fields into a binary format according to the
        CMD_DESCRIPTOR_FORMAT specification for HSE SMR verification.

        :return: Packed service descriptor bytes containing entry index, reserved field,
                 and verification options.
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.entry_index,  # entryIndex
            RESERVED,  # reserved - RFU, set to 0
            self.options.tag,  # options (hseSmrVerificationOptions_t)
        )

    def response_info(self) -> str:
        """Get formatted information about the response.

        Returns a human-readable string describing the SMR verification result
        based on the response status and entry details.

        :return: String representation of the SMR verification result including
                 entry index, options, and success/failure status.
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return f"SMR entry {self.entry_index} verification successful (options: {self.options.label})"
        return f"SMR entry {self.entry_index} verification failed"


class EleMessageHseSmrEntryErase(EleMessageHse):
    """HSE SMR Entry Erase service.

    This service erases one SMR (Secure Memory Region) entry from the internal HSE memory.
    The service removes the specified entry from the SMR table, effectively disabling
    the secure memory region configuration for that entry index.

    Important notes:

    - SuperUser (SU) access rights with privileges over HSE_SYS_AUTH_NVM_CONFIG data
      are required to perform this service
    - Erasing an SMR entry will remove all associated secure memory configurations
    - The operation is irreversible - the entry must be reinstalled if needed again
    - Care should be taken when erasing SMR entries that are referenced by Core Reset entries

    :cvar CMD: Command identifier for SMR entry erase service.
    :cvar CMD_DESCRIPTOR_FORMAT: Binary format specification for command descriptor.
    """

    CMD = HseMessageIDs.SMR_ENTRY_ERASE.tag
    CMD_DESCRIPTOR_FORMAT = LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8

    def __init__(
        self,
        entry_index: int,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_1,
    ):
        """Initialize the SMR Entry Erase message.

        Creates a new SMR (Secure Memory Region) entry erase message for HSE communication.
        This message is used to erase SMR entries from the SMR table at the specified
        entry index.

        :param entry_index: Index in the SMR table for the entry to be erased.
                              Must be within HSE_NUM_OF_SMR_ENTRIES range.
        :param srv_version: Service version to use for this message.
        :param mu_channel: Message unit channel to use for communication.
        :raises SPSDKValueError: If entry_index is invalid.
        """
        super().__init__(srv_version, mu_channel)
        if entry_index < 0 or entry_index > 7:
            raise SPSDKValueError(f"Invalid SMR entry index: {entry_index}. Must be 0-7.")
        self.entry_index = entry_index

        # No response data expected for this command beyond status
        self.response_data_size = 0

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor for the SMR Entry Erase command.

        Packs the service descriptor fields into a binary format according to the
        CMD_DESCRIPTOR_FORMAT specification for HSE SMR entry erase operation.

        :return: Packed service descriptor bytes containing entry index and reserved fields.
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.entry_index,  # smrEntryInd
            RESERVED,  # reserved[0]
            RESERVED,  # reserved[1]
            RESERVED,  # reserved[2]
        )

    def response_info(self) -> str:
        """Get formatted information about the response.

        Returns a human-readable string describing the SMR entry erase result
        based on the response status and entry details.

        :return: String representation of the SMR entry erase result including
                 entry index and success/failure status.
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return f"SMR entry {self.entry_index} erase successful"
        return f"SMR entry {self.entry_index} erase failed"


class EleMessageHseImportKey(EleMessageHse):
    """HSE Import Key service message.

    This class represents an ELE message for importing keys into the HSE key store.
    Supports importing symmetric keys, asymmetric key pairs, and public keys in both
    raw format and authenticated container format.

    :cvar CMD: Command identifier for the HSE import key service.
    :cvar CMD_DESCRIPTOR_FORMAT: Binary format structure for the command descriptor.
    """

    CMD = HseMessageIDs.IMPORT_KEY.tag
    BASE_DESCRIPTOR_FORMAT = (
        LITTLE_ENDIAN
        + UINT32
        + UINT32
        + UINT32
        + UINT32
        + UINT32
        + UINT16
        + UINT16
        + UINT16
        + UINT8
        + UINT8
    )

    def __init__(
        self,
        key_handle: KeyHandle,
        payload: "KeyImportPayload",
        cipher_key_handle: Optional[KeyHandle] = None,
        cipher_scheme: Optional[HseCipherSchemeBase] = None,
        key_format: Optional[KeyFormat] = None,
        key_container: Optional[KeyContainer] = None,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_1,
    ):
        """Initialize the HSE Import Key message.

        Creates a new HSE (Hardware Security Engine) import key message with the specified
        parameters for importing cryptographic keys into secure key slots.

        :param key_handle: Handle of the key slot where the key will be imported
        :param payload: Key import payload containing key data and metadata
        :param cipher_key_handle: Handle of the key used for decryption if key is encrypted
        :param cipher_scheme: Cipher scheme used for encrypted keys
        :param key_format: Format of the key being imported (defaults to RAW)
        :param srv_version: Service version to use for this message
        """
        super().__init__(srv_version, mu_channel)
        self.key_handle = key_handle
        self.payload = payload
        self.cipher_key_handle = cipher_key_handle or KeyHandle(KeyHandle.INVALID_KEY_HANDLE)
        self.cipher_scheme = cipher_scheme or HseAeadScheme()
        self.key_format = key_format
        self.key_container = key_container or KeyContainer()
        # No response data expected for this command beyond status
        self.response_data_size = 0

    @property
    def descriptor_size(self) -> int:
        """The size of service descriptor."""
        # Base descriptor fields
        base_size = calcsize(self.BASE_DESCRIPTOR_FORMAT)

        # Variable-length components
        variable_size = (
            self.cipher_key_handle.get_size()
            + self.cipher_scheme.get_size()
            + self.key_container.get_size()
            + 4  # key_format field
        )
        return base_size + variable_size

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor for the Import Key command.

        Packs all the command parameters into a binary format according to the HSE
        command descriptor structure for key import operations.

        :return: Packed service descriptor bytes containing key handles, addresses,
            cipher and authentication schemes, and other import parameters.
        """
        ret = pack(
            self.BASE_DESCRIPTOR_FORMAT,
            self.key_handle.handle,
            self.payload.key_info_address,
            self.payload.get_key_part_address(0),
            self.payload.get_key_part_address(1),
            self.payload.get_key_part_address(2),
            self.payload.key_lengths[0] or 0,
            self.payload.key_lengths[1] or 0,
            self.payload.key_lengths[2] or 0,
            RESERVED,  # reserved[0]
            RESERVED,  # reserved[1]
        )
        ret += self.cipher_key_handle.export()
        ret += self.cipher_scheme.export()
        ret += self.key_container.export()
        ret += (
            (self.key_format.tag).to_bytes(4, Endianness.LITTLE.value)
            if self.key_format
            else bytes(4)
        )
        return ret

    def response_info(self) -> str:
        """Get formatted information about the response.

        This method provides a human-readable string describing the result of the key import operation,
        indicating success or failure along with the associated key handle.

        :return: String representation of the key import result.
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return f"Key import successful for key handle {str(self.key_handle)}"
        return f"Key import failed for key handle {self.key_handle}"


class KeyImportPayload:
    """HSE Key Import Payload structure.

    Manages cryptographic key data and metadata for importing keys into HSE (Hardware
    Security Engine). This class encapsulates key information, converts keys to the
    appropriate format, and handles payload structure for key import operations.

    :cvar FEATURE: Database feature identifier for HSE operations.
    :cvar SUB_FEATURE: Sub-feature identifier for key import operations.
    """

    FEATURE = DatabaseManager.HSE
    SUB_FEATURE = "key_import"

    def __init__(
        self, key_info: KeyInfo, key: Union[PrivateKey, PublicKey, bytes], address: int = 0
    ) -> None:
        """Initialize the key import structure.

        :param key_info: Key information structure containing key metadata and configuration.
        :param key: The cryptographic key to import, can be private key, public key, or raw bytes.
        :param address: Address of payload in the memory.
        """
        self.key_info = key_info
        self.key = key
        self.key_data = self.convert_key(key, self.key_info.key_type)
        self.address = address

    @property
    def key_info_address(self) -> int:
        """Get key info binary address in the target memory."""
        return self.address

    @property
    def key_lengths(self) -> list[Optional[int]]:
        """Get the lengths of each key component.

        :return: List of lengths for each key component, None for missing components.
        """
        key_lengths = [len(k) if k is not None else None for k in self.key_data]
        return key_lengths

    @property
    def key_offsets(self) -> list[Optional[int]]:
        """Calculate the offsets of each key component in the payload.

        The offsets are calculated relative to the start of the payload, with the key_info structure
        at the beginning followed by key components.

        :return: List of offsets for each key component, None for missing components.
        """
        offsets: list[Optional[int]] = []
        current_offset = self.key_info.size

        for length in self.key_lengths:
            if length is None:
                offsets.append(None)
            else:
                offsets.append(current_offset)
                current_offset += length

        return offsets

    def get_key_part_address(self, key_part_index: int) -> int:
        """Get absolute address of key part. Return 0 if not defined."""
        key_part = self.key_offsets[key_part_index]
        if key_part is not None:
            return self.address + key_part
        return 0

    @property
    def size(self) -> int:
        """Get the total size of the key import payload in bytes.

        Includes the size of the key_info structure and all key components.

        :return: Total size in bytes.
        """
        result = self.key_info.size
        for key_chunk in self.key_data:
            if key_chunk is not None:
                result += len(key_chunk)
        return result

    def export(self) -> bytes:
        """Export the key import structure to bytes.

        The method serializes the key information and concatenates all non-null key data chunks
        to create a complete binary representation of the key import structure.

        :return: Serialized key import structure as bytes.
        """
        result = self.key_info.export()
        for key_chunk in self.key_data:
            if key_chunk is not None:
                result += key_chunk
        return result

    @staticmethod
    def convert_key(
        key: Union["PrivateKey", "PublicKey", bytes], key_type: Optional[KeyType] = None
    ) -> list[Optional[bytes]]:
        """Convert an SPSDK key to HSE key format.

        HSE key format consists of up to three chunks:

        - pKey[0]: Public key data (modulus for RSA, X/Y coordinates for ECC, etc.)
        - pKey[1]: Additional public key data (exponent for RSA, etc.)
        - pKey[2]: Private key data (private exponent for RSA, private scalar for ECC,
          symmetric key data)

        :param key: SPSDK key object (from spsdk.crypto.keys) or raw key bytes
        :param key_type: HSE key type, required when key is provided as raw bytes
        :raises SPSDKValueError: Invalid key type, unsupported key format, or invalid key length
        :return: List of up to three byte arrays representing the key components
        """
        # Initialize the three key parts
        key_parts: list[Optional[bytes]] = [None, None, None]

        # Handle raw bytes (for symmetric keys like AES)
        if isinstance(key, bytes):
            if not key_type:
                raise SPSDKValueError("Key type must be specified when providing raw key bytes")
            if key_type not in (
                KeyType.AES,
                KeyType.HMAC,
                KeyType.SIPHASH,
                KeyType.SHARED_SECRET,
            ):
                raise SPSDKValueError(f"Unsupported key type for raw bytes: {key_type}")
                # Validate key length for AES keys
            if key_type == KeyType.AES:
                valid_lengths = [16, 24, 32]  # AES-128, AES-192, AES-256 (in bytes)
                if len(key) not in valid_lengths:
                    raise SPSDKValueError(
                        f"Invalid AES key length: {len(key)} bytes. Must be one of {valid_lengths}"
                    )

            return [None, None, key]

        # Handle RSA keys
        if isinstance(key, (PrivateKeyRsa, PublicKeyRsa)):
            # For RSA, pKey[0] is the modulus (n)
            if isinstance(key, PrivateKeyRsa):
                public_key_rsa = key.get_public_key()
            else:
                public_key_rsa = key

            # RSA modulus (n) in big-endian
            modulus_bytes = public_key_rsa.n.to_bytes(
                math.ceil(public_key_rsa.n.bit_length() / 8), byteorder=Endianness.BIG.value
            )
            key_parts[0] = modulus_bytes

            # RSA public exponent (e) in big-endian
            exponent_bytes = public_key_rsa.e.to_bytes(
                math.ceil(public_key_rsa.e.bit_length() / 8), byteorder=Endianness.BIG.value
            )
            key_parts[1] = exponent_bytes

            # If it's a private key, add the private exponent (d)
            if isinstance(key, PrivateKeyRsa):
                private_exponent = key.key.private_numbers().d
                private_exponent_bytes = private_exponent.to_bytes(
                    key.key_size // 8, byteorder=Endianness.BIG.value
                )
                key_parts[2] = private_exponent_bytes

        # Handle ECC keys
        elif isinstance(key, (PrivateKeyEcc, PublicKeyEcc)):
            # For ECC, pKey[0] contains the public point coordinates
            if isinstance(key, PrivateKeyEcc):
                public_key_ecc = key.get_public_key()
            else:
                public_key_ecc = key

            # Raw format: X || Y
            key_parts[0] = public_key_ecc.export(encoding=SPSDKEncoding.NXP)

            # If it's a private key, add the private scalar (d)
            if isinstance(key, PrivateKeyEcc):
                private_scalar = key.d
                private_scalar_bytes = private_scalar.to_bytes(
                    public_key_ecc.coordinate_size, byteorder=Endianness.BIG.value
                )
                key_parts[2] = private_scalar_bytes

        else:
            raise SPSDKValueError(f"Unsupported key type: {type(key).__name__}")

        return key_parts


class EleMessageHseFormatKeyCatalogs(EleMessageHse):
    """HSE Format Key Catalogs service.

    This service configures NVM or RAM key catalogs for HSE Firmware operations.
    The catalogs format is defined according to the total number of groups and
    maximum available memory for NVM or RAM keys handled by the HSE Firmware.

    :cvar CMD: HSE message command identifier for format key catalogs operation.
    :cvar CMD_DESCRIPTOR_FORMAT: Binary format structure for service descriptor.
    """

    CMD = HseMessageIDs.FORMAT_KEY_CATALOGS.tag
    CMD_DESCRIPTOR_FORMAT = (
        LITTLE_ENDIAN + UINT32 + UINT32  # pNvmKeyCatalogCfg  # pRamKeyCatalogCfg
    )

    def __init__(
        self,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_1,
    ):
        """Initialize the HSE Format Key Catalogs message.

        This constructor sets up the message for formatting key catalogs in HSE,
        initializing catalog addresses and response configuration.

        :param srv_version: Service version to use for this message
        :raises SPSDKValueError: If key catalog configuration is invalid
        """
        super().__init__(srv_version, mu_channel)
        self.nvm_catalog_addr = 0
        self.ram_catalog_addr = 0

        # No response data expected for this command beyond status
        self.response_data_size = 0

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor for the Format Key Catalogs command.

        :return: Packed service descriptor bytes containing NVM and RAM catalog addresses.
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.nvm_catalog_addr,
            self.ram_catalog_addr,
        )

    def response_info(self) -> str:
        """Get formatted information about the response.

        :return: String representation of the key catalog formatting result.
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return "Key catalogs formatting successful"
        return "Key catalogs formatting failed"


class EleMessageHseEraseFirmware(EleMessageHse):
    """HSE Erase Firmware service.

    This service is used for erasing the HSE Firmware from flash-based devices (HSE_B variant).
    It also erases the SYS-IMG and backup (if present) in the secure flash from the device.

    Important restrictions:
    - Available for flash based devices only (HSE_B variant)
    - Can be performed only in CUST_DEL life cycle
    - Will return HSE_SRV_RSP_NOT_ALLOWED error if performed in other life cycles

    :cvar CMD: Command identifier for HSE firmware erase operation.
    :cvar CMD_DESCRIPTOR_FORMAT: Binary format specification for command descriptor.
    """

    CMD = HseMessageIDs.ERASE_FW.tag
    CMD_DESCRIPTOR_FORMAT = LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8  # reserved[4]

    def __init__(
        self,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_0,
    ):
        """Initialize the HSE Erase Firmware message.

        Creates a new HSE firmware erase message. This operation will completely erase
        the HSE firmware, SYS-IMG, and any backup images from the secure flash.

        Warning: This is a destructive operation that cannot be undone. Use with caution.

        :param srv_version: Service version to use for this message.
        """
        super().__init__(srv_version, mu_channel)

        # No response data expected for this command beyond status
        self.response_data_size = 0

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor for the Erase Firmware command.

        Creates a packed binary service descriptor containing only reserved fields
        as specified in the hseEraseFwSrv_t structure.

        :return: Packed service descriptor bytes with 4 reserved bytes set to zero.
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            RESERVED,  # reserved[0]
            RESERVED,  # reserved[1]
            RESERVED,  # reserved[2]
            RESERVED,  # reserved[3]
        )

    def response_info(self) -> str:
        """Get formatted information about the response.

        Returns a human-readable string describing the result of the HSE firmware
        erase operation, indicating success or failure with appropriate messaging.

        :return: String representation of the firmware erase operation result.
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return "HSE Firmware erase operation successful"
        if self.indication == HseResponseStatus.NOT_ALLOWED.tag:
            return "HSE Firmware erase failed - Operation not allowed (check life cycle state)"
        return "HSE Firmware erase operation failed"


class EleMessageHseFirmwareIntegrityCheck(EleMessageHse):
    """HSE Firmware Integrity Check service.

    This service performs an integrity check of the HSE Firmware and SYS-IMG inside HSE.
    It verifies the cryptographic integrity and authenticity of the firmware components
    to ensure they have not been corrupted or tampered with.

    Important notes:

    - Available for HSE_B variant only
    - No input data structure required
    - Returns success/failure status indicating firmware integrity state

    :cvar CMD: Command identifier for HSE firmware integrity check operation.
    :cvar CMD_DESCRIPTOR_FORMAT: Binary format specification for command descriptor.
    """

    CMD = HseMessageIDs.FW_INTEGRITY_CHECK.tag
    CMD_DESCRIPTOR_FORMAT = (
        LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8
    )  # reserved[4] - no data structure used

    def __init__(
        self,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_0,
    ):
        """Initialize the HSE Firmware Integrity Check message.

        Creates a new HSE firmware integrity check message. This operation will verify
        the integrity of the HSE firmware and SYS-IMG components without modifying them.

        :param srv_version: Service version to use for this message.
        """
        super().__init__(srv_version, mu_channel)

        # No response data expected for this command beyond status
        self.response_data_size = 0

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor for the Firmware Integrity Check command.

        Creates a packed binary service descriptor. Since no data structure is used
        for this service, the descriptor contains only reserved/padding bytes.

        :return: Packed service descriptor bytes with reserved fields set to zero.
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            RESERVED,  # reserved[0]
            RESERVED,  # reserved[1]
            RESERVED,  # reserved[2]
            RESERVED,  # reserved[3]
        )

    def response_info(self) -> str:
        """Get formatted information about the response.

        Returns a human-readable string describing the result of the HSE firmware
        integrity check operation, indicating whether the firmware integrity is valid.

        :return: String representation of the firmware integrity check result.
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return "HSE Firmware integrity check passed - Firmware is valid"
        return "HSE Firmware integrity check failed - Firmware may be corrupted"


class EleMessageHseCoreResetEntryInstall(EleMessageHse):
    """HSE Core Reset Entry Install service.

    This service updates an existing or adds a new entry in the Core Reset table.
    The Core Reset table manages the boot sequence and SMR verification for different
    processor cores in the system.

    Important notes:

    - SMR entries linked with the CR entry (via preBoot/altPreBoot/postBoot SMR maps)
      must be installed in HSE prior to the CR installation
    - SuperUser rights (for NVM Configuration) are needed to perform this service
    - Updating an existing CR entry requires all preBoot and postBoot SMR(s) linked
      with the previous entry to be verified successfully (applicable only in
      OEM_PROD/IN_FIELD life cycles)

    :cvar CMD: Command identifier for Core Reset entry installation service.
    :cvar CMD_DESCRIPTOR_FORMAT: Binary format specification for command descriptor.
    """

    CMD = HseMessageIDs.CORE_RESET_ENTRY_INSTALL.tag
    CMD_DESCRIPTOR_FORMAT = LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8 + UINT32

    def __init__(
        self,
        entry_index: int,
        entry_addr: int,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_1,
    ):
        """Initialize the Core Reset Entry Install message.

        Creates a new Core Reset (CR) entry installation message for HSE communication.
        This message is used to install or update CR entries in the Core Reset table
        with specified entry index and configuration.

        :param entry_index: Index in the Core Reset table to be added/updated.
                              Must be within HSE_NUM_OF_CORE_RESET_ENTRIES range.
        :param entry_addr: Address of Core Reset entry structure (hseCrEntry_t).
                             This structure contains the core configuration including
                             core ID, SMR maps, and other reset parameters.
        :param srv_version: Service version to use for this message.
        :param mu_channel: Message unit channel to use for communication.
        :raises SPSDKValueError: If entry_index is invalid.
        """
        super().__init__(srv_version, mu_channel)
        if entry_index < 0 or entry_index > 3:
            raise SPSDKValueError(f"Invalid Core Reset entry index: {entry_index}. Must be 0-3.")
        self.entry_index = entry_index
        self.entry_addr = entry_addr

        # No response data expected for this command beyond status
        self.response_data_size = 0

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor for the Core Reset Entry Install command.

        Packs the service descriptor fields into a binary format according to the
        CMD_DESCRIPTOR_FORMAT specification for HSE Core Reset entry installation.

        :return: Packed service descriptor bytes containing entry index, reserved fields,
                 and Core Reset entry address.
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.entry_index,
            RESERVED,
            RESERVED,
            RESERVED,
            self.entry_addr,
        )

    def response_info(self) -> str:
        """Get formatted information about the response.

        Returns a human-readable string describing the Core Reset entry installation
        result based on the response status and entry details.

        :return: String representation of the Core Reset entry installation result
                 including entry index and success/failure status.
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return f"Core Reset entry {self.entry_index} installation successful"
        return f"Core Reset entry {self.entry_index} installation failed"


class EleMessageHseCoreResetEntryErase(EleMessageHse):
    """HSE Core Reset Entry Erase service.

    This service erases one Core Reset entry from the internal HSE memory.
    The service removes the specified entry from the Core Reset table, effectively
    disabling the core reset configuration for that entry index.

    Important notes:

    - SuperUser (SU) access rights with privileges over HSE_SYS_AUTH_NVM_CONFIG data
      are required to perform this service
    - Erasing a CR entry will remove all associated boot configurations for that core
    - The operation is irreversible - the entry must be reinstalled if needed again

    :cvar CMD: Command identifier for Core Reset entry erase service.
    :cvar CMD_DESCRIPTOR_FORMAT: Binary format specification for command descriptor.
    """

    CMD = HseMessageIDs.CORE_RESET_ENTRY_ERASE.tag
    CMD_DESCRIPTOR_FORMAT = LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8

    def __init__(
        self,
        entry_index: int,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_1,
    ):
        """Initialize the Core Reset Entry Erase message.

        Creates a new Core Reset (CR) entry erase message for HSE communication.
        This message is used to erase CR entries from the Core Reset table at the
        specified entry index.

        :param entry_index: Index in the Core Reset table for the entry to be erased.
                              Must be within HSE_NUM_OF_CORE_RESET_ENTRIES range.
        :param srv_version: Service version to use for this message.
        :param mu_channel: Message unit channel to use for communication.
        :raises SPSDKValueError: If entry_index is invalid.
        """
        super().__init__(srv_version, mu_channel)
        if entry_index < 0 or entry_index > 3:
            raise SPSDKValueError(f"Invalid Core Reset entry index: {entry_index}. Must be 0-3.")
        self.entry_index = entry_index

        # No response data expected for this command beyond status
        self.response_data_size = 0

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor for the Core Reset Entry Erase command.

        Packs the service descriptor fields into a binary format according to the
        CMD_DESCRIPTOR_FORMAT specification for HSE Core Reset entry erase operation.

        :return: Packed service descriptor bytes containing entry index and reserved fields.
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.entry_index,  # crEntryInd
            RESERVED,  # reserved[0]
            RESERVED,  # reserved[1]
            RESERVED,  # reserved[2]
        )

    def response_info(self) -> str:
        """Get formatted information about the response.

        Returns a human-readable string describing the Core Reset entry erase
        result based on the response status and entry details.

        :return: String representation of the Core Reset entry erase result
                 including entry index and success/failure status.
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return f"Core Reset entry {self.entry_index} erase successful"
        return f"Core Reset entry {self.entry_index} erase failed"


class EleMessageHseActivatePassiveBlock(EleMessageHse):
    """HSE Activate Passive Block service.

    This service is an application request to switch passive flash block area.
    It activates the passive block, making it the active block for subsequent operations.

    Important notes:

    - Available for HSE_B variant only
    - Used for A/B swap functionality in dual-bank flash configurations
    - Switches between active and passive flash block areas

    :cvar CMD: Command identifier for HSE activate passive block operation.
    :cvar CMD_DESCRIPTOR_FORMAT: Binary format specification for command descriptor.
    """

    CMD = HseMessageIDs.ACTIVATE_PASSIVE_BLOCK.tag
    CMD_DESCRIPTOR_FORMAT = (
        LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8
    )  # reserved[4] - no data structure used

    def __init__(
        self,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
        mu_channel: MuChannel = MuChannel.CHANNEL_0,
    ):
        """Initialize the HSE Activate Passive Block message.

        Creates a new HSE activate passive block message. This operation will switch
        the passive flash block area to become the active block.

        :param srv_version: Service version to use for this message.
        :param mu_channel: Message unit channel to use for communication.
        """
        super().__init__(srv_version, mu_channel)

        # No response data expected for this command beyond status
        self.response_data_size = 0

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor for the Activate Passive Block command.

        Creates a packed binary service descriptor. Since no data structure is used
        for this service, the descriptor contains only reserved/padding bytes.

        :return: Packed service descriptor bytes with reserved fields set to zero.
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            RESERVED,  # reserved[0]
            RESERVED,  # reserved[1]
            RESERVED,  # reserved[2]
            RESERVED,  # reserved[3]
        )

    def response_info(self) -> str:
        """Get formatted information about the response.

        Returns a human-readable string describing the result of the HSE activate
        passive block operation, indicating whether the block switch was successful.

        :return: String representation of the activate passive block operation result.
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return "HSE Activate passive block operation successful - Passive block is now active"
        return "HSE Activate passive block operation failed"
