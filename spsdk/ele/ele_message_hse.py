#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
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
from spsdk.ele.ele_message import LITTLE_ENDIAN, UINT8, UINT16, UINT32, EleMessage
from spsdk.ele.hse_attrs import HseAttributeHandler, HseAttributeId
from spsdk.exceptions import SPSDKValueError
from spsdk.image.hse.key_info import KeyFormat, KeyHandle, KeyInfo, KeyType
from spsdk.utils.database import DatabaseManager
from spsdk.utils.misc import Endianness
from spsdk.utils.spsdk_enum import SpsdkEnum


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
    RESPONSE_HEADER_WORDS_COUNT = 1
    MSG_IDS = cast(Type[MessageIDs], HseMessageIDs)

    class ServiceVersion(SpsdkEnum):
        """HSE service version enumeration.

        Defines the available HSE service versions that can be used when
        constructing HSE messages for EdgeLock Enclave operations.
        """

        VERSION_0 = (0, "ver0", "Hse service version 0")
        VERSION_1 = (1, "ver1", "Hse service version 1")

    def __init__(self, srv_version: ServiceVersion = ServiceVersion.VERSION_0) -> None:
        """Initialize the HSE message with the specified service version.

        :param srv_version: Service version to use for this message, defaults to VERSION_0.
        """
        super().__init__()
        self.srv_version = srv_version

    def decode_response(self, response: bytes) -> None:
        """Decode the HSE response data.

        Extracts the response status from the HSE response data and sets the
        appropriate status and indication values based on the HSE response.

        :param response: Response data bytes to decode containing HSE status information.
        """
        hse_response = HseResponseStatus.from_tag(
            int.from_bytes(response[:4], byteorder=Endianness.LITTLE.value)
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
        return self.command_data_address.to_bytes(4, byteorder=Endianness.LITTLE.value)

    @property
    def command_words_count(self) -> int:
        """Get the count of command words.

        :return: Number of command words, always returns 1.
        """
        return 1

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
        return calcsize(self.CMD_HEADER_FORMAT) + calcsize(self.CMD_DESCRIPTOR_FORMAT)

    @property
    def command_data(self) -> bytes:
        """Get the complete command data.

        Combines the command header and service descriptor into the complete command data.
        The header is packed using CMD_ID_FORMAT with service_id and zero padding, then
        concatenated with the service descriptor bytes.

        :return: Complete command data as bytes.
        """
        header = pack(self.CMD_HEADER_FORMAT, self.service_id, 0, 0, 0, 0)
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
    ):
        """Initialize the HSE attribute message.

        :param attr_id: The attribute ID to operate on.
        :param srv_version: Service version to use for this message.
        """
        super().__init__(srv_version)
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
    ) -> None:
        """Initialize HSE attribute get message.

        Creates a new HSE attribute get message with the specified attribute ID and service version.
        The attribute value is initially set to None and will be populated when the response is received.

        :param attr_id: HSE attribute identifier to retrieve.
        :param srv_version: Service version for the HSE message, defaults to VERSION_0.
        """
        super().__init__(attr_id, srv_version)
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
            0,
            0,
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
    ) -> None:
        """Initialize HSE attribute message for getting attribute value.

        Creates a new HSE message instance for retrieving the value of a specified
        HSE attribute. The message can optionally specify a memory address where
        the attribute value should be stored.

        :param attr_id: HSE attribute identifier to get value for.
        :param value_addr: Optional memory address where attribute value will be stored.
        :param srv_version: Service version for the HSE message.
        """
        super().__init__(attr_id, srv_version)
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
            0,
            0,
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
    ):
        """Initialize the boot data image sign message.

        :param img_addr: Address of the image to sign.
        :param tag_len: Length of the tag (must be 16 or 28).
        :param srv_version: Service version to use for this message.
        :raises SPSDKValueError: If tag_len is not 16 or 28.
        """
        super().__init__(srv_version)
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
        super().__init__(srv_version)
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
            0,
            0,
            0,  # reserved[3]
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
    ):
        """Initialize the boot data image verify message.

        :param img_addr: Address of the image to verify (includes the authentication TAG).
        :param srv_version: Service version to use for this message.
        """
        super().__init__(srv_version)
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
    ):
        """Initialize the HSE Get Key Info message.

        :param key_handle: The key handle to get information for.
        :param srv_version: Service version to use for this message.
        """
        super().__init__(srv_version)
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
        smr_entry_addr: int,
        smr_data_addr: int,
        smr_data_length: int,
        auth_tag_addr: tuple = (0, 0),
        auth_tag_length: tuple = (0, 0),
        cipher_params: Optional[HseSmrCipherParams] = None,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
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
        super().__init__(srv_version)
        self.access_mode = access_mode
        self.entry_index = entry_index
        self.smr_entry_addr = smr_entry_addr
        self.smr_data_addr = smr_data_addr
        self.smr_data_length = smr_data_length
        self.auth_tag_addr = auth_tag_addr
        self.auth_tag_length = auth_tag_length
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
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.access_mode.tag,  # accessMode
            self.entry_index,  # entryIndex
            0,
            0,  # reserved[2]
            self.smr_entry_addr,  # pSmrEntry
            self.smr_data_addr,  # pSmrData
            self.smr_data_length,  # smrDataLength
            self.auth_tag_addr[0],  # pAuthTag[0]
            self.auth_tag_addr[1],  # pAuthTag[1]
            self.auth_tag_length[0],  # authTagLength[0]
            self.auth_tag_length[1],  # authTagLength[1]
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


class HseCipherScheme:
    """HSE Cipher Scheme structure.

    This class represents a cipher scheme configuration for HSE (Hardware Security Engine)
    operations, encapsulating algorithm type, mode, and additional cipher options for
    cryptographic operations.
    """

    def __init__(self, algorithm: int = 0, mode: int = 0, options: bytes = bytes(4)):
        """Initialize the cipher scheme structure.

        :param algorithm: Cipher algorithm identifier.
        :param mode: Cipher mode identifier.
        :param options: Additional cipher options (4 bytes).
        """
        self.algorithm = algorithm
        self.mode = mode
        self.options = options

    def pack(self) -> bytes:
        """Pack the cipher scheme into bytes.

        Serializes the cipher scheme object into a binary format using little-endian
        byte ordering with algorithm, mode, padding bytes, and options.

        :return: Packed cipher scheme as bytes in little-endian format.
        """
        return pack(
            LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8 + UINT32,
            self.algorithm,
            self.mode,
            0,
            0,
            int.from_bytes(self.options, byteorder=Endianness.LITTLE.value),
        )


class HseAuthScheme:
    """HSE Authentication Scheme structure.

    This class represents authentication parameters for HSE (Hardware Security Engine)
    operations, encapsulating algorithm identifiers, modes, and additional options
    required for secure authentication processes.
    """

    def __init__(self, algorithm: int = 0, mode: int = 0, options: bytes = bytes(4)):
        """Initialize the authentication scheme structure.

        :param algorithm: Authentication algorithm identifier.
        :param mode: Authentication mode identifier.
        :param options: Additional authentication options (4 bytes).
        """
        self.algorithm = algorithm
        self.mode = mode
        self.options = options

    def pack(self) -> bytes:
        """Pack the authentication scheme into bytes.

        Serializes the authentication scheme object into a binary format using little-endian
        byte order with specific field layout.

        :return: Packed authentication scheme as bytes with algorithm, mode, padding, and options.
        """
        return pack(
            LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8 + UINT32,
            self.algorithm,
            self.mode,
            0,
            0,
            int.from_bytes(self.options, byteorder=Endianness.LITTLE.value),
        )


class EleMessageHseImportKey(EleMessageHse):
    """HSE Import Key service message.

    This class represents an ELE message for importing keys into the HSE key store.
    Supports importing symmetric keys, asymmetric key pairs, and public keys in both
    raw format and authenticated container format.

    :cvar CMD: Command identifier for the HSE import key service.
    :cvar CMD_DESCRIPTOR_FORMAT: Binary format structure for the command descriptor.
    """

    CMD = HseMessageIDs.IMPORT_KEY.tag
    CMD_DESCRIPTOR_FORMAT = (
        LITTLE_ENDIAN
        + UINT32  # targetKeyHandle
        + UINT32  # pKeyInfo
        + UINT32  # pKey[0]
        + UINT32  # pKey[1]
        + UINT32  # pKey[2]
        + UINT16  # keyLen[0]
        + UINT16  # keyLen[1]
        + UINT16  # keyLen[2]
        + UINT8  # reserved[0]
        + UINT8  # reserved[1]
        + UINT32  # cipher.cipherKeyHandle
        + UINT8  # cipher.cipherScheme.algorithm
        + UINT8  # cipher.cipherScheme.mode
        + UINT8  # cipher.cipherScheme.reserved[0]
        + UINT8  # cipher.cipherScheme.reserved[1]
        + UINT32  # cipher.cipherScheme.options
        + UINT16  # keyContainer.keyContainerLen
        + UINT8  # keyContainer.reserved[0]
        + UINT8  # keyContainer.reserved[1]
        + UINT32  # keyContainer.pKeyContainer
        + UINT32  # keyContainer.authKeyHandle
        + UINT8  # keyContainer.authScheme.algorithm
        + UINT8  # keyContainer.authScheme.mode
        + UINT8  # keyContainer.authScheme.reserved[0]
        + UINT8  # keyContainer.authScheme.reserved[1]
        + UINT32  # keyContainer.authScheme.options
        + UINT16  # keyContainer.authLen[0]
        + UINT16  # keyContainer.authLen[1]
        + UINT32  # keyContainer.pAuth[0]
        + UINT32  # keyContainer.pAuth[1]
        + UINT8  # keyFormat
        + UINT8  # keyFormat padding to align
        + UINT16  # keyFormat padding to align
    )

    def __init__(
        self,
        key_handle: KeyHandle,
        payload: "KeyImportPayload",
        cipher_key_handle: int = 0xFFFFFFFF,  # HSE_INVALID_KEY_HANDLE
        cipher_scheme: Optional[HseCipherScheme] = None,
        key_container_len: int = 0,
        key_container_addr: int = 0,
        auth_key_handle: int = 0xFFFFFFFF,  # HSE_INVALID_KEY_HANDLE
        auth_scheme: Optional[HseAuthScheme] = None,
        auth_lengths: tuple = (0, 0),
        auth_address: tuple = (0, 0),
        key_format: Optional[KeyFormat] = None,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
    ):
        """Initialize the HSE Import Key message.

        Creates a new HSE (Hardware Security Engine) import key message with the specified
        parameters for importing cryptographic keys into secure key slots.

        :param key_handle: Handle of the key slot where the key will be imported
        :param payload: Key import payload containing key data and metadata
        :param cipher_key_handle: Handle of the key used for decryption if key is encrypted
        :param cipher_scheme: Cipher scheme used for encrypted keys
        :param key_container_len: Length of the key container in bytes
        :param key_container_addr: Memory address of the key container
        :param auth_key_handle: Handle of the key used for authentication verification
        :param auth_scheme: Authentication scheme for key container verification
        :param auth_lengths: Tuple of lengths for authentication tags (up to 2 elements)
        :param auth_address: Tuple of addresses for authentication tags (up to 2 elements)
        :param key_format: Format of the key being imported (defaults to RAW)
        :param srv_version: Service version to use for this message
        """
        super().__init__(srv_version)
        self.key_handle = key_handle
        self.payload = payload
        self.payload_address = 0

        self.cipher_key_handle = cipher_key_handle
        self.cipher_scheme = cipher_scheme or HseCipherScheme()

        self.key_container_len = key_container_len
        self.key_container_addr = key_container_addr
        self.auth_key_handle = auth_key_handle
        self.auth_scheme = auth_scheme or HseAuthScheme()

        # Ensure auth_lengths and auth_address are tuples of length 2
        if len(auth_lengths) < 2:
            auth_lengths = tuple(list(auth_lengths) + [0] * (2 - len(auth_lengths)))
        if len(auth_address) < 2:
            auth_address = tuple(list(auth_address) + [0] * (2 - len(auth_address)))
        self.auth_lengths = auth_lengths
        self.auth_address = auth_address

        self.key_format = key_format if key_format is not None else KeyFormat.RAW

        # No response data expected for this command beyond status
        self.response_data_size = 0

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor for the Import Key command.

        Packs all the command parameters into a binary format according to the HSE
        command descriptor structure for key import operations.

        :return: Packed service descriptor bytes containing key handles, addresses,
            cipher and authentication schemes, and other import parameters.
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.key_handle.handle,
            self.payload_address,  # key_info_addr
            (
                self.payload_address + self.payload.key_offsets[0]
                if self.payload.key_offsets[0] is not None
                else 0
            ),  # pKey[0]
            (
                self.payload_address + self.payload.key_offsets[1]
                if self.payload.key_offsets[1] is not None
                else 0
            ),  # pKey[1]
            (
                self.payload_address + self.payload.key_offsets[2]
                if self.payload.key_offsets[2] is not None
                else 0
            ),  # pKey[2]
            self.payload.key_lengths[0] or 0,
            self.payload.key_lengths[1] or 0,
            self.payload.key_lengths[2] or 0,
            0,  # reserved[0]
            0,  # reserved[1]
            self.cipher_key_handle,
            self.cipher_scheme.algorithm,
            self.cipher_scheme.mode,
            0,  # cipher.cipherScheme.reserved[0]
            0,  # cipher.cipherScheme.reserved[1]
            int.from_bytes(self.cipher_scheme.options, byteorder=Endianness.LITTLE.value),
            self.key_container_len,
            0,  # keyContainer.reserved[0]
            0,  # keyContainer.reserved[1]
            self.key_container_addr,
            self.auth_key_handle,
            self.auth_scheme.algorithm,
            self.auth_scheme.mode,
            0,  # keyContainer.authScheme.reserved[0]
            0,  # keyContainer.authScheme.reserved[1]
            int.from_bytes(self.auth_scheme.options, byteorder=Endianness.LITTLE.value),
            self.auth_lengths[0],
            self.auth_lengths[1],
            self.auth_address[0],
            self.auth_address[1],
            self.key_format.tag,
            0,  # padding
            0,  # padding
        )

    def response_info(self) -> str:
        """Get formatted information about the response.

        This method provides a human-readable string describing the result of the key import operation,
        indicating success or failure along with the associated key handle.

        :return: String representation of the key import result.
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return f"Key import successful for key handle 0x{self.key_handle:08X}"
        return f"Key import failed for key handle 0x{self.key_handle:08X}"


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
        self,
        key_info: KeyInfo,
        key: Union[PrivateKey, PublicKey, bytes],
    ) -> None:
        """Initialize the key import structure.

        :param key_info: Key information structure containing key metadata and configuration.
        :param key: The cryptographic key to import, can be private key, public key, or raw bytes.
        """
        self.key_info = key_info
        self.key = key
        self.key_data = self.convert_key(key, self.key_info.key_type)

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
    ):
        """Initialize the HSE Format Key Catalogs message.

        This constructor sets up the message for formatting key catalogs in HSE,
        initializing catalog addresses and response configuration.

        :param srv_version: Service version to use for this message
        :raises SPSDKValueError: If key catalog configuration is invalid
        """
        super().__init__(srv_version)

        # Addresses will be set later
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
