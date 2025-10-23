#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for HSE-specific ELE message implementation.

This module provides classes for handling HSE (Hardware Security Engine) specific ELE messages.
"""
from abc import abstractmethod
from struct import calcsize, pack, unpack
from typing import Mapping, Optional, Type, cast

from spsdk.ele.ele_constants import HseMessageIDs, HseResponseStatus, MessageIDs, ResponseStatus
from spsdk.ele.ele_message import LITTLE_ENDIAN, UINT8, UINT16, UINT32, EleMessage
from spsdk.exceptions import SPSDKParsingError, SPSDKValueError
from spsdk.utils.misc import Endianness
from spsdk.utils.spsdk_enum import SpsdkEnum


class EleMessageHse(EleMessage):
    """Base class for HSE-specific ELE messages.

    This class extends the EleMessage base class with HSE-specific functionality
    for command formatting, response handling, and service identification.
    """

    CMD_ID_FORMAT: str = LITTLE_ENDIAN + UINT32 + UINT8 + UINT8 + UINT8 + UINT8
    CMD_DESCRIPTOR_FORMAT: str
    RESPONSE_HEADER_WORDS_COUNT = 1
    MSG_IDS = cast(Type[MessageIDs], HseMessageIDs)

    class ServiceVersion(SpsdkEnum):
        """Enumeration of HSE service versions.

        Defines the available HSE service versions that can be used when
        constructing HSE messages.
        """

        VERSION_0 = (0, "ver0", "Hse service version 0")
        VERSION_1 = (1, "ver1", "Hse service version 1")

    def __init__(self, srv_version: ServiceVersion = ServiceVersion.VERSION_0) -> None:
        """Initialize the HSE message with the specified service version.

        :param srv_version: Service version to use for this message
        """
        super().__init__()
        self.srv_version = srv_version

    def decode_response(self, response: bytes) -> None:
        """Decode the HSE response data.

        Extracts the response status from the HSE response data and sets the
        appropriate status and indication values.

        :param response: Response data to decode
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
        """Print the response status information.

        :return: String with response status.
        """
        ret = f"Response status: {ResponseStatus.get_label(self.status)}\n"
        if self.status == ResponseStatus.ELE_FAILURE_IND:
            ret += (
                f"   Response indication: {HseResponseStatus.get_label(self.indication)}"
                f" - ({hex(self.indication)})\n"
            )
        return ret

    def export(self) -> bytes:
        """Command data to be loaded into target memory space."""
        return self.command_data_address.to_bytes(4, byteorder=Endianness.LITTLE.value)

    @property
    def command_words_count(self) -> int:
        """Command Words count."""
        return 1

    @abstractmethod
    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor."""

    @property
    def command_data_size(self) -> int:
        """Command data address in target memory space."""
        return calcsize(self.CMD_ID_FORMAT) + calcsize(self.CMD_DESCRIPTOR_FORMAT)

    @property
    def command_data(self) -> bytes:
        """Get the complete command data.

        Combines the command header and service descriptor into the complete command data.

        :return: Complete command data as bytes
        """
        header = pack(self.CMD_ID_FORMAT, self.service_id, 0, 0, 0, 0)
        descriptor = self.get_srv_descriptor()
        return header + descriptor

    @property
    def service_id(self) -> int:
        """Get the service ID for this message.

        Combines the command ID and service version into a single service ID value.

        :return: Service ID as an integer
        """
        return self.CMD | (self.srv_version.tag << 24)

    @property
    def service_index(self) -> int:
        """Get the service index from service_id (byte 0).

        :return: Service index (0..255)
        """
        return self.service_id.to_bytes(4, Endianness.LITTLE.value)[0]

    @property
    def service_class_index(self) -> int:
        """Get the service class index from service_id (byte 1).

        :return: Service class index (0..255)
        """
        return self.service_id.to_bytes(4, Endianness.LITTLE.value)[1]

    @property
    def service_cancelable(self) -> bool:
        """Check if the service can be canceled from service_id (byte 2).

        :return: True if service can be canceled (0x00), False if not (0xA5)
        """
        return self.service_id.to_bytes(4, Endianness.LITTLE.value)[2] != 0xA5

    @property
    def service_version(self) -> int:
        """Get the service version from service_id (byte 3).

        :return: Service version (0..255)
        """
        return self.service_id.to_bytes(4, Endianness.LITTLE.value)[3]


class HseAttributeId(SpsdkEnum):
    """Enumeration of HSE attribute IDs.

    Defines the available attribute IDs that can be used with HSE attribute
    get/set operations.
    """

    NONE = (0, "NONE")
    FW_VERSION = (1, "FW_VERSION")


class HseAttributeHandler:
    """Base class for HSE attribute handlers.

    Provides common functionality for handling HSE attributes, including
    data validation, size calculation, and abstract methods for decoding
    and string representation.
    """

    FORMAT: str
    ATTR_ID: HseAttributeId

    def __init__(self) -> None:
        """Initialize the attribute handler.

        :param attr_id: The attribute ID this handler is responsible for
        """
        self.attr_id = self.ATTR_ID
        self._data = bytes()

    @property
    def data(self) -> bytes:
        """Get the raw attribute data.

        :return: Raw attribute data as bytes
        """
        return self._data

    @data.setter
    def data(self, value: bytes) -> None:
        """Set the raw attribute data.

        Validates that the data size matches the expected size for this attribute type.

        :param value: Raw attribute data as bytes
        :raises ValueError: If the data size doesn't match the expected size
        """
        if len(value) != self.size:
            raise ValueError(
                f"Invalid data size. Expected {self.size} bytes, got {len(value)} bytes."
            )
        self._data = value

    @property
    def size(self) -> int:
        """Get the default size for this attribute type.

        :return: Size in bytes
        """
        return calcsize(self.FORMAT)

    @abstractmethod
    def __str__(self) -> str:
        """Format a decoded value for display.

        :return: Formatted string representation
        """

    @abstractmethod
    def decode(self) -> None:
        """Decode the raw attribute data into structured fields."""

    def _validate(self) -> None:
        """Validate that the data is present and has the correct length.

        :raises SPSDKParsingError: If data is missing or has invalid length
        """
        if not self.data:
            raise SPSDKParsingError(f"No data set for {self.__class__.__name__} object")
        if len(self.data) < self.size:
            raise SPSDKParsingError(f"Invalid data length for FW version: {len(self.data)}")


class FwVersionAttributeHandler(HseAttributeHandler):
    """Handler for HSE_FW_VERSION_ATTR_ID."""

    FORMAT = LITTLE_ENDIAN + UINT8 + UINT8 + UINT16 + UINT8 + UINT8 + UINT16
    ATTR_ID = HseAttributeId.FW_VERSION

    def __init__(self) -> None:
        """Initialize the firmware version attribute handler."""
        super().__init__()
        self.soc_type = self.fw_type = self.major = self.minor = self.patch = None

    def decode(self) -> None:
        """Decode the firmware version data into structured fields.

        Extracts SoC type, firmware type, and version components from the raw data.
        """
        self._validate()
        _, self.soc_type, self.fw_type, self.major, self.minor, self.patch = unpack(
            self.FORMAT, self.data
        )

    def __str__(self) -> str:
        ret = "Firmware Version:\n"
        ret += f"SoC Type: {self.soc_type}\n"
        ret += f"FW Type: {self.fw_type}\n"
        ret += f"Version: {self.major}.{self.minor}.{self.patch}\n"
        return ret


HSE_ATTRIBUTE_HANDLER: Mapping[HseAttributeId, Type[HseAttributeHandler]] = {
    HseAttributeId.FW_VERSION: FwVersionAttributeHandler
}


class EleMessageHseAttr(EleMessageHse):
    """Base class for HSE attribute operations.

    Provides common functionality for getting and setting HSE attributes,
    including attribute handler management and response processing.
    """

    CMD_DESCRIPTOR_FORMAT = LITTLE_ENDIAN + UINT16 + UINT8 + UINT8 + UINT32 + UINT32

    def __init__(
        self,
        attr_id: HseAttributeId,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
    ):
        """Initialize the HSE attribute message.

        :param attr_id: The attribute ID to operate on
        :param srv_version: Service version to use for this message
        """
        super().__init__(srv_version)
        self.attr_handler = self._get_attribute_handler(attr_id)
        self.attr_id = attr_id
        self.response_data_size = self.attr_handler.size

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor."""
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.attr_id.tag,
            0,
            0,
            self.attr_handler.size,
            self.response_data_address,
        )

    @classmethod
    def _get_attribute_handler(cls, attr_id: HseAttributeId) -> HseAttributeHandler:
        try:
            handler_cls = HSE_ATTRIBUTE_HANDLER[attr_id]
        except KeyError as e:
            raise ValueError(f"Unsupported attribute ID: {attr_id}") from e
        return handler_cls()

    def decode_response_data(self, response: bytes) -> None:
        """Decode the response data for this attribute.

        Sets the response data in the attribute handler and triggers decoding.

        :param response: Response data to decode
        """
        self.attr_handler.data = response
        self.attr_handler.decode()

    def response_info(self) -> str:
        """Get formatted information about the response.

        :return: String representation of the attribute data
        """
        return str(self.attr_handler)


class EleMessageHseGetAttr(EleMessageHseAttr):
    """Get HSE attribute."""

    CMD = HseMessageIDs.GET_ATTR.tag


class EleMessageHseSetAttr(EleMessageHseAttr):
    """Set HSE attribute."""

    CMD = HseMessageIDs.SET_ATTR.tag


class EleMessageHseBootDataImageSign(EleMessageHse):
    """Boot Data image sign.

    For HSE_H/M, handles IVT/DCD/ST/LPDDR4(S32Z/E devices)/AppBSB image.
    For HSE_B, handles IVT/AppBSB image.
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

        :param img_addr: Address of the image to sign
        :param tag_len: Length of the tag (must be 16 or 28)
        :param srv_version: Service version to use for this message
        :raises SPSDKValueError: If tag_len is not 16 or 28
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
        """Get service descriptor."""
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.img_addr,
            self.tag_len,
            self.response_data_address,
        )

    def decode_response_data(self, response: bytes) -> None:
        """Decode the response data for the boot data image sign operation.

        Extracts the initial vector (if present) and GMAC value from the response.

        :param response: Response data to decode
        :raises SPSDKValueError: If tag_len is not supported
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

        :return: String representation of the image signature data
        """
        ret = "Image Signature:\n"
        if self.initial_vector:
            ret += f"Initial Vector: {self.initial_vector.hex()}\n"
        ret += f"GMAC: {self.gmac_value.hex()}\n"
        return ret

    @property
    def signature(self) -> bytes:
        """Get the complete signature bytes."""
        ret = bytes()
        if self.initial_vector:
            ret += self.initial_vector
        ret += self.gmac_value
        return ret


class EleMessageHseFirmwareUpdate(EleMessageHse):
    """HSE Firmware Update command.

    This service is used to update the HSE firmware into the HSE internal flash memory.
    Supports both one-pass and streaming modes (START, UPDATE, FINISH).
    """

    CMD = HseMessageIDs.FIRMWARE_UPDATE.tag
    CMD_DESCRIPTOR_FORMAT = LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8 + UINT32 + UINT32

    class HseAccessMode(SpsdkEnum):
        """Enumeration of HSE firmware update access modes.

        Defines the available access modes for HSE firmware updates.
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

        :return: Packed service descriptor bytes
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

        :return: String representation of the firmware update status
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return f"Firmware update {self.access_mode.label.lower()} operation successful"
        return "Firmware update failed"


class EleMessageHseBootDataImageVerify(EleMessageHse):
    """Boot Data image verify.

    For HSE_H/M, verifies IVT/DCD/ST/LPDDR4(S32Z/E devices)/AppBSB image.
    For HSE_B, verifies IVT/AppBSB image.

    This service verifies the GMAC tag generated using the EleMessageHseBootDataImageSign service.
    """

    CMD = HseMessageIDs.BOOT_DATA_IMAGE_VERIFY.tag
    CMD_DESCRIPTOR_FORMAT = LITTLE_ENDIAN + UINT32

    def __init__(
        self,
        img_addr: int,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
    ):
        """Initialize the boot data image verify message.

        :param img_addr: Address of the image to verify (includes the authentication TAG)
        :param srv_version: Service version to use for this message
        """
        super().__init__(srv_version)
        self.img_addr = img_addr
        # No response data expected for this command beyond status
        self.response_data_size = 0

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor.

        :return: Packed service descriptor bytes
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.img_addr,  # pInImage
        )

    def response_info(self) -> str:
        """Get formatted information about the response.

        :return: String representation of the image verification result
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return "Boot Data Image verification successful"
        return "Boot Data Image verification failed"


class HseKeyType(SpsdkEnum):
    """Enumeration of HSE key types.

    Defines the available key types that can be used with HSE key operations.
    """

    SHE = (0x11, "SHE", "SHE key")
    AES = (0x12, "AES", "AES key")
    HMAC = (0x20, "HMAC", "HMAC key")
    SHARED_SECRET = (0x30, "SHARED_SECRET", "Shared secret key")
    SIPHASH = (0x40, "SIPHASH", "SipHash key")
    ECC_PAIR = (0x87, "ECC_PAIR", "ECC key pair")
    ECC_PUB = (0x88, "ECC_PUB", "ECC public key")
    ECC_PUB_EXT = (0x89, "ECC_PUB_EXT", "ECC public key external")
    RSA_PAIR = (0x97, "RSA_PAIR", "RSA key pair")
    RSA_PUB = (0x98, "RSA_PUB", "RSA public key")
    RSA_PUB_EXT = (0x99, "RSA_PUB_EXT", "RSA public key external")
    DH_PAIR = (0xA7, "DH_PAIR", "Diffie-Hellman key pair")
    DH_PUB = (0xA8, "DH_PUB", "Diffie-Hellman public key")


class HseKeyInfo:
    """HSE Key Information structure.

    Contains properties of a cryptographic key including flags, bit length, counter,
    SMR flags, and key type.
    """

    FORMAT = LITTLE_ENDIAN + UINT32 + UINT16 + UINT32 + UINT32 + UINT8 + UINT8 + UINT8 + UINT8

    def __init__(self) -> None:
        """Initialize the key information structure with default values."""
        self.key_flags = 0
        self.key_bit_len = 0
        self.key_counter = 0
        self.smr_flags = 0
        self.key_type = 0
        self.specific = bytes(4)  # Union field, 4 bytes for specific key type data
        self.reserved = bytes(2)  # Reserved bytes

    @property
    def size(self) -> int:
        """Get the size of the key info structure.

        :return: Size in bytes
        """
        return calcsize(self.FORMAT)

    def decode(self, data: bytes) -> None:
        """Decode the raw key info data into structured fields.

        :param data: Raw key info data as bytes
        :raises SPSDKParsingError: If data is missing or has invalid length
        """
        if not data:
            raise SPSDKParsingError("No data set for key info")
        if len(data) < self.size:
            raise SPSDKParsingError(f"Invalid data length for key info: {len(data)}")

        (
            self.key_flags,
            self.key_bit_len,
            self.key_counter,
            self.smr_flags,
            self.key_type,
            specific1,
            specific2,
            specific3,
        ) = unpack(self.FORMAT, data[: self.size])
        self.specific = bytes([specific1, specific2, specific3, 0])  # Pack specific bytes

    def __str__(self) -> str:
        """Format the key info for display.

        :return: Formatted string representation
        """
        ret = "Key Information:\n"
        ret += f"Key Flags: 0x{self.key_flags:08X}\n"

        ret += f"  Flags: {self.key_flags}\n"
        ret += f"Key Bit Length: {self.key_bit_len}\n"
        ret += f"Key Counter: {self.key_counter}\n"
        ret += f"SMR Flags: 0x{self.smr_flags:08X}\n"

        # Decode key type
        try:
            key_type_str = HseKeyType.get_label(self.key_type)
            ret += f"Key Type: {key_type_str} ({self.key_type})\n"
        except ValueError:
            ret += f"Key Type: Unknown ({self.key_type})\n"

        ret += f"Specific Data: {self.specific.hex()}\n"
        return ret


class EleMessageHseGetKeyInfo(EleMessageHse):
    """HSE Get Key Info command.

    This service returns the key information (or properties) using the key handle
    as input parameter.
    """

    CMD = HseMessageIDs.GET_KEY_INFO.tag
    CMD_DESCRIPTOR_FORMAT = LITTLE_ENDIAN + UINT32 + UINT32

    def __init__(
        self,
        key_handle: int,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
    ):
        """Initialize the HSE Get Key Info message.

        :param key_handle: The key handle to get information for
        :param srv_version: Service version to use for this message
        """
        super().__init__(srv_version)
        self.key_handle = key_handle
        self.key_info = HseKeyInfo()
        self.response_data_size = self.key_info.size

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor for the Get Key Info command.

        :return: Packed service descriptor bytes
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.key_handle,
            self.response_data_address,
        )

    def decode_response_data(self, response: bytes) -> None:
        """Decode the response data for the Get Key Info operation.

        Extracts the key information from the response.

        :param response: Response data to decode
        """
        self.key_info.decode(response)

    def response_info(self) -> str:
        """Get formatted information about the response.

        :return: String representation of the key information
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return str(self.key_info)
        return "Failed to retrieve key information"
