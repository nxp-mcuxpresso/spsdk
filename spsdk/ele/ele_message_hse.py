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
    for command formatting, response handling, and service identification. It provides
    the foundation for implementing HSE (Hardware Security Engine) communication
    protocols within the SPSDK framework.

    :cvar CMD_ID_FORMAT: Format string for HSE command ID structure.
    :cvar RESPONSE_HEADER_WORDS_COUNT: Number of words in HSE response header.
    :cvar MSG_IDS: HSE-specific message ID enumeration.
    """

    CMD_ID_FORMAT: str = LITTLE_ENDIAN + UINT32 + UINT8 + UINT8 + UINT8 + UINT8
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

        Calculates the total size by combining the command ID format size
        and command descriptor format size using struct.calcsize().

        :return: Size of command data in bytes.
        """
        return calcsize(self.CMD_ID_FORMAT) + calcsize(self.CMD_DESCRIPTOR_FORMAT)

    @property
    def command_data(self) -> bytes:
        """Get the complete command data.

        Combines the command header and service descriptor into the complete command data.
        The header is packed using CMD_ID_FORMAT with service_id and zero padding, then
        concatenated with the service descriptor bytes.

        :return: Complete command data as bytes.
        """
        header = pack(self.CMD_ID_FORMAT, self.service_id, 0, 0, 0, 0)
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


class HseAttributeId(SpsdkEnum):
    """HSE attribute identifier enumeration.

    Defines the available attribute IDs that can be used with HSE (Hardware
    Security Engine) attribute get/set operations for secure provisioning.
    """

    NONE = (0, "NONE")
    FW_VERSION = (1, "FW_VERSION")


class HseAttributeHandler:
    """Base class for HSE attribute handlers.

    Provides common functionality for handling HSE attributes including data validation,
    size calculation, and format management. This class serves as a foundation for
    specific HSE attribute implementations in the ELE messaging system.

    :cvar FORMAT: Struct format string for attribute data packing/unpacking.
    :cvar ATTR_ID: HSE attribute identifier this handler manages.
    """

    FORMAT: str
    ATTR_ID: HseAttributeId

    def __init__(self) -> None:
        """Initialize the attribute handler.

        Sets up the handler with its specific attribute ID and initializes internal data storage.
        """
        self.attr_id = self.ATTR_ID
        self._data = bytes()

    @property
    def data(self) -> bytes:
        """Get the raw attribute data.

        :return: Raw attribute data as bytes.
        """
        return self._data

    @data.setter
    def data(self, value: bytes) -> None:
        """Set the raw attribute data.

        Validates that the data size matches the expected size for this attribute type.

        :param value: Raw attribute data as bytes.
        :raises ValueError: If the data size doesn't match the expected size.
        """
        if len(value) != self.size:
            raise ValueError(
                f"Invalid data size. Expected {self.size} bytes, got {len(value)} bytes."
            )
        self._data = value

    @property
    def size(self) -> int:
        """Get the default size for this attribute type.

        The method calculates the size in bytes using the struct format string
        defined in the FORMAT attribute.

        :return: Size in bytes.
        """
        return calcsize(self.FORMAT)

    @abstractmethod
    def __str__(self) -> str:
        """Format a decoded value for display.

        :return: Formatted string representation.
        """

    @abstractmethod
    def decode(self) -> None:
        """Decode the raw attribute data into structured fields.

        This method processes the raw binary data stored in the attribute and
        converts it into meaningful structured fields that can be accessed and
        manipulated programmatically.

        :raises SPSDKError: If the raw data cannot be decoded or is corrupted.
        """

    def _validate(self) -> None:
        """Validate that the data is present and has the correct length.

        :raises SPSDKParsingError: If data is missing or has invalid length.
        """
        if not self.data:
            raise SPSDKParsingError(f"No data set for {self.__class__.__name__} object")
        if len(self.data) < self.size:
            raise SPSDKParsingError(f"Invalid data length for FW version: {len(self.data)}")


class FwVersionAttributeHandler(HseAttributeHandler):
    """HSE firmware version attribute handler.

    This class handles the decoding and representation of HSE firmware version
    attributes, extracting SoC type, firmware type, and version information
    from binary data.

    :cvar FORMAT: Binary format string for unpacking firmware version data.
    :cvar ATTR_ID: HSE attribute identifier for firmware version.
    """

    FORMAT = LITTLE_ENDIAN + UINT8 + UINT8 + UINT16 + UINT8 + UINT8 + UINT16
    ATTR_ID = HseAttributeId.FW_VERSION

    def __init__(self) -> None:
        """Initialize the firmware version attribute handler.

        Sets all firmware version attributes (soc_type, fw_type, major, minor, patch) to None
        and calls the parent class constructor.
        """
        super().__init__()
        self.soc_type = self.fw_type = self.major = self.minor = self.patch = None

    def decode(self) -> None:
        """Decode the firmware version data into structured fields.

        Extracts SoC type, firmware type, and version components from the raw data
        and populates the corresponding instance attributes.

        :raises SPSDKError: If data validation fails or data format is invalid.
        """
        self._validate()
        _, self.soc_type, self.fw_type, self.major, self.minor, self.patch = unpack(
            self.FORMAT, self.data
        )

    def __str__(self) -> str:
        """Return string representation of firmware version information.

        Provides a formatted string containing SoC type, firmware type, and version details
        in a human-readable format.

        :return: Formatted string with firmware version details.
        """
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

    :cvar CMD_DESCRIPTOR_FORMAT: Binary format string for service descriptor structure.
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
        self.attr_handler = self._get_attribute_handler(attr_id)
        self.attr_id = attr_id
        self.response_data_size = self.attr_handler.size

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor for HSE message.

        Packs the service descriptor data into binary format using the command descriptor
        format with attribute ID, handler size, and response data address.

        :return: Packed binary service descriptor data.
        """
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
        """Get HSE attribute handler for specified attribute ID.

        Retrieves the appropriate handler class for the given HSE attribute ID and returns
        an instance of that handler.

        :param attr_id: HSE attribute identifier to get handler for.
        :raises ValueError: Unsupported or unknown attribute ID.
        :return: Instance of the HSE attribute handler for the specified attribute ID.
        """
        try:
            handler_cls = HSE_ATTRIBUTE_HANDLER[attr_id]
        except KeyError as e:
            raise ValueError(f"Unsupported attribute ID: {attr_id}") from e
        return handler_cls()

    def decode_response_data(self, response: bytes) -> None:
        """Decode the response data for this attribute.

        Sets the response data in the attribute handler and triggers decoding.

        :param response: Response data to decode.
        """
        self.attr_handler.data = response
        self.attr_handler.decode()

    def response_info(self) -> str:
        """Get formatted information about the response.

        :return: String representation of the attribute data.
        """
        return str(self.attr_handler)


class EleMessageHseGetAttr(EleMessageHseAttr):
    """ELE message for retrieving HSE (Hardware Security Engine) attributes.

    This class implements the GET_ATTR command to request specific attribute
    values from the HSE subsystem, enabling read access to HSE configuration
    and status information.

    :cvar CMD: HSE message command identifier for get attribute operation.
    """

    CMD = HseMessageIDs.GET_ATTR.tag


class EleMessageHseSetAttr(EleMessageHseAttr):
    """ELE message for setting HSE (Hardware Security Engine) attributes.

    This class represents a command message used to set specific attributes
    in the Hardware Security Engine through the EdgeLock Enclave interface.

    :cvar CMD: Command identifier for HSE set attribute operation.
    """

    CMD = HseMessageIDs.SET_ATTR.tag


class EleMessageHseBootDataImageSign(EleMessageHse):
    """ELE message for HSE boot data image signing operations.

    Handles signing of boot data images for different HSE variants. For HSE_H/M devices,
    supports IVT/DCD/ST/LPDDR4(S32Z/E devices)/AppBSB image types. For HSE_B devices,
    supports IVT/AppBSB image types. The class manages the signing process and extracts
    authentication tags from the response data.
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

        Constructs and returns the service descriptor bytes by packing the image address,
        tag length, and response data address according to the command descriptor format.

        :return: Packed service descriptor as bytes containing image address, tag length,
                 and response data address.
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.img_addr,
            self.tag_len,
            self.response_data_address,
        )

    def decode_response_data(self, response: bytes) -> None:
        """Decode the response data for the boot data image sign operation.

        Extracts the initial vector (if present) and GMAC value from the response.
        The method processes different tag lengths: for 16-byte tags, only GMAC is extracted;
        for 28-byte tags, both initial vector (12 bytes) and GMAC (16 bytes) are extracted.

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

        Creates and returns a packed binary service descriptor containing access mode,
        stream length, and firmware file address for HSE firmware update operations.

        :return: Packed service descriptor bytes in the expected binary format.
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

        Returns a human-readable string describing the firmware update operation status based on
        the response status code and access mode.

        :return: String representation of the firmware update status.
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return f"Firmware update {self.access_mode.label.lower()} operation successful"
        return "Firmware update failed"


class EleMessageHseBootDataImageVerify(EleMessageHse):
    """HSE Boot Data Image Verification Message.

    Handles verification of boot data images including IVT, DCD, ST, LPDDR4 (S32Z/E devices),
    and AppBSB components. For HSE_H/M variants, verifies all image types. For HSE_B variant,
    verifies IVT and AppBSB images only.
    This message verifies GMAC authentication tags generated by the boot data image signing
    service, ensuring boot image integrity and authenticity.
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

        Returns a human-readable string indicating whether the Boot Data Image
        verification was successful or failed based on the response status.

        :return: String representation of the image verification result.
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return "Boot Data Image verification successful"
        return "Boot Data Image verification failed"


class HseKeyType(SpsdkEnum):
    """HSE key type enumeration for Hardware Security Engine operations.

    Defines the available cryptographic key types supported by HSE including
    symmetric keys (AES, HMAC, SHE), asymmetric key pairs and public keys
    (ECC, RSA, DH), and specialized keys (SipHash, shared secrets).
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
    SMR flags, and key type. This class provides functionality to decode raw key
    information data from HSE (Hardware Security Engine) into structured fields
    for cryptographic operations.

    :cvar FORMAT: Binary format string for packing/unpacking key information data.
    """

    FORMAT = LITTLE_ENDIAN + UINT32 + UINT16 + UINT32 + UINT32 + UINT8 + UINT8 + UINT8 + UINT8

    def __init__(self) -> None:
        """Initialize the key information structure with default values.

        This constructor sets up a new HSE key information structure with all fields
        initialized to their default values including key flags, bit length, counter,
        SMR flags, key type, and reserved fields.
        """
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

        :return: Size in bytes.
        """
        return calcsize(self.FORMAT)

    def decode(self, data: bytes) -> None:
        """Decode the raw key info data into structured fields.

        The method parses binary data and populates the object's key-related attributes
        including flags, bit length, counter, SMR flags, key type, and specific bytes.

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
        """Format the key information for display.

        Creates a human-readable string representation of HSE key information including
        key flags, bit length, counter, SMR flags, key type, and specific data.

        :return: Formatted string representation of the key information.
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
    """HSE Get Key Info command message.

    This class represents an ELE HSE message for retrieving key information and properties
    using a key handle as input parameter. It handles the command formatting, response
    decoding, and provides access to the retrieved key information.

    :cvar CMD: Command identifier for the Get Key Info operation.
    :cvar CMD_DESCRIPTOR_FORMAT: Binary format string for command descriptor packing.
    """

    CMD = HseMessageIDs.GET_KEY_INFO.tag
    CMD_DESCRIPTOR_FORMAT = LITTLE_ENDIAN + UINT32 + UINT32

    def __init__(
        self,
        key_handle: int,
        srv_version: EleMessageHse.ServiceVersion = EleMessageHse.ServiceVersion.VERSION_0,
    ):
        """Initialize the HSE Get Key Info message.

        :param key_handle: The key handle to get information for.
        :param srv_version: Service version to use for this message.
        """
        super().__init__(srv_version)
        self.key_handle = key_handle
        self.key_info = HseKeyInfo()
        self.response_data_size = self.key_info.size

    def get_srv_descriptor(self) -> bytes:
        """Get service descriptor for the Get Key Info command.

        :return: Packed service descriptor bytes containing key handle and response data address.
        """
        return pack(
            self.CMD_DESCRIPTOR_FORMAT,
            self.key_handle,
            self.response_data_address,
        )

    def decode_response_data(self, response: bytes) -> None:
        """Decode the response data for the Get Key Info operation.

        Extracts the key information from the response and stores it in the key_info attribute.

        :param response: Response data bytes to decode containing key information.
        :raises SPSDKError: If response data cannot be decoded properly.
        """
        self.key_info.decode(response)

    def response_info(self) -> str:
        """Get formatted information about the response.

        Returns a string representation of the key information if the response status
        indicates success, otherwise returns an error message.

        :return: String representation of the key information on success, or error message on failure.
        """
        if self.status == ResponseStatus.ELE_SUCCESS_IND.tag:
            return str(self.key_info)
        return "Failed to retrieve key information"
