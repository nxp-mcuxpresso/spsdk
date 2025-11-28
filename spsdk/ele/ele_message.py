#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK EdgeLock Enclave message handling and communication protocol.

This module provides comprehensive message classes for communicating with NXP's EdgeLock
Enclave security subsystem. It includes message formatting, serialization, and protocol
handling for various ELE operations including authentication, key management, lifecycle
operations, and system control functions.
"""
# pylint: disable=too-many-lines

import logging
from struct import pack, unpack
from typing import Optional

from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.ele.ele_constants import (
    EleCsalState,
    EleFwStatus,
    EleImemState,
    EleInfo2Commit,
    EleTrngState,
    KeyBlobEncryptionAlgorithm,
    KeyBlobEncryptionIeeCtrModes,
    LifeCycle,
    LifeCycleToSwitch,
    MessageIDs,
    MessageUnitId,
    ResponseIndication,
    ResponseStatus,
    SocId,
)
from spsdk.exceptions import SPSDKParsingError, SPSDKValueError
from spsdk.image.ahab.signed_msg import SignedMessage
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import Endianness, align, align_block
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)

LITTLE_ENDIAN = "<"
UINT8 = "B"
UINT16 = "H"
UINT32 = "L"
UINT64 = "Q"
RESERVED = 0


class EleMessage:
    """Base class for EdgeLock Enclave message communication.

    This class provides the foundation for creating and managing messages sent to and received from
    the EdgeLock Enclave security subsystem. It handles message structure including headers with
    tag, command ID, size and version fields, as well as memory alignment and addressing for both
    command and response data.

    :cvar TAG: Message tag identifier for commands (0x17).
    :cvar RSP_TAG: Message tag identifier for responses (0xE1).
    :cvar VERSION: Message protocol version (0x06).
    :cvar ELE_MSG_ALIGN: Memory alignment requirement for messages (8 bytes).
    """

    CMD = 0x00
    TAG = 0x17
    RSP_TAG = 0xE1
    VERSION = 0x06
    HEADER_FORMAT = LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8
    MSG_IDS = MessageIDs
    COMMAND_HEADER_WORDS_COUNT = 1
    COMMAND_PAYLOAD_WORDS_COUNT = 0
    RESPONSE_HEADER_WORDS_COUNT = 2
    RESPONSE_PAYLOAD_WORDS_COUNT = 0
    ELE_MSG_ALIGN = 8
    MAX_RESPONSE_DATA_SIZE = 0
    MAX_COMMAND_DATA_SIZE = 0

    def __init__(self) -> None:
        """Initialize ELE message object.

        Initialize all message attributes to their default values including abort code,
        indication, status, buffer address and size, command, and response data size.
        """
        self.abort_code = 0
        self.indication = 0
        self.status = 0
        self.buff_addr = 0
        self.buff_size = 0
        self.command = self.CMD
        self._response_data_size = self.MAX_RESPONSE_DATA_SIZE

    @property
    def command_address(self) -> int:
        """Get command address in target memory space.

        Returns the buffer address aligned to ELE message alignment requirements.

        :return: Aligned command address as integer value.
        """
        return align(self.buff_addr, self.ELE_MSG_ALIGN)

    @property
    def command_words_count(self) -> int:
        """Get the total count of command words.

        Calculates the total number of words in the command by summing the header
        words count and payload words count.

        :return: Total number of words in the command.
        """
        return self.COMMAND_HEADER_WORDS_COUNT + self.COMMAND_PAYLOAD_WORDS_COUNT

    @property
    def has_command_data(self) -> bool:
        """Check if command has additional data.

        :return: True if command has additional data, False otherwise.
        """
        return bool(self.command_data_size > 0)

    @property
    def command_data_address(self) -> int:
        """Get command data address in target memory space.

        Calculates the aligned address where command data should be placed in target memory,
        based on the command address and the number of command words.

        :return: Aligned address for command data placement in target memory.
        """
        return align(self.command_address + self.command_words_count * 4, self.ELE_MSG_ALIGN)

    @property
    def command_data_size(self) -> int:
        """Get the size of command data aligned to ELE message requirements.

        The method calculates the aligned size of command data, using either the actual
        data length or the maximum command data size if no data is present.

        :return: Size of command data aligned to ELE_MSG_ALIGN boundary.
        """
        return align(len(self.command_data) or self.MAX_COMMAND_DATA_SIZE, self.ELE_MSG_ALIGN)

    @property
    def command_data(self) -> bytes:
        """Get command data to be loaded into target memory space.

        :return: Command data as bytes, empty by default.
        """
        return b""

    @property
    def response_address(self) -> int:
        """Get response address in target memory space.

        Calculates the memory address where the response data should be placed,
        considering command data presence and proper alignment requirements.

        :return: Aligned memory address for response data placement.
        """
        if self.has_command_data:
            address = self.command_data_address + self.command_data_size
        else:
            address = self.buff_addr + self.command_words_count * 4
        return align(address, self.ELE_MSG_ALIGN)

    @property
    def response_words_count(self) -> int:
        """Get the total count of response words.

        Calculates the total number of words in the response by summing the header
        words count and payload words count.

        :return: Total number of words in the response message.
        """
        return self.RESPONSE_HEADER_WORDS_COUNT + self.RESPONSE_PAYLOAD_WORDS_COUNT

    @property
    def has_response_data(self) -> bool:
        """Check if response has additional data.

        :return: True if response contains additional data, False otherwise.
        """
        return bool(self.response_data_size > 0)

    @property
    def response_data_address(self) -> int:
        """Get response data address in target memory space.

        Calculates the aligned memory address where response data should be stored,
        based on the response address and the number of response words.

        :return: Aligned memory address for response data storage.
        """
        return align(self.response_address + self.response_words_count * 4, self.ELE_MSG_ALIGN)

    @property
    def response_data_size(self) -> int:
        """Get aligned response data size.

        Returns the response data size aligned to ELE message alignment requirements.

        :return: Aligned response data size in bytes.
        """
        return align(self._response_data_size, self.ELE_MSG_ALIGN)

    @response_data_size.setter
    def response_data_size(self, size: int) -> None:
        """Set response data size in target memory space.

        :param size: Size of the response data in bytes.
        """
        self._response_data_size = size

    @property
    def free_space_address(self) -> int:
        """Get first free address after ELE message in target memory space.

        The method calculates the aligned address that comes after the response data,
        ensuring proper memory alignment according to ELE message requirements.

        :return: Aligned memory address representing the first free location after the ELE message.
        """
        return align(self.response_data_address + self._response_data_size, self.ELE_MSG_ALIGN)

    @property
    def free_space_size(self) -> int:
        """Get free space size after ELE message in target memory space.

        Calculates the available space remaining in the buffer after the ELE message,
        aligned to the required ELE message alignment boundary.

        :return: Size of free space in bytes, aligned to ELE_MSG_ALIGN boundary.
        """
        return align(
            self.buff_size - (self.free_space_address - self.buff_addr), self.ELE_MSG_ALIGN
        )

    @property
    def status_string(self) -> str:
        """Get status in readable string format.

        Converts the response status and indication codes into a human-readable string
        representation for easier debugging and logging purposes.

        :return: Human-readable status string - "Succeeded" for success, "Failed: <indication>"
                 for failures, or "Invalid status!" for unknown status codes.
        """
        if not ResponseStatus.contains(self.status):
            return "Invalid status!"
        if self.status == ResponseStatus.ELE_SUCCESS_IND:
            return "Succeeded"
        indication = (
            ResponseIndication.get_label(self.indication)
            if ResponseIndication.contains(self.indication)
            else f"Invalid indication code: {self.indication:02X}"
        )
        return f"Failed: {indication}"

    def set_buffer_params(self, buff_addr: int, buff_size: int) -> None:
        """Set the communication buffer parameters to allow command update addresses inside command payload.

        :param buff_addr: Real address of communication buffer in target memory space.
        :param buff_size: Size of communication buffer in target memory space.
        :raises SPSDKError: Invalid buffer parameters during validation.
        """
        self.buff_addr = buff_addr
        self.buff_size = buff_size

        self.validate_buffer_params()

    def validate_buffer_params(self) -> None:
        """Validate communication buffer parameters.

        Checks if the communication buffer has sufficient size to accommodate the ELE message
        response data or response words based on the message configuration.

        :raises SPSDKValueError: Invalid buffer parameters - buffer too small for message.
        """
        if self.has_response_data:
            needed_space = self.response_data_address + self.response_data_size
        else:
            needed_space = self.response_address + self.response_words_count * 4

        if self.buff_size < needed_space - self.buff_addr:
            raise SPSDKValueError(
                "ELE Message: Communication buffer is to small to fit message. "
                f"({needed_space-self.buff_addr} > {self.buff_size})"
            )

    def validate(self) -> None:
        """Validate the ELE message structure and content.

        Performs validation checks on the message to ensure it meets the required
        format and contains valid data according to ELE protocol specifications.

        :raises SPSDKError: Invalid message structure or content.
        """

    def header_export(
        self,
    ) -> bytes:
        """Export message header to bytes.

        Converts the message header fields (version, command words count, command, and tag)
        into their binary representation using the predefined header format.

        :return: Bytes representation of message header.
        """
        return pack(
            self.HEADER_FORMAT, self.VERSION, self.command_words_count, self.command, self.TAG
        )

    def export(
        self,
    ) -> bytes:
        """Export message to final bytes array.

        :return: Bytes representation of message object.
        """
        return self.header_export()

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        Parses and validates the response message header and status information.
        The method verifies message tag, command, size, and version fields against
        expected values and extracts status, indication, and abort code.

        :param response: Raw response data bytes from target device.
        :raises SPSDKParsingError: Invalid response format or field values detected.
        """
        # Decode and validate header
        (version, size, command, tag) = unpack(self.HEADER_FORMAT, response[:4])
        if tag != self.RSP_TAG:
            raise SPSDKParsingError(f"Message TAG in response is invalid: {hex(tag)}")
        if command != self.command:
            raise SPSDKParsingError(f"Message COMMAND in response is invalid: {hex(command)}")
        if size not in range(self.RESPONSE_HEADER_WORDS_COUNT, self.response_words_count + 1):
            raise SPSDKParsingError(f"Message SIZE in response is invalid: {hex(size)}")
        if version != self.VERSION:
            raise SPSDKParsingError(f"Message VERSION in response is invalid: {hex(version)}")

        # Decode status word
        (
            self.status,
            self.indication,
            self.abort_code,
        ) = unpack(LITTLE_ENDIAN + UINT8 + UINT8 + UINT16, response[4:8])

    def decode_response_data(self, response_data: bytes) -> None:
        """Decode response data from target.

        The response data are specific per command and will be processed according to the
        command's expected response format.

        :param response_data: Raw response data bytes received from the target device.
        """

    def __eq__(self, other: object) -> bool:
        """Check equality between two EleMessage objects.

        Compares TAG, command, VERSION, and command_words_count attributes to determine
        if two EleMessage instances are equal.

        :param other: Object to compare with this EleMessage instance.
        :return: True if objects are equal EleMessage instances with matching attributes,
                 False otherwise.
        """
        if isinstance(other, EleMessage):
            if (
                self.TAG == other.TAG
                and self.command == other.command
                and self.VERSION == other.VERSION
                and self.command_words_count == other.command_words_count
            ):
                return True

        return False

    @staticmethod
    def get_msg_crc(payload: bytes) -> bytes:
        """Compute message CRC.

        The method calculates CRC using XOR operation on 4-byte chunks of the input payload.
        All data must be properly aligned to 4-byte boundaries for correct computation.

        :param payload: The input data to compute CRC on. Must be 4 bytes aligned.
        :raises SPSDKValueError: Payload is not 4 bytes aligned.
        :return: 4 bytes of CRC in little endian format.
        """
        if len(payload) % 4 != 0:
            raise SPSDKValueError("Payload must be 4 bytes aligned")
        res = 0
        for i in range(0, len(payload), 4):
            res ^= int.from_bytes(payload[i : i + 4], Endianness.LITTLE.value)
        return res.to_bytes(4, Endianness.LITTLE.value)

    def response_status(self) -> str:
        """Get response status information as formatted string.

        Formats the response status with detailed failure information including
        indication and abort code when applicable.

        :return: Formatted string containing response status details.
        """
        ret = f"Response status: {ResponseStatus.get_label(self.status)}\n"
        if self.status == ResponseStatus.ELE_FAILURE_IND:
            ret += (
                f"   Response indication: {ResponseIndication.get_label(self.indication)}"
                f" - ({hex(self.indication)})\n"
            )
            ret += f"   Response abort code: {hex(self.abort_code)}\n"
        return ret

    def info(self) -> str:
        """Get message information including live data.

        Returns a formatted string containing command details, word counts,
        data flags, and response status information.

        :return: Formatted string with comprehensive message information.
        """
        ret = f"Command:         {self.MSG_IDS.get_label(self.command)} - ({hex(self.command)})\n"
        ret += f"Command words:   {self.command_words_count}\n"
        ret += f"Command data:    {self.has_command_data}\n"
        ret += f"Response words:  {self.response_words_count}\n"
        ret += f"Response data:   {self.has_response_data}\n"
        # if self.status in ResponseStatus:
        ret += self.response_status()

        return ret


class EleMessagePing(EleMessage):
    """ELE Message Ping command implementation.

    This class represents a ping message used to test communication with the EdgeLock Enclave (ELE).
    The ping command is typically used for connectivity verification and basic health checks.

    :cvar CMD: Command identifier for ping request message.
    """

    CMD = MessageIDs.PING_REQ.tag


class EleMessageDumpDebugBuffer(EleMessage):
    """ELE Message for dumping EdgeLock Secure Enclave debug buffer.

    This class handles retrieval of debug logs from the EdgeLock Secure Enclave's
    internal logging mechanism. Logs are transmitted over MU interface with a maximum
    of 20 logs per exchange. Multiple calls may be required to retrieve all logs
    when the ELE buffer contains more than 20 entries.

    :cvar CMD: Command identifier for debug buffer dump request.
    :cvar RESPONSE_PAYLOAD_WORDS_COUNT: Maximum response length in words.
    :cvar ELE_DEBUG_LOG_MAX_RSP_LENGTH: Maximum response length constant.
    """

    CMD = MessageIDs.ELE_DUMP_DEBUG_BUFFER_REQ.tag
    RESPONSE_PAYLOAD_WORDS_COUNT = 21  # Maximum response length
    ELE_DEBUG_LOG_MAX_RSP_LENGTH = 0x17  # Maximum response length constant

    def __init__(self) -> None:
        """Initialize ELE message object.

        Initializes the ELE (EdgeLock Enclave) message with empty debug words list,
        zero log count, and sets the more logs flag to False.
        """
        super().__init__()
        self.debug_words: list[int] = []
        self.nb_logs = 0
        self.has_more_logs = False

    def decode_response(self, response: bytes) -> None:
        """Decode response from target containing debug log data.

        This method parses the ELE debug log response, extracting debug words and handling
        CRC verification when present. It determines if more logs are available and validates
        the message integrity.

        :param response: Raw response data bytes from the target device.
        :raises SPSDKParsingError: When response parsing fails or CRC verification fails.
        """
        super().decode_response(response)

        # Get response length from MU header (size field)
        rsp_length = (int.from_bytes(response[0:4], "little") & 0xFF00) >> 8

        # Calculate number of logs: remove header (2 words) and response indicator (0 words for payload calculation)
        self.nb_logs = rsp_length - 2

        # Check if CRC is present (response length > 4 words means CRC is included)
        has_crc = rsp_length > 4
        if has_crc:
            self.nb_logs -= 1  # Remove CRC word from log count

        # Check if there are more logs to fetch
        self.has_more_logs = rsp_length == self.ELE_DEBUG_LOG_MAX_RSP_LENGTH

        # Extract debug words (maximum 20 logs)
        max_debug_words = min(self.nb_logs, 20)
        if max_debug_words > 0:
            debug_data_end = 8 + (max_debug_words * 4)
            if has_crc:
                # Extract debug words and CRC
                *self.debug_words, crc = unpack(
                    LITTLE_ENDIAN + f"{max_debug_words}L4s", response[8 : debug_data_end + 4]
                )
                # Verify CRC
                crc_computed = self.get_msg_crc(response[0:debug_data_end])
                if crc != crc_computed:
                    raise SPSDKParsingError("Invalid message CRC for dump debug buffer")
            else:
                # Extract debug words without CRC
                self.debug_words = list(
                    unpack(LITTLE_ENDIAN + f"{max_debug_words}L", response[8:debug_data_end])
                )
        else:
            self.debug_words = []

    def response_info(self) -> str:
        """Get formatted debug buffer information in STEC team format.

        Formats the debug buffer data into a human-readable string following the STEC team
        format specification. The logs are displayed in pairs with hexadecimal formatting,
        and includes metadata about log count and availability of additional logs.

        :return: Formatted string containing debug log information, log count, and availability status.
        """
        if not self.debug_words:
            return "No debug logs available\n"

        ret = f"Number of logs: {self.nb_logs}\n"
        ret += f"More logs available: {'Yes' if self.has_more_logs else 'No'}\n"
        ret += "Debug logs (STEC format):\n"

        # Dump MU logs 2 by 2 as specified in the C example
        for i in range(0, len(self.debug_words), 2):
            if i + 1 < len(self.debug_words):
                # Print pair of logs in STEC format
                ret += f"S40X: 0x{self.debug_words[i]:x} 0x{self.debug_words[i + 1]:x}\n"
            else:
                # Handle odd number of logs
                ret += f"S40X: 0x{self.debug_words[i]:x}\n"

        if self.has_more_logs:
            ret += "\nNote: More logs available. Call dump-debug-buffer again to retrieve remaining logs.\n"

        return ret

    def get_debug_logs(self) -> list[int]:
        """Get the debug log words.

        :return: List of debug log words.
        """
        return self.debug_words.copy()

    def has_more_logs_available(self) -> bool:
        """Check if more logs are available to fetch.

        :return: True if more logs are available, False otherwise.
        """
        return self.has_more_logs

    def get_log_count(self) -> int:
        """Get the number of logs in current response.

        :return: Number of logs.
        """
        return self.nb_logs


class EleMessageReset(EleMessage):
    """ELE Message Reset command handler.

    This class implements the ELE (EdgeLock Enclave) reset message functionality,
    providing the ability to send reset requests to the ELE subsystem.

    :cvar CMD: Command identifier for reset request operations.
    :cvar RESPONSE_HEADER_WORDS_COUNT: Number of header words in reset response.
    """

    CMD = MessageIDs.RESET_REQ.tag
    RESPONSE_HEADER_WORDS_COUNT = 0


class EleMessageEleFwAuthenticate(EleMessage):
    """ELE firmware authentication request message.

    This class represents a message used to request authentication of ELE (EdgeLock Enclave)
    firmware. It handles the communication protocol for authenticating firmware loaded at a
    specific memory address in the target device.

    :cvar CMD: Message command identifier for ELE firmware authentication request.
    :cvar COMMAND_PAYLOAD_WORDS_COUNT: Number of payload words in the command message.
    """

    CMD = MessageIDs.ELE_FW_AUTH_REQ.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 3

    def __init__(self, ele_fw_address: int) -> None:
        """Initialize ELE message with firmware address.

        Be aware to have ELE FW in accessible memory for ROM, and
        do not use the RAM memory used to communicate with ELE.

        :param ele_fw_address: Address in target memory with ELE firmware.
        """
        super().__init__()
        self.ele_fw_address = ele_fw_address

    def export(self) -> bytes:
        """Export message to final bytes array.

        The method serializes the message object into a binary format by combining
        the exported header with packed firmware address data.

        :return: Bytes representation of message object.
        """
        ret = self.header_export()
        ret += pack(
            LITTLE_ENDIAN + UINT32 + UINT32 + UINT32, self.ele_fw_address, 0, self.ele_fw_address
        )
        return ret


class EleMessageOemContainerAuthenticate(EleMessage):
    """ELE message for OEM container authentication request.

    This class represents a message used to request authentication of an OEM container
    in the EdgeLock Enclave (ELE) system. It handles the formatting and export of
    authentication requests with the specified container address.

    :cvar CMD: Command identifier for OEM container authentication request.
    :cvar COMMAND_PAYLOAD_WORDS_COUNT: Number of payload words in the command.
    """

    CMD = MessageIDs.ELE_OEM_CNTN_AUTH_REQ.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 2

    def __init__(self, oem_cntn_addr: int) -> None:
        """Initialize OEM container message with target memory address.

        Be aware to have OEM Container in accessible memory for ROM.

        :param oem_cntn_addr: Address in target memory with OEM container.
        """
        super().__init__()
        self.oem_cntn_addr = oem_cntn_addr

    def export(self) -> bytes:
        """Export message to final bytes array.

        The method combines the header export with packed OEM container address
        to create the complete message representation.

        :return: Bytes representation of message object.
        """
        ret = self.header_export()
        ret += pack(LITTLE_ENDIAN + UINT32 + UINT32, 0, self.oem_cntn_addr)
        return ret


class EleMessageVerifyImage(EleMessage):
    """ELE message for verifying image integrity.

    This class implements the ELE Verify Image request message that commands the ELE
    to check the hash on one or more images after a container has been loaded into
    memory and processed with an Authenticate Container message.

    :cvar CMD: Message command identifier for verify image request.
    :cvar COMMAND_PAYLOAD_WORDS_COUNT: Number of payload words in command.
    :cvar RESPONSE_PAYLOAD_WORDS_COUNT: Number of payload words in response.
    """

    CMD = MessageIDs.ELE_VERIFY_IMAGE_REQ.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 1
    RESPONSE_PAYLOAD_WORDS_COUNT = 2

    def __init__(self, image_mask: int = 0x0000_0001) -> None:
        """Initialize Verify Image message.

        The Verify Image message is sent to the ELE after a container has been
        loaded into memory and processed with an Authenticate Container message.
        This commands the ELE to check the hash on one or more images.

        :param image_mask: Bitmask indicating which images to check. Each bit corresponds
            to a particular image index in the header (bit 0 for image 0, bit 1 for image 1, etc.).
            At least one image must be specified.
        """
        super().__init__()
        self.image_mask = image_mask
        self.valid_image_mask = 0
        self.invalid_image_mask = 0xFFFF_FFFF

    def export(self) -> bytes:
        """Export message to bytes array.

        Converts the message object into its binary representation by combining
        the exported header with the image mask field.

        :return: Binary representation of the message object.
        """
        ret = self.header_export()
        ret += pack(LITTLE_ENDIAN + UINT32, self.image_mask)
        return ret

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        Parses the response data to extract valid and invalid image masks, then validates
        that the combined masks match the originally requested image mask for checking.

        :param response: Raw response data bytes from the target device.
        :raises SPSDKParsingError: Response parse detect some error.
        """
        super().decode_response(response)
        self.valid_image_mask, self.invalid_image_mask = unpack(
            LITTLE_ENDIAN + "LL", response[8:16]
        )
        checked_mask = self.valid_image_mask | self.invalid_image_mask
        if self.image_mask != checked_mask:
            logger.error(
                "The invalid&valid mask doesn't cover requested mask to check! "
                f"valid: 0x{self.valid_image_mask:08X} | invalid: 0x{self.invalid_image_mask:08X}"
                f" != requested: 0x{self.image_mask:08X}"
            )

    def response_info(self) -> str:
        """Get response information as formatted string.

        Formats the valid and invalid image masks into a human-readable string
        representation with hexadecimal values.

        :return: Formatted string containing valid and invalid image mask information.
        """
        ret = f"Valid image mask    : 0x{self.valid_image_mask:08X}\n"
        ret += f"Invalid image mask  : 0x{self.invalid_image_mask:08X}"
        return ret


class EleMessageReleaseContainer(EleMessage):
    """ELE Message for releasing a container.

    This class represents an ELE (EdgeLock Enclave) message used to release
    a previously loaded container from the secure enclave memory.

    :cvar CMD: Command identifier for the release container request.
    """

    CMD = MessageIDs.ELE_RELEASE_CONTAINER_REQ.tag


class EleMessageForwardLifeCycleUpdate(EleMessage):
    """ELE message for forwarding life cycle update requests.

    This class represents a message used to request a life cycle state transition
    in the EdgeLock Enclave. The operation is non-revertible and changes the
    device's security state permanently.

    :cvar CMD: Command identifier for life cycle update requests.
    :cvar COMMAND_PAYLOAD_WORDS_COUNT: Number of payload words in the message.
    """

    CMD = MessageIDs.ELE_FWD_LIFECYCLE_UP_REQ.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 1

    def __init__(self, lifecycle_update: LifeCycleToSwitch) -> None:
        """Initialize lifecycle update message.

        Be aware that this is non-revertible operation.

        :param lifecycle_update: New life cycle value to switch to.
        """
        super().__init__()
        self.lifecycle_update = lifecycle_update

    def export(self) -> bytes:
        """Export message to bytes array representation.

        Converts the message object into its binary format by combining the header
        and lifecycle update data with proper padding.

        :return: Binary representation of the complete message.
        """
        ret = self.header_export()
        ret += pack(LITTLE_ENDIAN + UINT16 + UINT8 + UINT8, self.lifecycle_update.tag, 0, 0)
        return ret


class EleMessageGetEvents(EleMessage):
    """ELE message for retrieving system events from EdgeLock Enclave.

    This class handles requests to get singular events that have occurred since the firmware
    started. Events include command failures and successful commands with indications (warnings).
    The EdgeLock Enclave stores events in a fixed-size buffer, and when capacity is exceeded,
    new events are lost. The complete event buffer is always returned regardless of actual
    event count.
    Event layout:
    -------------------------
    - TAG - CMD - IND - STS -
    -------------------------

    :cvar CMD: Command identifier for get events request.
    :cvar RESPONSE_PAYLOAD_WORDS_COUNT: Expected response payload size in words.
    :cvar MAX_EVENT_CNT: Maximum number of events that can be stored.
    """

    CMD = MessageIDs.ELE_GET_EVENTS_REQ.tag
    RESPONSE_PAYLOAD_WORDS_COUNT = 10

    MAX_EVENT_CNT = 8

    def __init__(self) -> None:
        """Initialize ELE message for retrieving singular events.

        This message is used to retrieve any singular event that has occurred since the FW has
        started. A singular event occurs when the second word of a response to any request is
        different from ELE_SUCCESS_IND. That includes commands with failure response as well as
        commands with successful response containing an indication (i.e. warning response).
        The events are stored by the ELE in a fixed sized buffer. When the capacity of the buffer
        is exceeded, new occurring events are lost.
        The event buffer is systematically returned in full to the requester independently of
        the actual numbers of events stored.
        """
        super().__init__()
        self.event_cnt = 0
        self.events: list[int] = [0] * self.MAX_EVENT_CNT

    def decode_response(self, response: bytes) -> None:
        """Decode response from target device.

        Parses the response data to extract event count, maximum events, individual events,
        and validates the CRC checksum. Logs errors if maximum event count doesn't match
        expected value or if CRC validation fails.

        :param response: Raw response data bytes from the target device.
        :raises SPSDKParsingError: Response parsing detects an error or invalid data format.
        """
        super().decode_response(response)
        self.event_cnt, max_events, *self.events, crc = unpack(
            LITTLE_ENDIAN + UINT16 + UINT16 + "8L4s", response[8:48]
        )
        if max_events != self.MAX_EVENT_CNT:
            logger.error(f"Invalid maximal events count: {max_events}!={self.MAX_EVENT_CNT}")

        crc_computed = self.get_msg_crc(response[0:44])
        if crc != crc_computed:
            logger.error("Invalid message CRC for get events message")

    @staticmethod
    def get_ipc_id(event: int) -> str:
        """Get IPC ID in string from event.

        Extracts the IPC (Inter-Processor Communication) ID from the event value by shifting
        and masking bits, then converts it to a human-readable string description.

        :param event: Event value containing the IPC ID in bits 24-31.
        :return: String description of the IPC ID or empty string if not found.
        """
        ipc_id = (event >> 24) & 0xFF
        return MessageUnitId.get_description(ipc_id, f"Unknown MU: ({ipc_id})") or ""

    @staticmethod
    def get_cmd(event: int) -> str:
        """Get Command in string from event.

        Extracts the command field from an event value and returns its string description.

        :param event: Event value containing command information in bits 16-23.
        :return: String description of the command or empty string if not found.
        """
        cmd = (event >> 16) & 0xFF
        return MessageIDs.get_description(cmd, f"Unknown Command: (0x{cmd:02})") or ""

    @staticmethod
    def get_ind(event: int) -> str:
        """Get indication string from event value.

        Extracts the indication bits from the event value and converts them to a human-readable
        string description.

        :param event: Event value containing indication bits in bits 8-15.
        :return: String description of the indication or empty string if not found.
        """
        ind = (event >> 8) & 0xFF
        return ResponseIndication.get_description(ind, f"Unknown Indication: (0x{ind:02})") or ""

    @staticmethod
    def get_sts(event: int) -> str:
        """Get status string representation from event code.

        Extracts the status code from the lower 8 bits of the event and converts it to a
        human-readable string description.

        :param event: Event code containing status information in lower 8 bits.
        :return: String description of the status code, or empty string if conversion fails.
        """
        sts = event & 0xFF
        return ResponseStatus.get_description(sts, f"Unknown Status: (0x{sts:02})") or ""

    def response_info(self) -> str:
        """Get formatted string with events information.

        Formats and returns a string containing detailed information about all events,
        including event count, IPC ID, command, indication, and status for each event.
        If the event count exceeds the maximum supported limit, only the first events
        up to the limit are displayed with a warning message.

        :return: Formatted string with events information.
        """
        ret = f"Event count:     {self.event_cnt}"
        for i, event in enumerate(self.events[: min(self.event_cnt, self.MAX_EVENT_CNT)]):
            ret += f"\nEvent[{i}]:      0x{event:08X}"
            ret += f"\n  IPC ID:        {self.get_ipc_id(event)}"
            ret += f"\n  Command:       {self.get_cmd(event)}"
            ret += f"\n  Indication:    {self.get_ind(event)}"
            ret += f"\n  Status:        {self.get_sts(event)}"
        if self.event_cnt > self.MAX_EVENT_CNT:
            ret += "\nEvent count is bigger than maximal supported, "
            ret += f"only first {self.MAX_EVENT_CNT} events are listed."
        return ret


class EleMessageStartTrng(EleMessage):
    """ELE Message for starting the True Random Number Generator.

    This class represents a command message used to initiate the hardware-based
    True Random Number Generator (TRNG) in ELE (EdgeLock Enclave) secure subsystem.

    :cvar CMD: Command identifier for the start TRNG request message.
    """

    CMD = MessageIDs.START_RNG_REQ.tag


class EleMessageGetTrngState(EleMessage):
    """ELE Message for retrieving True Random Number Generator state.

    This class handles communication with EdgeLock Enclave to query the current
    state of both the TRNG (True Random Number Generator) and CSAL (Cryptographic
    Secure Application Library) components. It decodes the response to provide
    readable state information for both random number generation subsystems.

    :cvar CMD: Command identifier for TRNG state request.
    :cvar RESPONSE_PAYLOAD_WORDS_COUNT: Expected response payload size in words.
    """

    CMD = MessageIDs.GET_TRNG_STATE_REQ.tag
    RESPONSE_PAYLOAD_WORDS_COUNT = 1

    def __init__(self) -> None:
        """Initialize ELE message object.

        Sets up the ELE message with default TRNG state set to ELE_TRNG_PROGRAM
        and CSAL state set to ELE_CSAL_NOT_READY.
        """
        super().__init__()
        self.ele_trng_state = EleTrngState.ELE_TRNG_PROGRAM.tag
        self.ele_csal_state = EleCsalState.ELE_CSAL_NOT_READY.tag

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        This method parses the response bytes and extracts ELE TRNG state and CSAL state
        from the last 4 bytes of the response data.

        :param response: Raw response data bytes received from the target device.
        :raises SPSDKParsingError: Response parsing detected an error or invalid format.
        """
        super().decode_response(response)
        self.ele_trng_state, self.ele_csal_state, _ = unpack(
            LITTLE_ENDIAN + UINT8 + UINT8 + "2s", response[-4:]
        )

    def response_info(self) -> str:
        """Get EdgeLock Enclave response information.

        Returns formatted string containing the current state of EdgeLock Enclave TRNG
        and EdgeLock Secure Enclave RNG components.

        :return: Formatted string with TRNG and RNG state information.
        """
        return (
            f"EdgeLock Enclave TRNG state: {EleTrngState.get_description(self.ele_trng_state)}"
            + f"\nEdgeLock Secure Enclave RNG state: {EleCsalState.get_description(self.ele_csal_state)}"
        )


class EleMessageCommit(EleMessage):
    """ELE Message Commit command handler.

    This class implements the ELE commit message functionality for committing
    various types of information to the EdgeLock Enclave. It manages the
    creation of commit requests and processing of responses, including
    validation of which information was successfully committed.

    :cvar CMD: Command identifier for ELE commit request.
    :cvar COMMAND_PAYLOAD_WORDS_COUNT: Number of payload words in command.
    :cvar RESPONSE_PAYLOAD_WORDS_COUNT: Number of payload words in response.
    """

    CMD = MessageIDs.ELE_COMMIT_REQ.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 1
    RESPONSE_PAYLOAD_WORDS_COUNT = 1

    def __init__(self, info_to_commit: list[EleInfo2Commit]) -> None:
        """Initialize ELE message with information to commit.

        :param info_to_commit: List of ELE information objects that need to be committed.
        """
        super().__init__()
        self.info_to_commit = info_to_commit

    @property
    def info2commit_mask(self) -> int:
        """Get info to commit mask used in command.

        This method iterates through all info_to_commit rules and combines their tags
        using bitwise OR operation to create a composite mask value.

        :return: Combined bitmask of all info to commit rule tags.
        """
        ret = 0
        for rule in self.info_to_commit:
            ret |= rule.tag
        return ret

    def mask_to_info2commit(self, mask: int) -> list[EleInfo2Commit]:
        """Get list of info to commit from mask.

        Converts a bitmask into a list of EleInfo2Commit objects by checking each bit
        position and creating corresponding commit info objects.

        :param mask: Bitmask where each bit represents a specific info to commit.
        :return: List of EleInfo2Commit objects corresponding to set bits in the mask.
        """
        ret = []
        for bit in range(32):
            bit_mask = 1 << bit
            if mask and bit_mask:
                ret.append(EleInfo2Commit.from_tag(bit))
        return ret

    def export(self) -> bytes:
        """Export message to bytes array.

        Converts the message object into its binary representation by combining
        the exported header with the info2commit_mask field.

        :return: Binary representation of the message object.
        """
        ret = self.header_export()
        ret += pack(LITTLE_ENDIAN + UINT32, self.info2commit_mask)
        return ret

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        This method processes the response data and validates the commit mask against
        the expected information to commit. If there's a mismatch, it logs a warning
        about which information was actually committed versus what was requested.

        :param response: Raw response data bytes from the target device.
        :raises SPSDKParsingError: Response parsing detects an error.
        """
        super().decode_response(response)
        mask = int.from_bytes(response[8:12], Endianness.LITTLE.value)
        if mask != self.info2commit_mask:
            warning_message = (
                "Only the following information has been committed: "
                + f"{[x.label for x in self.mask_to_info2commit(mask)]},"
                + f" out of the provided information: {[x.label for x in self.info_to_commit]}"
            )
            logger.warning(warning_message)


class EleMessageGetFwStatus(EleMessage):
    """ELE Message for retrieving EdgeLock Enclave firmware status.

    This class implements the GET_FW_STATUS_REQ message command to query and decode
    the current firmware status of the EdgeLock Enclave security subsystem.

    :cvar CMD: Message command identifier for firmware status request.
    :cvar RESPONSE_PAYLOAD_WORDS_COUNT: Expected response payload size in words.
    """

    CMD = MessageIDs.GET_FW_STATUS_REQ.tag
    RESPONSE_PAYLOAD_WORDS_COUNT = 1

    def __init__(self) -> None:
        """Initialize ELE message object.

        Sets up the ELE message with default firmware status indicating that ELE firmware
        is not in place.
        """
        super().__init__()
        self.ele_fw_status = EleFwStatus.ELE_FW_STATUS_NOT_IN_PLACE.tag

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        The method parses the response bytes and extracts the ELE firmware status
        from the response data using little-endian byte order.

        :param response: Raw response data bytes received from the target device.
        :raises SPSDKParsingError: Response parsing detects an error in the data format.
        """
        super().decode_response(response)
        self.ele_fw_status, _ = unpack(LITTLE_ENDIAN + UINT8 + "3s", response[8:12])

    def response_info(self) -> str:
        """Get EdgeLock Enclave firmware status information.

        Returns a formatted string containing the current firmware state of the EdgeLock Enclave,
        providing human-readable status information for debugging and monitoring purposes.

        :return: Formatted string with ELE firmware status information.
        """
        return f"EdgeLock Enclave firmware state: {EleFwStatus.get_label(self.ele_fw_status)}"


class EleMessageGetFwVersion(EleMessage):
    """ELE Message for retrieving EdgeLock Enclave firmware version information.

    This class handles communication with the EdgeLock Enclave to request and process
    firmware version data, including version numbers and commit SHA1 information.

    :cvar CMD: Command identifier for firmware version request.
    :cvar RESPONSE_PAYLOAD_WORDS_COUNT: Expected response payload size in words.
    """

    CMD = MessageIDs.GET_FW_VERSION_REQ.tag
    RESPONSE_PAYLOAD_WORDS_COUNT = 2

    def __init__(self) -> None:
        """Initialize ELE message object.

        Sets up the ELE message instance with default firmware version attributes
        initialized to zero.
        """
        super().__init__()
        self.ele_fw_version_raw = 0
        self.ele_fw_version_sha1 = 0

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        Parses the response bytes to extract ELE firmware version information including
        the raw version and SHA1 hash values.

        :param response: Response data bytes from the target device.
        :raises SPSDKParsingError: Response parsing detected an error.
        """
        super().decode_response(response)
        self.ele_fw_version_raw = int.from_bytes(response[8:12], Endianness.LITTLE.value)
        self.ele_fw_version_sha1 = int.from_bytes(response[12:16], Endianness.LITTLE.value)

    def response_info(self) -> str:
        """Get EdgeLock Enclave firmware version information.

        Formats the ELE firmware version data into a human-readable string containing
        the firmware version in both raw hexadecimal and readable format, commit SHA1,
        and build status information.

        :return: Formatted string with ELE firmware version details.
        """
        ret = (
            f"EdgeLock Enclave firmware version: {self.ele_fw_version_raw:08X}\n"
            f"Readable form: {(self.ele_fw_version_raw>>16) & 0xff}."
            f"{(self.ele_fw_version_raw>>4) & 0xfff}.{self.ele_fw_version_raw & 0xf}\n"
            f"Commit SHA1 (First 4 bytes): {self.ele_fw_version_sha1:08X}"
        )
        if self.ele_fw_version_raw & 1 << 31:
            ret += "\nDirty build"
        return ret


class EleMessageReadCommonFuse(EleMessage):
    """ELE Message for reading common fuse values.

    This class implements the ELE (EdgeLock Enclave) message protocol for reading
    common fuse data from the target device. It handles the command formatting,
    response parsing, and provides access to the retrieved fuse value.

    :cvar CMD: Command identifier for read common fuse operation.
    :cvar COMMAND_PAYLOAD_WORDS_COUNT: Number of payload words in command.
    :cvar RESPONSE_PAYLOAD_WORDS_COUNT: Number of payload words in response.
    """

    CMD = MessageIDs.READ_COMMON_FUSE.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 1
    RESPONSE_PAYLOAD_WORDS_COUNT = 1

    def __init__(self, index: int) -> None:
        """Initialize ELE message for reading common fuse.

        Creates a new instance to read a specific fuse by its index identifier.

        :param index: Fuse identifier to read.
        """
        super().__init__()
        self.index = index
        self.fuse_value = 0

    def export(self) -> bytes:
        """Export message to bytes array representation.

        The method serializes the message object into a binary format by combining
        the exported header with the message index and padding.

        :return: Binary representation of the message object.
        """
        ret = self.header_export()
        ret += pack(LITTLE_ENDIAN + UINT16 + UINT16, self.index, 0)
        return ret

    def decode_response(self, response: bytes) -> None:
        """Decode response from target and extract fuse value.

        The method parses the response bytes and extracts the fuse value from bytes 8-12
        using little-endian byte order.

        :param response: Response data bytes from the target device.
        :raises SPSDKParsingError: Response parsing detected an error.
        """
        super().decode_response(response)
        self.fuse_value = int.from_bytes(response[8:12], Endianness.LITTLE.value)

    def response_info(self) -> str:
        """Get response information for fuse read operation.

        Formats the fuse ID and its value into a human-readable string representation
        for display purposes.

        :return: Formatted string containing fuse ID and value in hexadecimal format.
        """
        return f"Fuse ID_{self.index}: 0x{self.fuse_value:08X}\n"


class EleMessageReadShadowFuse(EleMessageReadCommonFuse):
    """ELE Message for reading shadow fuse values.

    This class represents an ELE (EdgeLock Enclave) message specifically designed
    for reading shadow fuse data from the device. Shadow fuses are temporary
    storage locations that mirror the actual fuse values.

    :cvar CMD: Message command identifier for shadow fuse read operations.
    """

    CMD = MessageIDs.READ_SHADOW_FUSE.tag

    def export(self) -> bytes:
        """Export message to bytes array.

        Converts the message object into its binary representation by combining
        the exported header with the packed index value.

        :return: Binary representation of the message object.
        """
        ret = self.header_export()
        ret += pack(LITTLE_ENDIAN + UINT32, self.index)
        return ret


class EleMessageGetInfo(EleMessage):
    """ELE Message for retrieving device information.

    This class implements the GET_INFO command for EdgeLock Enclave (ELE) communication,
    allowing retrieval of comprehensive device information including SoC details, lifecycle
    state, security configuration, and cryptographic hashes.

    :cvar CMD: Command identifier for GET_INFO request.
    :cvar COMMAND_PAYLOAD_WORDS_COUNT: Number of payload words in the command.
    :cvar MAX_RESPONSE_DATA_SIZE: Maximum size of response data in bytes.
    """

    CMD = MessageIDs.GET_INFO_REQ.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 3
    MAX_RESPONSE_DATA_SIZE = 256

    def __init__(self) -> None:
        """Initialize ELE message object with default values.

        Sets up all information fields to their default states including version info,
        SOC details, lifecycle state, security subsystem state, attestation version,
        UUID, hash values, and various state indicators.
        """
        super().__init__()
        self.info_length = 0
        self.info_version = 0
        self.info_cmd = 0
        self.info_soc_rev = 0
        self.info_soc_id = 0
        self.info_life_cycle = 0
        self.info_sssm_state = 0
        self.info_attest_api_version = 0
        self.info_uuid = bytes()
        self.info_sha256_rom_patch = bytes()
        self.info_sha256_fw = bytes()
        self.info_oem_srkh = bytes()
        self.info_imem_state = 0
        self.info_csal_state = 0
        self.info_trng_state = 0
        self.info_oem_pqc_srkh = bytes()

    def export(self) -> bytes:
        """Export message to bytes array.

        Converts the message object into its binary representation by packing
        the payload data and combining it with the exported header.

        :return: Binary representation of the message object.
        """
        payload = pack(
            LITTLE_ENDIAN + UINT32 + UINT32 + UINT16 + UINT16,
            0,
            self.response_data_address,
            self.response_data_size,
            0,
        )
        return self.header_export() + payload

    def decode_response_data(self, response_data: bytes) -> None:
        """Decode response data from target and populate info attributes.

        Parses the binary response data according to ELE message format and extracts
        various system information fields including SoC details, lifecycle state,
        cryptographic hashes, and security states.

        :param response_data: Binary response data from ELE target device.
        :raises struct.error: If response_data is too short or malformed.
        """
        # Word 0: Length(31-24), Version(23-16), Command(15-8), Reserved(7-0)
        word0 = unpack(LITTLE_ENDIAN + UINT32, response_data[0:4])[0]
        self.info_cmd = word0 & 0xFF
        self.info_version = (word0 >> 8) & 0xFF
        self.info_length = (word0 >> 16) & 0xFFFF
        # Word 1: Soc_rev(31-16), Soc_id(15-0)
        word1 = unpack(LITTLE_ENDIAN + UINT32, response_data[4:8])[0]
        self.info_soc_id = word1 & 0xFFFF
        self.info_soc_rev = (word1 >> 16) & 0xFFFF
        # Word 2: Attest API version(31-24), sssm_state(23-16), Lifecycle(15-0)
        word2 = unpack(LITTLE_ENDIAN + UINT32, response_data[8:12])[0]
        self.info_life_cycle = word2 & 0xFFFF
        self.info_sssm_state = (word2 >> 16) & 0xFF
        self.info_attest_api_version = (word2 >> 24) & 0xFF
        # Words 3-6: UID (128 bits / 16 bytes)
        self.info_uuid = response_data[12:28]
        # Words 7-14: Sha256 rom patch (256 bits / 32 bytes)
        self.info_sha256_rom_patch = response_data[28:60]
        # Words 15-22: Sha fw (256 bits / 32 bytes)
        self.info_sha256_fw = response_data[60:92]
        # Words 23-38: OEM SRKH (512 bits / 64 bytes)
        self.info_oem_srkh = response_data[92:156]
        # Word 39: Reserved(31-16), IMEM state (23-16), CSAL state(15-8), TRNG state(7-0)
        word39 = unpack(LITTLE_ENDIAN + UINT32, response_data[156:160])[0]
        self.info_trng_state = word39 & 0xFF
        self.info_csal_state = (word39 >> 8) & 0xFF
        self.info_imem_state = (word39 >> 16) & 0xFF
        # Reserved bits 31-16 can be stored if needed
        # Words 40-55: OEM PQC SRKH (512 bits / 64 bytes)
        if len(response_data) > 160:
            self.info_oem_pqc_srkh = response_data[160:224]
        else:
            self.info_oem_pqc_srkh = bytes()

    def response_info(self) -> str:
        """Get formatted ELE response information.

        Formats and returns comprehensive information about the ELE (EdgeLock Enclave)
        including command details, version, SoC information, life cycle state, security
        states, and cryptographic hashes in a human-readable string format.

        :return: Formatted string containing detailed ELE information including command,
            version, SoC details, life cycle, security states, and hashes.
        """
        ret = f"Command:              {hex(self.info_cmd)}\n"
        ret += f"Version:              {self.info_version}\n"
        ret += f"Length:               {self.info_length}\n"
        ret += f"SoC ID:               {SocId.get_label(self.info_soc_id)} - 0x{self.info_soc_id:04X}\n"
        ret += f"SoC version:          {self.info_soc_rev:04X}\n"
        ret += f"Life Cycle:           {LifeCycle.get_label(self.info_life_cycle)} - 0x{self.info_life_cycle:04X}\n"
        ret += f"SSSM state:           {self.info_sssm_state}\n"
        ret += f"Attest API version:   {self.info_attest_api_version}\n"

        ret += f"UUID:                 {self.info_uuid.hex()}\n"
        ret += f"SHA256 ROM PATCH:     {self.info_sha256_rom_patch.hex()}\n"
        ret += f"SHA256 FW:            {self.info_sha256_fw.hex()}\n"

        ret += "Advanced information:\n"

        if self.info_oem_srkh[32:] == b"\x00" * 32:
            ret += f"  OEM SRKH:           {self.info_oem_srkh[:32].hex()}\n"
        else:
            ret += f"  OEM SRKH:           {self.info_oem_srkh.hex()}\n"
        if self.info_version <= 0x02:
            ret += (
                f"  IMEM state:         "
                f"{EleImemState.get_description(self.info_imem_state, str(self.info_imem_state))}"
                f" - 0x{self.info_imem_state:02X}\n"
            )
        ret += (
            f"  CSAL state:         "
            f"{EleCsalState.get_description(self.info_csal_state, str(self.info_csal_state))}"
            f" - 0x{self.info_csal_state:02X}\n"
        )
        ret += (
            f"  TRNG state:         "
            f"{EleTrngState.get_description(self.info_trng_state, str(self.info_trng_state))}"
            f" - 0x{self.info_trng_state:02X}\n"
        )

        if self.info_version >= 0x03:
            if self.info_oem_pqc_srkh:
                ret += f"  OEM PQC SRKH:       {self.info_oem_pqc_srkh.hex()}\n"

        return ret


class EleMessageDeriveKey(EleMessage):
    """ELE Message for cryptographic key derivation operations.

    This class implements the ELE (EdgeLock Enclave) message protocol for deriving
    cryptographic keys with optional context-based diversification. It handles
    the communication with the ELE subsystem to generate derived keys of specified
    sizes using user-provided context data.

    :cvar CMD: ELE derive key request command identifier.
    :cvar SUPPORTED_KEY_SIZES: List of supported output key sizes in bytes.
    :cvar MAX_RESPONSE_DATA_SIZE: Maximum size of response data from ELE.
    """

    CMD = MessageIDs.ELE_DERIVE_KEY_REQ.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 6
    MAX_RESPONSE_DATA_SIZE = 32
    _MAX_COMMAND_DATA_SIZE = 65536
    SUPPORTED_KEY_SIZES = [16, 32]

    def __init__(self, key_size: int, context: Optional[bytes]) -> None:
        """Initialize ELE message for key derivation.

        Sets up the message with specified key size and optional context for key diversification.
        Validates that key size is supported and context length is within limits.

        :param key_size: Output key size in bytes, must be 16 or 32
        :param context: Optional user context bytes for key diversification
        :raises SPSDKValueError: If key size is not supported or context is too long
        """
        if key_size not in self.SUPPORTED_KEY_SIZES:
            raise SPSDKValueError(
                f"Output Key size ({key_size}) must be in {self.SUPPORTED_KEY_SIZES}"
            )
        if context and len(context) > self._MAX_COMMAND_DATA_SIZE:
            raise SPSDKValueError(
                f"User context length ({len(context)}) <= {self._MAX_COMMAND_DATA_SIZE}"
            )
        super().__init__()
        self.key_size = key_size
        self._response_data_size = key_size
        self.context = context
        self.derived_key = b""

    def export(self) -> bytes:
        """Export message to final bytes array.

        The method serializes the message object into a binary format by packing
        the payload data, combining it with the header, and appending a CRC checksum.

        :return: Bytes representation of the complete message including header, payload, and CRC.
        """
        payload = pack(
            LITTLE_ENDIAN + UINT32 + UINT32 + UINT32 + UINT32 + UINT16 + UINT16,
            0,
            self.response_data_address,
            0,
            self.command_data_address if self.context else 0,
            self.key_size,
            self.command_data_size,
        )
        header = self.header_export()
        return header + payload + self.get_msg_crc(header + payload)

    @property
    def command_data(self) -> bytes:
        """Get command data to be loaded into target memory space.

        Returns the context data if available, otherwise returns empty bytes.

        :return: Command data as bytes, or empty bytes if no context is available.
        """
        return self.context if self.context else b""

    def decode_response_data(self, response_data: bytes) -> None:
        """Decode response data from target and extract derived key.

        The response data are specific per command. This method extracts the derived key
        from the beginning of the response data based on the configured key size.

        :param response_data: Raw response data bytes from the target device.
        :raises IndexError: If response_data is shorter than the expected key_size.
        """
        self.derived_key = response_data[: self.key_size]

    def get_key(self) -> bytes:
        """Get derived key.

        :return: The derived cryptographic key as bytes.
        """
        return self.derived_key


class EleMessageSigned(EleMessage):
    """ELE Message for signed message containers.

    This class handles ELE (EdgeLock Enclave) messages that contain signed message
    containers, providing functionality to parse, validate, and export signed
    messages for secure communication with the ELE subsystem.

    :cvar COMMAND_PAYLOAD_WORDS_COUNT: Number of payload words in the command.
    """

    COMMAND_PAYLOAD_WORDS_COUNT = 2

    def __init__(self, signed_msg: bytes, family: FamilyRevision) -> None:
        """Initialize ELE message object from signed message data.

        Parses and validates the provided signed message container, extracting the command
        and storing the binary data for further processing.

        :param signed_msg: Binary data containing the signed message container
        :param family: Chip family revision information for message parsing
        :raises SPSDKValueError: Invalid or malformed signed message container
        """
        super().__init__()
        self.signed_msg_binary = signed_msg

        # Parse the signed message
        self.signed_msg = SignedMessage.parse(data=signed_msg, family=family)
        self.signed_msg.verify().validate()

        if not (
            self.signed_msg.signed_msg_container and self.signed_msg.signed_msg_container.message
        ):
            raise SPSDKValueError("Invalid signed message")
        self.command = self.signed_msg.signed_msg_container.message.cmd
        self._command_data_size = len(self.signed_msg_binary)

    def export(self) -> bytes:
        """Export message to bytes array.

        Converts the message object into its binary representation by combining
        the exported header with a payload containing command data address.

        :return: Binary representation of the message object.
        """
        payload = pack(
            LITTLE_ENDIAN + UINT32 + UINT32,
            0,
            self.command_data_address,
        )
        return self.header_export() + payload

    @property
    def command_data(self) -> bytes:
        """Get command data to be loaded into target memory space.

        :return: Binary data of the signed message ready for loading into target memory.
        """
        return self.signed_msg_binary

    def info(self) -> str:
        """Get information including live data about the message.

        The method retrieves basic message information from the parent class and appends
        detailed image information from the signed message component.

        :return: Formatted string containing comprehensive message information.
        """
        ret = super().info()
        ret += "\n" + self.signed_msg.image_info().draw()

        return ret


class EleMessageGenerateKeyBlob(EleMessage):
    """ELE Message for generating encrypted key blobs.

    This class handles the creation and processing of ELE (EdgeLock Enclave) messages
    that generate encrypted key blobs from raw cryptographic keys. It supports various
    encryption algorithms and manages the complete workflow from key input to encrypted
    blob output.

    :cvar KEYBLOB_NAME: Human-readable name for the key blob type.
    :cvar SUPPORTED_ALGORITHMS: Dictionary mapping algorithms to supported key sizes.
    :cvar KEYBLOB_TAG: Tag identifier for the key blob format.
    :cvar KEYBLOB_VERSION: Version of the key blob format.
    :cvar MAX_RESPONSE_DATA_SIZE: Maximum size of response data in bytes.
    """

    KEYBLOB_NAME = "Unknown"
    # List of supported algorithms and theirs key sizes
    SUPPORTED_ALGORITHMS: dict[SpsdkEnum, list[int]] = {}

    KEYBLOB_TAG = 0x81
    KEYBLOB_VERSION = 0x00
    CMD = MessageIDs.GENERATE_KEY_BLOB_REQ.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 7
    MAX_RESPONSE_DATA_SIZE = 512

    def __init__(
        self, key_identifier: int, algorithm: KeyBlobEncryptionAlgorithm, key: bytes
    ) -> None:
        """Initialize Generate Key Blob message.

        Creates a new instance for generating a key blob with specified encryption algorithm.

        :param key_identifier: Unique identifier for the key to be wrapped.
        :param algorithm: Encryption algorithm to use for key blob generation.
        :param key: Raw key data that will be wrapped into the key blob.
        """
        super().__init__()
        self.key_id = key_identifier
        self.algorithm = algorithm

        self.key = key
        self.key_blob = bytes()
        self.validate()

    def export(self) -> bytes:
        """Export message to final bytes array.

        Converts the message object into its binary representation by packing the header,
        payload data, and CRC checksum into a bytes array suitable for transmission.

        :return: Complete binary representation of the message including header, payload, and CRC.
        """
        payload = pack(
            LITTLE_ENDIAN + UINT32 + UINT32 + UINT32 + UINT32 + UINT32 + UINT16 + UINT16,
            self.key_id,
            0,
            self.command_data_address,
            0,
            self.response_data_address,
            self.MAX_RESPONSE_DATA_SIZE,
            0,
        )
        payload = self.header_export() + payload
        return payload + EleMessage.get_msg_crc(payload)

    def validate(self) -> None:
        """Validate keyblob message data.

        Validates that the algorithm is supported and the key size is compatible
        with the selected algorithm for the keyblob generation.

        :raises SPSDKValueError: Invalid used key size or encryption algorithm.
        """
        if self.algorithm not in self.SUPPORTED_ALGORITHMS:
            raise SPSDKValueError(
                f"{self.algorithm} is not supported by {self.KEYBLOB_NAME} keyblob in ELE."
            )

        if len(self.key) * 8 not in self.SUPPORTED_ALGORITHMS[self.algorithm]:
            raise SPSDKValueError(
                f"Unsupported size of input key by {self.KEYBLOB_NAME} keyblob"
                f" for {self.algorithm.label} algorithm."
                f"The list of supported keys in bit count: {self.SUPPORTED_ALGORITHMS[self.algorithm]}"
            )

    def info(self) -> str:
        """Get formatted information about the key blob message.

        The method returns a comprehensive string containing details about the key blob
        including its type, key ID, algorithm, and key size in bits.

        :return: Formatted string with key blob information including type, ID, algorithm,
                 and key size.
        """
        ret = super().info()
        ret += "\n"
        ret += f"KeyBlob type:    {self.KEYBLOB_NAME}\n"
        ret += f"Key ID:          {self.key_id}\n"
        ret += f"Algorithm:       {self.algorithm.label}\n"
        ret += f"Key size:        {len(self.key)*8} bits\n"
        return ret

    @classmethod
    def get_supported_algorithms(cls) -> list[str]:
        """Get the list of supported algorithms.

        :return: List of supported algorithm names.
        """
        return list(x.label for x in cls.SUPPORTED_ALGORITHMS)

    @classmethod
    def get_supported_key_sizes(cls) -> str:
        """Get table with supported key sizes per algorithm.

        The method iterates through all supported algorithms and formats their
        key sizes into a human-readable string representation.

        :return: Formatted string containing algorithm labels and their supported key sizes.
        """
        ret = ""
        for key, value in cls.SUPPORTED_ALGORITHMS.items():
            ret += key.label + ": " + str(value) + ",\n"
        return ret

    def decode_response_data(self, response_data: bytes) -> None:
        """Decode response data from target and extract key blob.

        The method parses the response data structure, validates the header fields
        (version, length, tag) and extracts the key blob. The response data format
        is command-specific.

        :param response_data: Raw response data bytes from target device.
        :raises SPSDKParsingError: Invalid tag, version, or length in response.
        """
        ver, length, tag = unpack(LITTLE_ENDIAN + UINT8 + UINT16 + UINT8, response_data[:4])
        if tag != self.KEYBLOB_TAG:
            raise SPSDKParsingError("Invalid TAG in generated KeyBlob")
        if ver != self.KEYBLOB_VERSION:
            raise SPSDKParsingError("Invalid Version in generated KeyBlob")
        if length > self.MAX_RESPONSE_DATA_SIZE:
            raise SPSDKParsingError("Invalid Length in generated KeyBlob")

        self.key_blob = response_data[:length]


class EleMessageGenerateKeyBlobDek(EleMessageGenerateKeyBlob):
    """ELE Message for generating DEK (Data Encryption Key) KeyBlob.

    This class handles the creation of ELE messages specifically for generating DEK KeyBlobs,
    which are used for data encryption operations. It supports AES-CBC and SM4-CBC encryption
    algorithms with various key sizes.

    :cvar KEYBLOB_NAME: Identifier for DEK keyblob type.
    :cvar SUPPORTED_ALGORITHMS: Dictionary mapping encryption algorithms to supported key sizes.
    """

    KEYBLOB_NAME = "DEK"
    # List of supported algorithms and theirs key sizes
    SUPPORTED_ALGORITHMS = {
        KeyBlobEncryptionAlgorithm.AES_CBC: [128, 192, 256],
        KeyBlobEncryptionAlgorithm.SM4_CBC: [128],
    }

    @property
    def command_data(self) -> bytes:
        """Generate command data to be loaded into target memory space.

        Creates a binary data structure containing the keyblob header, options, and key data
        formatted for ELE (EdgeLock Enclave) command processing.

        :return: Binary command data ready for target memory loading.
        """
        header = pack(
            LITTLE_ENDIAN + UINT8 + UINT16 + UINT8,
            self.KEYBLOB_VERSION,
            8 + len(self.key),
            self.KEYBLOB_TAG,
        )
        options = pack(
            LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8,
            0x01,  # Flags - DEK
            len(self.key),
            self.algorithm.tag,
            0,
        )
        return header + options + self.key


class EleMessageGenerateKeyBLobOtfad(EleMessageGenerateKeyBlob):
    """ELE Message Generate OTFAD KeyBlob.

    This class handles generation of OTFAD (On-The-Fly AES Decryption) keyblobs for ELE
    (EdgeLock Enclave) operations. It manages OTFAD-specific parameters including memory
    address ranges, AES counter values, and decryption configuration flags.

    :cvar KEYBLOB_NAME: Name identifier for OTFAD keyblob type.
    :cvar SUPPORTED_ALGORITHMS: Dictionary of supported encryption algorithms and key sizes.
    """

    KEYBLOB_NAME = "OTFAD"
    # List of supported algorithms and theirs key sizes
    SUPPORTED_ALGORITHMS = {KeyBlobEncryptionAlgorithm.AES_CTR: [128]}

    def __init__(
        self,
        key_identifier: int,
        key: bytes,
        aes_counter: bytes,
        start_address: int,
        end_address: int,
        read_only: bool = True,
        decryption_enabled: bool = True,
        configuration_valid: bool = True,
    ) -> None:
        """Initialize OTFAD keyblob for on-the-fly AES decryption configuration.

        Creates a keyblob instance for OTFAD (On-The-Fly AES Decryption) with specified
        encryption parameters and memory region configuration.

        :param key_identifier: Unique identifier for the encryption key
        :param key: AES encryption key bytes for OTFAD operations
        :param aes_counter: Initial counter value for AES-CTR mode encryption
        :param start_address: Starting memory address for the encrypted region
        :param end_address: Ending memory address for the encrypted region
        :param read_only: Enable read-only access protection, defaults to True
        :param decryption_enabled: Enable automatic decryption, defaults to True
        :param configuration_valid: Mark configuration as valid, defaults to True
        """
        self.aes_counter = aes_counter
        self.start_address = start_address
        self.end_address = end_address
        self.read_only = read_only
        self.decryption_enabled = decryption_enabled
        self.configuration_valid = configuration_valid
        super().__init__(key_identifier, KeyBlobEncryptionAlgorithm.AES_CTR, key)

    def validate(self) -> None:
        """Validate OTFAD keyblob parameters.

        Performs comprehensive validation of all OTFAD keyblob parameters including
        key identifier structure, AES counter length, and address alignment requirements.

        :raises SPSDKValueError: Invalid key identifier structure (struct index not 0-3).
        :raises SPSDKValueError: Invalid key identifier peripheral index (not 1-2 for FlexSPIx).
        :raises SPSDKValueError: Invalid key identifier reserved bytes (must be 0).
        :raises SPSDKValueError: Invalid AES counter length (must be 64 bits).
        :raises SPSDKValueError: Invalid start address alignment (must be 1024-byte aligned).
        :raises SPSDKValueError: Invalid end address alignment (must be 1024-byte aligned).
        """
        # Validate general members
        super().validate()
        # 1 Validate OTFAD Key identifier
        struct_index = self.key_id & 0xFF
        peripheral_index = (self.key_id >> 8) & 0xFF
        reserved = self.key_id & 0xFFFF0000

        if struct_index > 3:
            raise SPSDKValueError(
                "Invalid OTFAD Key Identifier. Byte 0 must be in range [0-3],"
                " to select used key struct, for proper scrambling."
            )

        if peripheral_index not in [1, 2]:
            raise SPSDKValueError(
                "Invalid OTFAD Key Identifier. Byte 1 must be in range [1-2],"
                " to select used peripheral [FlexSPIx]."
            )

        if reserved != 0:
            raise SPSDKValueError("Invalid OTFAD Key Identifier. Byte 2-3 must be set to 0.")

        # 2. validate AES counter
        if len(self.aes_counter) != 8:
            raise SPSDKValueError("Invalid AES counter length. It must be 64 bits.")

        # 3. start address
        if self.start_address != 0 and self.start_address != align(self.start_address, 1024):
            raise SPSDKValueError(
                "Invalid OTFAD start address. Start address has to be aligned to 1024 bytes."
            )

        # 4. end address
        if self.end_address != 0 and self.end_address != align(self.end_address, 1024):
            raise SPSDKValueError(
                "Invalid OTFAD end address. End address has to be aligned to 1024 bytes."
            )

    @property
    def command_data(self) -> bytes:
        """Get command data to be loaded into target memory space.

        Constructs the complete OTFAD keyblob command data by combining header,
        options, OTFAD configuration, and CRC checksum. The method packs all
        configuration parameters including encryption settings, memory addresses,
        and security flags into a binary format suitable for target loading.

        :return: Complete binary command data ready for target memory loading.
        """
        header = pack(
            LITTLE_ENDIAN + UINT8 + UINT16 + UINT8,
            self.KEYBLOB_VERSION,
            0x30,
            self.KEYBLOB_TAG,
        )
        options = pack(
            LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8,
            0x02,  # Flags - OTFAD
            0x28,
            self.algorithm.tag,
            0,
        )
        end_address = self.end_address
        if self.read_only:
            end_address |= 0x04
        if self.decryption_enabled:
            end_address |= 0x02
        if self.configuration_valid:
            end_address |= 0x01

        otfad_config = pack(
            LITTLE_ENDIAN + "16s" + "8s" + UINT32 + UINT32 + UINT32,
            self.key,
            self.aes_counter,
            self.start_address,
            end_address,
            0,
        )
        crc_obj = from_crc_algorithm(CrcAlg.CRC32_MPEG)
        crc: int = crc_obj.calculate(otfad_config)
        return header + options + otfad_config + crc.to_bytes(4, Endianness.LITTLE.value)

    def info(self) -> str:
        """Get formatted information string including live configuration data.

        Returns a multi-line string containing AES counter, memory addresses, and status flags
        for the ELE message configuration.

        :return: Formatted string with message configuration details.
        """
        ret = super().info()
        ret += f"AES Counter:     {self.aes_counter.hex()}\n"
        ret += f"Start address:   {self.start_address:08x}\n"
        ret += f"End address:     {self.end_address:08x}\n"
        ret += f"Read_only:       {self.read_only}\n"
        ret += f"Enabled:         {self.decryption_enabled}\n"
        ret += f"Valid:           {self.configuration_valid}\n"
        return ret


class EleMessageGenerateKeyBlobIee(EleMessageGenerateKeyBlob):
    """ELE Message for generating IEE (Inline Encryption Engine) KeyBlob.

    This class handles the creation of IEE-specific keyblobs for secure data encryption
    in NXP MCUs. It supports AES-XTS and AES-CTR encryption algorithms with various
    key sizes and provides configuration for IEE-specific parameters like page offset,
    region number, and CTR modes.

    :cvar KEYBLOB_NAME: Identifier name for IEE keyblob type.
    :cvar SUPPORTED_ALGORITHMS: Dictionary mapping supported encryption algorithms to their valid key sizes.
    """

    KEYBLOB_NAME = "IEE"
    # List of supported algorithms and theirs key sizes
    SUPPORTED_ALGORITHMS = {
        KeyBlobEncryptionAlgorithm.AES_XTS: [256, 512],
        KeyBlobEncryptionAlgorithm.AES_CTR: [128, 256],
    }

    def __init__(
        self,
        key_identifier: int,
        algorithm: KeyBlobEncryptionAlgorithm,
        key: bytes,
        ctr_mode: KeyBlobEncryptionIeeCtrModes,
        aes_counter: bytes,
        page_offset: int,
        region_number: int,
        bypass: bool = False,
        locked: bool = False,
    ) -> None:
        """Initialize IEE keyblob generator.

        Creates an instance for generating IEE (Inline Encryption Engine) keyblobs with
        specified encryption parameters and region configuration.

        :param key_identifier: Unique identifier for the encryption key
        :param algorithm: Encryption algorithm to be used for keyblob generation
        :param key: Raw IEE encryption key bytes
        :param ctr_mode: Counter mode configuration for AES CTR algorithm
        :param aes_counter: Initial counter value for AES CTR mode encryption
        :param page_offset: Memory page offset for IEE region configuration
        :param region_number: Target region number for IEE configuration
        :param bypass: Enable encryption bypass mode, defaults to False
        :param locked: Lock the keyblob configuration, defaults to False
        """
        self.ctr_mode = ctr_mode
        self.aes_counter = aes_counter
        self.page_offset = page_offset
        self.region_number = region_number
        self.bypass = bypass
        self.locked = locked
        super().__init__(key_identifier, algorithm, key)

    @property
    def command_data(self) -> bytes:
        """Generate command data to be loaded into target memory space.

        Creates a binary representation of the keyblob command including header, options,
        IEE configuration, and CRC checksum. The data is formatted according to the
        target device's memory layout requirements.

        :return: Binary command data ready for target memory loading.
        """
        header = pack(
            LITTLE_ENDIAN + UINT8 + UINT16 + UINT8,
            self.KEYBLOB_VERSION,
            88,
            self.KEYBLOB_TAG,
        )
        options = pack(
            LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8,
            0x03,  # Flags - IEE
            len(self.key),
            self.algorithm.tag,
            0,
        )
        region_attribute = 0
        if self.bypass:
            region_attribute |= 1 << 7
        if self.algorithm == KeyBlobEncryptionAlgorithm.AES_XTS:
            region_attribute |= 0b01 << 4
            if len(self.key) == 64:
                region_attribute |= 0x01
        else:
            region_attribute |= self.ctr_mode.tag << 4
            if len(self.key) == 32:
                region_attribute |= 0x01

        if self.algorithm == KeyBlobEncryptionAlgorithm.AES_CTR:
            key1 = align_block(self.key, 32, 0)
            key2 = align_block(self.aes_counter, 32, 0)
        else:
            key_len = len(self.key)
            key1 = align_block(self.key[: key_len // 2], 32, 0)
            key2 = align_block(self.key[key_len // 2 :], 32, 0)

        lock_options = pack(
            LITTLE_ENDIAN + UINT8 + UINT8 + UINT16,
            self.region_number,
            0x01 if self.locked else 0x00,
            0,
        )

        iee_config = pack(
            LITTLE_ENDIAN + UINT32 + UINT32 + "32s" + "32s" + "4s",
            region_attribute,
            self.page_offset,
            key1,
            key2,
            lock_options,
        )
        crc = from_crc_algorithm(CrcAlg.CRC32_MPEG).calculate(iee_config)
        return header + options + iee_config + crc.to_bytes(4, Endianness.LITTLE.value)

    def info(self) -> str:
        """Get formatted information about the key blob encryption message.

        Provides detailed information about the encryption algorithm, keys, counters,
        and configuration parameters. The output includes live data with proper
        formatting for debugging and verification purposes.

        :return: Formatted string containing message details including algorithm type,
            keys, counters, page offset, region number, bypass and lock status.
        """
        if self.algorithm == KeyBlobEncryptionAlgorithm.AES_CTR:
            key1 = align_block(self.key, 32, 0)
            key2 = align_block(self.aes_counter, 32, 0)
        else:
            key_len = len(self.key)
            key1 = align_block(self.key[: key_len // 2], 32, 0)
            key2 = align_block(self.key[key_len // 2 :], 32, 0)
        ret = super().info()
        if self.algorithm == KeyBlobEncryptionAlgorithm.AES_CTR:
            ret += f"AES Counter mode:{KeyBlobEncryptionIeeCtrModes.get_description(self.ctr_mode.tag)}\n"
            ret += f"AES Counter:     {self.aes_counter.hex()}\n"
        ret += f"Key1:            {key1.hex()}\n"
        ret += f"Key2:            {key2.hex()}\n"
        ret += f"Page offset:     {self.page_offset:08x}\n"
        ret += f"Region number:   {self.region_number:02x}\n"
        ret += f"Bypass:          {self.bypass}\n"
        ret += f"Locked:          {self.locked}\n"
        return ret


class EleMessageLoadKeyBLob(EleMessage):
    """ELE Message for loading key blob operations.

    This class implements the ELE (EdgeLock Enclave) message protocol for loading
    key blobs into the target device. It handles the packaging and export of key
    blob data along with key identifiers for secure provisioning operations.

    :cvar CMD: Command identifier for load key blob request.
    :cvar COMMAND_PAYLOAD_WORDS_COUNT: Number of payload words in the command.
    """

    CMD = MessageIDs.LOAD_KEY_BLOB_REQ.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 3

    def __init__(self, key_identifier: int, keyblob: bytes) -> None:
        """Initialize Load Key Blob instance.

        Creates a new Load Key Blob object with the specified key identifier and keyblob data.
        The constructor validates the provided parameters to ensure they meet the required format.

        :param key_identifier: Unique identifier for the key to be loaded
        :param keyblob: Binary data containing the encrypted key material to be wrapped
        :raises SPSDKError: Invalid key identifier or keyblob format
        """
        super().__init__()
        self.key_id = key_identifier

        self.keyblob = keyblob
        self.validate()

    def export(self) -> bytes:
        """Export message to final bytes array.

        The method serializes the message object into a binary format by packing
        the key ID, padding, and command data address into the payload, then
        combining it with the exported header.

        :return: Bytes representation of message object.
        """
        payload = pack(
            LITTLE_ENDIAN + UINT32 + UINT32 + UINT32, self.key_id, 0, self.command_data_address
        )
        payload = self.header_export() + payload
        return payload

    @property
    def command_data(self) -> bytes:
        """Get command data to be loaded into target memory space.

        :return: The keyblob data as bytes.
        """
        return self.keyblob

    def info(self) -> str:
        """Get information about the message including live data.

        The method provides detailed information about the message, including
        the key ID and keyblob size in addition to the base message information.

        :return: Formatted string containing message information with key ID and keyblob size.
        """
        ret = super().info()
        ret += "\n"
        ret += f"Key ID:          {self.key_id}\n"
        ret += f"KeyBlob size:    {len(self.keyblob)}\n"
        return ret


class EleMessageWriteFuse(EleMessage):
    """ELE message for writing fuse data.

    This class represents a request message to write data to fuses in ELE (EdgeLock Enclave).
    It handles OEM fuse writing operations with configurable bit positioning, length, and
    locking capabilities. Fuse accessibility depends on the chip lifecycle state.

    :cvar CMD: Message command identifier for write fuse operation.
    :cvar COMMAND_PAYLOAD_WORDS_COUNT: Number of payload words in the command.
    :cvar RESPONSE_PAYLOAD_WORDS_COUNT: Number of payload words in the response.
    """

    CMD = MessageIDs.WRITE_FUSE.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 2
    RESPONSE_PAYLOAD_WORDS_COUNT = 1

    def __init__(self, bit_position: int, bit_length: int, lock: bool, payload: int) -> None:
        """Initialize ELE fuse write message.

        This command allows to write to the fuses. OEM Fuses are accessible depending on the chip
        lifecycle.

        :param bit_position: Fuse identifier expressed as its position in bit in the fuse map.
        :param bit_length: Number of bits to be written.
        :param lock: Write lock requirement. When set to 1, fuse words are locked. When unset, no
            write lock is done.
        :param payload: Data to be written.
        """
        super().__init__()
        self.bit_position = bit_position
        self.bit_length = bit_length
        self.lock = lock
        self.payload = payload
        self.processed_idx = 0

    def export(self) -> bytes:
        """Export message to bytes array representation.

        Converts the message object into its binary format by combining the header
        with packed bit position, bit length (with lock flag), and payload data.

        :return: Binary representation of the complete message.
        """
        ret = self.header_export()

        ret += pack(
            LITTLE_ENDIAN + UINT16 + UINT16 + UINT32,
            self.bit_position,
            self.bit_length | (0x8000 if self.lock else 0),
            self.payload,
        )
        return ret

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        The method parses the response bytes and extracts the processed index value
        from the response data structure.

        :param response: Raw response data bytes from the target device.
        :raises SPSDKParsingError: Response parsing detects an error in the data format.
        """
        super().decode_response(response)
        if len(response) == self.response_words_count * 4:
            (self.processed_idx, _) = unpack(LITTLE_ENDIAN + UINT16 + UINT16, response[8:12])


class EleMessageWriteShadowFuse(EleMessage):
    """ELE message for writing shadow fuse values.

    This class represents a request message to write data to shadow fuses in the
    EdgeLock Enclave. Shadow fuses are temporary storage that mirrors the actual
    fuse values and can be modified without permanently altering the hardware fuses.

    :cvar CMD: Message command identifier for write shadow fuse operation.
    :cvar COMMAND_PAYLOAD_WORDS_COUNT: Number of payload words in the message.
    """

    CMD = MessageIDs.WRITE_SHADOW_FUSE.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 2

    def __init__(self, index: int, value: int) -> None:
        """Initialize ELE shadow fuse write command.

        This command allows to write to the shadow fuses.

        :param index: Fuse identifier expressed as its position in bit in the fuse map.
        :param value: Data to be written.
        """
        super().__init__()
        self.index = index
        self.value = value

    def export(self) -> bytes:
        """Export message to bytes array.

        Converts the message object into its binary representation by combining
        the exported header with the packed index and value fields.

        :return: Binary representation of the message object.
        """
        ret = self.header_export()

        ret += pack(
            LITTLE_ENDIAN + UINT32 + UINT32,
            self.index,
            self.value,
        )
        return ret


class EleMessageEnableApc(EleMessage):
    """ELE Message for enabling Application Processing Core (APC).

    This message class handles the ELE command to enable the Application Processing Core,
    which is responsible for managing application-level operations in the secure element.

    :cvar CMD: Command identifier for the ELE enable APC request.
    """

    CMD = MessageIDs.ELE_ENABLE_APC_REQ.tag


class EleMessageEnableRtc(EleMessage):
    """ELE message for enabling Real Time Core functionality.

    This class represents a command message used to enable the Real Time Core (RTC)
    in EdgeLock Enclave operations, providing access to real-time processing capabilities.

    :cvar CMD: Command identifier for the ELE enable RTC request.
    """

    CMD = MessageIDs.ELE_ENABLE_RTC_REQ.tag


class EleMessageResetApcContext(EleMessage):
    """ELE Message for resetting APC (Application Processing Core) context.

    This message requests the ELE (EdgeLock Enclave) to reset the APC context,
    which clears the current application processing state and reinitializes
    the core context for fresh operation.

    :cvar CMD: Message command identifier for APC context reset request.
    """

    CMD = MessageIDs.ELE_RESET_APC_CTX_REQ.tag


class EleMessageSessionOpen(EleMessage):
    """ELE Message Session Open.

    Session open command is used to initialize the EdgeLock Secure Enclave HSM services
    for the requestor. It establishes a route between the user and the EdgeLock Secure
    Enclave as well as a quality of service.
    A maximum of 20 sessions can be opened at the same time. Session open command must be
    called before any other APIs that use a session.

    :cvar CMD: Session open command ID (0x10).
    :cvar VERSION: Version for HSM API (0x07).
    :cvar COMMAND_PAYLOAD_WORDS_COUNT: Number of payload words in command (2).
    :cvar RESPONSE_PAYLOAD_WORDS_COUNT: Number of payload words in response (1).
    """

    CMD = 0x10  # Session open command ID
    VERSION = 0x07  # Version for HSM API
    COMMAND_PAYLOAD_WORDS_COUNT = 2  # Two reserved words
    RESPONSE_PAYLOAD_WORDS_COUNT = 1  # Session handle word

    def __init__(self) -> None:
        """Initialize ELE message object.

        Initializes the ELE message instance with default values including
        session handle set to 0.
        """
        super().__init__()
        self.session_handle = 0

    def export(self) -> bytes:
        """Export message to final bytes array.

        The method overrides the header to use HSM API version and adds two reserved
        words set to zero to create the complete message payload.

        :return: Bytes representation of message object.
        """
        # Override the header to use HSM API version
        header = pack(
            self.HEADER_FORMAT, self.VERSION, self.command_words_count, self.command, self.TAG
        )
        # Add two reserved words (set to 0)
        payload = pack(LITTLE_ENDIAN + UINT32 + UINT32, RESERVED, RESERVED)
        return header + payload

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        Parses and validates the response message header, extracts status information,
        and updates the message object with decoded values including status, indication,
        abort code, and session handle.

        :param response: Raw response data bytes from target device.
        :raises SPSDKParsingError: Invalid response format, tag, command, size or version.
        """
        # Decode and validate header
        (version, size, command, tag) = unpack(self.HEADER_FORMAT, response[:4])
        if tag != self.RSP_TAG:
            raise SPSDKParsingError(f"Message TAG in response is invalid: {hex(tag)}")
        if command != self.command:
            raise SPSDKParsingError(f"Message COMMAND in response is invalid: {hex(command)}")
        if size not in range(self.RESPONSE_HEADER_WORDS_COUNT, self.response_words_count + 1):
            raise SPSDKParsingError(f"Message SIZE in response is invalid: {hex(size)}")
        if version != self.VERSION:
            raise SPSDKParsingError(f"Message VERSION in response is invalid: {hex(version)}")

        # Decode status word
        (
            self.status,
            self.indication,
            self.abort_code,
        ) = unpack(LITTLE_ENDIAN + UINT8 + UINT8 + UINT16, response[4:8])

        # Decode session handle
        if len(response) >= 12:
            self.session_handle = unpack(LITTLE_ENDIAN + UINT32, response[8:12])[0]
        else:
            self.session_handle = 0

    def response_info(self) -> str:
        """Get session open response information.

        Formats and returns detailed information about the session handle status,
        including whether the session was successfully opened or failed.

        :return: Formatted string containing session handle and status information.
        """
        ret = f"Session handle: 0x{self.session_handle:08X}\n"
        if self.session_handle == 0:
            ret += "Session open failed - no valid session handle returned\n"
        else:
            ret += "Session successfully opened\n"
        return ret

    def info(self) -> str:
        """Get information about the session open command including live data.

        Provides detailed information about the EdgeLock Secure Enclave session open command,
        including its purpose, limitations, and current session state if available.

        :return: Formatted string containing comprehensive information about the session open
            command and its current state.
        """
        ret = super().info()
        ret += "\nSession Open Command:\n"
        ret += "- Initializes EdgeLock Secure Enclave HSM services\n"
        ret += "- Establishes route between user and EdgeLock Secure Enclave\n"
        ret += "- Maximum 20 sessions can be opened simultaneously\n"
        ret += "- Must be called before other HSM APIs that use a session\n"
        if hasattr(self, "session_handle"):
            ret += f"\n{self.response_info()}"
        return ret

    def get_session_handle(self) -> int:
        """Get the session handle from successful response.

        :return: Session handle, 0 if session open failed.
        """
        return self.session_handle

    def is_session_valid(self) -> bool:
        """Check if session was successfully opened.

        :return: True if session handle is valid (non-zero), False otherwise.
        """
        return self.session_handle != 0


class EleMessageSessionClose(EleMessage):
    """ELE Message Session Close.

    Session close command is used to close an opened session. Any data related to the session,
    including other services flow contexts, will be deleted.
    User can call this function only after having opened a valid session (see Session open (0x10)).
    Session close command will close any associated services to the session as well.

    :cvar CMD: Session close command ID (0x11).
    :cvar VERSION: Version for HSM API (0x07).
    :cvar COMMAND_PAYLOAD_WORDS_COUNT: Number of payload words in command (1).
    :cvar RESPONSE_PAYLOAD_WORDS_COUNT: Number of payload words in response (0).
    """

    CMD = 0x11  # Session close command ID
    VERSION = 0x07  # Version for HSM API
    COMMAND_PAYLOAD_WORDS_COUNT = 1  # Session handle word
    RESPONSE_PAYLOAD_WORDS_COUNT = 0  # No response payload

    def __init__(self, session_handle: int) -> None:
        """Initialize ELE message for session closure.

        :param session_handle: Session handle to close. Handle value returned by Session open (0x10).
        """
        super().__init__()
        self.session_handle = session_handle

    def export(self) -> bytes:
        """Export message to final bytes array.

        The method overrides the header to use HSM API version and adds session handle
        to create the complete message payload.

        :return: Bytes representation of message object.
        """
        # Override the header to use HSM API version
        header = pack(
            self.HEADER_FORMAT, self.VERSION, self.command_words_count, self.command, self.TAG
        )
        # Add session handle
        payload = pack(LITTLE_ENDIAN + UINT32, self.session_handle)
        return header + payload

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        Parses and validates the response message header and status information.
        The method verifies message tag, command, size, and version fields against
        expected values and extracts status, indication, and abort code.

        :param response: Raw response data bytes from target device.
        :raises SPSDKParsingError: Invalid response format or field values detected.
        """
        # Decode and validate header
        (version, size, command, tag) = unpack(self.HEADER_FORMAT, response[:4])
        if tag != self.RSP_TAG:
            raise SPSDKParsingError(f"Message TAG in response is invalid: {hex(tag)}")
        if command != self.command:
            raise SPSDKParsingError(f"Message COMMAND in response is invalid: {hex(command)}")
        if size not in range(self.RESPONSE_HEADER_WORDS_COUNT, self.response_words_count + 1):
            raise SPSDKParsingError(f"Message SIZE in response is invalid: {hex(size)}")
        if version != self.VERSION:
            raise SPSDKParsingError(f"Message VERSION in response is invalid: {hex(version)}")

        # Decode status word
        (
            self.status,
            self.indication,
            self.abort_code,
        ) = unpack(LITTLE_ENDIAN + UINT8 + UINT8 + UINT16, response[4:8])

    def info(self) -> str:
        """Get session close command information including live data.

        Provides detailed information about the session close command, including
        the session handle and operational constraints.

        :return: Formatted string containing session close command information.
        """
        ret = super().info()
        ret += "\nSession Close Command:\n"
        ret += f"- Session handle: 0x{self.session_handle:08X}\n"
        ret += "- Closes an opened session and deletes related data\n"
        ret += "- Closes any associated services to the session\n"
        ret += "- Can only be called after opening a valid session\n"
        ret += "- Must use same MU as used for session open\n"
        return ret


class EleMessageSabInit(EleMessage):
    """ELE Message SAB Init.

    SAB Init command is used to initialize the EdgeLock Secure Enclave Firmware HSM services.
    It must be called once, at boot, by any core.
    SAB Init command must be called before any other ones that use a SAB session.
    SAB Init command can be called multiple times, even if not recommended. EdgeLock Secure
    Enclave Firmware will do nothing and respond a success if the initialization is already done.

    :cvar CMD: SAB Init command ID (0x17).
    :cvar VERSION: Version for HSM API (0x07).
    """

    CMD = 0x17  # SAB Init command ID
    VERSION = 0x07  # Version for HSM API
    COMMAND_PAYLOAD_WORDS_COUNT = 0  # No payload words
    RESPONSE_PAYLOAD_WORDS_COUNT = 0  # No response payload

    def export(self) -> bytes:
        """Export message to bytes representation.

        Converts the message object to its final bytes array format by overriding
        the header with HSM API version and correct word size.

        :return: Bytes representation of message object.
        """
        # Override the header to use HSM API version and correct word size
        header = pack(
            self.HEADER_FORMAT, self.VERSION, self.command_words_count, self.command, self.TAG
        )
        return header

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        Parses and validates the response message header and status information.
        The method verifies message tag, command, size, and version fields against
        expected values and extracts status, indication, and abort code.

        :param response: Raw response data bytes from target device.
        :raises SPSDKParsingError: Invalid response format or field values detected.
        """
        # Decode and validate header
        (version, size, command, tag) = unpack(self.HEADER_FORMAT, response[:4])
        if tag != self.RSP_TAG:
            raise SPSDKParsingError(f"Message TAG in response is invalid: {hex(tag)}")
        if command != self.command:
            raise SPSDKParsingError(f"Message COMMAND in response is invalid: {hex(command)}")
        if size not in range(self.RESPONSE_HEADER_WORDS_COUNT, self.response_words_count + 1):
            raise SPSDKParsingError(f"Message SIZE in response is invalid: {hex(size)}")
        if version != self.VERSION:
            raise SPSDKParsingError(f"Message VERSION in response is invalid: {hex(version)}")

        # Decode status word
        (
            self.status,
            self.indication,
            self.abort_code,
        ) = unpack(LITTLE_ENDIAN + UINT8 + UINT8 + UINT16, response[4:8])

    def info(self) -> str:
        """Get information about SAB Init Command including live data.

        Returns detailed information about the SAB Init Command which initializes EdgeLock Secure
        Enclave Firmware HSM services. This command must be called once at boot by any core and
        before any other SAB session commands.

        :return: Formatted string containing information about the SAB Init Command.
        """
        ret = super().info()
        ret += "\nSAB Init Command:\n"
        ret += "- Initializes EdgeLock Secure Enclave Firmware HSM services\n"
        ret += "- Must be called once at boot by any core\n"
        ret += "- Must be called before any other SAB session commands\n"
        ret += "- Can be called multiple times (will return success if already initialized)\n"
        return ret


class EleMessageKeyStoreOpen(EleMessage):
    """ELE Message Key Store Open.

    ELE message for opening a key store service flow on NXP EdgeLock Enclave.
    Manages key store access with support for creation, loading, and configuration
    of shared or isolated key stores with up to 100 keys per store.

    :cvar CMD: Key store open command identifier (0x30).
    :cvar FLAG_CREATE_KEYSTORE: Flag bit for creating new key store.
    :cvar FLAG_SHARED_KEYSTORE: Flag bit for shared key store access.
    :cvar FLAG_MONOTONIC_COUNTER_INCREMENT: Flag bit for monotonic counter increment.
    :cvar FLAG_SYNC_OPERATION: Flag bit for synchronous NVM operations.
    """

    CMD = 0x30  # Key store open command ID
    VERSION = 0x07  # Version for HSM API
    COMMAND_PAYLOAD_WORDS_COUNT = 5  # Session handle, key store ID, nonce, flags, CRC
    RESPONSE_PAYLOAD_WORDS_COUNT = 1  # Key store handle

    # Flag bit definitions
    FLAG_CREATE_KEYSTORE = 0x01  # Bit 0: 1=Create, 0=Load
    FLAG_SHARED_KEYSTORE = 0x04  # Bit 2: 1=Shared, 0=Regular
    FLAG_MONOTONIC_COUNTER_INCREMENT = 0x20  # Bit 5: Monotonic counter increment
    FLAG_SYNC_OPERATION = 0x80  # Bit 7: SYNC operation

    def __init__(
        self,
        session_handle: int,
        key_store_id: int,
        nonce: int,
        create_keystore: bool = False,
        shared_keystore: bool = False,
        monotonic_counter_increment: bool = False,
        sync_operation: bool = False,
    ) -> None:
        """Initialize ELE message for key store operations.

        Configures the message with session parameters, key store settings, and operation flags
        for creating or loading key stores with optional synchronization and counter increment.

        :param session_handle: Handle identifying the current session
        :param key_store_id: Key store identifier set by the user
        :param nonce: Nonce used as authentication proof for accessing the key store
        :param create_keystore: True to create key store, False to load existing one
        :param shared_keystore: True for shared keystore, False for regular (isolated) keystore
        :param monotonic_counter_increment: True to increment monotonic counter (SYNC operation)
        :param sync_operation: True for SYNC operation (request completed only when written to NVM)
        """
        super().__init__()
        self.session_handle = session_handle
        self.key_store_id = key_store_id
        self.nonce = nonce
        self.create_keystore = create_keystore
        self.shared_keystore = shared_keystore
        self.monotonic_counter_increment = monotonic_counter_increment
        self.sync_operation = sync_operation
        self.key_store_handle = 0

    @property
    def flags(self) -> int:
        """Get flags byte from boolean parameters.

        Converts the boolean flag parameters into a single integer value by applying
        bitwise OR operations with corresponding flag constants.

        :return: Integer value representing combined flags from boolean parameters.
        """
        flags = 0
        if self.create_keystore:
            flags |= self.FLAG_CREATE_KEYSTORE
        if self.shared_keystore:
            flags |= self.FLAG_SHARED_KEYSTORE
        if self.monotonic_counter_increment:
            flags |= self.FLAG_MONOTONIC_COUNTER_INCREMENT
        if self.sync_operation:
            flags |= self.FLAG_SYNC_OPERATION
        return flags

    def export(self) -> bytes:
        """Export message to bytes representation.

        Converts the ELE message object into its final binary format by packing
        the header and payload with proper CRC calculation for transmission.

        :return: Complete message as bytes array ready for transmission.
        """
        # Override the header to use HSM API version
        header = pack(
            self.HEADER_FORMAT, self.VERSION, self.command_words_count, self.command, self.TAG
        )

        # Pack payload without CRC first
        payload_without_crc = pack(
            LITTLE_ENDIAN + UINT32 + UINT32 + UINT32 + UINT16 + UINT8 + UINT8,
            self.session_handle,
            self.key_store_id,
            self.nonce,
            RESERVED,  # Reserved 16 bits
            self.flags,
            RESERVED,  # Reserved 8 bits
        )

        # Calculate CRC over header + payload (without CRC field)
        data_for_crc = header + payload_without_crc
        crc = self.get_msg_crc(data_for_crc)

        # Add CRC to complete the payload
        payload = payload_without_crc + crc

        return header + payload

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        Parses and validates the response message header, extracts status information,
        and decodes the key store handle if present in the response data.

        :param response: Raw response data bytes from the target device.
        :raises SPSDKParsingError: Invalid response format, tag, command, size or version.
        """
        # Decode and validate header
        (version, size, command, tag) = unpack(self.HEADER_FORMAT, response[:4])
        if tag != self.RSP_TAG:
            raise SPSDKParsingError(f"Message TAG in response is invalid: {hex(tag)}")
        if command != self.command:
            raise SPSDKParsingError(f"Message COMMAND in response is invalid: {hex(command)}")
        if size not in range(self.RESPONSE_HEADER_WORDS_COUNT, self.response_words_count + 1):
            raise SPSDKParsingError(f"Message SIZE in response is invalid: {hex(size)}")
        if version != self.VERSION:
            raise SPSDKParsingError(f"Message VERSION in response is invalid: {hex(version)}")

        # Decode status word
        (
            self.status,
            self.indication,
            self.abort_code,
        ) = unpack(LITTLE_ENDIAN + UINT8 + UINT8 + UINT16, response[4:8])

        # Decode key store handle
        if len(response) >= 12:
            self.key_store_handle = unpack(LITTLE_ENDIAN + UINT32, response[8:12])[0]
        else:
            self.key_store_handle = 0

    def response_info(self) -> str:
        """Get key store open response information.

        Formats and returns detailed information about the key store operation including
        the handle, operation status, and key store type.

        :return: Formatted string containing key store handle, operation status, and type information.
        """
        ret = f"Key store handle: 0x{self.key_store_handle:08X}\n"
        if self.key_store_handle == 0:
            ret += "Key store open failed - no valid key store handle returned\n"
        else:
            operation = "created" if self.create_keystore else "loaded"
            keystore_type = "shared" if self.shared_keystore else "regular"
            ret += f"Key store successfully {operation} ({keystore_type})\n"
        return ret

    def info(self) -> str:
        """Get information about the Key Store Open Command message.

        The method provides comprehensive details about the key store operation including
        session handle, key store ID, nonce, operation type, and various configuration
        flags. If available, it also includes response information from the command
        execution.

        :return: Formatted string containing detailed information about the message
                 including operation parameters and system limitations.
        """
        ret = super().info()
        ret += "\nKey Store Open Command:\n"
        ret += f"- Session handle: 0x{self.session_handle:08X}\n"
        ret += f"- Key store ID: 0x{self.key_store_id:08X}\n"
        ret += f"- Nonce: 0x{self.nonce:08X}\n"
        ret += f"- Operation: {'Create' if self.create_keystore else 'Load'}\n"
        ret += f"- Type: {'Shared' if self.shared_keystore else 'Regular'}\n"
        ret += f"- Sync operation: {self.sync_operation}\n"
        ret += f"- Monotonic counter increment: {self.monotonic_counter_increment}\n"
        ret += "- Maximum 2 key stores can be created/opened\n"
        ret += "- Maximum 100 keys can be stored per key store\n"
        ret += "- Maximum 10 key store handles for shared key stores\n"
        if hasattr(self, "key_store_handle"):
            ret += f"\n{self.response_info()}"
        return ret

    def get_key_store_handle(self) -> int:
        """Get the key store handle from successful response.

        :return: Key store handle, 0 if key store open failed.
        """
        return self.key_store_handle

    def is_key_store_valid(self) -> bool:
        """Check if key store was successfully opened.

        :return: True if key store handle is valid (non-zero), False otherwise.
        """
        return self.key_store_handle != 0


class EleMessagePublicKeyExport(EleMessage):
    """ELE Message for Public Key Export operations.

    This class handles the export of public keys from asymmetric key pairs stored in the
    EdgeLock Secure Enclave key store. The public key is re-calculated from the stored
    private key since public keys are not stored by default in the key storage.
    For ECC keys, the public key is exported in non-compressed form {x, y} in big-endian
    order. For RSA keys, only the modulus is exported as the public exponent uses the
    default value (65,537). ECC Montgomery keys are exported in big-endian format per
    EdgeLock Secure Enclave specifications.
    Requires an active key store service session before use.

    :cvar CMD: Public key export command identifier (0x32)
    :cvar MAX_RESPONSE_DATA_SIZE: Maximum size limit for exported public key data
    """

    CMD = 0x32  # Public key export command ID
    VERSION = 0x07  # Version for HSM API
    COMMAND_PAYLOAD_WORDS_COUNT = 6  # Key store handle, key ID, addresses, size, CRC
    RESPONSE_PAYLOAD_WORDS_COUNT = 2  # Response indicator + output size
    MAX_RESPONSE_DATA_SIZE = 1024  # Maximum public key size

    def __init__(self, key_store_handle: int, key_id: int, output_buffer_size: int = 64) -> None:
        """Initialize ELE message for retrieving public key from key store.

        :param key_store_handle: Handle identifying the key store service flow
        :param key_id: ID of the asymmetric key stored in the key store
        :param output_buffer_size: Length in bytes of the output public key buffer
        """
        super().__init__()
        self.key_store_handle = key_store_handle
        self.key_id = key_id
        self.output_buffer_size = output_buffer_size
        self.output_public_key_size = 0
        self.public_key = b""
        self._response_data_size = min(output_buffer_size, self.MAX_RESPONSE_DATA_SIZE)

    def export(self) -> bytes:
        """Export message to bytes representation.

        Converts the ELE message object into its final binary format by packing
        the header, payload, and CRC into a bytes array ready for transmission.

        :return: Complete message as bytes including header, payload and CRC.
        """
        # Header: Version(07) | Word size(07) | Command ID(32) | Tag(17)
        header = pack(
            self.HEADER_FORMAT, self.VERSION, self.command_words_count, self.command, self.TAG
        )

        # Payload without CRC
        payload_without_crc = pack(
            LITTLE_ENDIAN + UINT32 + UINT32 + UINT32 + UINT32 + UINT16 + UINT16,
            self.key_store_handle,  # Word 1: Key store handle
            self.key_id,  # Word 2: Key ID
            0,  # Word 3: MSB address (must be 0)
            self.response_data_address,  # Word 4: LSB address (should be aligned)
            self.output_buffer_size,  # Word 5 upper: Reserved 16 bits
            RESERVED,  # Word 5 lower: Output size (reasonable size)
        )

        # Calculate CRC over header + payload (without CRC field)
        data_for_crc = header + payload_without_crc
        crc = self.get_msg_crc(data_for_crc)

        # Add CRC to complete the payload
        payload = payload_without_crc + crc

        return header + payload

    def decode_response(self, response: bytes) -> None:
        """Decode response from target device.

        Parses and validates the response message header, extracts status information,
        and decodes the output public key size from the response data.

        :param response: Raw response data bytes from the target device.
        :raises SPSDKParsingError: Invalid response format, tag, command, size, or version.
        """
        # Decode and validate header
        (version, size, command, tag) = unpack(self.HEADER_FORMAT, response[:4])
        if tag != self.RSP_TAG:
            raise SPSDKParsingError(f"Message TAG in response is invalid: {hex(tag)}")
        if command != self.command:
            raise SPSDKParsingError(f"Message COMMAND in response is invalid: {hex(command)}")
        if size not in range(self.RESPONSE_HEADER_WORDS_COUNT, self.response_words_count + 1):
            raise SPSDKParsingError(f"Message SIZE in response is invalid: {hex(size)}")
        if version != self.VERSION:
            raise SPSDKParsingError(f"Message VERSION in response is invalid: {hex(version)}")

        # Decode status word
        (
            self.status,
            self.indication,
            self.abort_code,
        ) = unpack(LITTLE_ENDIAN + UINT8 + UINT8 + UINT16, response[4:8])

        # Decode output public key size
        if len(response) >= 12:
            self.output_public_key_size, _ = unpack(LITTLE_ENDIAN + UINT16 + UINT16, response[8:12])
        else:
            self.output_public_key_size = 0

    def decode_response_data(self, response_data: bytes) -> None:
        """Decode response data from target.

        The method extracts the public key from the response data based on the
        configured output public key size. If no public key size is specified,
        an empty key is set.

        :param response_data: Raw response data bytes received from target.
        """
        if self.output_public_key_size > 0:
            self.public_key = response_data[: self.output_public_key_size]
        else:
            self.public_key = b""

    def response_info(self) -> str:
        """Get formatted information about public key export response.

        Provides detailed information about the exported public key including key store handle,
        key ID, size, and the actual key data with format specifications for different key types.

        :return: Formatted string containing comprehensive public key export information.
        """
        ret = f"Key store handle: 0x{self.key_store_handle:08X}\n"
        ret += f"Key ID: 0x{self.key_id:08X}\n"
        ret += f"Output public key size: {self.output_public_key_size} bytes\n"
        if self.public_key:
            ret += f"Public key (hex): {self.public_key.hex()}\n"
            ret += "Public key format:\n"
            ret += "- ECC: Non-compressed form {x, y} in big-endian order\n"
            ret += "- RSA: Modulus only (public exponent is 65537)\n"
            ret += "- Montgomery: Big-endian format (unlike RFC 7748)\n"
        else:
            ret += "No public key data received\n"
        return ret

    def info(self) -> str:
        """Get information about the Public Key Export Command message.

        Provides detailed information about the command including key store handle,
        key ID, output buffer size, and operational details. If response data is
        available, includes response information as well.

        :return: Formatted string containing comprehensive message information.
        """
        ret = super().info()
        ret += "\nPublic Key Export Command:\n"
        ret += f"- Key store handle: 0x{self.key_store_handle:08X}\n"
        ret += f"- Key ID: 0x{self.key_id:08X}\n"
        ret += f"- Output buffer size: {self.output_buffer_size} bytes\n"
        ret += "- Exports public key of asymmetric key from key store\n"
        ret += "- Public key is re-calculated (except Twisted Edwards/Montgomery)\n"
        ret += "- Must be called after opening valid key store service\n"
        if hasattr(self, "output_public_key_size"):
            ret += f"\n{self.response_info()}"
        return ret

    def get_public_key(self) -> bytes:
        """Get the exported public key.

        :return: Public key bytes, empty if export failed.
        """
        return self.public_key

    def get_public_key_size(self) -> int:
        """Get the size of exported public key.

        :return: Size in bytes of exported public key.
        """
        return self.output_public_key_size


class EleMessageKeyStoreClose(EleMessage):
    """ELE Message Key Store Close.

    EdgeLock Enclave message for closing a key store service flow identified by its handle.
    This command deletes the key store context and content from the EdgeLock Secure Enclave
    internal memory, with any updates not written to NVM being lost. The command can only
    be called after having opened a valid key store service.

    :cvar CMD: Message command identifier for key store close request.
    :cvar VERSION: HSM API version (0x07).
    :cvar COMMAND_PAYLOAD_WORDS_COUNT: Number of payload words in command (1).
    :cvar RESPONSE_PAYLOAD_WORDS_COUNT: Number of payload words in response (0).
    """

    CMD = MessageIDs.KEY_STORE_CLOSE_REQ.tag
    VERSION = 0x07  # Version for HSM API
    COMMAND_PAYLOAD_WORDS_COUNT = 1  # Key store handle only
    RESPONSE_PAYLOAD_WORDS_COUNT = 0  # No response payload

    def __init__(self, key_store_handle: int) -> None:
        """Initialize key store service close message.

        :param key_store_handle: Handle identifying the key store service flow to close
        """
        super().__init__()
        self.key_store_handle = key_store_handle

    def export(self) -> bytes:
        """Export message to bytes array.

        Converts the ELE message structure into a binary format suitable for transmission.
        The exported format includes a header with version, word count, command ID, and tag,
        followed by the payload containing the key store handle.

        :return: Binary representation of the ELE message.
        """
        # Header: Version(07) | Word size(02) | Command ID(31) | Tag(17)
        header = pack(
            self.HEADER_FORMAT, self.VERSION, self.command_words_count, self.command, self.TAG
        )

        # Payload: Key store handle only
        payload = pack(LITTLE_ENDIAN + UINT32, self.key_store_handle)

        return header + payload

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        Parses and validates the response message header and extracts status information.
        The method verifies message tag, command, size, and version fields, then decodes
        the status word containing response indicator and abort code.

        :param response: Raw response data bytes from target device.
        :raises SPSDKParsingError: Invalid response format or header field mismatch.
        """
        # Decode and validate header
        (version, size, command, tag) = unpack(self.HEADER_FORMAT, response[:4])
        if tag != self.RSP_TAG:
            raise SPSDKParsingError(f"Message TAG in response is invalid: {hex(tag)}")
        if command != self.command:
            raise SPSDKParsingError(f"Message COMMAND in response is invalid: {hex(command)}")
        if size != 2:  # Response word size should be 2 (header + response indicator)
            raise SPSDKParsingError(f"Message SIZE in response is invalid: {hex(size)}")
        if version != self.VERSION:
            raise SPSDKParsingError(f"Message VERSION in response is invalid: {hex(version)}")

        # Decode status word (response indicator)
        (
            self.status,
            self.indication,
            self.abort_code,
        ) = unpack(LITTLE_ENDIAN + UINT8 + UINT8 + UINT16, response[4:8])

    def info(self) -> str:
        """Get formatted information about the key store close command.

        Provides detailed information about the key store close operation including
        the key store handle and important warnings about data loss.

        :return: Formatted string containing command information and live data.
        """
        ret = super().info()
        ret += "\nKey Store Close Command:\n"
        ret += f"- Key store handle: 0x{self.key_store_handle:08X}\n"
        ret += "- Closes key store service flow and deletes context from ELE memory\n"
        ret += "- Any updates not written to NVM will be lost\n"
        return ret

    def response_info(self) -> str:
        """Get response information as formatted string.

        Formats the key store close response information including status and handle details
        into a human-readable string representation.

        :return: Formatted string containing response status and key store handle information.
        """
        ret = "Key Store Close Response:\n"
        ret += f"- Status: {self.status_string}\n"
        ret += f"- Key store handle 0x{self.key_store_handle:08X} closed successfully\n"
        return ret
