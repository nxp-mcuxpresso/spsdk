#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""EdgeLock Enclave Message."""


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
    """Base class for any EdgeLock Enclave Message.

    Message contains a header - tag, command id, size and version.
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
        """Class object initialized."""
        self.abort_code = 0
        self.indication = 0
        self.status = 0
        self.buff_addr = 0
        self.buff_size = 0
        self.command = self.CMD
        self._response_data_size = self.MAX_RESPONSE_DATA_SIZE

    @property
    def command_address(self) -> int:
        """Command address in target memory space."""
        return align(self.buff_addr, self.ELE_MSG_ALIGN)

    @property
    def command_words_count(self) -> int:
        """Command Words count."""
        return self.COMMAND_HEADER_WORDS_COUNT + self.COMMAND_PAYLOAD_WORDS_COUNT

    @property
    def has_command_data(self) -> bool:
        """Check if command has additional data."""
        return bool(self.command_data_size > 0)

    @property
    def command_data_address(self) -> int:
        """Command data address in target memory space."""
        return align(self.command_address + self.command_words_count * 4, self.ELE_MSG_ALIGN)

    @property
    def command_data_size(self) -> int:
        """Command data address in target memory space."""
        return align(len(self.command_data) or self.MAX_COMMAND_DATA_SIZE, self.ELE_MSG_ALIGN)

    @property
    def command_data(self) -> bytes:
        """Command data to be loaded into target memory space."""
        return b""

    @property
    def response_address(self) -> int:
        """Response address in target memory space."""
        if self.has_command_data:
            address = self.command_data_address + self.command_data_size
        else:
            address = self.buff_addr + self.command_words_count * 4
        return align(address, self.ELE_MSG_ALIGN)

    @property
    def response_words_count(self) -> int:
        """Response Words count."""
        return self.RESPONSE_HEADER_WORDS_COUNT + self.RESPONSE_PAYLOAD_WORDS_COUNT

    @property
    def has_response_data(self) -> bool:
        """Check if response has additional data."""
        return bool(self.response_data_size > 0)

    @property
    def response_data_address(self) -> int:
        """Response data address in target memory space."""
        return align(self.response_address + self.response_words_count * 4, self.ELE_MSG_ALIGN)

    @property
    def response_data_size(self) -> int:
        """Response data address in target memory space."""
        return align(self._response_data_size, self.ELE_MSG_ALIGN)

    @response_data_size.setter
    def response_data_size(self, size: int) -> None:
        """Response data address in target memory space."""
        self._response_data_size = size

    @property
    def free_space_address(self) -> int:
        """First free address after ele message in target memory space."""
        return align(self.response_data_address + self._response_data_size, self.ELE_MSG_ALIGN)

    @property
    def free_space_size(self) -> int:
        """Free space size after ele message in target memory space."""
        return align(
            self.buff_size - (self.free_space_address - self.buff_addr), self.ELE_MSG_ALIGN
        )

    @property
    def status_string(self) -> str:
        """Get status in readable string format."""
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

        :param buff_addr: Real address of communication buffer in target memory space
        :param buff_size: Size of communication buffer in target memory space
        """
        self.buff_addr = buff_addr
        self.buff_size = buff_size

        self.validate_buffer_params()

    def validate_buffer_params(self) -> None:
        """Validate communication buffer parameters.

        raises SPSDKValueError: Invalid buffer parameters.
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
        """Validate message."""

    def header_export(
        self,
    ) -> bytes:
        """Exports message header to bytes.

        :return: Bytes representation of message header.
        """
        return pack(
            self.HEADER_FORMAT, self.VERSION, self.command_words_count, self.command, self.TAG
        )

    def export(
        self,
    ) -> bytes:
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
        """
        return self.header_export()

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        :param response: Data of response.
        :raises SPSDKParsingError: Response parse detect some error.
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

        :note: The response data are specific per command.
        :param response_data: Data of response.
        """

    def __eq__(self, other: object) -> bool:
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

        :param payload: The input data to compute CRC on them. Must be 4 bytes aligned.
        :return: 4 bytes of CRC in little endian format.
        """
        if len(payload) % 4 != 0:
            raise SPSDKValueError("Payload must be 4 bytes aligned")
        res = 0
        for i in range(0, len(payload), 4):
            res ^= int.from_bytes(payload[i : i + 4], Endianness.LITTLE.value)
        return res.to_bytes(4, Endianness.LITTLE.value)

    def response_status(self) -> str:
        """Print the response status information.

        :return: String with response status.
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
        """Print information including live data.

        :return: Information about the message.
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
    """ELE Message Ping."""

    CMD = MessageIDs.PING_REQ.tag


class EleMessageDumpDebugBuffer(EleMessage):
    """ELE Message Dump Debug buffer.

    EdgeLock Secure Enclave have a logging mechanism for debugging purposes.
    Logs are sent over MU with maximum 20 logs per exchange. If ELE has more than
    20 logs in buffer, this API must be called multiple times.
    EdgeLock Secure Enclave internal buffer log size is approximately 2kB.
    """

    CMD = MessageIDs.ELE_DUMP_DEBUG_BUFFER_REQ.tag
    RESPONSE_PAYLOAD_WORDS_COUNT = 21  # Maximum response length
    ELE_DEBUG_LOG_MAX_RSP_LENGTH = 0x17  # Maximum response length constant

    def __init__(self) -> None:
        """Class object initialized."""
        super().__init__()
        self.debug_words: list[int] = []
        self.nb_logs = 0
        self.has_more_logs = False

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        :param response: Data of response.
        :raises SPSDKParsingError: Response parse detect some error.
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
        """Print Dumped data of debug buffer in STEC team format."""
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
    """ELE Message Reset."""

    CMD = MessageIDs.RESET_REQ.tag
    RESPONSE_HEADER_WORDS_COUNT = 0


class EleMessageEleFwAuthenticate(EleMessage):
    """Ele firmware authenticate request."""

    CMD = MessageIDs.ELE_FW_AUTH_REQ.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 3

    def __init__(self, ele_fw_address: int) -> None:
        """Constructor.

        Be aware to have ELE FW in accessible memory for ROM, and
        do not use the RAM memory used to communicate with ELE.

        :param ele_fw_address: Address in target memory with ele firmware.
        """
        super().__init__()
        self.ele_fw_address = ele_fw_address

    def export(self) -> bytes:
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
        """
        ret = self.header_export()
        ret += pack(
            LITTLE_ENDIAN + UINT32 + UINT32 + UINT32, self.ele_fw_address, 0, self.ele_fw_address
        )
        return ret


class EleMessageOemContainerAuthenticate(EleMessage):
    """OEM container authenticate request."""

    CMD = MessageIDs.ELE_OEM_CNTN_AUTH_REQ.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 2

    def __init__(self, oem_cntn_addr: int) -> None:
        """Constructor.

        Be aware to have OEM Container in accessible memory for ROM.

        :param oem_cntn_addr: Address in target memory with oem container.
        """
        super().__init__()
        self.oem_cntn_addr = oem_cntn_addr

    def export(self) -> bytes:
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
        """
        ret = self.header_export()
        ret += pack(LITTLE_ENDIAN + UINT32 + UINT32, 0, self.oem_cntn_addr)
        return ret


class EleMessageVerifyImage(EleMessage):
    """Verify image request."""

    CMD = MessageIDs.ELE_VERIFY_IMAGE_REQ.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 1
    RESPONSE_PAYLOAD_WORDS_COUNT = 2

    def __init__(self, image_mask: int = 0x0000_0001) -> None:
        """Constructor.

        The Verify Image message is sent to the ELE after a container has been
        loaded into memory and processed with an Authenticate Container message.
        This commands the ELE to check the hash on one or more images.

        :param image_mask: Used to indicate which images are to be checked. There must be at least
            one image. Each bit corresponds to a particular image index in the header, for example,
            bit 0 is for image 0, and bit 1 is for image 1, and so on.
        """
        super().__init__()
        self.image_mask = image_mask
        self.valid_image_mask = 0
        self.invalid_image_mask = 0xFFFF_FFFF

    def export(self) -> bytes:
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
        """
        ret = self.header_export()
        ret += pack(LITTLE_ENDIAN + UINT32, self.image_mask)
        return ret

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        :param response: Data of response.
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
        """Print Dumped data of debug buffer."""
        ret = f"Valid image mask    : 0x{self.valid_image_mask:08X}\n"
        ret += f"Invalid image mask  : 0x{self.invalid_image_mask:08X}"
        return ret


class EleMessageReleaseContainer(EleMessage):
    """ELE Message Release container."""

    CMD = MessageIDs.ELE_RELEASE_CONTAINER_REQ.tag


class EleMessageForwardLifeCycleUpdate(EleMessage):
    """Forward Life cycle update request."""

    CMD = MessageIDs.ELE_FWD_LIFECYCLE_UP_REQ.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 1

    def __init__(self, lifecycle_update: LifeCycleToSwitch) -> None:
        """Constructor.

        Be aware that this is non-revertible operation.

        :param lifecycle_update: New life cycle value.
        """
        super().__init__()
        self.lifecycle_update = lifecycle_update

    def export(self) -> bytes:
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
        """
        ret = self.header_export()
        ret += pack(LITTLE_ENDIAN + UINT16 + UINT8 + UINT8, self.lifecycle_update.tag, 0, 0)
        return ret


class EleMessageGetEvents(EleMessage):
    """Get events request.

    \b
    Event layout:
    -------------------------
    - TAG - CMD - IND - STS -
    -------------------------
    \b
    """

    CMD = MessageIDs.ELE_GET_EVENTS_REQ.tag
    RESPONSE_PAYLOAD_WORDS_COUNT = 10

    MAX_EVENT_CNT = 8

    def __init__(self) -> None:
        """Constructor.

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
        """Decode response from target.

        :param response: Data of response.
        :raises SPSDKParsingError: Response parse detect some error.
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
        """Get IPC ID in string from event."""
        ipc_id = (event >> 24) & 0xFF
        return MessageUnitId.get_description(ipc_id, f"Unknown MU: ({ipc_id})") or ""

    @staticmethod
    def get_cmd(event: int) -> str:
        """Get Command in string from event."""
        cmd = (event >> 16) & 0xFF
        return MessageIDs.get_description(cmd, f"Unknown Command: (0x{cmd:02})") or ""

    @staticmethod
    def get_ind(event: int) -> str:
        """Get Indication in string from event."""
        ind = (event >> 8) & 0xFF
        return ResponseIndication.get_description(ind, f"Unknown Indication: (0x{ind:02})") or ""

    @staticmethod
    def get_sts(event: int) -> str:
        """Get Status in string from event."""
        sts = event & 0xFF
        return ResponseStatus.get_description(sts, f"Unknown Status: (0x{sts:02})") or ""

    def response_info(self) -> str:
        """Print events info."""
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
    """ELE Message Start True Random Generator."""

    CMD = MessageIDs.START_RNG_REQ.tag


class EleMessageGetTrngState(EleMessage):
    """ELE Message Get True Random Generator State."""

    CMD = MessageIDs.GET_TRNG_STATE_REQ.tag
    RESPONSE_PAYLOAD_WORDS_COUNT = 1

    def __init__(self) -> None:
        """Class object initialized."""
        super().__init__()
        self.ele_trng_state = EleTrngState.ELE_TRNG_PROGRAM.tag
        self.ele_csal_state = EleCsalState.ELE_CSAL_NOT_READY.tag

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        :param response: Data of response.
        :raises SPSDKParsingError: Response parse detect some error.
        """
        super().decode_response(response)
        self.ele_trng_state, self.ele_csal_state, _ = unpack(
            LITTLE_ENDIAN + UINT8 + UINT8 + "2s", response[-4:]
        )

    def response_info(self) -> str:
        """Print specific information of ELE.

        :return: Information about the TRNG.
        """
        return (
            f"EdgeLock Enclave TRNG state: {EleTrngState.get_description(self.ele_trng_state)}"
            + f"\nEdgeLock Secure Enclave RNG state: {EleCsalState.get_description(self.ele_csal_state)}"
        )


class EleMessageCommit(EleMessage):
    """ELE Message Get FW status."""

    CMD = MessageIDs.ELE_COMMIT_REQ.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 1
    RESPONSE_PAYLOAD_WORDS_COUNT = 1

    def __init__(self, info_to_commit: list[EleInfo2Commit]) -> None:
        """Class object initialized."""
        super().__init__()
        self.info_to_commit = info_to_commit

    @property
    def info2commit_mask(self) -> int:
        """Get info to commit mask used in command."""
        ret = 0
        for rule in self.info_to_commit:
            ret |= rule.tag
        return ret

    def mask_to_info2commit(self, mask: int) -> list[EleInfo2Commit]:
        """Get list of info to commit from mask."""
        ret = []
        for bit in range(32):
            bit_mask = 1 << bit
            if mask and bit_mask:
                ret.append(EleInfo2Commit.from_tag(bit))
        return ret

    def export(self) -> bytes:
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
        """
        ret = self.header_export()
        ret += pack(LITTLE_ENDIAN + UINT32, self.info2commit_mask)
        return ret

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        :param response: Data of response.
        :raises SPSDKParsingError: Response parse detect some error.
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
    """ELE Message Get FW status."""

    CMD = MessageIDs.GET_FW_STATUS_REQ.tag
    RESPONSE_PAYLOAD_WORDS_COUNT = 1

    def __init__(self) -> None:
        """Class object initialized."""
        super().__init__()
        self.ele_fw_status = EleFwStatus.ELE_FW_STATUS_NOT_IN_PLACE.tag

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        :param response: Data of response.
        :raises SPSDKParsingError: Response parse detect some error.
        """
        super().decode_response(response)
        self.ele_fw_status, _ = unpack(LITTLE_ENDIAN + UINT8 + "3s", response[8:12])

    def response_info(self) -> str:
        """Print specific information of ELE.

        :return: Information about the ELE.
        """
        return f"EdgeLock Enclave firmware state: {EleFwStatus.get_label(self.ele_fw_status)}"


class EleMessageGetFwVersion(EleMessage):
    """ELE Message Get FW version."""

    CMD = MessageIDs.GET_FW_VERSION_REQ.tag
    RESPONSE_PAYLOAD_WORDS_COUNT = 2

    def __init__(self) -> None:
        """Class object initialized."""
        super().__init__()
        self.ele_fw_version_raw = 0
        self.ele_fw_version_sha1 = 0

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        :param response: Data of response.
        :raises SPSDKParsingError: Response parse detect some error.
        """
        super().decode_response(response)
        self.ele_fw_version_raw = int.from_bytes(response[8:12], Endianness.LITTLE.value)
        self.ele_fw_version_sha1 = int.from_bytes(response[12:16], Endianness.LITTLE.value)

    def response_info(self) -> str:
        """Print specific information of ELE.

        :return: Information about the ELE.
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
    """ELE Message Read common fuse."""

    CMD = MessageIDs.READ_COMMON_FUSE.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 1
    RESPONSE_PAYLOAD_WORDS_COUNT = 1

    def __init__(self, index: int) -> None:
        """Constructor.

        Read common fuse.

        :param index: Fuse ID.
        """
        super().__init__()
        self.index = index
        self.fuse_value = 0

    def export(self) -> bytes:
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
        """
        ret = self.header_export()
        ret += pack(LITTLE_ENDIAN + UINT16 + UINT16, self.index, 0)
        return ret

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        :param response: Data of response.
        :raises SPSDKParsingError: Response parse detect some error.
        """
        super().decode_response(response)
        self.fuse_value = int.from_bytes(response[8:12], Endianness.LITTLE.value)

    def response_info(self) -> str:
        """Print fuse value.

        :return: Read fuse value.
        """
        return f"Fuse ID_{self.index}: 0x{self.fuse_value:08X}\n"


class EleMessageReadShadowFuse(EleMessageReadCommonFuse):
    """ELE Message Read shadow fuse."""

    CMD = MessageIDs.READ_SHADOW_FUSE.tag

    def export(self) -> bytes:
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
        """
        ret = self.header_export()
        ret += pack(LITTLE_ENDIAN + UINT32, self.index)
        return ret


class EleMessageGetInfo(EleMessage):
    """ELE Message Get Info."""

    CMD = MessageIDs.GET_INFO_REQ.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 3
    MAX_RESPONSE_DATA_SIZE = 256

    def __init__(self) -> None:
        """Class object initialized."""
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
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
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
        """Decode response data from target.

        :note: The response data are specific per command.
        :param response_data: Data of response.
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
        """Print specific information of ELE.

        :return: Information about the ELE.
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
    """ELE Message Derive Key."""

    CMD = MessageIDs.ELE_DERIVE_KEY_REQ.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 6
    MAX_RESPONSE_DATA_SIZE = 32
    _MAX_COMMAND_DATA_SIZE = 65536
    SUPPORTED_KEY_SIZES = [16, 32]

    def __init__(self, key_size: int, context: Optional[bytes]) -> None:
        """Class object initialized.

        :param key_size: Output key size [16,32] is valid
        :param context:  User's context to be used for key diversification
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
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
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
        """Command data to be loaded into target memory space."""
        return self.context if self.context else b""

    def decode_response_data(self, response_data: bytes) -> None:
        """Decode response data from target.

        :note: The response data are specific per command.
        :param response_data: Data of response.
        """
        self.derived_key = response_data[: self.key_size]

    def get_key(self) -> bytes:
        """Get derived key."""
        return self.derived_key


class EleMessageSigned(EleMessage):
    """ELE Message Signed."""

    COMMAND_PAYLOAD_WORDS_COUNT = 2

    def __init__(self, signed_msg: bytes, family: FamilyRevision) -> None:
        """Class object initialized.

        :param signed_msg: Signed message container.
        :param family: Chip family name.
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
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
        """
        payload = pack(
            LITTLE_ENDIAN + UINT32 + UINT32,
            0,
            self.command_data_address,
        )
        return self.header_export() + payload

    @property
    def command_data(self) -> bytes:
        """Command data to be loaded into target memory space."""
        return self.signed_msg_binary

    def info(self) -> str:
        """Print information including live data.

        :return: Information about the message.
        """
        ret = super().info()
        ret += "\n" + self.signed_msg.image_info().draw()

        return ret


class EleMessageGenerateKeyBlob(EleMessage):
    """ELE Message Generate KeyBlob."""

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
        """Constructor of Generate Key Blob class.

        :param key_identifier: ID of key
        :param algorithm: Select supported algorithm
        :param key: Key to be wrapped
        """
        super().__init__()
        self.key_id = key_identifier
        self.algorithm = algorithm

        self.key = key
        self.key_blob = bytes()
        self.validate()

    def export(self) -> bytes:
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
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
        """Validate generate keyblob message data.

        :raises SPSDKValueError: Invalid used key size or encryption algorithm
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
        """Print information including live data.

        :return: Information about the message.
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

        :return: Table with supported key size in text.
        """
        ret = ""
        for key, value in cls.SUPPORTED_ALGORITHMS.items():
            ret += key.label + ": " + str(value) + ",\n"
        return ret

    def decode_response_data(self, response_data: bytes) -> None:
        """Decode response data from target.

        :note: The response data are specific per command.
        :param response_data: Data of response.
        :raises SPSDKParsingError: Invalid response detected.
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
    """ELE Message Generate DEK KeyBlob."""

    KEYBLOB_NAME = "DEK"
    # List of supported algorithms and theirs key sizes
    SUPPORTED_ALGORITHMS = {
        KeyBlobEncryptionAlgorithm.AES_CBC: [128, 192, 256],
        KeyBlobEncryptionAlgorithm.SM4_CBC: [128],
    }

    @property
    def command_data(self) -> bytes:
        """Command data to be loaded into target memory space."""
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
    """ELE Message Generate OTFAD KeyBlob."""

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
        """Constructor of generate OTFAD keyblob class.

        :param key_identifier: ID of Key
        :param key: OTFAD key
        :param aes_counter: AES counter value
        :param start_address: Start address in memory to be encrypted
        :param end_address: End address in memory to be encrypted
        :param read_only: Read only flag, defaults to True
        :param decryption_enabled: Decryption enable flag, defaults to True
        :param configuration_valid: Configuration valid flag, defaults to True
        """
        self.aes_counter = aes_counter
        self.start_address = start_address
        self.end_address = end_address
        self.read_only = read_only
        self.decryption_enabled = decryption_enabled
        self.configuration_valid = configuration_valid
        super().__init__(key_identifier, KeyBlobEncryptionAlgorithm.AES_CTR, key)

    def validate(self) -> None:
        """Validate generate OTFAD keyblob."""
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
        """Command data to be loaded into target memory space."""
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
        """Print information including live data.

        :return: Information about the message.
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
    """ELE Message Generate IEE KeyBlob."""

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
        """Constructor of generate IEE keyblob class.

        :param key_identifier: ID of key
        :param algorithm: Used algorithm
        :param key: IEE key
        :param ctr_mode: In case of AES CTR algorithm, the CTR mode must be selected
        :param aes_counter: AES counter in case of AES CTR algorithm
        :param page_offset: IEE page offset
        :param region_number: Region number
        :param bypass: Encryption bypass flag, defaults to False
        :param locked: Locked flag, defaults to False
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
        """Command data to be loaded into target memory space."""
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
        """Print information including live data.

        :return: Information about the message.
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
    """ELE Message Load KeyBlob."""

    CMD = MessageIDs.LOAD_KEY_BLOB_REQ.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 3

    def __init__(self, key_identifier: int, keyblob: bytes) -> None:
        """Constructor of Load Key Blob class.

        :param key_identifier: ID of key
        :param keyblob: Keyblob to be wrapped
        """
        super().__init__()
        self.key_id = key_identifier

        self.keyblob = keyblob
        self.validate()

    def export(self) -> bytes:
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
        """
        payload = pack(
            LITTLE_ENDIAN + UINT32 + UINT32 + UINT32, self.key_id, 0, self.command_data_address
        )
        payload = self.header_export() + payload
        return payload

    @property
    def command_data(self) -> bytes:
        """Command data to be loaded into target memory space."""
        return self.keyblob

    def info(self) -> str:
        """Print information including live data.

        :return: Information about the message.
        """
        ret = super().info()
        ret += "\n"
        ret += f"Key ID:          {self.key_id}\n"
        ret += f"KeyBlob size:    {len(self.keyblob)}\n"
        return ret


class EleMessageWriteFuse(EleMessage):
    """Write Fuse request."""

    CMD = MessageIDs.WRITE_FUSE.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 2
    RESPONSE_PAYLOAD_WORDS_COUNT = 1

    def __init__(self, bit_position: int, bit_length: int, lock: bool, payload: int) -> None:
        """Constructor.

        This command allows to write to the fuses.
        OEM Fuses are accessible depending on the chip lifecycle.

        :param bit_position: Fuse identifier expressed as its position in bit in the fuse map.
        :param bit_length: Number of bits to be written.
        :param lock: Write lock requirement. When set to 1, fuse words are locked. When unset, no write lock is done.
        :param payload: Data to be written
        """
        super().__init__()
        self.bit_position = bit_position
        self.bit_length = bit_length
        self.lock = lock
        self.payload = payload
        self.processed_idx = 0

    def export(self) -> bytes:
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
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

        :param response: Data of response.
        :raises SPSDKParsingError: Response parse detect some error.
        """
        super().decode_response(response)
        if len(response) == self.response_words_count * 4:
            (self.processed_idx, _) = unpack(LITTLE_ENDIAN + UINT16 + UINT16, response[8:12])


class EleMessageWriteShadowFuse(EleMessage):
    """Write shadow fuse request."""

    CMD = MessageIDs.WRITE_SHADOW_FUSE.tag
    COMMAND_PAYLOAD_WORDS_COUNT = 2

    def __init__(self, index: int, value: int) -> None:
        """Constructor.

        This command allows to write to the shadow fuses.

        :param index: Fuse identifier expressed as its position in bit in the fuse map.
        :param value: Data to be written.
        """
        super().__init__()
        self.index = index
        self.value = value

    def export(self) -> bytes:
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
        """
        ret = self.header_export()

        ret += pack(
            LITTLE_ENDIAN + UINT32 + UINT32,
            self.index,
            self.value,
        )
        return ret


class EleMessageEnableApc(EleMessage):
    """Enable APC (Application core) ELE Message."""

    CMD = MessageIDs.ELE_ENABLE_APC_REQ.tag


class EleMessageEnableRtc(EleMessage):
    """Enable RTC (Real time core) ELE Message."""

    CMD = MessageIDs.ELE_ENABLE_RTC_REQ.tag


class EleMessageResetApcContext(EleMessage):
    """Send request to reset APC context ELE Message."""

    CMD = MessageIDs.ELE_RESET_APC_CTX_REQ.tag


class EleMessageSessionOpen(EleMessage):
    """ELE Message Session Open.

    Session open command is used to initialize the EdgeLock Secure Enclave HSM services
    for the requestor. It establishes a route between the user and the EdgeLock Secure
    Enclave as well as a quality of service.

    A maximum of 20 sessions can be opened at the same time.
    Session open command must be called before any other APIs that use a session.
    """

    CMD = 0x10  # Session open command ID
    VERSION = 0x07  # Version for HSM API
    COMMAND_PAYLOAD_WORDS_COUNT = 2  # Two reserved words
    RESPONSE_PAYLOAD_WORDS_COUNT = 1  # Session handle word

    def __init__(self) -> None:
        """Class object initialized."""
        super().__init__()
        self.session_handle = 0

    def export(self) -> bytes:
        """Exports message to final bytes array.

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

        :param response: Data of response.
        :raises SPSDKParsingError: Response parse detect some error.
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
        """Print specific information about session open response.

        :return: Information about the session.
        """
        ret = f"Session handle: 0x{self.session_handle:08X}\n"
        if self.session_handle == 0:
            ret += "Session open failed - no valid session handle returned\n"
        else:
            ret += "Session successfully opened\n"
        return ret

    def info(self) -> str:
        """Print information including live data.

        :return: Information about the message.
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
    """

    CMD = 0x11  # Session close command ID
    VERSION = 0x07  # Version for HSM API
    COMMAND_PAYLOAD_WORDS_COUNT = 1  # Session handle word
    RESPONSE_PAYLOAD_WORDS_COUNT = 0  # No response payload

    def __init__(self, session_handle: int) -> None:
        """Class object initialized.

        :param session_handle: Session handle to close. Handle value returned by Session open (0x10).
        """
        super().__init__()
        self.session_handle = session_handle

    def export(self) -> bytes:
        """Exports message to final bytes array.

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

        :param response: Data of response.
        :raises SPSDKParsingError: Response parse detect some error.
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
        """Print information including live data.

        :return: Information about the message.
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
    """

    CMD = 0x17  # SAB Init command ID
    VERSION = 0x07  # Version for HSM API
    COMMAND_PAYLOAD_WORDS_COUNT = 0  # No payload words
    RESPONSE_PAYLOAD_WORDS_COUNT = 0  # No response payload

    def export(self) -> bytes:
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
        """
        # Override the header to use HSM API version and correct word size
        header = pack(
            self.HEADER_FORMAT, self.VERSION, self.command_words_count, self.command, self.TAG
        )
        return header

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        :param response: Data of response.
        :raises SPSDKParsingError: Response parse detect some error.
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
        """Print information including live data.

        :return: Information about the message.
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

    Key store open command is used to open a service flow on the specified key store.
    A maximum of 2 key stores can be created/opened and a maximum of 100 keys can be stored per key store.

    User can call Key store open command only after having opened a valid session (see Session open (0x10)).
    Key store open command must be called before any other APIs that use a key store service.
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
        """Class object initialized.

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
        """Get flags byte from boolean parameters."""
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
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
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

        :param response: Data of response.
        :raises SPSDKParsingError: Response parse detect some error.
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
        """Print specific information about key store open response.

        :return: Information about the key store.
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
        """Print information including live data.

        :return: Information about the message.
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
    """ELE Message Public Key Export.

    Public key export command exports the public key of an asymmetric key whose private key
    is present in the key store. By default, public key is not stored in EdgeLock Secure
    Enclave key storage and it's then re-calculated.

    For ECC key type, public key is exported in a non-compressed form {x, y}, in big-endian order.
    For RSA key type, only the modulus is exported as public exponent is only the default value (65 537).
    Unlike RFC 7748, ECC PUBLIC KEY MONTGOMERY is exported in big-endian format.

    User can call Public key export command only after having opened a valid key store service.
    """

    CMD = 0x32  # Public key export command ID
    VERSION = 0x07  # Version for HSM API
    COMMAND_PAYLOAD_WORDS_COUNT = 6  # Key store handle, key ID, addresses, size, CRC
    RESPONSE_PAYLOAD_WORDS_COUNT = 2  # Response indicator + output size
    MAX_RESPONSE_DATA_SIZE = 1024  # Maximum public key size

    def __init__(self, key_store_handle: int, key_id: int, output_buffer_size: int = 64) -> None:
        """Class object initialized.

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
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
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
        """Decode response from target.

        :param response: Data of response.
        :raises SPSDKParsingError: Response parse detect some error.
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

        :param response_data: Data of response.
        """
        if self.output_public_key_size > 0:
            self.public_key = response_data[: self.output_public_key_size]
        else:
            self.public_key = b""

    def response_info(self) -> str:
        """Print specific information about public key export response.

        :return: Information about the exported public key.
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
        """Print information including live data.

        :return: Information about the message.
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

    Key store close command is used to close a key store service flow identified by its handle.
    Key store context and content is deleted from the EdgeLock Secure Enclave internal memory.
    Any update not written in the NVM will be lost.

    User can call Key store close command only after having opened a valid key store service.
    """

    CMD = MessageIDs.KEY_STORE_CLOSE_REQ.tag
    VERSION = 0x07  # Version for HSM API
    COMMAND_PAYLOAD_WORDS_COUNT = 1  # Key store handle only
    RESPONSE_PAYLOAD_WORDS_COUNT = 0  # No response payload

    def __init__(self, key_store_handle: int) -> None:
        """Class object initialized.

        :param key_store_handle: Handle identifying the key store service flow to close
        """
        super().__init__()
        self.key_store_handle = key_store_handle

    def export(self) -> bytes:
        """Exports message to final bytes array."""
        # Header: Version(07) | Word size(02) | Command ID(31) | Tag(17)
        header = pack(
            self.HEADER_FORMAT, self.VERSION, self.command_words_count, self.command, self.TAG
        )

        # Payload: Key store handle only
        payload = pack(LITTLE_ENDIAN + UINT32, self.key_store_handle)

        return header + payload

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        :param response: Data of response.
        :raises SPSDKParsingError: Response parse detect some error.
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
        """Print information including live data."""
        ret = super().info()
        ret += "\nKey Store Close Command:\n"
        ret += f"- Key store handle: 0x{self.key_store_handle:08X}\n"
        ret += "- Closes key store service flow and deletes context from ELE memory\n"
        ret += "- Any updates not written to NVM will be lost\n"
        return ret

    def response_info(self) -> str:
        """Print response information."""
        ret = "Key Store Close Response:\n"
        ret += f"- Status: {self.status_string}\n"
        ret += f"- Key store handle 0x{self.key_store_handle:08X} closed successfully\n"
        return ret
