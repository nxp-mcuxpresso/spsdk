#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""EdgeLock Enclave Message."""


from struct import pack, unpack
from typing import Dict, List

from crcmod.predefined import mkPredefinedCrcFun

from spsdk.ele.ele_constants import (
    EleCsalState,
    EleFwStatus,
    EleTrngState,
    KeyBlobEncryptionAlgorithm,
    KeyBlobEncryptionIeeCtrModes,
    LifeCycle,
    MessageIDs,
    ResponseIndication,
    ResponseStatus,
)
from spsdk.exceptions import SPSDKParsingError, SPSDKValueError
from spsdk.image.ahab.signed_msg import SignedMessage
from spsdk.utils.misc import align, align_block

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

    @property
    def status_string(self) -> str:
        """Get status in readable string format."""
        if self.status not in ResponseStatus:
            return "Invalid status!"
        if self.status == ResponseStatus.ELE_SUCCESS_IND:
            return "Succeeded"
        return f"Failed: {ResponseIndication.name(self.indication, f'Invalid indication code: {self.indication:02X}')}"

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
                f"ELE Message: Communication buffer is to small to fit message. ({needed_space} > {self.buff_size})"
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
        if size not in [self.response_words_count, self.RESPONSE_HEADER_WORDS_COUNT]:
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
        assert len(payload) % 4 == 0
        res = 0
        for i in range(0, len(payload), 4):
            res ^= int.from_bytes(payload[i : i + 4], "little")
        return res.to_bytes(4, "little")

    def response_status(self) -> str:
        """Print the response status information.

        :return: String with response status.
        """
        ret = f"Response status: {ResponseStatus.name(self.status, f'Unknown: {self.status}')}\n"
        if self.status == ResponseStatus.ELE_FAILURE_IND:
            ret += (
                f"   Response indication: {ResponseIndication.name(self.indication, 'Unknown')}"
                f" - ({hex(self.indication)})\n"
            )
            ret += f"   Response abort code: {hex(self.abort_code)}\n"
        return ret

    def info(self) -> str:
        """Print information including live data.

        :return: Information about the message.
        """
        ret = (
            f"Command:         {MessageIDs.name(self.command, 'Unknown')} - ({hex(self.command)})\n"
        )
        ret += f"Command words:   {self.command_words_count}\n"
        ret += f"Command data:    {self.has_command_data}\n"
        ret += f"Response words:  {self.response_words_count}\n"
        ret += f"Response data:   {self.has_response_data}\n"
        # if self.status in ResponseStatus:
        ret += self.response_status()

        return ret


class EleMessagePing(EleMessage):
    """ELE Message Ping."""

    CMD = MessageIDs.PING_REQ


class EleMessageReset(EleMessage):
    """ELE Message Reset."""

    CMD = MessageIDs.RESET_REQ
    RESPONSE_HEADER_WORDS_COUNT = 0


class EleMessageEleFwAuthenticate(EleMessage):
    """Ele firmware authenticate request."""

    CMD = MessageIDs.ELE_FW_AUTH_REQ
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
        ret = super().export()
        ret += pack(
            LITTLE_ENDIAN + UINT32 + UINT32 + UINT32, self.ele_fw_address, 0, self.ele_fw_address
        )
        return ret


class EleMessageReleaseContainer(EleMessage):
    """ELE Message Release container."""

    CMD = MessageIDs.ELE_RELEASE_CONTAINER_REQ


class EleMessageStartTrng(EleMessage):
    """ELE Message Start True Random Generator."""

    CMD = MessageIDs.START_RNG_REQ


class EleMessageGetTrngState(EleMessage):
    """ELE Message Get True Random Generator State."""

    CMD = MessageIDs.GET_TRNG_STATE_REQ
    RESPONSE_PAYLOAD_WORDS_COUNT = 1

    def __init__(self) -> None:
        """Class object initialized."""
        super().__init__()
        self.ele_trng_state = EleTrngState.ELE_TRNG_PROGRAM
        self.ele_csal_state = EleCsalState.ELE_CSAL_NOT_READY

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        :param response: Data of response.
        :raises SPSDKParsingError: Response parse detect some error.
        """
        super().decode_response(response)
        self.ele_trng_state, self.ele_csal_state, _ = unpack(
            LITTLE_ENDIAN + UINT8 + UINT8 + "2s", response[8:12]
        )

    def response_info(self) -> str:
        """Print specific information of ELE.

        :return: Information about the TRNG.
        """
        return (
            f"EdgeLock Enclave TRNG state: {EleTrngState.name(self.ele_trng_state, 'Unknown')}"
            + f"\nEdgeLock Enclave CSAL state: {EleCsalState.name(self.ele_csal_state, 'Unknown')}"
        )


class EleMessageGetFwStatus(EleMessage):
    """ELE Message Get FW status."""

    CMD = MessageIDs.GET_FW_STATUS_REQ
    RESPONSE_PAYLOAD_WORDS_COUNT = 1

    def __init__(self) -> None:
        """Class object initialized."""
        super().__init__()
        self.ele_fw_status = EleFwStatus.ELE_FW_STATUS_NOT_IN_PLACE

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
        return f"EdgeLock Enclave firmware state: {EleFwStatus.name(self.ele_fw_status, 'Unknown')}"


class EleMessageGetFwVersion(EleMessage):
    """ELE Message Get FW version."""

    CMD = MessageIDs.GET_FW_VERSION_REQ
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
        self.ele_fw_version_raw = int.from_bytes(response[8:12], "little")
        self.ele_fw_version_sha1 = int.from_bytes(response[12:16], "little")

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

    CMD = MessageIDs.READ_COMMON_FUSE
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
        ret = super().export()
        ret += pack(LITTLE_ENDIAN + UINT16 + UINT16, self.index, 0)
        return ret

    def decode_response(self, response: bytes) -> None:
        """Decode response from target.

        :param response: Data of response.
        :raises SPSDKParsingError: Response parse detect some error.
        """
        super().decode_response(response)
        self.fuse_value = int.from_bytes(response[8:12], "little")

    def response_info(self) -> str:
        """Print fuse value.

        :return: Read fuse value.
        """
        return f"Fuse ID_{self.index}: 0x{self.fuse_value:08X}\n"


class EleMessageReadShadowFuse(EleMessageReadCommonFuse):
    """ELE Message Read shadow fuse."""

    CMD = MessageIDs.READ_SHADOW_FUSE

    def export(self) -> bytes:
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
        """
        ret = super().export()
        ret += pack(LITTLE_ENDIAN + UINT32, self.index)
        return ret


class EleMessageGetInfo(EleMessage):
    """ELE Message Get Info."""

    CMD = MessageIDs.GET_INFO_REQ
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
        self.info_uuid = bytes()
        self.info_sha256_rom_patch = bytes()
        self.info_sha256_fw = bytes()
        self.info_oem_srkh = bytes()
        self.info_imem_state = 0
        self.info_csal_state = 0
        self.info_trng_state = 0

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
        (self.info_cmd, self.info_version, self.info_length) = unpack(
            LITTLE_ENDIAN + UINT8 + UINT8 + UINT16, response_data[:4]
        )

        (self.info_soc_id, self.info_soc_rev) = unpack(
            LITTLE_ENDIAN + UINT16 + UINT16, response_data[4:8]
        )
        (self.info_life_cycle, self.info_sssm_state, _) = unpack(
            LITTLE_ENDIAN + UINT16 + UINT8 + UINT8, response_data[8:12]
        )
        self.info_uuid = response_data[12:28]
        self.info_sha256_rom_patch = response_data[28:60]
        self.info_sha256_fw = response_data[60:92]
        if self.info_version == 0x02:
            self.info_oem_srkh = response_data[92:156]
            self.info_oem_srkh = response_data[92:156]
            (self.info_trng_state, self.info_csal_state, self.info_imem_state, _) = unpack(
                LITTLE_ENDIAN + UINT8 + UINT8 + UINT8 + UINT8, response_data[156:160]
            )

    def response_info(self) -> str:
        """Print specific information of ELE.

        :return: Information about the ELE.
        """
        ret = f"Command:          {hex(self.info_cmd)}\n"
        ret += f"Version:          {self.info_version}\n"
        ret += f"Length:           {self.info_length}\n"
        ret += f"SoC ID:           {self.info_soc_id:04X}\n"
        ret += f"SoC version:      {self.info_soc_rev:04X}\n"
        ret += f"Life Cycle:       {LifeCycle.name(self.info_life_cycle, 'Unknown')} - 0x{self.info_life_cycle:04X}\n"
        ret += f"SSSM state:       {self.info_sssm_state}\n"
        ret += f"UUID:             {self.info_uuid.hex()}\n"
        ret += f"SHA256 ROM PATCH: {self.info_sha256_rom_patch.hex()}\n"
        ret += f"SHA256 FW:        {self.info_sha256_fw.hex()}\n"
        if self.info_version == 0x02:
            ret += "Advanced information:\n"
            ret += f"  OEM SRKH:       {self.info_oem_srkh.hex()}\n"
            ret += f"  IMEM state:     {self.info_imem_state}\n"
            ret += (
                f"  CSAL state:     "
                f"{EleCsalState.name(self.info_csal_state, f'Unknown: {hex(self.info_csal_state)}')}\n"
            )
            ret += (
                f"  TRNG state:     "
                f"{EleTrngState.name(self.info_trng_state, f'Unknown: {hex(self.info_trng_state)}')}\n"
            )

        return ret


class EleMessageSigned(EleMessage):
    """ELE Message Signed."""

    COMMAND_PAYLOAD_WORDS_COUNT = 2

    def __init__(self, signed_msg: bytes) -> None:
        """Class object initialized.

        :param signed_msg: Signed message container.
        """
        super().__init__()
        self.signed_msg_binary = signed_msg
        # Get the command inside the signed message
        self.signed_msg = SignedMessage.parse(signed_msg)
        self.signed_msg.update_fields()
        assert self.signed_msg.message
        self.command = self.signed_msg.message.cmd
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


class EleMessageGenerateKeyBLob(EleMessage):
    """ELE Message Generate KeyBlob."""

    KEYBLOB_NAME = "Unknown"
    # List of supported algorithms and theirs key sizes
    SUPPORTED_ALGORITHMS: Dict[int, List[int]] = {}

    KEYBLOB_TAG = 0x81
    KEYBLOB_VERSION = 0x00
    CMD = MessageIDs.GENERATE_KEY_BLOB_REQ
    COMMAND_PAYLOAD_WORDS_COUNT = 7
    MAX_RESPONSE_DATA_SIZE = 512

    def __init__(self, key_identifier: int, algorithm: int, key: bytes) -> None:
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
                f"{KeyBlobEncryptionAlgorithm.name(self.algorithm, f'Unknown algorithm ({self.algorithm})')} "
                f"in not supported by {self.KEYBLOB_NAME} keyblob in ELE."
            )

        if len(self.key) * 8 not in self.SUPPORTED_ALGORITHMS[self.algorithm]:
            raise SPSDKValueError(
                f"Unsupported size of input key by {self.KEYBLOB_NAME} keyblob"
                f" for {KeyBlobEncryptionAlgorithm.name(self.algorithm, 'Unknown')} algorithm."
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
        ret += f"Algorithm:       {KeyBlobEncryptionAlgorithm.name(self.algorithm, f'Unknown: {self.algorithm}')}\n"
        ret += f"Key size:        {len(self.key)*8} bits\n"
        return ret

    @classmethod
    def get_supported_algorithms(cls) -> List[str]:
        """Get the list of supported algorithms.

        :return: List of supported algorithm names.
        """
        return list(KeyBlobEncryptionAlgorithm.name(x) for x in cls.SUPPORTED_ALGORITHMS)

    @classmethod
    def get_supported_key_sizes(cls) -> str:
        """Get table with supported key sizes per algorithm.

        :return: Table with supported key size in text.
        """
        ret = ""
        for key, value in cls.SUPPORTED_ALGORITHMS.items():
            ret += KeyBlobEncryptionAlgorithm.name(key) + ": " + str(value) + ",\n"
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


class EleMessageGenerateKeyBLobDek(EleMessageGenerateKeyBLob):
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
            self.algorithm,
            0,
        )
        return header + options + self.key


class EleMessageGenerateKeyBLobOtfad(EleMessageGenerateKeyBLob):
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
            self.algorithm,
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
        crc32_function = mkPredefinedCrcFun("crc-32-mpeg")
        crc: int = crc32_function(otfad_config)
        return header + options + otfad_config + crc.to_bytes(4, "little")

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


class EleMessageGenerateKeyBLobIee(EleMessageGenerateKeyBLob):
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
        algorithm: int,
        key: bytes,
        ctr_mode: int,
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
            self.algorithm,
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
            region_attribute |= self.ctr_mode << 4
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
        crc32_function = mkPredefinedCrcFun("crc-32-mpeg")
        crc: int = crc32_function(iee_config)

        return header + options + iee_config + crc.to_bytes(4, "little")

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
            ret += f"AES Counter mode:{KeyBlobEncryptionIeeCtrModes.desc(self.ctr_mode)}\n"
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

    CMD = MessageIDs.LOAD_KEY_BLOB_REQ
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

    CMD = MessageIDs.WRITE_FUSE
    COMMAND_PAYLOAD_WORDS_COUNT = 2

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

    def export(self) -> bytes:
        """Exports message to final bytes array.

        :return: Bytes representation of message object.
        """
        ret = super().export()

        ret += pack(
            LITTLE_ENDIAN + UINT16 + UINT16 + UINT32,
            self.bit_position,
            self.bit_length | 0x8000 if self.lock else 0,
            self.payload,
        )
        return ret


class EleMessageWriteShadowFuse(EleMessage):
    """Write shadow fuse request."""

    CMD = MessageIDs.WRITE_SHADOW_FUSE
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
        ret = super().export()

        ret += pack(
            LITTLE_ENDIAN + UINT32 + UINT32,
            self.index,
            self.value,
        )
        return ret
