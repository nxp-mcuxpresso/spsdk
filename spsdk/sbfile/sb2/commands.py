#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB2.1 file format command definitions and implementations.

This module provides command classes and utilities for creating and parsing
SB2.1 (Secure Binary) file format commands. It includes base command functionality,
specific command implementations for operations like load, fill, jump, erase,
and utilities for device and memory identification.
"""

import math
from abc import abstractmethod
from struct import calcsize, pack, unpack_from
from typing import Mapping, Optional, Type

from typing_extensions import Self

from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.exceptions import SPSDKError
from spsdk.mboot.memories import ExtMemId
from spsdk.sbfile.misc import SecBootBlckSize
from spsdk.utils.abstract import BaseClass
from spsdk.utils.misc import Endianness
from spsdk.utils.spsdk_enum import SpsdkEnum

########################################################################################################################
# Constants
########################################################################################################################

DEVICE_ID_MASK = 0xFF
DEVICE_ID_SHIFT = 0
GROUP_ID_MASK = 0xF00
GROUP_ID_SHIFT = 8


########################################################################################################################
# Enums
########################################################################################################################
class EnumCmdTag(SpsdkEnum):
    """SB2 command tag enumeration.

    This enumeration defines all supported command tags used in SB2 (Secure Binary 2) files
    for bootloader operations including memory management, execution control, and security
    functions.
    """

    NOP = (0x0, "NOP")
    TAG = (0x1, "TAG")
    LOAD = (0x2, "LOAD")
    FILL = (0x3, "FILL")
    JUMP = (0x4, "JUMP")
    CALL = (0x5, "CALL")
    ERASE = (0x7, "ERASE")
    RESET = (0x8, "RESET")
    MEM_ENABLE = (0x9, "MEM_ENABLE")
    PROG = (0xA, "PROG")
    FW_VERSION_CHECK = (0xB, "FW_VERSION_CHECK", "Check FW version fuse value")
    WR_KEYSTORE_TO_NV = (
        0xC,
        "WR_KEYSTORE_TO_NV",
        "Restore key-store restore to non-volatile memory",
    )
    WR_KEYSTORE_FROM_NV = (0xD, "WR_KEYSTORE_FROM_NV", "Backup key-store from non-volatile memory")


class EnumSectionFlag(SpsdkEnum):
    """SB2 section flags enumeration.

    Defines the available flags that can be applied to sections in SB2 (Secure Binary version 2)
    files, including bootable sections, cleartext sections, and section termination markers.
    """

    BOOTABLE = (0x0001, "BOOTABLE")
    CLEARTEXT = (0x0002, "CLEARTEXT")
    LAST_SECT = (0x8000, "LAST_SECT")


########################################################################################################################
# Header Class
########################################################################################################################
class CmdHeader(BaseClass):
    """SBFile command header for SB2 format.

    This class represents a command header structure used in SB2 (Secure Binary) files,
    providing functionality to create, validate, and export command headers with
    proper CRC calculation and binary formatting.

    :cvar FORMAT: Binary format string for struct packing/unpacking.
    :cvar SIZE: Size of the header structure in bytes.
    """

    FORMAT = "<2BH3L"
    SIZE = calcsize(FORMAT)

    @property
    def crc(self) -> int:
        """Calculate CRC for the header data.

        Computes a checksum using a custom algorithm that starts with 0x5A and
        adds each byte from the raw data (excluding the first byte) with overflow
        handling to maintain 8-bit values.

        :return: Calculated CRC checksum as an 8-bit integer value.
        """
        raw_data = self._raw_data(crc=0)
        checksum = 0x5A
        for i in range(1, self.SIZE):
            checksum = (checksum + raw_data[i]) & 0xFF
        return checksum

    def __init__(self, tag: int, flags: int = 0, zero_filling: bool = False) -> None:
        """Initialize SB2 command header with specified parameters.

        Creates a new command header instance with the given tag and optional flags.
        Initializes all header fields to default values and validates the command tag.

        :param tag: Command tag identifier from EnumCmdTag enumeration
        :param flags: Optional command flags, defaults to 0
        :param zero_filling: Enable zero filling for the command, defaults to False
        :raises SPSDKError: Invalid command tag not found in EnumCmdTag
        """
        if tag not in EnumCmdTag.tags():
            raise SPSDKError("Incorrect command tag")
        self.tag = tag
        self.flags = flags
        self.address = 0
        self.count = 0
        self.data = 0
        self.zero_filling = zero_filling

    def __repr__(self) -> str:
        """Return string representation of SB2 command header.

        This method provides a human-readable string representation of the SB2 command header,
        displaying the command tag for debugging and logging purposes.

        :return: String representation containing the command tag.
        """
        return f"SB2 Command header, TAG:{self.tag}"

    def __str__(self) -> str:
        """Return string representation of the command.

        Provides a formatted string containing the command's tag, flags, address, count, and data values.
        The tag is displayed as a human-readable label if available, otherwise as hexadecimal.

        :return: Formatted string with command details including tag, flags, address, count and data.
        """
        tag = (
            EnumCmdTag.get_label(self.tag) if self.tag in EnumCmdTag.tags() else f"0x{self.tag:02X}"
        )
        return (
            f"tag={tag}, flags=0x{self.flags:04X}, "
            f"address=0x{self.address:08X}, count=0x{self.count:08X}, data=0x{self.data:08X}"
        )

    def _raw_data(self, crc: int) -> bytes:
        """Return raw data of the header with specified CRC.

        The method packs the header data into binary format using the defined FORMAT structure,
        including the provided CRC value along with tag, flags, address, count, and data fields.

        :param crc: CRC value to be included in the header.
        :return: Binary representation of the header as bytes.
        """
        return pack(self.FORMAT, crc, self.tag, self.flags, self.address, self.count, self.data)

    def export(self) -> bytes:
        """Export command header as bytes.

        Serializes the command header data including CRC into a byte representation
        suitable for transmission or storage.

        :return: Raw byte data of the command header with CRC.
        """
        return self._raw_data(self.crc)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command header from bytes array.

        The method unpacks binary data into a CMDHeader object and validates
        the CRC checksum to ensure data integrity.

        :param data: Input binary data containing the command header.
        :return: Parsed CMDHeader object with populated fields.
        :raises SPSDKError: Raised when input data size is insufficient.
        :raises SPSDKError: Raised when CRC checksum validation fails.
        """
        if calcsize(cls.FORMAT) > len(data):
            raise SPSDKError("Incorrect size")
        obj = cls(EnumCmdTag.NOP.tag)
        (crc, obj.tag, obj.flags, obj.address, obj.count, obj.data) = unpack_from(cls.FORMAT, data)
        if crc != obj.crc:
            raise SPSDKError("CRC does not match")
        return obj


########################################################################################################################
# Commands Classes
########################################################################################################################
class CmdBaseClass(BaseClass):
    """Base class for all SB2 commands.

    This class provides the foundation for all Secure Binary 2.0 command implementations,
    managing common command structure including headers and basic serialization functionality.

    :cvar ROM_MEM_DEVICE_ID_MASK: Bit mask for extracting device ID from flags.
    :cvar ROM_MEM_DEVICE_ID_SHIFT: Bit shift value for device ID within flags.
    :cvar ROM_MEM_GROUP_ID_MASK: Bit mask for extracting group ID from flags.
    :cvar ROM_MEM_GROUP_ID_SHIFT: Bit shift value for group ID within flags.
    """

    # bit mask for device ID inside flags
    ROM_MEM_DEVICE_ID_MASK = 0xFF00
    # shift for device ID inside flags
    ROM_MEM_DEVICE_ID_SHIFT = 8
    # bit mask for group ID inside flags
    ROM_MEM_GROUP_ID_MASK = 0xF0
    # shift for group ID inside flags
    ROM_MEM_GROUP_ID_SHIFT = 4

    def __init__(self, tag: EnumCmdTag) -> None:
        """Initialize CmdBase.

        :param tag: Command tag enumeration value used to set the header tag.
        """
        self._header = CmdHeader(tag.tag)

    @property
    def header(self) -> CmdHeader:
        """Return command header.

        :return: Command header object containing header information.
        """
        return self._header

    @property
    def raw_size(self) -> int:
        """Return size of the command in binary format (including header).

        :return: Size of the command in bytes, defaults to header size only.
        """
        return CmdHeader.SIZE  # this is default implementation

    def __repr__(self) -> str:
        """Return string representation of the command.

        This method provides a default implementation that displays the command type
        followed by the header information.

        :return: String representation showing "Command: " followed by the header.
        """
        return "Command: " + str(self._header)  # default implementation: use command name

    def __str__(self) -> str:
        """Return text info about the instance.

        :return: String representation of the instance with newline character.
        """
        return repr(self) + "\n"  # default implementation is same as __repr__

    def export(self) -> bytes:
        """Export object as serialized byte representation.

        This method provides the default implementation for object serialization
        by delegating to the header's export functionality.

        :return: Serialized object data as bytes.
        """
        return self._header.export()  # default implementation


class CmdNop(CmdBaseClass):
    """SB2 No Operation command implementation.

    This class represents a NOP (No Operation) command in the SB2 file format,
    which serves as a placeholder or padding command that performs no actual
    operation when executed by the target device.
    """

    def __init__(self) -> None:
        """Initialize Command Nop.

        Creates a new NOP (No Operation) command instance that performs no action
        when executed. This command is typically used as a placeholder or for
        timing purposes in command sequences.
        """
        super().__init__(EnumCmdTag.NOP)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array into CMD Nop object.

        This method validates the command header tag and creates a new CMD Nop instance
        if the header contains the correct NOP tag.

        :param data: Input data as bytes array containing the command structure
        :return: CMD Nop object instance
        :raises SPSDKError: When there is incorrect header tag
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.NOP:
            raise SPSDKError("Incorrect header tag")
        return cls()


class CmdTag(CmdBaseClass):
    """Command TAG class for SB file operations.

    This class represents a TAG command used in Secure Binary (SB) files and serves
    as a header for boot sections in SB file version 1.x. It provides functionality
    for creating and parsing TAG commands within the SB file structure.
    """

    def __init__(self) -> None:
        """Initialize Command Tag.

        Initialize a new Command Tag instance by calling the parent constructor
        with the TAG enumeration value.
        """
        super().__init__(EnumCmdTag.TAG)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        Parses the binary data to create a command instance by extracting and validating
        the command header information.

        :param data: Input data as bytes array containing command information.
        :raises SPSDKError: When there is incorrect header tag.
        :return: Parsed command instance.
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.TAG:
            raise SPSDKError("Incorrect header tag")
        result = cls()
        result._header = header
        return result


class CmdLoad(CmdBaseClass):
    """SB2 Load Command for memory data operations.

    This command class represents a load operation that stores data into target processor
    memory at a specified address. It handles memory addressing, data alignment, and
    provides functionality for exporting and parsing load commands in SB2 format.
    """

    @property
    def address(self) -> int:
        """Return address in target processor to load data.

        :return: Address value where data should be loaded in target processor memory.
        """
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Set the target address for data loading.

        :param value: Address in target processor memory where data will be loaded (0x00000000-0xFFFFFFFF).
        :raises SPSDKError: When the address is outside the valid 32-bit range.
        """
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect address")
        self._header.address = value

    @property
    def flags(self) -> int:
        """Return command's flag.

        :return: Command flags as integer value.
        """
        return self._header.flags

    @flags.setter
    def flags(self, value: int) -> None:
        """Set command's flag.

        :param value: Flag value to be set for the command.
        """
        self._header.flags = value

    @property
    def raw_size(self) -> int:
        """Calculate aligned size of the command including header and data.

        The method calculates the total size by adding the header size and data length,
        then aligns the result to the nearest multiple of header size for proper memory alignment.

        :return: Aligned size in bytes including command header and data payload.
        """
        size = CmdHeader.SIZE + len(self.data)
        if size % CmdHeader.SIZE:
            size += CmdHeader.SIZE - (size % CmdHeader.SIZE)
        return size

    def __init__(
        self, address: int, data: bytes, mem_id: int = 0, zero_filling: bool = False
    ) -> None:
        """Initialize CMD Load command.

        Creates a new Load command that writes data to a specified memory address.
        The command supports different memory interfaces through mem_id parameter
        and can be configured for zero filling behavior.

        :param address: Target memory address where data will be written.
        :param data: Binary data to be loaded into memory.
        :param mem_id: Memory interface identifier, defaults to 0.
        :param zero_filling: Enable zero filling for unaligned data, defaults to False.
        """
        super().__init__(EnumCmdTag.LOAD)
        assert isinstance(data, (bytes, bytearray))
        self.address = address
        self.data = bytes(data)
        self.mem_id = mem_id

        device_id = get_device_id(mem_id)
        group_id = get_group_id(mem_id)

        self.flags |= (self.flags & ~self.ROM_MEM_DEVICE_ID_MASK) | (
            (device_id << self.ROM_MEM_DEVICE_ID_SHIFT) & self.ROM_MEM_DEVICE_ID_MASK
        )

        self.flags |= (self.flags & ~self.ROM_MEM_GROUP_ID_MASK) | (
            (group_id << self.ROM_MEM_GROUP_ID_SHIFT) & self.ROM_MEM_GROUP_ID_MASK
        )

        self.zero_filling = zero_filling

    def __str__(self) -> str:
        """Return string representation of the LOAD command.

        Provides a formatted string containing the command's address, data length,
        flags, and memory ID in hexadecimal format for debugging and logging purposes.

        :return: Formatted string with LOAD command details.
        """
        return (
            f"LOAD: Address=0x{self.address:08X}, DataLen={len(self.data)}, "
            f"Flags=0x{self.flags:08X}, MemId=0x{self.mem_id:08X}"
        )

    def export(self) -> bytes:
        """Export command as binary data.

        Updates internal data before exporting the command and appends the command's
        data to the base export result.

        :return: Binary representation of the command including its data.
        """
        self._update_data()
        result = super().export()
        return result + self.data

    def _update_data(self) -> None:
        """Update command data with proper alignment and CRC calculation.

        This method handles data padding based on zero_filling configuration and updates
        the command header with the data length and CRC32-MPEG checksum.
        """
        # padding data
        if self.zero_filling or self._header.zero_filling:
            self.data = SecBootBlckSize.align_block_fill_zeros(self.data)
        else:
            self.data = SecBootBlckSize.align_block_fill_random(self.data)
        # update header
        self._header.count = len(self.data)
        crc_ob = from_crc_algorithm(CrcAlg.CRC32_MPEG)
        self._header.data = crc_ob.calculate(self.data)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes.

        This method parses a LOAD command from binary data by extracting and validating
        the command header, verifying CRC integrity, and reconstructing the command object
        with proper memory identification.

        :param data: Input data as bytes containing the command structure.
        :return: CMD Load object parsed from the input data.
        :raises SPSDKError: Raised when there is invalid CRC in the command header.
        :raises SPSDKError: When there is incorrect header tag (not LOAD command).
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.LOAD:
            raise SPSDKError("Incorrect header tag")
        header_count = SecBootBlckSize.align(header.count)
        cmd_data = data[CmdHeader.SIZE : CmdHeader.SIZE + header_count]
        crc_obj = from_crc_algorithm(CrcAlg.CRC32_MPEG)
        if header.data != crc_obj.calculate(cmd_data):
            raise SPSDKError("Invalid CRC in the command header")
        device_id = (header.flags & cls.ROM_MEM_DEVICE_ID_MASK) >> cls.ROM_MEM_DEVICE_ID_SHIFT
        group_id = (header.flags & cls.ROM_MEM_GROUP_ID_MASK) >> cls.ROM_MEM_GROUP_ID_SHIFT
        mem_id = get_memory_id(device_id, group_id)
        obj = cls(header.address, cmd_data, mem_id)
        obj.header.data = header.data
        obj.header.flags = header.flags
        obj._update_data()
        return obj


class CmdFill(CmdBaseClass):
    """SB2 Fill command for memory initialization operations.

    This command fills a specified memory range with a given pattern, supporting
    various data patterns and lengths. The fill operation ensures proper alignment
    and handles pattern conversion for secure boot file generation.

    :cvar PADDING_VALUE: Default padding value used for alignment operations.
    """

    PADDING_VALUE = 0x00

    @property
    def address(self) -> int:
        """Get address of the command Fill.

        :return: Address value of the Fill command.
        """
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Set address for the command Fill.

        :param value: Address value to set, must be within 32-bit range (0x00000000-0xFFFFFFFF).
        :raises SPSDKError: If address value is outside valid 32-bit range.
        """
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect address")
        self._header.address = value

    @property
    def raw_size(self) -> int:
        """Calculate raw size of the command header.

        The method calculates the total size including the pattern length minus 4 bytes,
        with padding to align to CmdHeader.SIZE boundary.

        :return: Raw size of the header in bytes.
        """
        size = CmdHeader.SIZE
        size += len(self._pattern) - 4
        if size % CmdHeader.SIZE:
            size += CmdHeader.SIZE - (size % CmdHeader.SIZE)
        return size

    def __init__(
        self, address: int, pattern: int, length: Optional[int] = None, zero_filling: bool = False
    ) -> None:
        """Initialize Command Fill.

        Creates a fill command that writes a pattern to a specified memory address.
        The pattern is replicated to fill the specified length of memory. The pattern
        must be 1, 2, or 4 bytes long and will be automatically replicated to create
        a 4-byte pattern for efficient memory filling.

        :param address: Memory address where data should be written.
        :param pattern: Data pattern to be written (integer value).
        :param length: Length of memory range to fill in bytes, defaults to 4.
        :param zero_filling: Flag indicating if this is zero filling operation.
        :raises SPSDKError: Length is not aligned to 4 bytes or pattern size invalid.
        """
        super().__init__(EnumCmdTag.FILL)
        length = length or 4
        if length % 4:
            raise SPSDKError("Length of memory range to fill must be a multiple of 4")
        # if the pattern is a zero, the length is considered also as zero and the
        # conversion to bytes produces empty byte "array", which is wrong, as
        # zero should be converted to zero byte. Thus in case the pattern_len
        # evaluates to 0, we set it to 1.
        pattern_len = pattern.bit_length() / 8 or 1
        # We can get a number of 3 bytes, so we consider this as a word and set
        # the length to 4 bytes with the first byte being zero.
        if 3 == math.ceil(pattern_len):
            pattern_len = 4
        pattern_bytes = pattern.to_bytes(math.ceil(pattern_len), Endianness.BIG.value)
        # The pattern length is computed above, but as we transform the number
        # into bytes, compute the len again just in case - a bit paranoid
        # approach chosen.
        if len(pattern_bytes) not in [1, 2, 4]:
            raise SPSDKError("Pattern must be 1, 2 or 4 bytes long")
        replicate = 4 // len(pattern_bytes)
        final_pattern = replicate * pattern_bytes
        self.address = address
        self._pattern = final_pattern
        # update header
        self._header.data = unpack_from(">L", self._pattern)[0]
        self._header.count = length
        self.zero_filling = zero_filling

    @property
    def pattern(self) -> bytes:
        """Return binary data pattern used for filling.

        :return: Binary data pattern as bytes.
        """
        return self._pattern

    def __str__(self) -> str:
        """Return string representation of the FILL command.

        The string includes the target address in hexadecimal format and the fill pattern
        as space-separated hexadecimal bytes.

        :return: Formatted string showing address and pattern details.
        """
        return f"FILL: Address=0x{self.address:08X}, Pattern=" + " ".join(
            f"{byte:02X}" for byte in self._pattern
        )

    def export(self) -> bytes:
        """Export command in binary form with proper alignment.

        The method serializes the command to binary format and applies block alignment
        using either zero filling or random filling based on the zero_filling flag.

        :return: Serialized command data with proper block alignment.
        """
        # export cmd
        data = super().export()
        # export additional data
        if self.zero_filling or self._header.zero_filling:
            data = SecBootBlckSize.align_block_fill_zeros(data)
        else:
            data = SecBootBlckSize.align_block_fill_random(data)
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes.

        Parses the binary data to create a Fill command object by extracting and validating
        the command header information.

        :param data: Input data as bytes containing the command structure
        :return: Command Fill object
        :raises SPSDKError: If incorrect header tag
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.FILL:
            raise SPSDKError("Incorrect header tag")
        return cls(header.address, header.data, header.count)


class CmdJump(CmdBaseClass):
    """SB2 Jump command for transferring execution control.

    This command represents a jump instruction in SB2 (Secure Binary) files that transfers
    program execution to a specified memory address. It supports optional stack pointer
    configuration and can carry additional arguments for the target execution context.
    """

    @property
    def address(self) -> int:
        """Get the address of the Jump command.

        :return: Address value of the Jump command.
        """
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Set address of the command Jump.

        :param value: Address value to set, must be within 32-bit range (0x00000000-0xFFFFFFFF).
        :raises SPSDKError: Invalid address value outside the valid range.
        """
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect address")
        self._header.address = value

    @property
    def argument(self) -> int:
        """Get command's argument value.

        :return: The argument value stored in the command header.
        """
        return self._header.data

    @argument.setter
    def argument(self, value: int) -> None:
        """Set command's argument.

        :param value: The argument value to set for the command.
        """
        self._header.data = value

    @property
    def spreg(self) -> Optional[int]:
        """Return command's Stack Pointer.

        The Stack Pointer value is only available when the command header flags field
        is set to 2, indicating that the count field contains the stack pointer value.

        :return: Stack pointer value if flags equals 2, None otherwise.
        """
        if self._header.flags == 2:
            return self._header.count

        return None

    @spreg.setter
    def spreg(self, value: Optional[int] = None) -> None:
        """Set command's Stack Pointer.

        Configures the stack pointer value for the command. When value is None, the flags and count
        are reset to 0. When a value is provided, the flags are set to 2 and count is set to the
        specified value.

        :param value: Stack pointer value to set, or None to reset the configuration.
        """
        if value is None:
            self._header.flags = 0
            self._header.count = 0
        else:
            self._header.flags = 2
            self._header.count = value

    def __init__(self, address: int = 0, argument: int = 0, spreg: Optional[int] = None) -> None:
        """Initialize Command Jump.

        :param address: Jump target address, defaults to 0.
        :param argument: Additional argument for jump command, defaults to 0.
        :param spreg: Optional stack pointer register value.
        """
        super().__init__(EnumCmdTag.JUMP)
        self.address = address
        self.argument = argument
        self.spreg = spreg

    def __str__(self) -> str:
        """Return string representation of JUMP command.

        Provides a formatted string containing the jump address, argument value,
        and optionally the stack pointer register value if specified.

        :return: Formatted string with JUMP command details including address, argument, and SP if set.
        """
        nfo = f"JUMP: Address=0x{self.address:08X}, Argument=0x{self.argument:08X}"
        if self.spreg is not None:
            nfo += f", SP=0x{self.spreg:08X}"
        return nfo

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes.

        Parses the input byte data to create a Jump command object by extracting
        and validating the command header information.

        :param data: Input data as bytes containing the command structure.
        :return: Command Jump object created from parsed data.
        :raises SPSDKError: If incorrect header tag is found in the data.
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.JUMP:
            raise SPSDKError("Incorrect header tag")
        return cls(header.address, header.data, header.count if header.flags else None)


class CmdCall(CmdBaseClass):
    """SB2 Call command for bootloader function execution.

    This command represents a bootloader call instruction that executes a function
    from files previously loaded into memory. It encapsulates the target address
    and optional argument for the function call operation.
    """

    @property
    def address(self) -> int:
        """Return command's address.

        :return: The address value stored in the command header.
        """
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Set command's address.

        :param value: Address value to set, must be within 32-bit range (0x00000000-0xFFFFFFFF).
        :raises SPSDKError: If address value is outside valid 32-bit range.
        """
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect address")
        self._header.address = value

    @property
    def argument(self) -> int:
        """Get command's argument value.

        :return: The argument value stored in the command header.
        """
        return self._header.data

    @argument.setter
    def argument(self, value: int) -> None:
        """Set command's argument.

        :param value: The argument value to set for the command.
        """
        self._header.data = value

    def __init__(self, address: int = 0, argument: int = 0) -> None:
        """Initialize Command Call.

        :param address: Memory address for the call command, defaults to 0.
        :param argument: Additional argument for the call command, defaults to 0.
        """
        super().__init__(EnumCmdTag.CALL)
        self.address = address
        self.argument = argument

    def __str__(self) -> str:
        """Return string representation of CALL command.

        Provides a formatted string showing the call address and argument values
        in hexadecimal format for debugging and logging purposes.

        :return: Formatted string with address and argument values.
        """
        return f"CALL: Address=0x{self.address:08X}, Argument=0x{self.argument:08X}"

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array into Command Call object.

        This method validates the command header tag and creates a new Command Call
        instance with the parsed address and data from the input bytes.

        :param data: Input data as bytes array containing command information
        :return: Command Call object with parsed address and data
        :raises SPSDKError: If incorrect header tag is found in the data
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.CALL:
            raise SPSDKError("Incorrect header tag")
        return cls(header.address, header.data)


class CmdErase(CmdBaseClass):
    """SB2 erase command for memory operations.

    This command handles erasing operations on target memory devices, allowing
    specification of memory address, length, and device-specific flags. The command
    automatically manages device and group ID encoding within the flags field.
    """

    @property
    def address(self) -> int:
        """Get command's address.

        :return: The address value stored in the command header.
        """
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Set command's address.

        :param value: Address value to set, must be within 32-bit range (0x00000000-0xFFFFFFFF).
        :raises SPSDKError: If address value is outside valid 32-bit range.
        """
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect address")
        self._header.address = value

    @property
    def length(self) -> int:
        """Return command's count.

        :return: Number of commands in the command block.
        """
        return self._header.count

    @length.setter
    def length(self, value: int) -> None:
        """Set command's count.

        :param value: The count value to set for the command.
        """
        self._header.count = value

    @property
    def flags(self) -> int:
        """Return command's flags value.

        :return: The flags value from the command header.
        """
        return self._header.flags

    @flags.setter
    def flags(self, value: int) -> None:
        """Set command's flag.

        :param value: Flag value to be set for the command.
        """
        self._header.flags = value

    def __init__(self, address: int = 0, length: int = 0, flags: int = 0, mem_id: int = 0) -> None:
        """Initialize Command Erase.

        Creates an erase command with specified memory address, length, and flags.
        The constructor automatically sets device ID and group ID in the flags based on mem_id.

        :param address: Memory address to start erasing from.
        :param length: Number of bytes to erase.
        :param flags: Command flags for erase operation.
        :param mem_id: Memory identifier used to extract device and group IDs.
        """
        super().__init__(EnumCmdTag.ERASE)
        self.address = address
        self.length = length
        self.flags = flags
        self.mem_id = mem_id

        device_id = get_device_id(mem_id)
        group_id = get_group_id(mem_id)

        self.flags |= (self.flags & ~self.ROM_MEM_DEVICE_ID_MASK) | (
            (device_id << self.ROM_MEM_DEVICE_ID_SHIFT) & self.ROM_MEM_DEVICE_ID_MASK
        )

        self.flags |= (self.flags & ~self.ROM_MEM_GROUP_ID_MASK) | (
            (group_id << self.ROM_MEM_GROUP_ID_SHIFT) & self.ROM_MEM_GROUP_ID_MASK
        )

    def __str__(self) -> str:
        """Return string representation of the ERASE command.

        Provides a formatted string containing the erase operation details including
        memory address, length, flags, and memory ID in hexadecimal format.

        :return: Formatted string with erase command parameters.
        """
        return (
            f"ERASE: Address=0x{self.address:08X}, Length={self.length}, Flags=0x{self.flags:08X}, "
            f"MemId=0x{self.mem_id:08X}"
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array into CmdErase object.

        Extracts header information and validates the command tag. Decodes device ID and group ID
        from header flags to determine memory ID for the erase operation.

        :param data: Input data as bytes containing the command structure
        :raises SPSDKError: If incorrect header tag for erase command
        :return: CmdErase object with parsed address, count, flags and memory ID
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.ERASE:
            raise SPSDKError("Invalid header tag")
        device_id = (header.flags & cls.ROM_MEM_DEVICE_ID_MASK) >> cls.ROM_MEM_DEVICE_ID_SHIFT
        group_id = (header.flags & cls.ROM_MEM_GROUP_ID_MASK) >> cls.ROM_MEM_GROUP_ID_SHIFT
        mem_id = get_memory_id(device_id, group_id)
        return cls(header.address, header.count, header.flags, mem_id)


class CmdReset(CmdBaseClass):
    """SB2 Reset command implementation.

    This class represents a reset command in the SB2 (Secure Binary 2) file format,
    which instructs the target device to perform a system reset operation.
    """

    def __init__(self) -> None:
        """Initialize Command Reset.

        Initializes a new Reset command instance by calling the parent constructor
        with the RESET command tag.
        """
        super().__init__(EnumCmdTag.RESET)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        Parses the binary data to create a Reset command object by first validating
        the command header tag matches the expected RESET tag.

        :param data: Input data as bytes array containing the command structure.
        :raises SPSDKError: If incorrect header tag found in the data.
        :return: Cmd Reset object instance.
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.RESET:
            raise SPSDKError("Invalid header tag")
        return cls()


class CmdMemEnable(CmdBaseClass):
    """SB2 command to enable and configure memory initialization.

    This command configures memory devices by specifying the source address
    of configuration data, the size of that data, and the target memory
    identifier. It manages memory device and group identification through
    flag manipulation.
    """

    @property
    def address(self) -> int:
        """Return command's address.

        :return: The address value stored in the command header.
        """
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Set command's address.

        :param value: The address value to set for the command.
        """
        self._header.address = value

    @property
    def size(self) -> int:
        """Return command's size in bytes.

        :return: Size of the command including header.
        """
        return self._header.count

    @size.setter
    def size(self, value: int) -> None:
        """Set command's size.

        :param value: The size value to set for the command.
        """
        self._header.count = value

    @property
    def flags(self) -> int:
        """Return command's flag.

        :return: Command flags as integer value.
        """
        return self._header.flags

    @flags.setter
    def flags(self, value: int) -> None:
        """Set command's flag.

        :param value: Flag value to be set for the command.
        """
        self._header.flags = value

    def __init__(self, address: int, size: int, mem_id: int):
        """Initialize CmdMemEnable command.

        This command enables and configures memory using the provided configuration data.
        The method extracts device and group IDs from the memory ID and sets appropriate
        flags for memory initialization.

        :param address: Source address with configuration data for memory initialization.
        :param size: Size of configuration data used for memory initialization.
        :param mem_id: Identification of memory containing device and group information.
        """
        super().__init__(EnumCmdTag.MEM_ENABLE)
        self.address = address
        self.mem_id = mem_id
        self.size = size

        device_id = get_device_id(mem_id)
        group_id = get_group_id(mem_id)

        self.flags |= (self.flags & ~self.ROM_MEM_DEVICE_ID_MASK) | (
            (device_id << self.ROM_MEM_DEVICE_ID_SHIFT) & self.ROM_MEM_DEVICE_ID_MASK
        )

        self.flags |= (self.flags & ~self.ROM_MEM_GROUP_ID_MASK) | (
            (group_id << self.ROM_MEM_GROUP_ID_SHIFT) & self.ROM_MEM_GROUP_ID_MASK
        )

    def __str__(self) -> str:
        """Return string representation of the MEM-ENABLE command.

        Provides a formatted string containing the memory enable command details including
        address, size, flags, and memory ID in hexadecimal format.

        :return: Formatted string representation of the command.
        """
        return (
            f"MEM-ENABLE: Address=0x{self.address:08X}, Size={self.size}, "
            f"Flags=0x{self.flags:08X}, MemId=0x{self.mem_id:08X}"
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse Memory Enable command from binary data.

        This method extracts device ID and group ID from the command header flags
        and constructs a Memory Enable command object with the parsed parameters.

        :param data: Binary data containing the Memory Enable command structure.
        :raises SPSDKError: If the header tag is not MEM_ENABLE.
        :return: Parsed Memory Enable command object.
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.MEM_ENABLE:
            raise SPSDKError("Invalid header tag")
        device_id = (header.flags & cls.ROM_MEM_DEVICE_ID_MASK) >> cls.ROM_MEM_DEVICE_ID_SHIFT
        group_id = (header.flags & cls.ROM_MEM_GROUP_ID_MASK) >> cls.ROM_MEM_GROUP_ID_SHIFT
        mem_id = get_memory_id(device_id, group_id)
        return cls(header.address, header.count, mem_id)


class CmdProg(CmdBaseClass):
    """SB2.1 Program command for writing data to target memory.

    This command handles programming operations in SB2.1 secure boot files,
    allowing data to be written to specific memory addresses on the target
    processor. It manages the target address, command flags, and associated
    data words for the programming operation.
    """

    @property
    def address(self) -> int:
        """Return address in target processor to program data.

        :return: Address value for programming data in target processor.
        """
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Set the target address for data loading.

        :param value: Address in target processor memory where data will be loaded.
        :raises SPSDKError: When the address is outside valid 32-bit range (0x00000000-0xFFFFFFFF).
        """
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect address")
        self._header.address = value

    @property
    def flags(self) -> int:
        """Return command's flags value.

        :return: The flags value from the command header.
        """
        return self._header.flags

    @flags.setter
    def flags(self, value: int) -> None:
        """Set command's flag.

        Updates the command's flags by first setting the eight-byte flag based on the
        is_eight_byte property, then applying the provided value using bitwise OR.

        :param value: Flag value to be applied to the command.
        """
        self._header.flags = self.is_eight_byte
        self._header.flags |= value

    @property
    def data_word1(self) -> int:
        """Return data word 1.

        Get the count value from the header which represents the first data word
        in the command structure.

        :return: The count value from the header as data word 1.
        """
        return self._header.count

    @data_word1.setter
    def data_word1(self, value: int) -> None:
        """Set the first data word value.

        This method validates and sets the first data word in the header count field.

        :param value: First data word value (must be within 32-bit unsigned integer range)
        :raises SPSDKError: When the value is outside the valid range (0x00000000-0xFFFFFFFF)
        """
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect data word 1")
        self._header.count = value

    @property
    def data_word2(self) -> int:
        """Return data word 2.

        :return: The value of data word 2 from the header.
        """
        return self._header.data

    @data_word2.setter
    def data_word2(self, value: int) -> None:
        """Set the second data word value.

        :param value: Second data word value (must be within 32-bit unsigned integer range).
        :raises SPSDKError: When the value is outside the valid range (0x00000000-0xFFFFFFFF).
        """
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect data word 2")
        self._header.data = value

    def __init__(
        self, address: int, mem_id: int, data_word1: int, data_word2: int = 0, flags: int = 0
    ) -> None:
        """Initialize CMD Prog command.

        Creates a new program command for writing data to memory with specified address,
        memory ID, and data words. Supports both 4-byte and 8-byte data operations.

        :param address: Target memory address for programming operation.
        :param mem_id: Memory device identifier (0-255).
        :param data_word1: First 32-bit data word to program.
        :param data_word2: Second 32-bit data word for 8-byte operations, defaults to 0.
        :param flags: Additional command flags, defaults to 0.
        :raises SPSDKError: Invalid memory ID (must be 0-255).
        """
        super().__init__(EnumCmdTag.PROG)

        if data_word2:
            self.is_eight_byte = 1
        else:
            self.is_eight_byte = 0

        if mem_id < 0 or mem_id > 0xFF:
            raise SPSDKError("Invalid ID of memory")

        self.address = address
        self.data_word1 = data_word1
        self.data_word2 = data_word2
        self.mem_id = mem_id
        self.flags = flags

        self.flags = (self.flags & ~self.ROM_MEM_DEVICE_ID_MASK) | (
            (self.mem_id << self.ROM_MEM_DEVICE_ID_SHIFT) & self.ROM_MEM_DEVICE_ID_MASK
        )

    def __str__(self) -> str:
        """Get string representation of PROG command.

        Formats the PROG command as a human-readable string showing the address index,
        data words, flags, and memory ID in hexadecimal format.

        :return: Formatted string representation of the PROG command.
        """
        return (
            f"PROG: Index=0x{self.address:08X}, DataWord1=0x{self.data_word1:08X}, "
            f"DataWord2=0x{self.data_word2:08X}, Flags=0x{self.flags:08X}, MemId=0x{self.mem_id:08X}"
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes.

        The method parses the input byte data to create a command object by extracting
        header information and validating the command tag.

        :param data: Input data as bytes to be parsed into command object.
        :raises SPSDKError: If incorrect header tag is found in the data.
        :return: Parsed command object instance.
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.PROG:
            raise SPSDKError("Invalid header tag")
        mem_id = (header.flags & cls.ROM_MEM_DEVICE_ID_MASK) >> cls.ROM_MEM_DEVICE_ID_SHIFT
        return cls(header.address, mem_id, header.count, header.data, header.flags)


class VersionCheckType(SpsdkEnum):
    """Version check type enumeration for SB2 commands.

    Defines the types of firmware version checking that can be performed,
    distinguishing between secure and non-secure firmware validation.
    """

    SECURE_VERSION = (0, "SECURE_VERSION")
    NON_SECURE_VERSION = (1, "NON_SECURE_VERSION")


class CmdVersionCheck(CmdBaseClass):
    """SB2 firmware version check command.

    Represents a command that validates the version of secure or non-secure firmware
    during the secure boot process. The command fails if the actual firmware version
    is less than the expected minimum version, providing version control and security
    enforcement capabilities.
    """

    def __init__(self, ver_type: VersionCheckType, version: int) -> None:
        """Initialize CmdVersionCheck command.

        :param ver_type: Version check type, see `VersionCheckType` enum.
        :param version: Version value to be checked.
        :raises SPSDKError: If invalid version check type.
        """
        super().__init__(EnumCmdTag.FW_VERSION_CHECK)
        if ver_type not in VersionCheckType:
            raise SPSDKError("Invalid version check type")
        self.header.address = ver_type.tag
        self.header.count = version

    @property
    def type(self) -> VersionCheckType:
        """Get type of the version check.

        Returns the type of version check operation based on the header address
        using VersionCheckType enumeration.

        :return: Type of the version check operation.
        """
        return VersionCheckType.from_tag(self.header.address)

    @property
    def version(self) -> int:
        """Return minimal version expected.

        :return: Minimal version value from header count.
        """
        return self.header.count

    def __str__(self) -> str:
        """Return string representation of the CVER command.

        Provides a formatted string containing the command type, version information,
        and header flags in hexadecimal format.

        :return: Formatted string with command details.
        """
        return (
            f"CVER: Type={self.type.label}, Version={str(self.version)}, "
            f"Flags=0x{self.header.flags:08X}"
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array into command object.

        Parses the binary data to extract command header information and creates
        a firmware version check command instance with the appropriate version type
        and version number.

        :param data: Input binary data containing the command structure
        :raises SPSDKError: If incorrect header tag is found in the data
        :return: Parsed firmware version check command object
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.FW_VERSION_CHECK:
            raise SPSDKError("Invalid header tag")
        ver_type = VersionCheckType.from_tag(header.address)
        version = header.count
        return cls(ver_type, version)


class CmdKeyStoreBackupRestore(CmdBaseClass):
    """SB2 Key Store Backup and Restore Command.

    Abstract base class for implementing key store backup and restore operations
    in SB2 files. Provides shared functionality for managing memory controller
    identification and address handling for key store operations.

    :cvar ROM_MEM_DEVICE_ID_MASK: Bit mask for extracting controller ID from flags.
    :cvar ROM_MEM_DEVICE_ID_SHIFT: Bit shift value for controller ID positioning.
    """

    # bit mask for controller ID inside flags
    ROM_MEM_DEVICE_ID_MASK = 0xFF00
    # shift for controller ID inside flags
    ROM_MEM_DEVICE_ID_SHIFT = 8

    @classmethod
    @abstractmethod
    def cmd_id(cls) -> EnumCmdTag:
        """Return command ID for the SB2 command.

        This is an abstract method that must be implemented by derived command classes
        to provide their specific command identifier.

        :return: Command tag enumeration value.
        :raises NotImplementedError: Derived class has to implement this method.
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def __init__(self, address: int, controller_id: ExtMemId):
        """Initialize CmdKeyStoreBackupRestore.

        :param address: Address where to backup key-store or source for restoring key-store.
        :param controller_id: ID of the memory to backup key-store or source memory to load
            key-store back.
        :raises SPSDKError: If invalid address.
        :raises SPSDKError: If invalid id of memory.
        """
        super().__init__(self.cmd_id())
        if address < 0 or address > 0xFFFFFFFF:
            raise SPSDKError("Invalid address")
        self.header.address = address
        if controller_id.tag < 0 or controller_id.tag > 0xFF:
            raise SPSDKError("Invalid ID of memory")
        self.header.flags = (self.header.flags & ~self.ROM_MEM_DEVICE_ID_MASK) | (
            (controller_id.tag << self.ROM_MEM_DEVICE_ID_SHIFT) & self.ROM_MEM_DEVICE_ID_MASK
        )
        self.header.count = (
            4  # this is useless, but it is kept for backward compatibility with elftosb
        )

    @property
    def address(self) -> int:
        """Return address where to backup key-store or source for restoring key-store.

        :return: Address value from the header.
        """
        return self.header.address

    @property
    def controller_id(self) -> int:
        """Get controller ID of the memory device.

        Extracts the controller ID from the header flags that identifies the memory
        device used to backup key-store or source memory to load key-store back.

        :return: Controller ID extracted from the ROM memory device ID mask.
        """
        return (self.header.flags & self.ROM_MEM_DEVICE_ID_MASK) >> self.ROM_MEM_DEVICE_ID_SHIFT

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array into CmdKeyStoreBackupRestore object.

        The method extracts header information, validates the command tag, and constructs
        the command object with parsed address and controller ID parameters.

        :param data: Input data as bytes array containing the command structure
        :return: CmdKeyStoreBackupRestore object with parsed parameters
        :raises SPSDKError: When there is invalid header tag
        """
        header = CmdHeader.parse(data)
        if header.tag != cls.cmd_id():
            raise SPSDKError("Invalid header tag")
        address = header.address
        controller_id = (header.flags & cls.ROM_MEM_DEVICE_ID_MASK) >> cls.ROM_MEM_DEVICE_ID_SHIFT
        return cls(address, ExtMemId.from_tag(controller_id))


class CmdKeyStoreBackup(CmdKeyStoreBackupRestore):
    """SB2 command for backing up keystore data from non-volatile memory.

    This command handles the backup operation of keystore information stored
    in the device's non-volatile memory, allowing for secure retrieval and
    storage of cryptographic keys and certificates.
    """

    @classmethod
    def cmd_id(cls) -> EnumCmdTag:
        """Return command ID for backup operation.

        :return: Command tag enumeration value for write keystore from non-volatile memory operation.
        """
        return EnumCmdTag.WR_KEYSTORE_FROM_NV


class CmdKeyStoreRestore(CmdKeyStoreBackupRestore):
    """SB2 command for restoring keystore data into non-volatile memory.

    This command handles the restoration of previously backed up keystore data
    from memory back into the device's non-volatile storage, completing the
    keystore recovery process.
    """

    @classmethod
    def cmd_id(cls) -> EnumCmdTag:
        """Return command ID for restore operation.

        :return: Command tag enumeration value for write keystore to non-volatile memory operation.
        """
        return EnumCmdTag.WR_KEYSTORE_TO_NV


########################################################################################################################
# Command parser from binary format
########################################################################################################################
_CMD_CLASS: Mapping[EnumCmdTag, Type[CmdBaseClass]] = {
    EnumCmdTag.NOP: CmdNop,
    EnumCmdTag.TAG: CmdTag,
    EnumCmdTag.LOAD: CmdLoad,
    EnumCmdTag.FILL: CmdFill,
    EnumCmdTag.JUMP: CmdJump,
    EnumCmdTag.CALL: CmdCall,
    EnumCmdTag.ERASE: CmdErase,
    EnumCmdTag.RESET: CmdReset,
    EnumCmdTag.MEM_ENABLE: CmdMemEnable,
    EnumCmdTag.PROG: CmdProg,
    EnumCmdTag.FW_VERSION_CHECK: CmdVersionCheck,
    EnumCmdTag.WR_KEYSTORE_TO_NV: CmdKeyStoreRestore,
    EnumCmdTag.WR_KEYSTORE_FROM_NV: CmdKeyStoreBackup,
}


def parse_command(data: bytes) -> CmdBaseClass:
    """Parse SB 2.x command from bytes.

    The method parses binary data representing an SB 2.x command and returns the appropriate
    command object based on the command tag found in the header.

    :param data: Input data as bytes containing the SB 2.x command.
    :return: Parsed command object instance.
    :raises SPSDKError: Raised when there is unsupported command provided.
    """
    header_tag = data[1]
    for cmd_tag, cmd in _CMD_CLASS.items():
        if cmd_tag.tag == header_tag:
            return cmd.parse(data)
    raise SPSDKError(f"Unsupported command: {str(header_tag)}")


def get_device_id(mem_id: int) -> int:
    """Get device ID from memory ID.

    Extracts the device identifier from the given memory ID by applying
    a device ID mask and performing bit shifting operation.

    :param mem_id: Memory identifier value to extract device ID from.
    :return: Extracted device identifier.
    """
    return ((mem_id) & DEVICE_ID_MASK) >> DEVICE_ID_SHIFT


def get_group_id(mem_id: int) -> int:
    """Get group ID from memory ID.

    Extracts the group identifier from a memory ID using bitwise operations
    with GROUP_ID_MASK and GROUP_ID_SHIFT constants.

    :param mem_id: Memory identifier to extract group ID from.
    :return: Extracted group identifier.
    """
    return ((mem_id) & GROUP_ID_MASK) >> GROUP_ID_SHIFT


def get_memory_id(device_id: int, group_id: int) -> int:
    """Get memory ID from device ID and group ID.

    Combines device ID and group ID using bit shifting and masking operations
    to create a unique memory identifier for SB2 commands.

    :param device_id: Device identifier value.
    :param group_id: Group identifier value.
    :return: Combined memory ID created from device and group identifiers.
    """
    return (((group_id) << GROUP_ID_SHIFT) & GROUP_ID_MASK) | (
        ((device_id) << DEVICE_ID_SHIFT) & DEVICE_ID_MASK
    )
