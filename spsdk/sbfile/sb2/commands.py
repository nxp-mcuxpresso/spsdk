#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Commands used by SBFile module."""
import math
from abc import abstractmethod
from struct import calcsize, pack, unpack_from
from typing import Any, Mapping, Optional, Type

from crcmod.predefined import mkPredefinedCrcFun

from spsdk import SPSDKError
from spsdk.mboot import ExtMemId, MemId
from spsdk.sbfile.misc import SecBootBlckSize
from spsdk.utils.crypto.abstract import BaseClass
from spsdk.utils.crypto.common import swap16
from spsdk.utils.easy_enum import Enum
from spsdk.utils.misc import DebugInfo


########################################################################################################################
# Enums
########################################################################################################################
class EnumCmdTag(Enum):
    """Command tags."""

    NOP = 0x0
    TAG = 0x1
    LOAD = 0x2
    FILL = 0x3
    JUMP = 0x4
    CALL = 0x5
    ERASE = 0x7
    RESET = 0x8
    MEM_ENABLE = 0x9
    PROG = 0xA
    FW_VERSION_CHECK = (0xB, "Check FW version fuse value")
    WR_KEYSTORE_TO_NV = (0xC, "Restore key-store restore to non-volatile memory")
    WR_KEYSTORE_FROM_NV = (0xD, "Backup key-store from non-volatile memory")


class EnumSectionFlag(Enum):
    """Section flags."""

    BOOTABLE = 0x0001
    CLEARTEXT = 0x0002
    LAST_SECT = 0x8000


########################################################################################################################
# Header Class
########################################################################################################################
class CmdHeader:
    """SBFile command header."""

    FORMAT = "<2BH3L"
    SIZE = calcsize(FORMAT)

    @property
    def crc(self) -> int:
        """Calculate CRC for the header data."""
        raw_data = self._raw_data(crc=0)
        checksum = 0x5A
        for i in range(1, self.SIZE):
            checksum = (checksum + raw_data[i]) & 0xFF
        return checksum

    def __init__(self, tag: int, flags: int = 0) -> None:
        """Initialize header."""
        if tag not in EnumCmdTag.tags():
            raise SPSDKError("Incorrect command tag")
        self.tag = tag
        self.flags = flags
        self.address = 0
        self.count = 0
        self.data = 0

    def __eq__(self, obj: Any) -> bool:
        return isinstance(obj, self.__class__) and vars(obj) == vars(self)

    def __ne__(self, obj: Any) -> bool:
        return not self.__eq__(obj)

    def __str__(self) -> str:
        tag = EnumCmdTag.get(self.tag, f"0x{self.tag:02X}")
        return (
            f"tag={tag}, flags=0x{self.flags:04X}, "
            f"address=0x{self.address:08X}, count=0x{self.count:08X}, data=0x{self.data:08X}"
        )

    def _raw_data(self, crc: int) -> bytes:
        """Return raw data of the header with specified CRC.

        :param crc: value to be used
        :return: binary representation of the header
        """
        return pack(self.FORMAT, crc, self.tag, self.flags, self.address, self.count, self.data)

    def export(self) -> bytes:
        """Export command header as bytes."""
        return self._raw_data(self.crc)

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdHeader":
        """Parse command header from bytes.

        :param data: Input data as bytes
        :param offset: The offset of input data
        :return: CMDHeader object
        :raise Exception: raised when size is incorrect
        :raises SPSDKError: Raised when CRC is incorrect
        """
        if calcsize(cls.FORMAT) > len(data) - offset:
            raise Exception()
        obj = cls(EnumCmdTag.NOP)
        (crc, obj.tag, obj.flags, obj.address, obj.count, obj.data) = unpack_from(
            cls.FORMAT, data, offset
        )
        if crc != obj.crc:
            raise SPSDKError("CRC does not match")
        return obj


########################################################################################################################
# Commands Classes
########################################################################################################################
class CmdBaseClass(BaseClass):
    """Base class for all commands."""

    def __init__(self, tag: int) -> None:
        """Initialize CmdBase."""
        self._header = CmdHeader(tag)

    # TODO Refactor: so header is not published, it should not be accessed publicly
    @property
    def header(self) -> CmdHeader:
        """Return command header."""
        return self._header

    @property
    def raw_size(self) -> int:
        """Return size of the command in binary format (including header)."""
        return CmdHeader.SIZE  # this is default implementation

    def __str__(self) -> str:
        return "Command: " + str(self._header)  # default implementation: use command name

    def info(self) -> str:
        """Return text info about the instance."""
        return self.__str__() + "\n"  # default implementation is same as __str__

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Return object serialized into bytes."""
        dbg_info.append_section("Command:" + EnumCmdTag.name(self.header.tag))
        cmd_data = self._header.export()  # default implementation
        dbg_info.append_binary_data("cmd-header", cmd_data)
        return cmd_data

    @classmethod
    @abstractmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdBaseClass":
        """Deserialize object from binary."""


class CmdNop(CmdBaseClass):
    """Command NOP class."""

    def __init__(self) -> None:
        """Initialize Command Nop."""
        super().__init__(EnumCmdTag.NOP)

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdNop":
        """Parse command from bytes.

        :param data: Input data as bytes
        :param offset: The offset of input data
        :return: CMD Nop object
        :raises SPSDKError: When there is incorrect header tag
        """
        header = CmdHeader.parse(data, offset)
        if header.tag != EnumCmdTag.NOP:
            raise SPSDKError("Incorrect header tag")
        return cls()


class CmdTag(CmdBaseClass):
    """Command TAG class.

    It is also used as header for boot section for SB file 1.x.
    """

    def __init__(self) -> None:
        """Initialize Command Tag."""
        super().__init__(EnumCmdTag.TAG)

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdTag":
        """Parse command from bytes.

        :param data: Input data as bytes
        :param offset: The offset of input data
        :return: parsed instance
        :raises SPSDKError: When there is incorrect header tag
        """
        header = CmdHeader.parse(data, offset)
        if header.tag != EnumCmdTag.TAG:
            raise SPSDKError("Incorrect header tag")
        result = cls()
        result._header = header
        return result


class CmdLoad(CmdBaseClass):
    """Command Load. The load statement is used to store data into the memory."""

    @property
    def address(self) -> int:
        """Return address in target processor to load data."""
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Setter.

        :param value: address in target processor to load data
        :raises SPSDKError: When there is incorrect address
        """
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect address")
        self._header.address = value

    @property
    def raw_size(self) -> int:
        """Return aligned size of the command including header and data."""
        size = CmdHeader.SIZE + len(self.data)
        if size % CmdHeader.SIZE:
            size += CmdHeader.SIZE - (size % CmdHeader.SIZE)
        return size

    def __init__(self, address: int, data: bytes) -> None:
        """Initialize CMD Load."""
        super().__init__(EnumCmdTag.LOAD)
        assert isinstance(data, (bytes, bytearray))
        self.address = address
        self.data = bytes(data)

    def __str__(self) -> str:
        return f"LOAD: Address=0x{self.address:08X}, DataLen={len(self.data)}"

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export command as binary."""
        self._update_data()
        result = super().export(dbg_info)
        dbg_info.append_binary_section("load-data", self.data)
        return result + self.data

    def _update_data(self) -> None:
        """Update command data."""
        # padding data
        self.data = SecBootBlckSize.align_block_fill_random(self.data)
        # update header
        self._header.count = len(self.data)
        crc32_function = mkPredefinedCrcFun("crc-32-mpeg")
        self._header.data = crc32_function(self.data, 0xFFFFFFFF)

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdLoad":
        """Parse command from bytes.

        :param data: Input data as bytes
        :param offset: The offset of input data
        :return: CMD Load object
        :raises SPSDKError: Raised when there is invalid CRC
        :raises SPSDKError: When there is incorrect header tag
        """
        header = CmdHeader.parse(data, offset)
        if header.tag != EnumCmdTag.LOAD:
            raise SPSDKError("Incorrect header tag")
        offset += CmdHeader.SIZE
        header_count = SecBootBlckSize.align(header.count)
        cmd_data = data[offset : offset + header_count]
        crc32_function = mkPredefinedCrcFun("crc-32-mpeg")
        if header.data != crc32_function(cmd_data, 0xFFFFFFFF):
            raise SPSDKError("Invalid CRC in the command header")
        obj = CmdLoad(header.address, cmd_data)
        obj.header.data = header.data
        obj.header.flags = header.flags
        obj._update_data()
        return obj


class CmdFill(CmdBaseClass):
    """Command Fill class."""

    PADDING_VALUE = 0x00

    @property
    def address(self) -> int:
        """Return address of the command Fill."""
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Set address for the command Fill."""
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect address")
        self._header.address = value

    @property
    def raw_size(self) -> int:
        """Calculate raw size of header."""
        size = CmdHeader.SIZE
        size += len(self._pattern) - 4
        if size % CmdHeader.SIZE:
            size += CmdHeader.SIZE - (size % CmdHeader.SIZE)
        return size

    def __init__(self, address: int, pattern: int, length: Optional[int] = None) -> None:
        """Initialize Command Fill.

        :param address: to write data
        :param pattern: data to be written
        :param length: length of data to be filled, defaults to 4
        :raises SPSDKError: Raised when size is not aligned to 4 bytes
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
        pattern_bytes = pattern.to_bytes(math.ceil(pattern_len), "big")
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

    @property
    def pattern(self) -> bytes:
        """Return binary data to fill."""
        return self._pattern

    def __str__(self) -> str:
        return f"FILL: Address=0x{self.address:08X}, Pattern=" + " ".join(
            f"{byte:02X}" for byte in self._pattern
        )

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Return command in binary form (serialization)."""
        # export cmd
        data = super().export(dbg_info)
        # export additional data
        data = SecBootBlckSize.align_block_fill_random(data)
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdFill":
        """Parse command from bytes.

        :param data: Input data as bytes
        :param offset: The offset of input data
        :return: Command Fill object
        :raises SPSDKError: If incorrect header tag
        """
        header = CmdHeader.parse(data, offset)
        if header.tag != EnumCmdTag.FILL:
            raise SPSDKError("Incorrect header tag")
        # The last 4 bytes of header are part of pattern value
        offset += CmdHeader.SIZE - 4
        return cls(header.address, header.data, header.count)


class CmdJump(CmdBaseClass):
    """Command Jump class."""

    @property
    def address(self) -> int:
        """Return address of the command Jump."""
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Set address of the command Jump."""
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect address")
        self._header.address = value

    @property
    def argument(self) -> int:
        """Return command's argument."""
        return self._header.data

    @argument.setter
    def argument(self, value: int) -> None:
        """Set command's argument."""
        if value < 0x00 or value > 0xFF:
            raise SPSDKError("Incorrect argument")
        self._header.data = value

    @property
    def spreg(self) -> Optional[int]:
        """Return command's Stack Pointer."""
        if self._header.flags == 2:
            return self._header.count

        return None

    @spreg.setter
    def spreg(self, value: Optional[int] = None) -> None:
        """Set command's Stack Pointer."""
        if value is None:
            self._header.flags = 0
            self._header.count = 0
        else:
            self._header.flags = 2
            self._header.count = value

    def __init__(self, address: int = 0, argument: int = 0, spreg: Optional[int] = None) -> None:
        """Initialize Command Jump."""
        super().__init__(EnumCmdTag.JUMP)
        self.address = address
        self.argument = argument
        self.spreg = spreg

    def __str__(self) -> str:
        nfo = f"JUMP: Address=0x{self.address:08X}, Argument=0x{self.argument:08X}"
        if self.spreg is not None:
            nfo += f", SP=0x{self.spreg:08X}"
        return nfo

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdJump":
        """Parse command from bytes.

        :param data: Input data as bytes
        :param offset: The offset of input data
        :return: Command Jump object
        :raises SPSDKError: If incorrect header tag
        """
        header = CmdHeader.parse(data, offset)
        if header.tag != EnumCmdTag.JUMP:
            raise SPSDKError("Incorrect header tag")
        return cls(header.address, header.data, header.count if header.flags else None)


class CmdCall(CmdBaseClass):
    """Command Call.

    The call statement is used for inserting a bootloader command that executes a function
    from one of the files that are loaded into the memory.
    """

    @property
    def address(self) -> int:
        """Return command's address."""
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Set command's address."""
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect address")
        self._header.address = value

    @property
    def argument(self) -> int:
        """Return command's argument."""
        return self._header.data

    @argument.setter
    def argument(self, value: int) -> None:
        """Set command's argument."""
        self._header.data = value

    def __init__(self, address: int = 0, argument: int = 0) -> None:
        """Initialize Command Call."""
        super().__init__(EnumCmdTag.CALL)
        self.address = address
        self.argument = argument

    def __str__(self) -> str:
        return f"CALL: Address=0x{self.address:08X}, Argument=0x{self.argument:08X}"

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdCall":
        """Parse command from bytes.

        :param data: Input data as bytes
        :param offset: The offset of input data
        :return: Command Call object
        :raises SPSDKError: If incorrect header tag
        """
        header = CmdHeader.parse(data, offset)
        if header.tag != EnumCmdTag.CALL:
            raise SPSDKError("Incorrect header tag")
        return cls(header.address, header.data)


class CmdErase(CmdBaseClass):
    """Command Erase class."""

    @property
    def address(self) -> int:
        """Return command's address."""
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Set command's address."""
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect address")
        self._header.address = value

    @property
    def length(self) -> int:
        """Return command's count."""
        return self._header.count

    @length.setter
    def length(self, value: int) -> None:
        """Set command's count."""
        self._header.count = value

    @property
    def flags(self) -> int:
        """Return command's flag."""
        return self._header.flags

    @flags.setter
    def flags(self, value: int) -> None:
        """Set command's flag."""
        self._header.flags = value

    def __init__(self, address: int = 0, length: int = 0, flags: int = 0) -> None:
        """Initialize Command Erase."""
        super().__init__(EnumCmdTag.ERASE)
        self.address = address
        self.length = length
        self.flags = flags

    def __str__(self) -> str:
        return (
            f"ERASE: Address=0x{self.address:08X}, Length={self.length}, Flags=0x{self.flags:08X}"
        )

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdErase":
        """Parse command from bytes.

        :param data: Input data as bytes
        :param offset: The offset of input data
        :return: Command Erase object
        :raises SPSDKError: If incorrect header tag
        """
        header = CmdHeader.parse(data, offset)
        if header.tag != EnumCmdTag.ERASE:
            raise SPSDKError("Invalid header tag")
        return cls(header.address, header.count, header.flags)


class CmdReset(CmdBaseClass):
    """Command Reset class."""

    def __init__(self) -> None:
        """Initialize Command Reset."""
        super().__init__(EnumCmdTag.RESET)

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdReset":
        """Parse command from bytes.

        :param data: Input data as bytes
        :param offset: The offset of input data
        :return: Cmd Reset object
        :raises SPSDKError: If incorrect header tag
        """
        header = CmdHeader.parse(data, offset)
        if header.tag != EnumCmdTag.RESET:
            raise SPSDKError("Invalid header tag")
        return cls()


class CmdMemEnable(CmdBaseClass):
    """Command to configure certain memory."""

    @property
    def address(self) -> int:
        """Return command's address."""
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Set command's address."""
        self._header.address = value

    @property
    def size(self) -> int:
        """Return command's size."""
        return self._header.count

    @size.setter
    def size(self, value: int) -> None:
        """Set command's size."""
        self._header.count = value

    @property
    def mem_type(self) -> MemId:
        """Return memory to be enabled."""
        return MemId.from_int(swap16(self._header.flags))

    @mem_type.setter
    def mem_type(self, value: MemId) -> None:
        """Setter.

        :param value: memory to be enabled
        """
        self._header.flags = swap16(value)

    def __init__(self, address: int, size: int, mem_type: MemId):
        """Initialize CmdMemEnable.

        :param address: source address with configuration data for memory initialization
        :param size: size of configuration data used for memory initialization
        :param mem_type: identification of external memory type, see enum for details
        """
        super().__init__(EnumCmdTag.MEM_ENABLE)
        self.address = address
        self.mem_type = mem_type
        self.size = size

    def __str__(self) -> str:
        return f"MEM-ENABLE: Address=0x{self.address:08X}, Size={self.size}, MemType=0x{self.mem_type:08X}"

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdMemEnable":
        """Parse command from bytes.

        :param data: Input data as bytes
        :param offset: The offset of input data
        :return: Command Memory Enable object
        :raises SPSDKError: If incorrect header tag
        """
        header = CmdHeader.parse(data, offset)
        if header.tag != EnumCmdTag.MEM_ENABLE:
            raise SPSDKError("Invalid header tag")
        return cls(header.address, header.count, MemId.from_int(swap16(header.flags)))


class CmdProg(CmdBaseClass):
    """Command Program class."""

    def __init__(self) -> None:
        """Initialize Cmd Program."""
        super().__init__(EnumCmdTag.PROG)

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdProg":
        """Parse command from bytes.

        :param data: Input data as bytes
        :param offset: The offset of input data
        :return: parsed command object
        :raises SPSDKError: If incorrect header tag
        """
        header = CmdHeader.parse(data, offset)
        if header.tag != EnumCmdTag.PROG:
            raise SPSDKError("Invalid header tag")
        return cls()


class VersionCheckType(Enum):
    """Select type of the version check: either secure or non-secure firmware to be checked."""

    SECURE_VERSION = 0
    NON_SECURE_VERSION = 1


class CmdVersionCheck(CmdBaseClass):
    """FW Version Check command class.

    Validates version of secure or non-secure firmware.
    The command fails if version is < expected.
    """

    def __init__(self, ver_type: VersionCheckType, version: int) -> None:
        """Initialize CmdVersionCheck.

        :param ver_type: version check type, see `VersionCheckType` enum
        :param version: to be checked
        :raises SPSDKError: If invalid version check type
        """
        super().__init__(EnumCmdTag.FW_VERSION_CHECK)
        if ver_type not in VersionCheckType.tags():
            raise SPSDKError("Invalid version check type")
        self.header.address = ver_type
        self.header.count = version

    @property
    def type(self) -> VersionCheckType:
        """Return type of the check version, see VersionCheckType enumeration."""
        return VersionCheckType.from_int(self.header.address)

    @property
    def version(self) -> int:
        """Return minimal version expected."""
        return self.header.count

    def __str__(self) -> str:
        return (
            super().__str__()
            + f" type={VersionCheckType.name(self.type)}, version={str(self.version)}"
        )

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdVersionCheck":
        """Parse command from bytes.

        :param data: Input data as bytes
        :param offset: The offset of input data
        :return: parsed command object
        :raises SPSDKError: If incorrect header tag
        """
        header = CmdHeader.parse(data, offset)
        if header.tag != EnumCmdTag.FW_VERSION_CHECK:
            raise SPSDKError("Invalid header tag")
        ver_type = VersionCheckType.from_int(header.address)
        version = header.count
        return CmdVersionCheck(ver_type, version)


class CmdKeyStoreBackupRestore(CmdBaseClass):
    """Shared, abstract implementation for key-store backup and restore command."""

    # bit mask for controller ID inside flags
    ROM_MEM_DEVICE_ID_MASK = 0xFF00
    # shift for controller ID inside flags
    ROM_MEM_DEVICE_ID_SHIFT = 8

    @classmethod
    @abstractmethod
    def cmd_id(cls) -> EnumCmdTag:
        """Return command ID.

        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def __init__(self, address: int, controller_id: ExtMemId):
        """Initialize CmdKeyStoreBackupRestore.

        :param address: where to backup key-store or source for restoring key-store
        :param controller_id: ID of the memory to backup key-store or source memory to load key-store back
        :raises SPSDKError: If invalid address
        :raises SPSDKError: If invalid id of memory
        """
        super().__init__(self.cmd_id())
        if address < 0 or address > 0xFFFFFFFF:
            raise SPSDKError("Invalid address")
        self.header.address = address
        if controller_id < 0 or controller_id > 0xFF:
            raise SPSDKError("Invalid ID of memory")
        self.header.flags = (self.header.flags & ~self.ROM_MEM_DEVICE_ID_MASK) | (
            (controller_id << self.ROM_MEM_DEVICE_ID_SHIFT) & self.ROM_MEM_DEVICE_ID_MASK
        )
        self.header.count = (
            4  # this is useless, but it is kept for backward compatibility with elftosb
        )

    @property
    def address(self) -> int:
        """Return address where to backup key-store or source for restoring key-store."""
        return self.header.address

    @property
    def controller_id(self) -> int:
        """Return controller ID of the memory to backup key-store or source memory to load key-store back."""
        return (self.header.flags & self.ROM_MEM_DEVICE_ID_MASK) >> self.ROM_MEM_DEVICE_ID_SHIFT

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdKeyStoreBackupRestore":
        """Parse command from bytes.

        :param data: Input data as bytes
        :param offset: The offset of input data
        :return: CmdKeyStoreBackupRestore object
        :raises SPSDKError: When there is invalid header tag
        """
        header = CmdHeader.parse(data, offset)
        if header.tag != cls.cmd_id():
            raise SPSDKError("Invalid header tag")
        address = header.address
        controller_id = (header.flags & cls.ROM_MEM_DEVICE_ID_MASK) >> cls.ROM_MEM_DEVICE_ID_SHIFT
        return cls(address, controller_id)  # type: ignore


class CmdKeyStoreBackup(CmdKeyStoreBackupRestore):
    """Command to backup keystore from non-volatile memory."""

    @classmethod
    def cmd_id(cls) -> EnumCmdTag:
        """Return command ID for backup operation."""
        return EnumCmdTag.WR_KEYSTORE_FROM_NV


class CmdKeyStoreRestore(CmdKeyStoreBackupRestore):
    """Command to restore keystore into non-volatile memory."""

    @classmethod
    def cmd_id(cls) -> EnumCmdTag:
        """Return command ID for restore operation."""
        return EnumCmdTag.WR_KEYSTORE_TO_NV


########################################################################################################################
# Command parser from binary format
########################################################################################################################
_CMD_CLASS: Mapping[int, Type[CmdBaseClass]] = {
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


def parse_command(data: bytes, offset: int = 0) -> CmdBaseClass:
    """Parse SB 2.x command from bytes.

    :param data: Input data as bytes
    :param offset: The offset of input data to start parsing
    :return: parsed command object
    :raises SPSDKError: Raised when there is unsupported command provided
    """
    header_tag = data[offset + 1]
    if header_tag not in _CMD_CLASS:
        raise SPSDKError(f"Unsupported command: {str(header_tag)}")
    return _CMD_CLASS[header_tag].parse(data, offset)
