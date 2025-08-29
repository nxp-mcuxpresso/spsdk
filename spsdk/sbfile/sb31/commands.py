#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for creation commands."""

import lzma
import os
from enum import Enum as BuiltinEnum
from struct import calcsize, pack, unpack_from
from typing import Mapping, Type, Union

from typing_extensions import Self

from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.sbfile.sb31.constants import EnumCmdTag
from spsdk.utils.abstract import BaseClass
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.misc import (
    Endianness,
    align,
    align_block,
    find_file,
    load_binary,
    load_text,
    value_to_bytes,
    value_to_int,
    write_file,
)
from spsdk.utils.spsdk_enum import SpsdkEnum

########################################################################################################################
# Base Command Class
########################################################################################################################


class BaseCmd(BaseClass):
    """Functions for creating cmd intended for inheritance."""

    FORMAT = "<4L"
    SIZE = calcsize(FORMAT)
    TAG = 0x55AAAA55
    CMD_TAG = EnumCmdTag.NONE

    @property
    def address(self) -> int:
        """Get address."""
        return self._address

    @address.setter
    def address(self, value: int) -> None:
        """Set address."""
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Invalid address")
        self._address = value

    @property
    def length(self) -> int:
        """Get length."""
        return self._length

    @length.setter
    def length(self, value: int) -> None:
        """Set value."""
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Invalid length")
        self._length = value

    @property
    def export_length(self) -> int:
        """Get export length.

        :return: The length of the exported command data
        """
        return self.SIZE

    def __init__(self, address: int, length: int) -> None:
        """Constructor for Commands header.

        :param address: Input address
        :param length: Input length
        """
        self._address = address
        self._length = length

    def __repr__(self) -> str:
        return f"SB3.1 Command: {self.__class__.__name__}"

    def __str__(self) -> str:
        """Get info of command.

        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def export(self) -> bytes:
        """Export command as bytes."""
        return pack(self.FORMAT, self.TAG, self.address, self.length, self.CMD_TAG.tag)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse object from bytes array.

        :param data: Input data as bytes array
        :return: Parsed command object
        :raises NotImplementedError: Derived class must implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    @classmethod
    def header_parse_raw(cls, data: bytes) -> tuple[int, int, int]:
        """Parse header command from bytes array.

        :param data: Input data as bytes array
        :raises SPSDKError: Raised if tag is not equal to required TAG
        :raises SPSDKError: Raised if cmd is not equal EnumCmdTag
        :return: Tuple
        """
        tag, address, length, cmd = unpack_from(cls.FORMAT, data)
        if tag != cls.TAG:
            raise SPSDKError("TAG is not valid.")
        return address, length, cmd

    @classmethod
    def header_parse(cls, data: bytes) -> tuple[int, int]:
        """Parse header command from bytes array.

        :param data: Input data as bytes array
        :raises SPSDKError: Raised if tag is not equal to required TAG
        :raises SPSDKError: Raised if cmd is not equal EnumCmdTag
        :return: Tuple
        """
        address, length, cmd = cls.header_parse_raw(data)
        if cmd != cls.CMD_TAG.tag:
            raise SPSDKError("Values are not same.")
        return address, length

    @classmethod
    def load_from_config(cls, config: Config) -> list[Self]:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :return: Command object loaded from configuration.
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def get_config_context(self, data_path: str = "./") -> Config:
        """Create configuration of the commands feature.

        Abstract method that must be implemented by all inherited command classes.
        Each implementation should return a configuration object containing
        command-specific settings and parameters.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration object with command-specific settings.
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the SecureBinary4 feature.

        Generates a configuration object representing the current state of the SecureBinary4 instance.

        :param data_path: Path to store the data files of configuration.
        """
        config = Config({})
        config[self.CMD_TAG.label] = self.get_config_context(data_path)
        return config


########################################################################################################################
# Commands Classes version 3.1
########################################################################################################################
class CmdLoadBase(BaseCmd):
    """Base class for commands loading data."""

    HAS_MEMORY_ID_BLOCK = True

    def __init__(
        self,
        address: int,
        data: bytes,
        memory_id: int = 0,
        compress: bool = False,
    ) -> None:
        """Constructor for command.

        :param cmd_tag: Command tag for the derived class
        :param address: Address for the load command
        :param data: Data to load
        :param memory_id: Memory ID
        :param compress: Compress data
        """
        self.compressed = False
        self.crc = 0
        self.check_size = 0

        if compress:
            compressed_data = self._compress_data(data=data)
            # check if it makes sense to use compression
            if len(compressed_data) + 16 < len(data):
                self.compressed = True
                self.crc = self._calc_crc(data=data)
                self.check_size = len(data)
                self.compressed_data = compressed_data

        super().__init__(address=address, length=len(data))
        self.memory_id = memory_id
        self.data = data

    def _compress_data(self, data: bytes) -> bytes:
        settings = {
            "id": lzma.FILTER_LZMA1,
            "preset": 9 | lzma.PRESET_EXTREME,
            "dict_size": 4 * 1024,
            "mode": lzma.MODE_FAST,
        }

        compressed_data = lzma.compress(data=data, format=lzma.FORMAT_ALONE, filters=[settings])
        return compressed_data

    def _decompress_data(self) -> bytes:
        return lzma.decompress(self.data)

    def _calc_crc(self, data: bytes) -> int:
        crc_obj = from_crc_algorithm(CrcAlg.CRC32_MPEG)
        return crc_obj.calculate(data)

    def export(self) -> bytes:
        """Export command as bytes."""
        data = super().export()
        if self.HAS_MEMORY_ID_BLOCK:
            data += pack("<L", self.memory_id)
            if self.compressed:
                data += b"LZMA"
                data += pack("<2L", self.crc, self.check_size)
            else:
                data += pack("<3L", 0, 0, 0)

        data += self.data
        data = align_block(data, alignment=16)
        return data

    @property
    def export_length(self) -> int:
        """Get export length.

        Calculate the total export length including the command header, memory ID block (if present),
        and the data payload (aligned to 16-byte boundary).

        :return: The length of the exported command data in bytes
        """
        # Start with the base command header size
        length = self.SIZE

        # Add memory ID block size if present
        if self.HAS_MEMORY_ID_BLOCK:
            length += 16  # memory_id + padding or compression info (4 words)

        # Add data length rounded up to 16-byte alignment
        length += align(len(self.data), alignment=16)

        return length

    def __str__(self) -> str:
        """Get info about the load command."""
        msg = f"{self.CMD_TAG.label}: "
        if self.HAS_MEMORY_ID_BLOCK:
            msg += f"Address=0x{self.address:08X}, Length={self.length}, Memory ID={self.memory_id}"
        else:
            msg += f"Address=0x{self.address:08X}, Length={self.length}"
        return msg

    @classmethod
    def _extract_data(cls, data: bytes) -> tuple[int, int, bytes, int, int, bool, int, int]:
        """Extract data from the command bytes.

        :param data: Command data bytes
        :return: Tuple containing (address, length, data, cmd_tag, memory_id, is_compressed, crc, check_size)
        :raises SPSDKError: If TAG is invalid
        """
        tag, address, length, cmd = unpack_from(cls.FORMAT, data)
        memory_id = 0
        is_compressed = False
        crc = 0
        check_size = 0

        if tag != cls.TAG:
            raise SPSDKError(f"Invalid TAG, expected: {cls.TAG}")

        offset = BaseCmd.SIZE
        if cls.HAS_MEMORY_ID_BLOCK:
            memory_id, pad0, pad1, pad2 = unpack_from("<4L", data, offset=offset)

            # Check if data is compressed (pad0 is "LZMA" magic string)
            if data[offset + 4 : offset + 8] == b"LZMA":
                is_compressed = True
                crc = pad1
                check_size = pad2
            elif not pad0 == pad1 == pad2 == 0:
                raise SPSDKError("Invalid padding")

            offset += 16

        load_data = data[offset : offset + length]

        # If data is compressed, decompress it and verify CRC
        if is_compressed:
            try:
                decompressed_data = lzma.decompress(load_data)
                calculated_crc = from_crc_algorithm(CrcAlg.CRC32_MPEG).calculate(decompressed_data)

                if calculated_crc != crc:
                    raise SPSDKError(f"CRC mismatch: expected {crc}, got {calculated_crc}")

                if len(decompressed_data) != check_size:
                    raise SPSDKError(
                        f"Size mismatch: expected {check_size}, got {len(decompressed_data)}"
                    )

                # Replace compressed data with decompressed data
                load_data = decompressed_data
            except lzma.LZMAError as exc:
                raise SPSDKError(f"Failed to decompress LZMA data: {str(exc)}") from exc

        return address, length, load_data, cmd, memory_id, is_compressed, crc, check_size

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :return: Command instance
        :raises SPSDKError: Invalid cmd_tag was found
        """
        address, _, data, cmd_tag, memory_id, is_compressed, _, _ = cls._extract_data(data)
        cmd_tag_enum = EnumCmdTag.from_tag(cmd_tag)
        if cmd_tag_enum != cls.CMD_TAG:
            raise SPSDKError(f"Invalid cmd_tag found: {cmd_tag_enum}")

        return cls(address=address, data=data, memory_id=memory_id, compress=is_compressed)

    # pylint: disable=redundant-returns-doc
    @classmethod
    def load_from_config(cls, config: Config) -> list[Self]:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :return: Command object loaded from configuration.
        """
        raise NotImplementedError("Derived class has to implement this method.")


class CmdErase(BaseCmd):
    """Erase given address range. The erase will be rounded up to the sector size."""

    CMD_TAG = EnumCmdTag.ERASE

    def __init__(self, address: int, length: int, memory_id: int = 0) -> None:
        """Constructor for command.

        :param address: Input address
        :param length: Input length
        :param memory_id: Memory ID
        """
        super().__init__(address=address, length=length)
        self.memory_id = memory_id

    def __str__(self) -> str:
        """Get info of command."""
        return (
            f"ERASE: Address=0x{self.address:08X}, Length={self.length}, Memory ID={self.memory_id}"
        )

    def export(self) -> bytes:
        """Export command as bytes."""
        data = super().export()
        data += pack("<4L", self.memory_id, 0, 0, 0)
        return data

    @property
    def export_length(self) -> int:
        """Get export length.

        :return: The length of the exported command data
        """
        return self.SIZE + 16  # BaseCmd.SIZE (16) + additional 16 bytes for memory_id and padding

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :return: CmdErase
        :raises SPSDKError: Invalid padding
        """
        address, length = cls.header_parse(data=data)
        memory_id, pad0, pad1, pad2 = unpack_from("<4L", data, offset=16)
        if not pad0 == pad1 == pad2 == 0:
            raise SPSDKError("Invalid padding")
        return cls(address=address, length=length, memory_id=memory_id)

    @classmethod
    def load_from_config(cls, config: Config) -> list[Self]:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :return: Command object loaded from configuration.
        """
        address = config.get_int("address", 0)
        length = config.get_int("size", 0)
        memory_id = config.get_int("memoryId", 0)
        return [cls(address=address, length=length, memory_id=memory_id)]

    def get_config_context(self, data_path: str = "./") -> Config:
        """Create configuration for the ERASE command.

        This method generates a configuration dictionary containing the command's properties
        and settings, including memory address, length, and memory ID.

        The ERASE command erases a specified memory region, with the operation being
        rounded up to the sector size for the specified memory.

        :param data_path: Path to store any data files (not used for this command)
        :return: Configuration object with command-specific settings
        """
        config_dict = {"address": self.address, "size": self.length, "memoryId": self.memory_id}
        return Config(config_dict)


def load_cmd_data_from_cfg(config: Config) -> bytes:
    """Load command data from configuration.

    This function attempts to extract binary data from configuration using multiple approaches:
    1. Direct conversion to bytes if possible
    2. Parsing as list of values or comma-separated string
    3. Loading from a file specified in configuration

    :param config: Dictionary with configuration fields
    :return: Binary data extracted from configuration
    :raises SPSDKError: When data cannot be loaded from any source
    """
    # We kept there the backward compatibility code to load obsolete keys: value/values/file
    data = config.get("data", config.get("value", config.get("values", config.get("file"))))
    if data is None:
        raise SPSDKError(f"No data source found for LOAD SBx.x command from {config}")
    # Try to convert directly to bytes
    try:
        return value_to_bytes(data, byte_cnt=4, endianness=Endianness.LITTLE)
    except SPSDKError:
        pass
    # Try to handle as list or comma-separated values
    try:
        values = []
        if isinstance(data, list):
            # Handle data as list of integers or list of strings
            values = [value_to_int(item, 0) for item in data]
        elif isinstance(data, str) and "," in data:
            # Handle data as comma-separated string
            values = [value_to_int(s, 0) for s in data.split(",")]

        if values:
            return pack(f"<{len(values)}L", *values)
    except SPSDKError:
        pass

    # Try to load from file
    try:
        return load_binary(find_file(data, search_paths=config.search_paths))
    except SPSDKError as exc:
        raise SPSDKError(f"Cannot load the data for LOAD SBx.x command from {data}") from exc


class CmdLoad(CmdLoadBase):
    """Data to write follows the range header."""

    CMD_TAG = EnumCmdTag.LOAD

    def __init__(
        self, address: int, data: bytes, memory_id: int = 0, compress: bool = False
    ) -> None:
        """Constructor for command.

        :param address: Address for the load command
        :param data: Data to load
        :param memory_id: Memory ID
        """
        super().__init__(
            address=address,
            data=data,
            memory_id=memory_id,
            compress=compress,
        )

    @classmethod
    def load_from_config(cls, config: Config) -> list[Self]:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :return: Command object loaded from configuration.
        :raises SPSDKError: Invalid configuration field.
        """
        address = config.get_int("address", 0)
        memory_id = config.get_int("memoryId", 0)
        # We kept there the backward compatibility code to load obsolete keys: value/values/file
        data_bytes = load_cmd_data_from_cfg(config)

        compress = config.get_bool("compress", False)
        if not compress:
            return [cls(address=address, data=data_bytes, memory_id=memory_id)]

        sector_size = config.get_int("sectorSize", 8_192)
        if address % sector_size:
            raise SPSDKValueError(
                f"Address for load command must be aligned to sectorSize "
                f"({sector_size}) when using compression"
            )
        # TODO align data_bytes to sector_size and validate compression requirements?
        return [
            cls(
                address=address + i * sector_size,
                data=data_bytes[offset : offset + sector_size],
                memory_id=memory_id,
                compress=True,
            )
            for i, offset in enumerate(range(0, len(data_bytes), sector_size))
        ]

    def get_config_context(self, data_path: str = "./") -> Config:
        """Create configuration for the LOAD command.

        This method generates a configuration dictionary containing the command's properties
        and settings, including address, memory ID, and data representation.

        The LOAD command writes data to a specified memory address, which is essential for
        programming firmware, configuration parameters, or other data into device memory.

        :param data_path: Path to store any data files that might be created for large data
        :return: Configuration object with command-specific settings
        """
        config_dict: dict[str, Union[str, int]] = {
            "address": self.address,
            "memoryId": self.memory_id,
        }

        # Handle data based on its size
        data_len = len(self.data)

        if data_len == 4:
            # For 4 bytes data, use hex string
            value = int.from_bytes(self.data, byteorder="little")
            config_dict["data"] = f"0x{value:08X}"
        elif data_len <= 40 and data_len % 4 == 0:
            # For data <= 40 bytes in multiples of 4, use comma-separated hex values
            values = []
            for i in range(0, data_len, 4):
                value = int.from_bytes(self.data[i : i + 4], byteorder="little")
                values.append(f"0x{value:08X}")
            config_dict["data"] = ",".join(values)
        else:
            # For larger data, create a file
            file_name = f"load_data_{self.address:08x}.bin"
            file_path = os.path.join(data_path, file_name)
            write_file(self.data, file_path, mode="wb")
            config_dict["data"] = file_name

        return Config(config_dict)


class CmdExecute(BaseCmd):
    """Address will be the jump-to address."""

    CMD_TAG = EnumCmdTag.EXECUTE

    def __init__(self, address: int) -> None:
        """Constructor for Command.

        :param address: Input address
        """
        super().__init__(address=address, length=0)

    def __str__(self) -> str:
        """Get info of command."""
        return f"EXECUTE: Address=0x{self.address:08X}"

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :return: CmdExecute
        """
        address, _ = cls.header_parse(data=data)
        return cls(address=address)

    @classmethod
    def load_from_config(cls, config: Config) -> list[Self]:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :return: Command object loaded from configuration.
        """
        return [cls(address=config.get_int("address", 0))]

    def get_config_context(self, data_path: str = "./") -> Config:
        """Create configuration for the EXECUTE command.

        This method generates a configuration dictionary containing the command's properties
        and settings, including the address to jump to for execution.

        The EXECUTE command triggers execution at a specified address, which is typically
        used to start running code after it has been loaded into memory.

        :param data_path: Path to store any data files (not used for this command)
        :return: Configuration object with command-specific settings
        """
        config_dict = {"address": self.address}
        return Config(config_dict)


class CmdCall(BaseCmd):
    """Address will be the address to jump."""

    CMD_TAG = cmd_tag = EnumCmdTag.CALL

    def __init__(self, address: int) -> None:
        """Constructor for Command.

        :param address: Input address
        """
        super().__init__(address=address, length=0)

    def __str__(self) -> str:
        """Get info of command."""
        return f"CALL: Address=0x{self.address:08X}"

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :return: CmdCall
        """
        address, _ = cls.header_parse(data=data)
        return cls(address=address)

    @classmethod
    def load_from_config(cls, config: Config) -> list[Self]:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :return: Command object loaded from configuration.
        """
        return [cls(address=config.get_int("address", 0))]

    def get_config_context(self, data_path: str = "./") -> Config:
        """Create configuration for the CALL command.

        This method generates a configuration dictionary containing the command's properties
        and settings, including the address to call.

        The CALL command executes code at a specified address but unlike EXECUTE, it returns
        control to the bootloader after completion.

        :param data_path: Path to store any data files (not used for this command)
        :return: Configuration object with command-specific settings
        """
        config_dict = {"address": self.address}
        return Config(config_dict)


class CmdProgFuses(CmdLoadBase):
    """Address will be address of fuse register."""

    HAS_MEMORY_ID_BLOCK = False
    CMD_TAG = EnumCmdTag.PROGRAM_FUSES

    def __init__(self, address: int, data: bytes) -> None:
        """Constructor for Command.

        :param address: Input address
        :param data: Input data
        """
        super().__init__(address=address, data=data)
        self.length //= 4

    @classmethod
    def _extract_data_prog_fuses(cls, data: bytes) -> tuple[int, int, bytes, int, int]:
        tag, address, length, cmd = unpack_from(cls.FORMAT, data)
        length *= 4
        memory_id = 0
        if tag != cls.TAG:
            raise SPSDKError(f"Invalid TAG, expected: {cls.TAG}")
        offset = BaseCmd.SIZE
        if cls.HAS_MEMORY_ID_BLOCK:
            memory_id, pad0, pad1, pad2 = unpack_from("<4L", data)
            if pad0 != pad1 != pad2 != 0:
                raise SPSDKError("Invalid padding")
            offset += 16
        load_data = data[offset : offset + length]
        return address, length, load_data, cmd, memory_id

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :return: CmdProgFuses
        """
        address, _, data, _, _ = cls._extract_data_prog_fuses(data=data)
        return cls(address=address, data=data)

    @classmethod
    def load_from_config(cls, config: Config) -> list[Self]:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :return: Command object loaded from configuration.
        """
        address = config.get_int("address", 0)
        if isinstance(config["values"], int):
            fuses = [config["values"]]
        else:
            fuses = [value_to_int(fuse, 0) for fuse in config.get_str("values").split(",")]
        data = pack(f"<{len(fuses)}L", *fuses)
        return [cls(address=address, data=data)]

    def get_config_context(self, data_path: str = "./") -> Config:
        """Create configuration for the PROGRAM_FUSES command.

        This method generates a configuration dictionary containing the command's properties
        and settings, including the fuse register address and values to be programmed.

        Fuse values are represented as comma-separated hexadecimal or decimal values.

        :param data_path: Path to store any data files (not used for this command)
        :return: Configuration object with command-specific settings
        """
        config_dict: dict[str, Union[str, int]] = {"address": self.address}

        # Extract fuse values from data
        # For CmdProgFuses, data should be multiples of 4 bytes (32-bit values)
        fuse_values = []
        for i in range(0, len(self.data), 4):
            value = int.from_bytes(self.data[i : i + 4], byteorder="little")
            fuse_values.append(f"0x{value:08X}")

        # If there's only one value, store as a single value
        if len(fuse_values) == 1:
            config_dict["values"] = fuse_values[0]
        else:
            config_dict["values"] = ",".join(fuse_values)

        return Config(config_dict)


class CmdProgIfr(CmdLoadBase):
    """Address will be the address into the IFR region."""

    CMD_TAG = EnumCmdTag.PROGRAM_IFR
    HAS_MEMORY_ID_BLOCK = False

    def __init__(self, address: int, data: bytes) -> None:
        """Constructor for Command.

        :param address: Input address
        :param data: Input data as bytes array
        """
        super().__init__(address=address, data=data)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :return: CmdProgFuses
        """
        address, _, data, _, _, _, _, _ = cls._extract_data(data=data)
        return cls(address=address, data=data)

    @classmethod
    def load_from_config(cls, config: Config) -> list[Self]:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :return: Command object loaded from configuration.
        """
        address = config.get_int("address", 0)
        data = load_cmd_data_from_cfg(config)
        return [cls(address=address, data=data)]

    def get_config_context(self, data_path: str = "./") -> Config:
        """Create configuration for the PROGRAM_IFR command.

        This method generates a configuration dictionary containing the command's properties
        and settings, including the address into the IFR region and the data to be programmed.

        The IFR data is stored in a separate binary file for better management.

        :param data_path: Path where the IFR data file will be stored
        :return: Configuration object with command-specific settings
        """
        # Create base config with address
        config_dict: dict[str, Union[str, int]] = {"address": self.address}

        file_name = f"ifr_data_{self.address:08x}.bin"
        file_path = os.path.join(data_path, file_name)

        # Write IFR data to the file
        write_file(self.data, file_path, mode="wb")

        # Add file reference to configuration
        config_dict["file"] = file_name

        return Config(config_dict)


class CmdLoadCmac(CmdLoadBase):
    """Load cmac. ROM is calculating cmac from loaded data."""

    CMD_TAG = EnumCmdTag.LOAD_CMAC

    def __init__(self, address: int, data: bytes, memory_id: int = 0) -> None:
        """Constructor for command.

        :param address: Address for the load command
        :param data: Data to load
        :param memory_id: Memory ID
        """
        super().__init__(address=address, data=data, memory_id=memory_id)

    @classmethod
    def load_from_config(cls, config: Config) -> list[Self]:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :return: Command object loaded from configuration.
        :raises SPSDKError: Invalid configuration field.
        """
        address = config.get_int("address", 0)
        memory_id = config.get_int("memoryId", 0)
        data = load_binary(config.get_input_file_name("file"))
        return [cls(address=address, data=data, memory_id=memory_id)]

    def get_config_context(self, data_path: str = "./") -> Config:
        """Create configuration for the LOAD_CMAC command.

        This method generates a configuration dictionary containing the command's properties
        and settings, including address, memory ID, and CMAC data.

        The CMAC data is stored in a separate binary file for better management.

        :param data_path: Path where the CMAC data file will be stored
        :return: Configuration object with command-specific settings
        """
        # Create base config with address
        config_dict: dict[str, Union[str, int]] = {
            "address": self.address,
            "memoryId": self.memory_id,
        }

        file_name = f"load_cmac_data_{self.address:08x}.bin"
        file_path = os.path.join(data_path, file_name)

        # Write Load CMAC data to the file
        write_file(self.data, file_path, mode="wb")

        # Add file reference to configuration
        config_dict["file"] = file_name

        return Config(config_dict)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :return: Command instance
        :raises SPSDKError: Invalid cmd_tag was found
        """
        address, _, data, cmd_tag, memory_id, _, _, _ = cls._extract_data(data)
        cmd_tag_enum = EnumCmdTag.from_tag(cmd_tag)
        if cmd_tag_enum != cls.CMD_TAG:
            raise SPSDKError(f"Invalid cmd_tag found: {cmd_tag_enum}")

        return cls(address=address, data=data, memory_id=memory_id)


class CmdCopy(BaseCmd):
    """Copy data from one place to another."""

    CMD_TAG = EnumCmdTag.COPY

    def __init__(
        self,
        address: int,
        length: int,
        destination_address: int = 0,
        memory_id_from: int = 0,
        memory_id_to: int = 0,
    ) -> None:
        """Constructor for command.

        :param address: Input address
        :param length: Input length
        :param destination_address: Destination address
        :param memory_id_from: Memory ID
        :param memory_id_to: Memory ID
        """
        super().__init__(address=address, length=length)
        self.destination_address = destination_address
        self.memory_id_from = memory_id_from
        self.memory_id_to = memory_id_to

    def __str__(self) -> str:
        """Get info of command."""
        return (
            f"COPY: Address=0x{self.address:08X}, Length={self.length}, "
            f"Destination address={self.destination_address}"
            f"Memory ID from={self.memory_id_from}, Memory ID to={self.memory_id_to}"
        )

    def export(self) -> bytes:
        """Export command as bytes."""
        data = super().export()
        data += pack("<4L", self.destination_address, self.memory_id_from, self.memory_id_to, 0)
        return data

    @property
    def export_length(self) -> int:
        """Export length of command.

        :return: Length of command in bytes
        """
        return (
            super().export_length + 16
        )  # 16 bytes for base header + 16 bytes for additional COPY command fields

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :return: CmdCopy
        :raises SPSDKError: Invalid padding
        """
        address, length = cls.header_parse(data=data)
        destination_address, memory_id_from, memory_id_to, pad0 = unpack_from(
            "<4L", data, offset=16
        )
        if pad0 != 0:
            raise SPSDKError("Invalid padding")
        return cls(
            address=address,
            length=length,
            destination_address=destination_address,
            memory_id_from=memory_id_from,
            memory_id_to=memory_id_to,
        )

    @classmethod
    def load_from_config(cls, config: Config) -> list[Self]:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :return: Command object loaded from configuration.
        """
        address = config.get_int("addressFrom", 0)
        length = config.get_int("size", 0)
        destination_address = config.get_int("addressTo", 0)
        memory_id_from = config.get_int("memoryIdFrom", 0)
        memory_id_to = config.get_int("memoryIdTo", 0)
        return [
            cls(
                address=address,
                length=length,
                destination_address=destination_address,
                memory_id_from=memory_id_from,
                memory_id_to=memory_id_to,
            )
        ]

    def get_config_context(self, data_path: str = "./") -> Config:
        """Create configuration for the COPY command.

        This method generates a configuration dictionary containing the command's properties
        and settings, including source address, destination address, size, and memory IDs.

        The COPY command transfers data between different memory regions, which is useful
        for copying firmware or data from one memory location to another.

        :param data_path: Path to store any data files (not used for this command)
        :return: Configuration object with command-specific settings
        """
        config_dict = {
            "address": self.address,  # Source address
            "size": self.length,  # Amount of data to copy
            "addressTo": self.destination_address,  # Destination address
            "memoryIdFrom": self.memory_id_from,  # Source memory ID
            "memoryIdTo": self.memory_id_to,  # Destination memory ID
        }

        return Config(config_dict)


class CmdLoadHashLocking(CmdLoadBase):
    """Load hash. ROM is calculating hash."""

    CMD_TAG = EnumCmdTag.LOAD_HASH_LOCKING

    def __init__(self, address: int, data: bytes, memory_id: int = 0) -> None:
        """Constructor for command.

        :param address: Address for the load command
        :param data: Data to load
        :param memory_id: Memory ID
        """
        super().__init__(address=address, data=data, memory_id=memory_id)

    def export(self) -> bytes:
        """Export command as bytes."""
        data = super().export()
        data += bytes(64)
        return data

    @property
    def export_length(self) -> int:
        """Export length of command.

        :return: Length of command in bytes
        """
        return super().export_length + 64

    @classmethod
    def load_from_config(cls, config: Config) -> list[Self]:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :return: Command object loaded from configuration.
        :raises SPSDKError: Invalid configuration field.
        """
        address = config.get_int("address", 0)
        memory_id = config.get_int("memoryId", 0)
        data = load_binary(config.get_input_file_name("file"))
        return [cls(address=address, data=data, memory_id=memory_id)]

    def get_config_context(self, data_path: str = "./") -> Config:
        """Create configuration for the LOAD_HASH_LOCKING command.

        This method generates a configuration dictionary containing the command's properties
        and settings, including address, memory ID, and hash data.

        The hash data is stored in a separate binary file for better management.

        :param data_path: Path where the hash data file will be stored
        :return: Configuration object with command-specific settings
        """
        # Create base config with address and memory ID
        config_dict: dict[str, Union[str, int]] = {
            "address": self.address,
            "memoryId": self.memory_id,
        }

        # Create a file name for hash data
        file_name = f"hash_locking_data_{self.address:08x}.bin"
        file_path = os.path.join(data_path, file_name)

        # Write hash data to the file
        write_file(self.data, file_path, mode="wb")

        # Add file reference to configuration
        config_dict["file"] = file_name

        return Config(config_dict)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :return: Command instance
        :raises SPSDKError: Invalid cmd_tag was found
        """
        address, _, data, cmd_tag, memory_id, _, _, _ = cls._extract_data(data)
        cmd_tag_enum = EnumCmdTag.from_tag(cmd_tag)
        if cmd_tag_enum != cls.CMD_TAG:
            raise SPSDKError(f"Invalid cmd_tag found: {cmd_tag_enum}")

        return cls(address=address, data=data, memory_id=memory_id)


class CmdLoadKeyBlob(BaseCmd):
    """Load key blob."""

    CMD_TAG = EnumCmdTag.LOAD_KEY_BLOB

    FORMAT = "<L2H2L"

    class _KeyWraps(BuiltinEnum):
        """KeyWrap IDs used by the CmdLoadKeyBlob command."""

        NXP_CUST_KEK_INT_SK = 16
        NXP_CUST_KEK_EXT_SK = 17

    class _KeyWrapsV2(BuiltinEnum):
        """KeyWrap IDs used by the CmdLoadKeyBlob command."""

        NXP_CUST_KEK_INT_SK = 18
        NXP_CUST_KEK_EXT_SK = 19

    class KeyTypes(BuiltinEnum):
        """KeyTypes for NXP_CUST_KEK_INT_SK, NXP_CUST_KEK_EXT_SK."""

        NXP_CUST_KEK_INT_SK = 1
        NXP_CUST_KEK_EXT_SK = 2

    @classmethod
    def get_key_id(cls, family: FamilyRevision, key_name: KeyTypes) -> int:
        """Get key ID based on family and key name.

        :param family: chip family
        :param key_name: NXP_CUST_KEK_INT_SK or NXP_CUST_KEK_EXT_SK
        :return: integer value representing key
        """
        database = get_db(family)
        feature_name = [x for x in database.features.keys() if str(x).startswith("sb")][0]
        key_wraps_version = database.get_int(feature_name, "key_wraps_version")
        key_wraps = {1: cls._KeyWraps, 2: cls._KeyWrapsV2}.get(key_wraps_version)
        if key_wraps is None:
            raise SPSDKValueError(f"KeyWraps version {key_wraps_version} is not defined")
        return key_wraps[key_name.name].value

    def __init__(
        self, offset: int, data: bytes, key_wrap_id: int, plain_input: bool = False
    ) -> None:
        """Constructor for command.

        :param offset: Input offset
        :param key_wrap_id: Key wrap ID (NXP_CUST_KEK_INT_SK = 16, NXP_CUST_KEK_EXT_SK = 17)
        :param data: Wrapped key blob
        """
        super().__init__(address=offset, length=len(data))
        self.key_wrap_id = key_wrap_id
        self.data = data
        self.plain_input = plain_input

    def __str__(self) -> str:
        """Get info of command."""
        return f"LOAD_KEY_BLOB: Offset=0x{self.address:08X}, Length={self.length}, Key wrap ID={self.key_wrap_id}"

    @property
    def length(self) -> int:
        """Get data length."""
        return len(self.data)

    @length.setter
    def length(self, value: int) -> None:
        """Set data length."""
        raise SPSDKError(f"Length property for {self.__class__.__name__} is read-only")

    def export(self) -> bytes:
        """Export command as bytes."""
        result_data = pack(
            self.FORMAT,
            self.TAG,
            self.address,
            self.key_wrap_id,
            self.length,
            self.CMD_TAG.tag,
        )
        result_data += self.data

        result_data = align_block(data=result_data, alignment=16, padding=0)
        return result_data

    @property
    def export_length(self) -> int:
        """Calculate the total export length including the command header and data.

        This property returns the total size in bytes that the command will occupy
        when exported to binary format, including both the fixed-size command header
        and any variable-length data payload.

        :return: Total length in bytes of the exported command
        """
        # Calculate the total export length including the command header and data
        return align((calcsize(self.FORMAT) + len(self.data)), alignment=16)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :return: CmdLoadKeyBlob
        """
        _, cmpa_offset, key_wrap_id, length, _ = unpack_from(cls.FORMAT, data)
        key_blob_data = unpack_from(f"<{length}s", data, cls.SIZE)[0]
        return cls(offset=cmpa_offset, key_wrap_id=key_wrap_id, data=key_blob_data)

    @classmethod
    def load_from_config(cls, config: Config) -> list[Self]:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :return: Command object loaded from configuration.
        """
        offset = config.get_int("offset", 0)
        key_wrap_name = config["wrappingKeyId"]
        family = FamilyRevision.load_from_config(config)
        key_wrap_id = cls.get_key_id(family, cls.KeyTypes[key_wrap_name])
        plain_input = config.get_str("plainInput", "bin")

        if plain_input == "hex":
            hex_data = load_text(config.get_input_file_name("file"))
            data = bytes.fromhex(hex_data)
        else:
            data = load_binary(config.get_input_file_name("file"))

        return [
            cls(offset=offset, data=data, key_wrap_id=key_wrap_id, plain_input=plain_input != "no")
        ]

    def get_config_context(self, data_path: str = "./") -> Config:
        """Create configuration for the LOAD_KEY_BLOB command.

        This method generates a configuration dictionary containing the command's properties
        and settings, including offset, key wrap ID, and the key blob data.

        The key blob data is stored in a separate binary file for better management and security.

        :param data_path: Path where the key blob file will be stored
        :return: Configuration object with command-specific settings
        """
        # Find the key wrap type based on the ID
        key_wrap_type = None
        for key_type in self.KeyTypes:
            # Search through potential key wrap versions
            for key_wraps_class in [self._KeyWraps, self._KeyWrapsV2]:
                try:
                    if key_wraps_class[key_type.name].value == self.key_wrap_id:
                        key_wrap_type = key_type.name
                        break
                except (KeyError, AttributeError):
                    pass
            if key_wrap_type:
                break

        if not key_wrap_type:
            key_wrap_type = f"UNKNOWN_KEY_{self.key_wrap_id}"

        # Create base config with offset and wrapping key ID
        config_dict = {"offset": self.address, "wrappingKeyId": key_wrap_type}

        # Set plain input format type
        if hasattr(self, "plain_input") and self.plain_input:
            config_dict["plainInput"] = "hex"

        # Create a file name for the key blob
        file_name = f"key_blob_{self.address:08x}.bin"
        file_path = os.path.join(data_path, file_name)

        # Write key blob data to the file
        write_file(self.data, file_path, mode="wb")

        # Add file reference to configuration
        config_dict["file"] = file_name

        return Config(config_dict)


class CmdConfigureMemory(BaseCmd):
    """Configure memory."""

    CMD_TAG = EnumCmdTag.CONFIGURE_MEMORY

    def __init__(self, address: int, memory_id: int = 0) -> None:
        """Constructor for command.

        :param address: Input address
        :param memory_id: Memory ID
        """
        super().__init__(address=address, length=0)
        self.memory_id = memory_id

    def __str__(self) -> str:
        """Get info of command."""
        return f"CONFIGURE_MEMORY: Address=0x{self.address:08X}, Memory ID={self.memory_id}"

    def export(self) -> bytes:
        """Export command as bytes."""
        return pack(self.FORMAT, self.TAG, self.memory_id, self.address, self.CMD_TAG.tag)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :return: CmdConfigureMemory
        """
        memory_id, address = cls.header_parse(data=data)
        return cls(address=address, memory_id=memory_id)

    @classmethod
    def load_from_config(cls, config: Config) -> list[Self]:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :return: Command object loaded from configuration.
        """
        return [
            cls(address=config.get_int("configAddress", 0), memory_id=config.get_int("memoryId", 0))
        ]

    def get_config_context(self, data_path: str = "./") -> Config:
        """Create configuration for the CONFIGURE_MEMORY command.

        This method generates a configuration dictionary containing the command's properties
        and settings, including the memory configuration address and memory ID.

        The CONFIGURE_MEMORY command sets up memory parameters required before performing
        operations on the specified memory.

        :param data_path: Path to store any data files (not used for this command)
        :return: Configuration object with command-specific settings
        """
        config_dict = {"configAddress": self.address, "memoryId": self.memory_id}

        return Config(config_dict)


class CmdFillMemory(BaseCmd):
    """Fill memory range by pattern."""

    CMD_TAG = EnumCmdTag.FILL_MEMORY

    def __init__(self, address: int, length: int, pattern: int) -> None:
        """Constructor for command.

        :param address: Input address
        :param length: Input length
        :param pattern: Pattern for fill memory with
        """
        super().__init__(address=address, length=length)
        self.pattern = pattern

    def __str__(self) -> str:
        """Get info of command."""
        return f"FILL_MEMORY: Address=0x{self.address:08X}, Length={self.length}, PATTERN={hex(self.pattern)}"

    def export(self) -> bytes:
        """Export command as bytes."""
        data = super().export()
        data += pack("<4L", self.pattern, 0, 0, 0)
        return data

    @property
    def export_length(self) -> int:
        """Calculate the total export length including the command header and data.

        :return: Total length in bytes of the exported command
        """
        return super().export_length + 16

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :return: CmdErase
        :raises SPSDKError: Invalid padding
        """
        address, length = cls.header_parse(data=data)
        pattern, pad0, pad1, pad2 = unpack_from("<4L", data, offset=16)
        if pad0 != pad1 != pad2 != 0:
            raise SPSDKError("Invalid padding")
        return cls(address=address, length=length, pattern=pattern)

    @classmethod
    def load_from_config(cls, config: Config) -> list[Self]:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :return: Command object loaded from configuration.
        """
        address = config.get_int("address", 0)
        length = config.get_int("size", 0)
        pattern = config.get_int("pattern", 0)
        return [cls(address=address, length=length, pattern=pattern)]

    def get_config_context(self, data_path: str = "./") -> Config:
        """Create configuration for the FILL_MEMORY command.

        This method generates a configuration dictionary containing the command's properties
        and settings, including the starting address, size of the region to fill, and
        the pattern value to use for filling.

        The FILL_MEMORY command fills a specified memory region with a repeating pattern,
        which is useful for initializing memory areas or erasing sensitive data.

        :param data_path: Path to store any data files (not used for this command)
        :return: Configuration object with command-specific settings
        """
        config_dict = {"address": self.address, "size": self.length, "pattern": self.pattern}

        return Config(config_dict)


class CmdFwVersionCheck(BaseCmd):
    """Check counter value with stored value, if values are not same, SB file is rejected."""

    CMD_TAG = EnumCmdTag.FW_VERSION_CHECK

    class CounterID(SpsdkEnum):
        """Counter IDs used by the CmdFwVersionCheck command."""

        NONE = (0, "none")
        NONSECURE = (1, "nonsecure")
        SECURE = (2, "secure")
        RADIO = (3, "radio")
        SNT = (4, "snt")
        BOOTLOADER = (5, "bootloader")
        RADIO_IP = (7, "radio_ip")

    def __init__(self, value: int, counter_id: CounterID) -> None:
        """Constructor for command.

        :param value: Input value
        :param counter_id: Counter ID (NONSECURE = 1, SECURE = 2)
        """
        super().__init__(address=0, length=0)
        self.value = value
        self.counter_id = counter_id

    def __str__(self) -> str:
        """Get info of command."""
        return f"FW_VERSION_CHECK: Value={self.value}, Counter ID={self.counter_id}"

    def export(self) -> bytes:
        """Export command as bytes."""
        return pack(self.FORMAT, self.TAG, self.value, self.counter_id.tag, self.CMD_TAG.tag)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :return: CmdFwVersionCheck
        """
        value, counter_id = cls.header_parse(data=data)
        return cls(value=value, counter_id=cls.CounterID.from_tag(counter_id))

    @classmethod
    def load_from_config(cls, config: Config) -> list[Self]:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :return: Command object loaded from configuration.
        """
        value = value_to_int(config["value"], 0)
        counter_id = CmdFwVersionCheck.CounterID.from_label(config.get_str("counterId"))
        return [cls(value=value, counter_id=counter_id)]

    def get_config_context(self, data_path: str = "./") -> Config:
        """Create configuration for the FW_VERSION_CHECK command.

        This method generates a configuration dictionary containing the command's properties
        and settings, including the version value to check and the counter ID.

        The FW_VERSION_CHECK command verifies that the firmware version meets or exceeds
        the specified value for the given counter type. This prevents downgrade attacks
        or installation of incompatible firmware.

        Counter IDs include:
        - none (0): No counter
        - nonsecure (1): Non-secure firmware counter
        - secure (2): Secure firmware counter
        - radio (3): Radio firmware counter
        - snt (4): SNT firmware counter
        - bootloader (5): Bootloader firmware counter

        :param data_path: Path to store any data files (not used for this command)
        :return: Configuration object with command-specific settings
        """
        config_dict = {
            "value": f"0x{self.value:08X}",  # Format as hex string
            "counterId": self.counter_id.label,  # Use the label (name) of the counter
        }

        return Config(config_dict)


class CmdReset(BaseCmd):
    """Reset command, added for SBx."""

    CMD_TAG = EnumCmdTag.RESET

    def __init__(self) -> None:
        """Constructor for reset command."""
        super().__init__(address=0, length=0)

    def __str__(self) -> str:
        """Get info about command."""
        return "RESET"

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :return: CmdReset
        """
        _, _ = cls.header_parse(data=data)
        return cls()

    @classmethod
    def load_from_config(cls, config: Config) -> list[Self]:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :return: Command object loaded from configuration.
        """
        return [cls()]

    def get_config_context(self, data_path: str = "./") -> Config:
        """Create configuration for the RESET command.

        This method generates a minimal configuration dictionary as the RESET command
        doesn't require any specific parameters.

        The RESET command triggers a system reset of the device, which is useful for
        completing a programming sequence or to ensure the device starts from a clean state
        after applying configuration changes.

        :param data_path: Path to store any data files (not used for this command)
        :return: Configuration object with command-specific settings (empty for this command)
        """
        # Reset command doesn't need any parameters
        return Config({})


class CmdWriteIfr(BaseCmd):
    """Address will be the address into the IFR region."""

    CMD_TAG = EnumCmdTag.WRITE_IFR

    class WriteIfrType(BuiltinEnum):
        """Write IFR types."""

        CFPA = 0
        CFPA_AND_CMPA = 1

    def __init__(self, address: int, data: bytes, ifr_type: WriteIfrType) -> None:
        """Constructor for Command.

        :param address: Input address
        :param data: Input data as bytes array
        """
        super().__init__(address=address, length=len(data))
        self.ifr_type = ifr_type
        self.data = data

    def __str__(self) -> str:
        """Get info of command."""
        return (
            f"WRITE IFR: Address=0x{self.address:08X}, Length={self.length}, "
            f"Destination address={self.ifr_type.name}"
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :return: CmdWriteIfr
        :raises SPSDKError: Invalid padding
        """
        address, length = cls.header_parse(data=data)
        ifr_type, pad0, pad1, pad2 = unpack_from("<4L", data, offset=16)
        if pad0 != pad1 != pad2 != 0:
            raise SPSDKError("Invalid padding")
        offset = BaseCmd.SIZE + 16
        ifr_data = data[offset : offset + length]
        return cls(address=address, data=ifr_data, ifr_type=CmdWriteIfr.WriteIfrType(ifr_type))

    def export(self) -> bytes:
        """Export command as bytes."""
        data = super().export()
        data += pack("<4L", self.ifr_type.value, 0, 0, 0)
        data += self.data
        data = align_block(data, alignment=16)
        return data

    @classmethod
    def load_from_config(cls, config: Config) -> list[Self]:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :return: Command object loaded from configuration.
        """
        data = load_cmd_data_from_cfg(config)
        # address is always 0 as it point to the beginning of IFR region
        return [cls(address=0, data=data, ifr_type=CmdWriteIfr.WriteIfrType[config["type"]])]

    def get_config_context(self, data_path: str = "./") -> Config:
        """Create configuration for the WRITE_IFR command.

        This method generates a configuration dictionary containing the command's properties
        and settings, including the address into the IFR region and the data to be written.

        The IFR data is stored in a separate binary file for better management.

        :param data_path: Path where the IFR data file will be stored
        :return: Configuration object with command-specific settings
        """
        # Create base config with address
        config_dict: dict[str, Union[str, int]] = {
            "address": self.address,
            "type": self.ifr_type.name,
        }

        file_name = f"ifr_data_{self.address:08x}.bin"
        file_path = os.path.join(data_path, file_name)

        # Write IFR data to the file
        write_file(self.data, file_path, mode="wb")

        # Add file reference to configuration
        config_dict["file"] = file_name

        return Config(config_dict)


class CmdSectionHeader(BaseClass):
    """Create section header."""

    FORMAT = "<4L"
    SIZE = calcsize(FORMAT)

    # pylint: disable=super-init-not-called
    def __init__(self, length: int, section_uid: int = 1, section_type: int = 1) -> None:
        """Constructor for Commands section.

        :param section_uid: Input uid
        :param section_type: Input type
        :param length: Input length
        """
        self.section_uid = section_uid
        self.section_type = section_type
        self.length = length
        self._pad = 0

    def __repr__(self) -> str:
        return f"SB3.1 Command Section Header, Type:{self.section_type}"

    def __str__(self) -> str:
        """Get info of Section header."""
        return f"Section header: UID=0x{self.section_uid:08X}, Type={self.section_type}, Length={self.length}"

    def export(self) -> bytes:
        """Export command as bytes."""
        return pack(self.FORMAT, self.section_uid, self.section_type, self.length, self._pad)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :raises SPSDKError: Raised when FORMAT is bigger than length of the data without offset
        :return: CmdSectionHeader
        """
        if calcsize(cls.FORMAT) > len(data):
            raise SPSDKError("FORMAT is bigger than length of the data without offset!")
        section_uid, section_type, length, _ = unpack_from(cls.FORMAT, data)
        return cls(section_uid=section_uid, section_type=section_type, length=length)


TAG_TO_CLASS: Mapping[EnumCmdTag, Type[BaseCmd]] = {
    EnumCmdTag.ERASE: CmdErase,
    EnumCmdTag.LOAD: CmdLoad,
    EnumCmdTag.EXECUTE: CmdExecute,
    EnumCmdTag.CALL: CmdCall,
    EnumCmdTag.PROGRAM_FUSES: CmdProgFuses,
    EnumCmdTag.PROGRAM_IFR: CmdProgIfr,
    EnumCmdTag.LOAD_CMAC: CmdLoadCmac,
    EnumCmdTag.COPY: CmdCopy,
    EnumCmdTag.LOAD_HASH_LOCKING: CmdLoadHashLocking,
    EnumCmdTag.LOAD_KEY_BLOB: CmdLoadKeyBlob,
    EnumCmdTag.CONFIGURE_MEMORY: CmdConfigureMemory,
    EnumCmdTag.FILL_MEMORY: CmdFillMemory,
    EnumCmdTag.FW_VERSION_CHECK: CmdFwVersionCheck,
    EnumCmdTag.RESET: CmdReset,
    EnumCmdTag.WRITE_IFR: CmdWriteIfr,
}

CFG_NAME_TO_CLASS: Mapping[str, Type[BaseCmd]] = {
    "erase": CmdErase,
    "load": CmdLoad,
    "loadCompress": CmdLoad,
    "execute": CmdExecute,
    "call": CmdCall,
    "programFuses": CmdProgFuses,
    "programIFR": CmdProgIfr,
    "loadCMAC": CmdLoadCmac,
    "copy": CmdCopy,
    "loadHashLocking": CmdLoadHashLocking,
    "loadKeyBlob": CmdLoadKeyBlob,
    "configureMemory": CmdConfigureMemory,
    "fillMemory": CmdFillMemory,
    "checkFwVersion": CmdFwVersionCheck,
    "reset": CmdReset,
    "writeIFR": CmdWriteIfr,
}


########################################################################################################################
# Command parser from raw data
########################################################################################################################
def parse_command(data: bytes) -> object:
    """Parse command from bytes array.

    :param data: Input data as bytes array
    :raises SPSDKError: Raised when tag is not in cmd_class
    :raises SPSDKError: Raised when tag is invalid
    :return: object
    """
    #  verify that first 4 bytes of frame are 55aaaa55
    tag, _, _, cmd = unpack_from("<4L", data)
    if tag != BaseCmd.TAG:
        raise SPSDKError("Invalid tag.")
    enum_cmd_tag = EnumCmdTag.from_tag(cmd)
    if enum_cmd_tag not in TAG_TO_CLASS:
        raise SPSDKError(f"Invalid command tag: {cmd}")
    return TAG_TO_CLASS[enum_cmd_tag].parse(data)
