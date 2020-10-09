#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for creation commands."""

from struct import pack, unpack_from, calcsize
from typing import Mapping, Type, List

from spsdk.sbfile.sb31.constants import EnumCmdTag
from spsdk.sbfile.sb31.functions import BaseCmd, MainCmd
from spsdk.utils.misc import align_block


########################################################################################################################
# Commands Classes version 3.1
########################################################################################################################
class CmdErase(BaseCmd):
    """Erase given address range."""

    def __init__(self, address: int, length: int, memory_id: int = 0) -> None:
        """Constructor for command.

        :param address:Input address
        :param length: Input length
        :param memory_id: Memory ID
        """
        super().__init__(cmd_tag=EnumCmdTag.ERASE, address=address, length=length)
        self.memory_id = memory_id

    def info(self) -> str:
        """Get info of command."""
        return f"ERASE: Address=0x{self.address:08X}, Length={self.length}, Memory ID={self.memory_id}"

    def export(self) -> bytes:
        """Export command as bytes."""
        data = super().export()
        data += pack("<4L", self.memory_id, 0, 0, 0)
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdErase":
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :param offset: The offset of input data
        :return: CmdErase
        """
        address, length = cls.header_parse(data=data, offset=offset, cmd_tag=EnumCmdTag.ERASE)
        memory_id, pad0, pad1, pad2 = unpack_from("<4L", data, offset=offset+16)
        assert pad0 == pad1 == pad2 == 0
        return cls(address=address, length=length, memory_id=memory_id)


class CmdLoad(BaseCmd):
    """Data to write follows the range header."""

    def __init__(self, address: int, length: int, memory_id: int = 0) -> None:
        """Constructor for command.

        :param address:Input address
        :param length: Input length
        :param memory_id: Memory ID
        """
        super().__init__(cmd_tag=EnumCmdTag.LOAD, address=address, length=length)
        self.memory_id = memory_id

    def info(self) -> str:
        """Get info of command."""
        return f"LOAD: Address=0x{self.address:08X}, Length={self.length}, Memory ID={self.memory_id}"

    def export(self) -> bytes:
        """Export command as bytes."""
        data = super().export()
        data += pack("<4L", self.memory_id, 0, 0, 0)
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdLoad":
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :param offset: The offset of input data
        :return: CmdLoad
        """
        address, length = cls.header_parse(data=data, offset=offset, cmd_tag=EnumCmdTag.LOAD)
        memory_id, pad0, pad1, pad2 = unpack_from("<4L", data, offset=offset+16)
        assert pad0 == pad1 == pad2 == 0
        return cls(address=address, length=length, memory_id=memory_id)


class CmdExecute(BaseCmd):
    """Address will be the jump-to address."""

    def __init__(self, address: int) -> None:
        """Constructor for Command.

        :param address: Input address
        """
        super().__init__(cmd_tag=EnumCmdTag.EXECUTE, address=address, length=0)

    def info(self) -> str:
        """Get info of command."""
        return f"EXECUTE: Address=0x{self.address:08X}"

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdExecute":
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :param offset: The offset of input data
        :return: CmdExecute
        """
        address, _ = cls.header_parse(data=data, offset=offset, cmd_tag=EnumCmdTag.EXECUTE)
        return cls(address=address)


class CmdCall(BaseCmd):
    """Address will be the address to jump."""

    def __init__(self, address: int) -> None:
        """Constructor for Command.

        :param address: Input address
        """
        super().__init__(cmd_tag=EnumCmdTag.CALL, address=address, length=0)

    def info(self) -> str:
        """Get info of command."""
        return f"CALL: Address=0x{self.address:08X}"

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdCall":
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :param offset: The offset of input data
        :return: CmdCall
        """
        address, _ = cls.header_parse(data=data, offset=offset, cmd_tag=EnumCmdTag.CALL)
        return cls(address=address)


class CmdProgFuses(BaseCmd):
    """Address will be address of fuse register."""

    @property
    def data(self) -> List[int]:
        """Get data."""
        return self._data

    @data.setter
    def data(self, value: List[int]) -> None:
        """Set data."""
        assert isinstance(value, list)
        self._data = value
        self._length = len(self._data)

    def __init__(self, address: int, data: List[int]) -> None:
        """Constructor for Command.

        :param address: Input address
        :param data: Input values
        """
        super().__init__(cmd_tag=EnumCmdTag.PROGRAM_FUSES, address=address, length=len(data))
        self.data = data

    def info(self) -> str:
        """Get info of command."""
        return f"PROGRAM_FUSES: Address=0x{self.address:08X}, Values={self.data}"

    def export(self) -> bytes:
        """Export command as bytes."""
        data = super().export()
        for value in self.data:
            data += pack("<L", value)
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdProgFuses":
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :param offset: The offset of input data
        :return: CmdProgFuses
        """
        address, length = cls.header_parse(data=data, offset=offset, cmd_tag=EnumCmdTag.PROGRAM_FUSES)
        values = []
        for i in range(length):
            values.append(unpack_from("<L", data, offset + BaseCmd.SIZE + (i * 4))[0])
        return cls(address=address, data=values)


class CmdProgIfr(BaseCmd):
    """Address will be the address into the IFR region."""

    @property
    def data(self) -> bytes:
        """Get data."""
        return self._data

    @data.setter
    def data(self, value: bytes) -> None:
        """Set data."""
        assert isinstance(value, bytes)
        self._data = value
        self._length = len(self._data)

    def __init__(self, data: bytes, address: int) -> None:
        """Constructor for Command.

        :param address: Input address
        :param data: Input data as bytes array
        """
        super().__init__(cmd_tag=EnumCmdTag.PROGRAM_IFR, address=address, length=len(data))
        self.data = data

    def info(self) -> str:
        """Get info of command."""
        return f"PROGRAM_IFR: Address=0x{self.address:08X}, DataLen={len(self.data)}"

    def export(self) -> bytes:
        """Export command as bytes."""
        data = super().export()
        data += bytes(self.data)
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdProgIfr":
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :param offset: The offset of input data
        :return: CmdProgIfr
        """
        address, length = cls.header_parse(data=data, offset=offset, cmd_tag=EnumCmdTag.PROGRAM_IFR)
        offset += BaseCmd.SIZE
        load_data = data[offset: offset + length]
        return cls(address=address, data=load_data)


class CmdLoadCmac(BaseCmd):
    """Load cmac. ROM is calculating cmac from loaded data."""

    def __init__(self, address: int, length: int, memory_id: int = 0) -> None:
        """Constructor for command.

        :param address:Input address
        :param length: Input length
        :param memory_id: Memory ID
        """
        super().__init__(cmd_tag=EnumCmdTag.LOAD_CMAC, address=address, length=length)
        self.memory_id = memory_id

    def info(self) -> str:
        """Get info of command."""
        return f"LOAD_CMAC: Address=0x{self.address:08X}, Length={self.length}, Memory ID={self.memory_id}"

    def export(self) -> bytes:
        """Export command as bytes."""
        data = super().export()
        data += pack("<4L", self.memory_id, 0, 0, 0)
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdLoadCmac":
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :param offset: The offset of input data
        :return: CmdLoadCmac
        """
        address, length = cls.header_parse(data=data, offset=offset, cmd_tag=EnumCmdTag.LOAD_CMAC)
        memory_id, pad0, pad1, pad2 = unpack_from("<4L", data, offset=offset+16)
        assert pad0 == pad1 == pad2 == 0
        return cls(address=address, length=length, memory_id=memory_id)


class CmdCopy(BaseCmd):
    """Copy data from one place to another."""

    def __init__(self,
                 address: int,
                 length: int,
                 destination_address: int = 0,
                 memory_id_from: int = 0,
                 memory_id_to: int = 0
                 ) -> None:
        """Constructor for command.

        :param address:Input address
        :param length: Input length
        :param destination_address: Destination address
        :param memory_id_from: Memory ID
        :param memory_id_to: Memory ID
        """
        super().__init__(cmd_tag=EnumCmdTag.COPY, address=address, length=length)
        self.destination_address = destination_address
        self.memory_id_from = memory_id_from
        self.memory_id_to = memory_id_to

    def info(self) -> str:
        """Get info of command."""
        return f"COPY: Address=0x{self.address:08X}, Length={self.length}, " \
               f"Destination address={self.destination_address}" \
               f"Memory ID from={self.memory_id_from}, Memory ID to={self.memory_id_to}"

    def export(self) -> bytes:
        """Export command as bytes."""
        data = super().export()
        data += pack("<4L", self.destination_address, self.memory_id_from, self.memory_id_to, 0)
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdCopy":
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :param offset: The offset of input data
        :return: CmdCopy
        """
        address, length = cls.header_parse(data=data, offset=offset, cmd_tag=EnumCmdTag.COPY)
        destination_address, memory_id_from, memory_id_to, pad0 = unpack_from("<4L", data, offset=offset+16)
        assert pad0 == 0
        return cls(
            address=address, length=length, destination_address=destination_address,
            memory_id_from=memory_id_from, memory_id_to=memory_id_to
        )


class CmdLoadHashLocking(BaseCmd):
    """Load hash. ROM is calculating hash."""

    def __init__(self, address: int, length: int, memory_id: int = 0) -> None:
        """Constructor for command.

        :param address:Input address
        :param length: Input length
        :param memory_id: Memory ID
        """
        super().__init__(cmd_tag=EnumCmdTag.LOAD_HASH_LOCKING, address=address, length=length)
        self.memory_id = memory_id

    def info(self) -> str:
        """Get info of command."""
        return f"LOAD_HASH_LOCKING: Address=0x{self.address:08X}, Length={self.length}, Memory ID={self.memory_id}"

    def export(self) -> bytes:
        """Export command as bytes."""
        data = super().export()
        data += pack("<4L", self.memory_id, 0, 0, 0)
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdLoadHashLocking":
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :param offset: The offset of input data
        :return: CmdCopy
        """
        address, length = cls.header_parse(data=data, offset=offset, cmd_tag=EnumCmdTag.LOAD_HASH_LOCKING)
        memory_id, pad0, pad1, pad2 = unpack_from("<4L", data, offset=offset+16)
        assert pad0 == pad1 == pad2 == 0
        return cls(address=address, length=length, memory_id=memory_id)


class CmdLoadKeyBlob(BaseCmd):
    """Load key blob."""
    FORMAT = "<L2H2L"

    NXP_CUST_KEK_INT_SK = 16
    NXP_CUST_KEK_EXT_SK = 17

    def __init__(self, offset: int, key_wrap_id: int, data: bytes) -> None:
        """Constructor for command.

        :param offset: Input offset
        :param key_wrap_id: Key wrap ID (NXP_CUST_KEK_INT_SK = 16, NXP_CUST_KEK_EXT_SK = 17)
        :param data: Wrapped key blob
        """
        super().__init__(cmd_tag=EnumCmdTag.LOAD_KEY_BLOB, address=offset, length=len(data))
        self.key_wrap_id = key_wrap_id
        self.data = data

    def info(self) -> str:
        """Get info of command."""
        return f"LOAD_KEY_BLOB: Offset=0x{self.address:08X}, Length={self.length}, Key wrap ID={self.key_wrap_id}"

    def export(self) -> bytes:
        """Export command header as bytes array."""
        result_data = pack(self.FORMAT, self.TAG, self.address, self.key_wrap_id, self.length, self.cmd_tag)
        result_data += self.data

        result_data = align_block(data=result_data, alignment=16, padding=0)
        return result_data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdLoadKeyBlob":
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :param offset: The offset of input data
        :return: CmdLoadKeyBlob
        """
        tag, cmpa_offset, key_wrap_id, length, cmd = unpack_from(cls.FORMAT, data, offset)
        key_blob_data = unpack_from(f"<{length}s", data, offset+cls.SIZE)[0]
        return cls(offset=cmpa_offset, key_wrap_id=key_wrap_id, data=key_blob_data)


class CmdConfigureMemory(BaseCmd):
    """Configure memory."""

    def __init__(self, address: int, memory_id: int = 0) -> None:
        """Constructor for command.

        :param address: Input address
        :param memory_id: Memory ID
        """
        super().__init__(address=address, length=0, cmd_tag=EnumCmdTag.CONFIGURE_MEMORY)
        self.memory_id = memory_id

    def info(self) -> str:
        """Get info of command."""
        return f"CONFIGURE_MEMORY: Address=0x{self.address:08X}, Memory ID={self.memory_id}"

    def export(self) -> bytes:
        """Export command header as bytes array."""
        return pack(self.FORMAT, self.TAG, self.address, self.memory_id, self.cmd_tag)

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdConfigureMemory":
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :param offset: The offset of input data
        :return: CmdConfigureMemory
        """
        address, memory_id = cls.header_parse(
            cmd_tag=EnumCmdTag.CONFIGURE_MEMORY, data=data, offset=offset
        )
        return cls(address=address, memory_id=memory_id)


class CmdFillMemory(BaseCmd):
    """Fill memory range by pattern."""

    def __init__(self, address: int, length: int, memory_id: int = 0) -> None:
        """Constructor for command.

        :param address:Input address
        :param length: Input length
        :param memory_id: Memory ID
        """
        super().__init__(cmd_tag=EnumCmdTag.FILL_MEMORY, address=address, length=length)
        self.memory_id = memory_id

    def info(self) -> str:
        """Get info of command."""
        return f"FILL_MEMORY: Address=0x{self.address:08X}, Length={self.length}, Memory ID={self.memory_id}"

    def export(self) -> bytes:
        """Export command as bytes."""
        data = super().export()
        data += pack("<4L", self.memory_id, 0, 0, 0)
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdFillMemory":
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :param offset: The offset of input data
        :return: CmdErase
        """
        address, length = cls.header_parse(data=data, offset=offset, cmd_tag=EnumCmdTag.FILL_MEMORY)
        memory_id, pad0, pad1, pad2 = unpack_from("<4L", data, offset=offset + 16)
        assert pad0 == pad1 == pad2 == 0
        return cls(address=address, length=length, memory_id=memory_id)


class CmdFwVersionCheck(BaseCmd):
    """Check counter value with stored value, if values are not same, SB file is rejected."""

    NONSECURE = 1
    SECURE = 2

    def __init__(self, value: int, counter_id: int) -> None:
        """Constructor for command.

        :param value: Input value
        :param counter_id: Counter ID (NONSECURE = 1, SECURE = 2)
        """
        super().__init__(address=0, length=0, cmd_tag=EnumCmdTag.FW_VERSION_CHECK)
        self.value = value
        self.counter_id = counter_id

    def info(self) -> str:
        """Get info of command."""
        return f"FW_VERSION_CHECK: Value={self.value}, Counter ID={self.counter_id}"

    def export(self) -> bytes:
        """Export command header as bytes array."""
        return pack(self.FORMAT, self.TAG, self.value, self.counter_id, self.cmd_tag)

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdFwVersionCheck":
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :param offset: The offset of input data
        :return: CmdFwVersionCheck
        """
        value, counter_id = cls.header_parse(
            data=data, offset=offset, cmd_tag=EnumCmdTag.FW_VERSION_CHECK
        )
        return cls(value=value, counter_id=counter_id)


class CmdSectionHeader(MainCmd):
    """Create section header."""
    FORMAT = "<4L"
    SIZE = calcsize(FORMAT)

    def __init__(self, section_uid: int = 0, section_type: int = 0, length: int = 0) -> None:
        """Constructor for Commands section.

        :param section_uid: Input uid
        :param section_type: Input type
        :param length: Input length
        """
        self.section_uid = section_uid
        self.section_type = section_type
        self.length = length
        self._pad = 0

    def info(self) -> str:
        """Get info of Section header."""
        return f"Section header: UID=0x{self.section_uid:08X}, Type={self.section_type}, Length={self.length}"

    def export(self) -> bytes:
        """Export command as bytes."""
        return pack(self.FORMAT, self.section_uid, self.section_type, self.length, self._pad)

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "CmdSectionHeader":
        """Parse command from bytes array.

        :param data: Input data as bytes array
        :param offset: The offset of input data
        :raises ValueError: Raise when FORMAT is bigger than length of the data without offset
        :return: CmdSectionHeader
        """
        if calcsize(cls.FORMAT) > len(data) - offset:
            raise ValueError("FORMAT is bigger than length of the data without offset!")
        obj = cls()
        (obj.section_uid, obj.section_type, obj.length, obj._pad) = unpack_from(cls.FORMAT, data, offset)
        return obj


########################################################################################################################
# Command parser from raw data
########################################################################################################################
def parse_command(data: bytes, offset: int = 0) -> object:
    """Parse command from bytes array.

    :param data: Input data as bytes array
    :param offset: The offset of input data
    :raises ValueError: Raise when tag is not in cmd_class
    :return: object
    """
    cmd_class: Mapping[int, Type[BaseCmd]] = {
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
        EnumCmdTag.FW_VERSION_CHECK: CmdFwVersionCheck
    }
    #  verify that first 4 bytes of frame are 55aaaa55
    tag = unpack_from("<L", data, offset=offset)[0]
    assert tag == BaseCmd.TAG, "Invalid tag."
    cmd_tag = unpack_from("<L", data, offset=offset + 12)[0]
    if cmd_tag not in cmd_class:
        raise ValueError(f"Invalid command tag: {cmd_tag}")
    return cmd_class[cmd_tag].parse(data, offset)
