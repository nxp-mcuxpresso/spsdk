#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Commands for image module."""

from abc import ABC
from datetime import datetime
from struct import pack, unpack_from
from typing import Iterable, List, Optional, Tuple, Union, Any, Iterator, Mapping, Type

from asn1crypto import cms, util, x509

from spsdk.crypto import Certificate, Encoding
from spsdk.utils.crypto import matches_key_and_cert, crypto_backend
from spsdk.utils.easy_enum import Enum
from spsdk.utils.misc import DebugInfo
from .header import CmdTag, CmdHeader
from .secret import BaseClass, CertificateImg, EnumAlgorithm, MAC, Signature, SrkTable


########################################################################################################################
# Enums
########################################################################################################################

class EnumWriteOps(Enum):
    """Enum definition for 'flags' control flags in 'par' parameter of Write Data command."""
    WRITE_VALUE = (0, 'Write value')
    WRITE_CLEAR_BITS = (1, 'Write clear bits')
    CLEAR_BITMASK = (2, 'Clear bitmask')
    SET_BITMASK = (3, 'Set bitmask')


class EnumCheckOps(Enum):
    """Enum definition for 'par' parameter of Check Data command."""
    ALL_CLEAR = (0, 'All bits clear')
    ALL_SET = (1, 'All bits set')
    ANY_CLEAR = (2, 'Any bit clear')
    ANY_SET = (3, 'Any bit set')


class EnumCertFormat(Enum):
    """Certificate format tags."""
    SRK = (0x03, 'SRK certificate format')
    X509 = (0x09, 'X.509v3 certificate format')
    CMS = (0xC5, 'CMS/PKCS#7 signature format')
    BLOB = (0xBB, 'SHW-specific wrapped key format')
    AEAD = (0xA3, 'Proprietary AEAD MAC format')


class EnumInsKey(Enum):
    """Flags for Install Key commands."""
    CLR = (0, 'No flags set')
    ABS = (1, 'Absolute certificate address')
    CSF = (2, 'Install CSF key')
    DAT = (4, 'Key binds to Data Type')
    CFG = (8, 'Key binds to Configuration')
    FID = (16, 'Key binds to Fabrication UID')
    MID = (32, 'Key binds to Manufacturing ID')
    CID = (64, 'Key binds to Caller ID')
    HSH = (128, 'Certificate hash present')


class EnumAuthDat(Enum):
    """Flags for Authenticate Data commands."""
    CLR = (0, 'No flags set')
    ABS = (1, 'Absolute signature address')


class EnumEngine(Enum):
    """Engine plugin tags."""
    ANY = (0x00, 'First compatible engine will be selected (no engine configuration parameters are allowed)')
    SCC = (0x03, 'Security controller')
    RTIC = (0x05, 'Run-time integrity checker')
    SAHARA = (0x06, 'Crypto accelerator')
    CSU = (0x0A, 'Central Security Unit')
    SRTC = (0x0C, 'Secure clock')
    DCP = (0x1B, 'Data Co-Processor')
    CAAM = (0x1D, 'Cryptographic Acceleration and Assurance Module')
    SNVS = (0x1E, 'Secure Non-Volatile Storage')
    OCOTP = (0x21, 'Fuse controller')
    DTCP = (0x22, 'DTCP co-processor')
    ROM = (0x36, 'Protected ROM area')
    HDCP = (0x24, 'HDCP co-processor')
    SW = (0xFF, 'Software engine')


class EnumCAAM(Enum):
    """CAAM Engine Configuration."""
    DEFAULT = 0x00
    IN_SWAP8 = 0x01
    IN_SWAP16 = 0x02
    OUT_SWAP8 = 0x08
    OUT_SWAP16 = 0x10
    DSC_SWAP8 = 0x40
    DSC_SWAP16 = 0x80


class EnumItm(Enum):
    """Engine configuration flags of Set command."""
    MID = (0x01, 'Manufacturing ID (MID) fuse locations')
    ENG = (0x03, 'Preferred engine for a given algorithm')


########################################################################################################################
# Abstract Class
########################################################################################################################

class CmdBase:
    """Base class for all commands."""

    def __init__(self, tag: CmdTag, param: int, length: Optional[int] = None):
        """Constructor.

        :param tag: command tag
        :param param: TODO
        :param length: of the binary command representation, in bytes
        """
        self._header = CmdHeader(tag, param, length)

    @property
    def size(self) -> int:
        """Size of command."""
        return self._header.length

    @property
    def tag(self) -> CmdTag:
        """Command tag."""
        return self._header.tag

    @property
    def needs_cmd_data_reference(self) -> bool:
        """Whether the command needs a reference to an additional data.

        If returns True, the following methods must be implemented:
        - cmd_data_offset
        - cmd_data_reference
        """
        return False  # default implementation

    @property
    def cmd_data_offset(self) -> int:
        """Offset of an additional data (such as certificate, signature, etc) in binary image."""
        return 0

    @cmd_data_offset.setter
    def cmd_data_offset(self, value: int) -> None:
        """Setter.

        :param value: offset to set
        :raises TypeError: if cmd-data not supported by the command
        """
        raise TypeError('cmd-data not supported by the command')

    @property
    def cmd_data_reference(self) -> Optional[BaseClass]:
        """Reference to a command data (such as certificate, signature, etc).

        None if no reference was assigned;
        Value type is command-specific
        """
        return None

    @cmd_data_reference.setter
    def cmd_data_reference(self, value: BaseClass) -> None:
        """Setter.

        By default, the command does not support cmd_data_reference
        Note: the method must be implemented in `self.has_cmd_data_reference` returns True

        :param value: to be set
        :raise TypeError: if reference not supported by the command
        """
        raise TypeError('cmd-data not supported by the command')

    def parse_cmd_data(self, data: bytes, offset: int) -> Any:
        """Parse additional command data from binary data.

        :param data: to be parsed
        :param offset: start position in data to parse
        :raises TypeError: if cmd_data is not supported by the command
        """
        raise TypeError('cmd-data not supported by the command')

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, self.__class__) and vars(other) == vars(self)

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def info(self) -> str:
        """Text representation of the command."""
        return f'Command "{CmdTag.desc(self.tag)}"   [Tag={str(self.tag)}, length={str(self.size)}]\n'

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export to binary form (serialization).

        :param dbg_info: debug information about exported data
        :return: binary representation of the command
        """
        hdr_data = self._header.export()
        dbg_info.append_binary_data('header', hdr_data)
        return hdr_data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> 'CmdBase':
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :param offset: current position to readd from data
        :return: parse command
        """
        raise NotImplementedError()


########################################################################################################################
# HAB Commands
########################################################################################################################

class CmdWriteData(CmdBase):
    """Write data command."""

    @property
    def num_bytes(self) -> int:
        """Number of bytes being written by the command."""
        return self._header.param & 0x7

    @num_bytes.setter
    def num_bytes(self, value: int) -> None:
        """Setter.

        :param value: number of bytes being written by the command
        """
        assert value in (1, 2, 4)
        self._header.param &= ~0x7
        self._header.param |= value

    @property
    def ops(self) -> int:
        """Type of write operation."""
        return (self._header.param >> 3) & 0x3

    @ops.setter
    def ops(self, value: int) -> None:
        assert value in EnumWriteOps
        self._header.param &= ~(0x3 << 3)
        self._header.param |= int(value) << 3

    def __init__(self, numbytes: int = 4, ops: int = EnumWriteOps.WRITE_VALUE,
                 data: Iterable[Tuple[int, int]] = None) -> None:
        """Initialize Write Data command.

        :param numbytes: number of bytes. Must be value: 1, 2 or 4
        :param ops: type of write operation
        :param data: list of tuples: address and value
        """
        assert numbytes in (1, 2, 4)
        assert ops in EnumWriteOps
        super().__init__(CmdTag.WRT_DAT, ((int(ops) & 0x3) << 3) | (numbytes & 0x7))
        self._data: List[List[int]] = []
        if data is not None:
            assert isinstance(data, (list, tuple))
            for address, value in data:
                self.append(address, value)

    def __repr__(self) -> str:
        return f"CmdWriteData <{EnumWriteOps.name(self.ops)}/{self.num_bytes}, {len(self._data)}>"

    def __len__(self) -> int:
        return len(self._data)

    def __getitem__(self, key: int) -> List[int]:
        return self._data[key]

    def __setitem__(self, key: int, value: List[int]) -> None:
        self._data[key] = value

    def __iter__(self) -> Iterator[List[int]]:
        return self._data.__iter__()

    def info(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().info()
        msg += "Write Data Command (Ops: {0:s}, Bytes: {1:d})\n".format(EnumWriteOps.name(self.ops),
                                                                        self.num_bytes)
        for cmd in self._data:
            msg += "- Address: 0x{0:08X}, Value: 0x{1:08X}\n".format(cmd[0], cmd[1])
        msg += "-" * 60 + "\n"
        return msg

    def append(self, address: int, value: int) -> None:
        """Append of Write data command."""
        assert 0 <= address <= 0xFFFFFFFF, "address out of range"
        assert 0 <= value <= 0xFFFFFFFF, "value out of range"
        self._data.append([address, value])
        self._header.length += 8

    def pop(self, index: int) -> List[int]:
        """Pop of Write data command."""
        assert 0 <= index < len(self._data)
        cmd = self._data.pop(index)
        self._header.length -= 8
        return cmd

    def clear(self) -> None:
        """Clear of Write data command."""
        self._data.clear()
        self._header.length = self._header.size

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export to binary form (serialization).

        :param dbg_info: debug information about exported data
        :return: binary representation of the command
        """
        raw_data = super().export(dbg_info=dbg_info)
        for cmd in self._data:
            raw_data += pack(">LL", cmd[0], cmd[1])
        return raw_data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> 'CmdWriteData':
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :param offset: current position to readd from data
        :return: parse command
        """
        header = CmdHeader.parse(data, offset=offset, required_tag=CmdTag.WRT_DAT)
        obj = cls(header.param & 0x7, (header.param >> 3) & 0x3)
        index = header.size
        while index < header.length:
            (address, value) = unpack_from(">LL", data, offset + index)
            obj.append(address, value)
            index += 8
        return obj


class CmdCheckData(CmdBase):
    """Check data command."""

    @property
    def num_bytes(self) -> int:
        """Number of bytes."""
        return self._header.param & 0x7

    @num_bytes.setter
    def num_bytes(self, value: int) -> None:
        assert value in (1, 2, 4)
        self._header.param &= ~0x7
        self._header.param |= int(value)

    @property
    def ops(self) -> int:
        """Operation of Check data command."""
        return (self._header.param >> 3) & 0x3

    @ops.setter
    def ops(self, value: int) -> None:
        assert value in EnumCheckOps
        self._header.param &= ~(0x3 << 3)
        self._header.param |= int(value) << 3

    def __init__(self, numbytes: int = 4, ops: int = EnumCheckOps.ALL_SET, address: int = 0, mask: int = 0,
                 count: Optional[int] = None) -> None:
        """Initialize the check data command.

        :param numbytes: number of bytes
        :param ops: type of  operation
        :param address: list of tuples: address and value
        :param mask: mask value
        :param count: count value
        """
        assert numbytes in (1, 2, 4)
        assert ops in EnumCheckOps
        super().__init__(CmdTag.CHK_DAT, ((int(ops) & 0x3) << 3) | (numbytes & 0x7))
        self.address = address
        self.mask = mask
        self.count = count
        # the length of 'address'(4B), 'mask'(4B) and count(0 or 4B)  need to be added into Header.length
        self._header.length += 4 + 4 + (4 if count else 0)

    def __repr__(self) -> str:
        return "CmdCheckData <{}/{}, ADDR=0x{:X}, MASK=0x{:X}>".format(EnumCheckOps[self.ops],  # type: ignore
                                                                       self.num_bytes, self.address, self.mask)

    def info(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().info()
        msg += "Check Data Command (Ops: {0:s}, Bytes: {1:d})\n".format(EnumCheckOps[self.ops],  # type: ignore
                                                                        self.num_bytes)
        msg += "- Address: 0x{0:08X}, Mask: 0x{1:08X}".format(self.address, self.mask)
        if self.count:
            msg += ", Count: {0:d}".format(self.count)
        msg += "\n"
        msg += "-" * 60 + "\n"
        return msg

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export to binary form (serialization).

        :param dbg_info: debug information about exported data
        :return: binary representation of the command
        """
        raw_data = super().export(dbg_info=dbg_info)
        raw_data += pack(">LL", self.address, self.mask)
        if self.count is not None:
            raw_data += pack(">L", self.count)
        return raw_data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> 'CmdCheckData':
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :param offset: current position to readd from data
        :return: parse command
        """
        header = CmdHeader.parse(data, offset, CmdTag.CHK_DAT)
        numbytes = header.param & 0x7
        ops = (header.param >> 3) & 0x3
        address, mask = unpack_from(">LL", data, offset + header.size)
        count = None
        if (header.length - header.size) > 8:
            count = unpack_from(">L", data, offset + header.size + 8)[0]
        return cls(numbytes, ops, address, mask, count)


class CmdNop(CmdBase):
    """Nop command."""

    def __init__(self, param: int = 0):
        """Initialize the nop command."""
        super().__init__(CmdTag.NOP, param)

    def __repr__(self) -> str:
        return "CmdNop"

    def __eq__(self, cmd: Any) -> bool:
        if not isinstance(cmd, CmdNop):
            return False
        return True

    def info(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().info()
        msg += "-" * 60 + "\n"
        return msg

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> 'CmdNop':
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :param offset: current position to readd from data
        :return: parse command
        """
        header = CmdHeader.parse(data, offset, CmdTag.NOP)
        if header.length != header.size:
            pass
        return cls(header.param)


class CmdSet(CmdBase):
    """Set command."""

    @property
    def itm(self) -> int:
        """Item of Set command."""
        return self._header.param

    @itm.setter
    def itm(self, value: EnumItm) -> None:
        assert value in EnumItm
        self._header.param = value

    @property
    def hash_algorithm(self) -> EnumAlgorithm:
        """Type of hash algorithm."""
        return self._hash_alg

    @hash_algorithm.setter
    def hash_algorithm(self, value: EnumAlgorithm) -> None:
        assert value in EnumAlgorithm
        self._hash_alg = value

    @property
    def engine(self) -> EnumEngine:
        """Engine plugin tags."""
        return self._engine

    @engine.setter
    def engine(self, value: EnumEngine) -> None:
        assert value in EnumEngine
        self._engine = value

    def __init__(self, itm: EnumItm = EnumItm.ENG, hash_alg: EnumAlgorithm = EnumAlgorithm.ANY,
                 engine: EnumEngine = EnumEngine.ANY, engine_cfg: int = 0):
        """Initialize the set command."""
        assert itm in EnumItm
        super().__init__(CmdTag.SET, itm)
        self.hash_algorithm: EnumAlgorithm = hash_alg
        self.engine = engine
        self.engine_cfg = engine_cfg
        self._header.length = CmdHeader.SIZE + 4

    def __repr__(self) -> str:
        return "CmdSet <{}, {}, {}, eng_cfg=0x{:X}>".format(
            EnumItm.name(self.itm), EnumAlgorithm.name(self.hash_algorithm), EnumEngine.name(self.engine),
            self.engine_cfg
        )

    def info(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().info()
        msg += "Set Command ITM : {EnumItm.name(self.itm)}\n"
        msg += f"HASH Algo      : {self.hash_algorithm} ({EnumAlgorithm.desc(self.hash_algorithm)})\n"
        msg += f"Engine         : {self.engine} ({EnumEngine.desc(self.engine)})\n"
        msg += f"Engine Conf    : {hex(self.engine_cfg)})\n"
        msg += "-" * 60 + "\n"
        return msg

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export to binary form (serialization).

        :param dbg_info: debug information about exported data
        :return: binary representation of the command
        """
        raw_data = super().export(dbg_info=dbg_info)
        raw_data += pack("4B", 0x00, self.hash_algorithm, self.engine, self.engine_cfg)
        dbg_info.append_binary_data('data', raw_data)
        return raw_data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> 'CmdSet':
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :param offset: current position to readd from data
        :return: parse command
        """
        header = CmdHeader.parse(data, offset, CmdTag.SET)
        (_, alg, eng, cfg) = unpack_from("4B", data, offset + CmdHeader.SIZE)
        return CmdSet(EnumItm.from_int(header.param), EnumAlgorithm.from_int(alg), EnumEngine.from_int(eng), cfg)


class CmdInitialize(CmdBase):
    """Initialize command."""

    @property
    def engine(self) -> int:
        """Engine."""
        return self._header.param

    @engine.setter
    def engine(self, value: EnumEngine) -> None:
        assert value in EnumEngine
        self._header.param = value

    def __init__(self, engine: int = EnumEngine.ANY, data: List[int] = None) -> None:
        """Initialize the initialize command."""
        assert engine in EnumEngine
        super().__init__(CmdTag.INIT, engine)
        self._data = data if data else []

    def __repr__(self) -> str:
        return "CmdInitialize <{}, {}>".format(EnumEngine[self.engine], len(self._data))  # type: ignore

    def __len__(self) -> int:
        return len(self._data)

    def __getitem__(self, key: int) -> int:
        return self._data[key]

    def __setitem__(self, key: int, value: int) -> None:
        self._data[key] = value

    def __iter__(self) -> Iterator[int]:
        return self._data.__iter__()

    def info(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().info()
        msg += "Initialize Command (Engine: {0:s})\n".format(EnumEngine[self.engine])  # type: ignore
        cnt = 0
        for val in self._data:
            msg += " {0:02d}) Value: 0x{1:08X}\n".format(cnt, val)
            cnt += 1
        msg += "-" * 60 + "\n"
        return msg

    def append(self, value: int) -> None:
        """Appending of Initialize command."""
        assert isinstance(value, int), "value must be INT type"
        assert 0 <= value < 0xFFFFFFFF, "value out of range"
        self._data.append(value)
        self._header.length += 4

    def pop(self, index: int) -> int:
        """Pop of Initialize command."""
        assert 0 <= index < len(self._data)
        val = self._data.pop(index)
        self._header.length -= 4
        return val

    def clear(self) -> None:
        """Clear of Initialize command."""
        self._data.clear()
        self._header.length = self._header.size

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export to binary form (serialization).

        :param dbg_info: debug information about exported data
        :return: binary representation of the command
        """
        raw_data = super().export(dbg_info=dbg_info)
        for val in self._data:
            raw_data += pack(">L", val)
        return raw_data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> 'CmdInitialize':
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :param offset: current position to readd from data
        :return: parse command
        """
        header = CmdHeader.parse(data, offset, CmdTag.INIT)
        obj = cls(EnumEngine.from_int(header.param))
        index = header.size
        while index < header.length:
            assert (offset + index) < len(data)
            val = unpack_from(">L", data, offset + index)
            obj.append(val[0])
            index += 4
        return obj


class CmdUnlockAbstract(CmdBase, ABC):
    """Abstract unlock engine command; the command depends on engine type."""

    def __init__(self, engine: EnumEngine = EnumEngine.ANY, features: int = 0):
        """Constructor.

        :param engine: to be unlocked
        :param features: engine specific features
        """
        super().__init__(CmdTag.UNLK, EnumEngine.from_int(engine))
        self.features = features
        self._header.length = CmdHeader.SIZE + 4

    @property
    def engine(self) -> EnumEngine:
        """Engine to be unlocked.

        The term `engine` denotes a peripheral involved in one or more of the following functions:
        - cryptographic computation
        - security state management
        - security alarm handling
        - access control
        """
        return EnumEngine.from_int(self._header.param)

    def info(self) -> str:
        """Text description of the command."""
        msg = super().info()
        msg += "Unlock Command\n"
        msg += f"Engine : {EnumEngine.desc(self.engine)}\n"
        return msg

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> CmdBase:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :param offset: current position to readd from data
        :return: Unlock command
        """
        header = CmdHeader.parse(data, offset, CmdTag.UNLK)
        features = unpack_from(">L", data, offset + header.size)[0]
        engine = EnumEngine.from_int(header.param)

        if engine == EnumEngine.SNVS:
            obj: CmdUnlockAbstract = CmdUnlockSNVS(features)
        else:
            # The UID parameter is present only for OCOTP engine
            # while the 'Leave LP SW reset unlocked.' feature is being used
            parse_uid = header.param == EnumEngine.OCOTP and features == 0x1
            uid = unpack_from(">Q", data, offset + header.size + 4)[0] if parse_uid else 0
            obj = CmdUnlock(engine, features, uid)
        return obj


class CmdUnlockSNVS(CmdUnlockAbstract):
    """Command Unlock Secure Non-Volatile Storage (SNVS) Engine."""

    # mask unlock LP_SWR
    FEATURE_UNLOCK_LP_SWR = 1
    # mask unlock ZMK_WRITE
    FEATURE_UNLOCK_ZMK_WRITE = 2

    def __init__(self, features: int = 0) -> None:
        """Constructor.

        :param features: mask of FEATURE_UNLOCK_* constants
        """
        super().__init__(EnumEngine.SNVS, features)

    @property
    def unlock_lp_swr(self) -> bool:
        """Leave LP SW reset unlocked."""
        return self.features & CmdUnlockSNVS.FEATURE_UNLOCK_LP_SWR != 0

    @property
    def unlock_zmk_write(self) -> bool:
        """Leave Zero is able Master Key write unlocked."""
        return self.features & CmdUnlockSNVS.FEATURE_UNLOCK_ZMK_WRITE != 0

    def info(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().info()
        msg += f"Unlock LP SWR    : {self.unlock_lp_swr}\n"
        msg += f"Unlock ZMK Write : {self.unlock_zmk_write}\n"
        msg += "-" * 60 + "\n"
        return msg

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export to binary form (serialization).

        :param dbg_info: debug information about exported data
        :return: binary representation of the command
        """
        assert self.size == CmdHeader.SIZE + 4
        raw_data = super().export(dbg_info=dbg_info)
        data = pack(">L", self.features)
        dbg_info.append_binary_data('data', data)
        raw_data += data
        return raw_data


class CmdUnlock(CmdUnlockAbstract):
    """Generic unlock engine command."""

    def __init__(self, engine: EnumEngine = EnumEngine.ANY, features: int = 0, uid: int = 0):
        """Constructor.

        :param engine: to be unlocked
        :param features: TODO
        :param uid: TODO
        """
        super().__init__(engine, features)
        self.uid = uid
        self._header.length = CmdHeader.SIZE + 12

    def __repr__(self) -> str:
        return "CmdUnlock <{}, {}, {}>".format(
            EnumEngine.desc(self.engine), self.features, self.uid
        )

    def __iter__(self) -> Iterator[int]:
        return self.__iter__()

    def info(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().info()
        msg += "Features: {})\n".format(self.features)
        msg += "UID:      {})\n".format(self.uid)
        msg += "-" * 60 + "\n"
        return msg

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export to binary form (serialization).

        :param dbg_info: debug information about exported data
        :return: binary representation of the command
        """
        self._header.length = self.size
        raw_data = super().export(dbg_info=dbg_info)
        raw_data += pack(">LQ", self.features, self.uid)
        return raw_data


class CmdInstallKey(CmdBase):
    """Install key command."""

    def __init__(self, flags: EnumInsKey = EnumInsKey.CLR, cert_fmt: EnumCertFormat = EnumCertFormat.SRK,
                 hash_alg: EnumAlgorithm = EnumAlgorithm.ANY, src_index: int = 0, tgt_index: int = 0,
                 location: int = 0) -> None:
        """Constructor.

        :param flags: from EnumInsKey
        :param cert_fmt: format of the certificate; key authentication protocol
        :param hash_alg: hash algorithm
        :param src_index: source key (verification key, KEK) index
        :param tgt_index: target key index
        :param location: start address of an additional data such as KEY to be installed;
                Typically it is relative to CSF start; Might be absolute for DEK key
        """
        super().__init__(CmdTag.INS_KEY, flags)
        self._cert_fmt: EnumCertFormat = cert_fmt
        self.hash_algorithm: EnumAlgorithm = hash_alg
        self.source_index = src_index
        self.target_index = tgt_index
        self.cmd_data_location = location
        self._header.length = CmdHeader.SIZE + 8
        self._certificate_ref: Optional[Union[CertificateImg, SrkTable]] = None

    @property
    def flags(self) -> EnumInsKey:
        """Flags."""
        return EnumInsKey.from_int(self._header.param)

    @flags.setter
    def flags(self, value: EnumInsKey) -> None:
        assert value in EnumInsKey
        self._header.param = value

    @property
    def certificate_format(self) -> EnumCertFormat:
        """Certificate format."""
        return self._cert_fmt

    @certificate_format.setter
    def certificate_format(self, value: EnumCertFormat) -> None:
        """Setter.

        :param value: certificate format
        """
        assert value in EnumCertFormat
        self._cert_fmt = value

    @property
    def hash_algorithm(self) -> EnumAlgorithm:
        """Hash algorithm."""
        return self._hash_alg

    @hash_algorithm.setter
    def hash_algorithm(self, value: EnumAlgorithm) -> None:
        """Setter.

        :param value: hash algorithm
        """
        assert value in EnumAlgorithm
        self._hash_alg = value

    @property
    def source_index(self) -> int:
        """Source key (verification key, KEK) index.

        - For SRK, it is index of the SRK key (0-3)
        - For other keys it is index of previously installed target key, typically 0
        """
        return self._src_index

    @source_index.setter
    def source_index(self, value: int) -> None:
        """Setter.

        :param value: source key (verification key, KEK) index
        """
        if self._cert_fmt == EnumCertFormat.SRK:
            assert value in (0, 1, 2, 3)  # RT10xx supports just 4 SRK keys; this might need update for other devices
        else:
            assert value in (0, 2, 3, 4, 5)
        self._src_index = value

    @property
    def target_index(self) -> int:
        """Target key index."""
        return self._tgt_index

    @target_index.setter
    def target_index(self, value: int) -> None:
        """Setter.

        :param value: target key index
        """
        assert value in (0, 1, 2, 3, 4, 5)
        self._tgt_index = value

    @property
    def cmd_data_offset(self) -> int:
        """Offset of an additional data (such as certificate, signature, etc) in binary image."""
        return self.cmd_data_location

    @cmd_data_offset.setter
    def cmd_data_offset(self, value: int) -> None:
        """Setter.

        :param value: offset to set
        """
        self.cmd_data_location = value

    @property
    def needs_cmd_data_reference(self) -> bool:
        """Whether the command contains a reference to an additional data."""
        if self.flags == EnumInsKey.ABS:  # reference is an absolute address; instance not assigned; used for DEK key
            assert self._certificate_ref is None
            return False
        return True

    @property
    def cmd_data_reference(self) -> Optional[Union[CertificateImg, SrkTable]]:
        """Reference to an additional data (such as certificate, signature, etc).

        None if no reference was assigned;
        Value type is command-specific
        """
        return self._certificate_ref

    @cmd_data_reference.setter
    def cmd_data_reference(self, value: Union[CertificateImg, SrkTable]) -> None:
        """Setter.

        By default, the command does not support cmd_data_reference

        :param value: to be set
        :raise ValueError: if cmd reference not supported by the command
        """
        assert isinstance(value, (CertificateImg, SrkTable))
        self._certificate_ref = value

    def parse_cmd_data(self, data: bytes, offset: int) -> Union[CertificateImg, SrkTable, None]:
        """Parse additional command data from binary data.

        :param data: to be parsed
        :param offset: start position in data to parse
        :return: parsed data object; command-specific: certificate or SrkTable to be installed
        """
        if self.certificate_format == EnumCertFormat.SRK:
            result: Union[CertificateImg, SrkTable] = SrkTable.parse(data, offset)
        else:
            result = CertificateImg.parse(data, offset)
        self.cmd_data_reference = result
        return result

    @property
    def certificate_ref(self) -> Union[CertificateImg, SrkTable, None]:
        """Corresponding certificate referenced by key-location."""
        return self._certificate_ref

    @certificate_ref.setter
    def certificate_ref(self, value: Union[CertificateImg, SrkTable]) -> None:
        """Setter.

        :param value: certificate to be installed by the command
        """
        self._certificate_ref = value

    def __repr__(self) -> str:
        return "CmdInstallKey <{}, {}, {}, {}, {}, 0x{:X}>". \
            format(EnumInsKey[self.flags], EnumCertFormat[self.certificate_format],  # type: ignore
                   EnumAlgorithm[self.hash_algorithm],  # type: ignore
                   self.source_index, self.target_index, self.cmd_data_location)

    def info(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().info()
        msg += " Flag      : {:d} ({})\n".format(self.flags, EnumInsKey.desc(self.flags))
        msg += " CertFormat: {:d} ({})\n".format(self.certificate_format,
                                                 EnumCertFormat.desc(self.certificate_format))  # type: ignore
        msg += " Algorithm : {:d} ({})\n".format(self.hash_algorithm,
                                                 EnumAlgorithm.desc(self.hash_algorithm))  # type: ignore
        msg += " SrcKeyIdx : {:d} (Source key index) \n".format(self.source_index)
        msg += " TgtKeyIdx : {:d} (Target key index) \n".format(self.target_index)
        msg += " Location  : 0x{:08X} (Start address of certificate(s) to install) \n".format(self.cmd_data_location)
        if self.certificate_ref:
            msg += '[related-certificate]\n'
            msg += self.certificate_ref.info()
        msg += "-" * 60 + "\n"
        return msg

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export to binary form (serialization).

        :param dbg_info: debug information about exported data
        :return: binary representation of the command
        """
        raw_data = super().export(dbg_info=dbg_info)
        data = pack(">4BL", self.certificate_format, self.hash_algorithm, self.source_index, self.target_index,
                    self.cmd_data_location)
        raw_data += data
        dbg_info.append_binary_data('data', data)
        return raw_data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> CmdBase:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :param offset: current position to read from data
        :return: parse command
        """
        header = CmdHeader.parse(data, offset, CmdTag.INS_KEY)
        protocol, algorithm, src_index, tgt_index, location = unpack_from(">4BL", data, offset + header.size)
        return cls(EnumInsKey.from_int(header.param), protocol, algorithm, src_index, tgt_index, location)


# the type represents referenced command data: either Signature or MAC
SignatureOrMAC = Union[MAC, Signature]


class CmdAuthData(CmdBase):
    """Authenticate data command."""

    @property
    def flags(self) -> int:
        """Flag of Authenticate data command."""
        return self._header.param

    @flags.setter
    def flags(self, value: int) -> None:
        assert value in EnumAuthDat
        self._header.param = value

    @property
    def key_index(self) -> int:
        """Key index."""
        return self._key_index

    @key_index.setter
    def key_index(self, value: int) -> None:
        assert value in (0, 1, 2, 3, 4, 5)
        self._key_index = value

    @property
    def engine(self) -> EnumEngine:
        """Engine."""
        return self._engine

    @engine.setter
    def engine(self, value: EnumEngine) -> None:
        assert value in EnumEngine
        self._engine = value

    def __init__(self, flags: EnumAuthDat = EnumAuthDat.CLR, key_index: int = 1,
                 sig_format: EnumCertFormat = EnumCertFormat.CMS, engine: EnumEngine = EnumEngine.ANY,
                 engine_cfg: int = 0, location: int = 0, certificate: Optional[Certificate] = None,
                 private_key_pem_data: Optional[bytes] = None):
        """Initialize the Authenticate data command."""
        super().__init__(CmdTag.AUT_DAT, flags)
        self.key_index = key_index
        self.sig_format = sig_format
        self.engine = engine
        self.engine_cfg = engine_cfg
        self.location = location
        self.certificate = certificate
        self.private_key_pem_data = private_key_pem_data
        self._header.length = CmdHeader.SIZE + 8
        self._blocks: List[Tuple[int, int]] = []  # list of (start-address, size)
        self._signature: Optional[SignatureOrMAC] = None
        if certificate and private_key_pem_data:
            assert isinstance(certificate, Certificate)
            assert isinstance(private_key_pem_data, bytes)
            assert matches_key_and_cert(private_key_pem_data, certificate)

    @property
    def needs_cmd_data_reference(self) -> bool:
        """Whether the command contains a reference to an additional data."""
        return True

    @property
    def cmd_data_offset(self) -> int:
        """Offset of an additional data (such as signature or MAC, etc) in binary image."""
        return self.location

    @cmd_data_offset.setter
    def cmd_data_offset(self, value: int) -> None:
        """Setter.

        :param value: offset to set
        """
        self.location = value

    @property
    def cmd_data_reference(self) -> Optional[SignatureOrMAC]:
        """Reference to an additional data (such as certificate, signature, etc).

        -   None if no reference was assigned;
        -   Value type is command-specific
        """
        return self._signature

    @cmd_data_reference.setter
    def cmd_data_reference(self, value: SignatureOrMAC) -> None:
        """Setter.

        By default, the command does not support cmd_data_reference

        :param value: to be set
        :raise ValueError: if cmd reference not supported by the command
        """
        if self.sig_format == EnumCertFormat.AEAD:
            assert isinstance(value, MAC)
        elif self.sig_format == EnumCertFormat.CMS:
            assert isinstance(value, Signature)
        else:
            assert False
        self._signature = value

    def parse_cmd_data(self, data: bytes, offset: int) -> SignatureOrMAC:
        """Parse additional command data from binary data.

        :param data: to be parsed
        :param offset: start position in data to parse
        :return: parsed data object; command-specific: Signature or MAC
        """
        if self.key_index == 0:  # TODO check by header
            self._signature = MAC.parse(data, offset)
        else:
            self._signature = Signature.parse(data, offset)
        return self._signature

    @property
    def signature(self) -> Optional[SignatureOrMAC]:
        """Signature referenced by `location` attribute."""
        return self._signature

    @signature.setter
    def signature(self, value: SignatureOrMAC) -> None:
        """Setter.

        :param value: signature to be installed by the command
        """
        self.cmd_data_reference = value

    def __repr__(self) -> str:
        return "CmdAuthData <{}, {}, {}, key:{}, 0x{:X}>". \
            format(EnumAuthDat[self.flags], EnumEngine[self.engine],  # type: ignore
                   self.engine_cfg, self.key_index, self.location)

    def __len__(self) -> int:
        return len(self._blocks)

    def __getitem__(self, key: int) -> Tuple[int, int]:
        return self._blocks[key]

    def __setitem__(self, key: int, value: Tuple[int, int]) -> None:
        assert isinstance(value, (list, tuple))
        assert len(value) == 2
        self._blocks[key] = value

    def __iter__(self) -> Iterator[Union[Tuple[Any, ...], List[Any]]]:
        return self._blocks.__iter__()

    def info(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().info()
        msg += " Flag:        {:d} ({})\n".format(self.flags, EnumAuthDat.desc(self.flags))
        msg += " Key index:   {:d}\n".format(self.key_index)
        msg += " Engine:      {:d} ({})\n".format(self.engine, EnumEngine.desc(self.engine))
        msg += " Engine Conf: {:d}\n".format(self.engine_cfg)
        msg += " Location:    0x{:08X} (Start address of authentication data) \n".format(self.location)
        if self.signature:
            msg += '[related signature]\n'
            msg += self.signature.info()
        msg += "-" * 60 + "\n"
        for blk in self._blocks:
            msg += "- Start: 0x{0:08X}, Length: {1:d} Bytes\n".format(blk[0], blk[1])
        return msg

    def append(self, start_address: int, size: int) -> None:
        """Append of Authenticate data command."""
        self._blocks.append((start_address, size), )
        self._header.length += 8

    def pop(self, index: int) -> Tuple[int, int]:
        """Pop of Authenticate data command."""
        assert 0 <= index < len(self._blocks)
        value = self._blocks.pop(index)
        self._header.length -= 8
        return value

    def clear(self) -> None:
        """Clear of Authenticate data command."""
        self._blocks.clear()
        self._header.length = self._header.size + 8

    def _cms_signature(self, zulu: datetime, data: bytes) -> bytes:
        """Sign provided data and return CMS signature.

        :param zulu: current UTC time+date
        :param data: to be signed
        :return: CMS signature (binary)
        """
        assert self.certificate is not None
        assert self.private_key_pem_data is not None

        # signed data (main section)
        signed_data = cms.SignedData()
        signed_data['version'] = 'v1'
        signed_data['encap_content_info'] = util.OrderedDict([
            ('content_type', 'data')
        ])
        signed_data['digest_algorithms'] = [util.OrderedDict([
            ('algorithm', 'sha256'),
            ('parameters', None)])]

        # signer info sub-section
        signer_info = cms.SignerInfo()
        signer_info['version'] = 'v1'
        signer_info['digest_algorithm'] = util.OrderedDict([
            ('algorithm', 'sha256'),
            ('parameters', None)])
        signer_info['signature_algorithm'] = util.OrderedDict([
            ('algorithm', 'rsassa_pkcs1v15'),
            ('parameters', b'')])
        # signed identifier: issuer amd serial number
        asn1cert = x509.Certificate.load(self.certificate.public_bytes(Encoding.DER))
        signer_info['sid'] = cms.SignerIdentifier({
            'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                'issuer': asn1cert.issuer,
                'serial_number': asn1cert.serial_number
            })
        })
        # signed attributes
        signed_attrs = cms.CMSAttributes()
        signed_attrs.append(cms.CMSAttribute({
            'type': 'content_type',
            'values': [cms.ContentType('data')],
        }))
        # check time-zone is assigned (expected UTC+0)
        assert zulu.tzinfo
        signed_attrs.append(cms.CMSAttribute({
            'type': 'signing_time',
            'values': [cms.Time(name='utc_time', value=zulu.strftime('%y%m%d%H%M%SZ'))],
        }))
        signed_attrs.append(cms.CMSAttribute({
            'type': 'message_digest',
            'values': [cms.OctetString(crypto_backend().hash(data))],  # digest
        }))
        signer_info['signed_attrs'] = signed_attrs

        # create signature
        signer_info['signature'] = crypto_backend().rsa_sign(self.private_key_pem_data, signed_attrs.dump())

        # Adding SignerInfo object to SignedData object
        signed_data['signer_infos'] = [signer_info]

        # content info
        content_info = cms.ContentInfo()
        content_info['content_type'] = 'signed_data'
        content_info['content'] = signed_data

        return content_info.dump()

    def update_signature(self, zulu: datetime, data: bytes, base_data_addr: int = 0xFFFFFFFF) -> bool:
        """Update signature.

        This method must be called from parent to provide data to be signed

        :param zulu: current UTC time+date
        :param data: currently generated binary data
        :param base_data_addr: base address of the generated data
        :raises ValueError: When certificate or private key are not assigned
        :raises ValueError: When signatures not assigned explicitly
        :return: True if length of the signature was unchanged, as this may affect content of the CSF section (pointer
                        to data);
        """
        if not self.certificate or not self.private_key_pem_data:
            raise ValueError('certificate or private key not assigned, cannot update signature')

        if self.signature is None:
            raise ValueError('signature must be assigned explicitly, so its version matches to CST version')

        if self._blocks:
            sign_data = b''
            if data:  # if not data specified, create "fake" signature to update length
                total_len = 0
                for blk in self._blocks:
                    start = blk[0] - base_data_addr
                    end = blk[0] + blk[1] - base_data_addr
                    assert start >= 0
                    assert end <= len(data)
                    sign_data += data[start: end]
                    total_len += blk[1]
                assert len(sign_data) == total_len
        else:
            sign_data = data  # if no blocks defined, sign complete data; used for CSF
        if isinstance(self.signature, Signature):
            new_signature = self._cms_signature(zulu, sign_data)
            result = len(self.signature.data) == len(new_signature)
            self.signature.data = new_signature
        else:
            assert isinstance(self.signature, MAC)
            result = True
        return result

    def export(self, dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Export to binary form (serialization).

        :param dbg_info: debug information about exported data
        :return: binary representation of the command
        """
        self._header.length = self.size
        raw_data = super().export(dbg_info=dbg_info)
        data = pack(">4BL", self.key_index, self.sig_format, self.engine, self.engine_cfg, self.location)
        dbg_info.append_binary_data('data', data)
        raw_data += data
        for blk in self._blocks:
            blk_data = pack(">2L", blk[0], blk[1])
            dbg_info.append_binary_data('block', blk_data)
            raw_data += blk_data
        return raw_data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> 'CmdAuthData':
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :param offset: current position to read from data
        :return: parse command
        """
        header = CmdHeader.parse(data, offset, CmdTag.AUT_DAT)
        key, sig_format, eng, cfg, location = unpack_from(">4BL", data, offset + header.size)
        obj = cls(EnumAuthDat.from_int(header.param), key, sig_format, EnumEngine.from_int(eng), cfg, location)
        index = header.size + 8
        while index < header.length:
            start_address, size = unpack_from(">2L", data, offset + index)
            obj.append(start_address, size)
            index += 8
        return obj


# mapping of supported commands to the corresponding class
_CMD_TO_CLASS: Mapping[CmdTag, Type[CmdBase]] = {
    CmdTag.WRT_DAT: CmdWriteData,
    CmdTag.CHK_DAT: CmdCheckData,
    CmdTag.NOP: CmdNop,
    CmdTag.SET: CmdSet,
    CmdTag.INIT: CmdInitialize,
    CmdTag.UNLK: CmdUnlockAbstract,
    CmdTag.INS_KEY: CmdInstallKey,
    CmdTag.AUT_DAT: CmdAuthData
}


def parse_command(data: bytes, offset: int = 0) -> CmdBase:
    """Parse CSF/DCD command.

    :param data: binary data to be parsed
    :param offset: to start parsing
    :return: instance of the command
    :raise ValueError: if the command is not valid
    """
    try:
        cmdtag = CmdTag.from_int(data[offset])
    except ValueError:
        raise ValueError("Unknown command at position: " + hex(offset))
    cmd_class = _CMD_TO_CLASS[cmdtag]
    return cmd_class.parse(data, offset)
