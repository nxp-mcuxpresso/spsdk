#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Commands for image module."""

from abc import ABC
from datetime import datetime
from struct import pack, unpack_from
from typing import Any, Iterable, Iterator, Mapping, Optional, Type, Union

from typing_extensions import Self

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.cms import cms_sign
from spsdk.crypto.keys import PrivateKey
from spsdk.crypto.signature_provider import SignatureProvider
from spsdk.exceptions import SPSDKAttributeError, SPSDKError, SPSDKKeyError, SPSDKValueError

########################################################################################################################
# Enums
########################################################################################################################
from spsdk.image.header import CmdHeader, CmdTag, Header, SegTag
from spsdk.image.secret import (
    MAC,
    BaseSecretClass,
    CertificateImg,
    EnumAlgorithm,
    Signature,
    SrkTable,
)
from spsdk.utils.abstract import BaseClass
from spsdk.utils.spsdk_enum import SpsdkEnum


class EnumWriteOps(SpsdkEnum):
    """Enum definition for 'flags' control flags in 'par' parameter of Write Data command."""

    WRITE_VALUE = (0, "WRITE_VALUE", "Write value")
    WRITE_CLEAR_BITS = (1, "WRITE_CLEAR_BITS", "Write clear bits")
    CLEAR_BITMASK = (2, "CLEAR_BITMASK", "Clear bitmask")
    SET_BITMASK = (3, "SET_BITMASK", "Set bitmask")


class EnumCheckOps(SpsdkEnum):
    """Enum definition for 'par' parameter of Check Data command."""

    ALL_CLEAR = (0, "ALL_CLEAR", "All bits clear")
    ALL_SET = (1, "ALL_SET", "All bits set")
    ANY_CLEAR = (2, "ANY_CLEAR", "Any bit clear")
    ANY_SET = (3, "ANY_SET", "Any bit set")


class EnumCertFormat(SpsdkEnum):
    """Certificate format tags."""

    SRK = (0x03, "SRK", "SRK certificate format")
    X509 = (0x09, "X509", "X.509v3 certificate format")
    CMS = (0xC5, "CMS", "CMS/PKCS#7 signature format")
    BLOB = (0xBB, "BLOB", "SHW-specific wrapped key format")
    AEAD = (0xA3, "AEAD", "Proprietary AEAD MAC format")


class EnumInsKey(SpsdkEnum):
    """Flags for Install Key commands."""

    CLR = (0, "CLR", "No flags set")
    ABS = (1, "ABS", "Absolute certificate address")
    CSF = (2, "CSF", "Install CSF key")
    DAT = (4, "DAT", "Key binds to Data Type")
    CFG = (8, "CFG", "Key binds to Configuration")
    FID = (16, "FID", "Key binds to Fabrication UID")
    MID = (32, "MID", "Key binds to Manufacturing ID")
    CID = (64, "CID", "Key binds to Caller ID")
    HSH = (128, "HSH", "Certificate hash present")


class EnumAuthDat(SpsdkEnum):
    """Flags for Authenticate Data commands."""

    CLR = (0, "CLR", "No flags set")
    ABS = (1, "ABS", "Absolute signature address")


class EnumEngine(SpsdkEnum):
    """Engine plugin tags."""

    ANY = (
        0x00,
        "ANY",
        "First compatible engine will be selected (no engine configuration parameters are allowed)",
    )
    SCC = (0x03, "ANY", "Security controller")
    RTIC = (0x05, "RTIC", "Run-time integrity checker")
    SAHARA = (0x06, "SAHARA", "Crypto accelerator")
    CSU = (0x0A, "CSU", "Central Security Unit")
    SRTC = (0x0C, "SRTC", "Secure clock")
    DCP = (0x1B, "DCP", "Data Co-Processor")
    CAAM = (0x1D, "CAAM", "Cryptographic Acceleration and Assurance Module")
    SNVS = (0x1E, "SNVS", "Secure Non-Volatile Storage")
    OCOTP = (0x21, "OCOTP", "Fuse controller")
    DTCP = (0x22, "DTCP", "DTCP co-processor")
    ROM = (0x36, "ROM", "Protected ROM area")
    HDCP = (0x24, "HDCP", "HDCP co-processor")
    SW = (0xFF, "SW", "Software engine")


class EnumCAAM(SpsdkEnum):
    """CAAM Engine Configuration."""

    DEFAULT = (0x00, "DEFAULT")
    IN_SWAP8 = (0x01, "IN_SWAP8")
    IN_SWAP16 = (0x02, "IN_SWAP16")
    OUT_SWAP8 = (0x08, "OUT_SWAP8")
    OUT_SWAP16 = (0x10, "OUT_SWAP16")
    DSC_SWAP8 = (0x40, "DSC_SWAP8")
    DSC_SWAP16 = (0x80, "DSC_SWAP16")


class EnumItm(SpsdkEnum):
    """Engine configuration flags of Set command."""

    MID = (0x01, "MID", "Manufacturing ID (MID) fuse locations")
    ENG = (0x03, "ENG", "Preferred engine for a given algorithm")


########################################################################################################################
# Abstract Class
########################################################################################################################


class CmdBase(BaseClass):
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
    def tag(self) -> int:
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
    def cmd_data_offset(self, value: int) -> None:  # pylint: disable=no-self-use
        """Setter.

        :param value: offset to set
        :raises SPSDKError: If cmd-data not supported by the command
        """
        raise SPSDKError("cmd-data not supported by the command")

    @property
    def cmd_data_reference(self) -> Optional[BaseSecretClass]:
        """Reference to a command data (such as certificate, signature, etc).

        None if no reference was assigned;
        Value type is command-specific
        """
        return None

    @cmd_data_reference.setter
    def cmd_data_reference(self, value: BaseSecretClass) -> None:  # pylint: disable=no-self-use
        """Setter.

        By default, the command does not support cmd_data_reference
        Note: the method must be implemented in `self.has_cmd_data_reference` returns True

        :param value: to be set
        :raises SPSDKError: If reference not supported by the command
        """
        raise SPSDKError("cmd-data not supported by the command")

    def parse_cmd_data(self, data: bytes) -> Any:  # pylint: disable=no-self-use
        """Parse additional command data from binary data.

        :param data: to be parsed
        :raises SPSDKError: If cmd_data is not supported by the command
        """
        raise SPSDKError("cmd-data not supported by the command")

    def __repr__(self) -> str:
        return f"Command: {CmdTag.get_description(self.tag)}"

    def __str__(self) -> str:
        """Text representation of the command."""
        return f'Command "{CmdTag.get_description(self.tag)}"   [Tag={str(self.tag)}, length={str(self.size)}]\n'

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: binary representation of the command
        """
        hdr_data = self._header.export()
        return hdr_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: parse command
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")


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
        :raises SPSDKError: When number of bytes is not 1, 2 nor 4
        """
        if value not in (1, 2, 4):
            raise SPSDKError("number of bytes is not 1, 2 nor 4")
        self._header.param &= ~0x7
        self._header.param |= value

    @property
    def ops(self) -> EnumWriteOps:
        """Type of write operation."""
        return EnumWriteOps.from_tag((self._header.param >> 3) & 0x3)

    @ops.setter
    def ops(self, value: EnumWriteOps) -> None:
        if value not in EnumWriteOps:
            raise SPSDKValueError("Value not defined")
        self._header.param &= ~(0x3 << 3)
        self._header.param |= int(value.tag) << 3

    def __init__(
        self,
        numbytes: int = 4,
        ops: EnumWriteOps = EnumWriteOps.WRITE_VALUE,
        data: Optional[Iterable[tuple[int, int]]] = None,
    ) -> None:
        """Initialize Write Data command.

        :param numbytes: number of bytes. Must be value: 1, 2 or 4
        :param ops: type of write operation
        :param data: list of tuples: address and value
        :raises SPSDKError: When incorrect number of bytes
        :raises SPSDKError: When incorrect type of operation
        """
        if numbytes not in (1, 2, 4):
            raise SPSDKError("Incorrect number of bytes")
        if ops not in EnumWriteOps:
            raise SPSDKError("Incorrect type of operation")
        super().__init__(CmdTag.WRT_DAT, ((int(ops.tag) & 0x3) << 3) | (numbytes & 0x7))
        self._data: list[list[int]] = []
        if data is not None:
            assert isinstance(data, (list, tuple))
            for address, value in data:
                self.append(address, value)

    def __repr__(self) -> str:
        return f"CmdWriteData <{self.ops.label}/{self.num_bytes}, {len(self._data)}>"

    def __len__(self) -> int:
        return len(self._data)

    def __getitem__(self, key: int) -> list[int]:
        return self._data[key]

    def __setitem__(self, key: int, value: list[int]) -> None:
        self._data[key] = value

    def __iter__(self) -> Iterator[list[int]]:
        return self._data.__iter__()

    def __str__(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().__str__()
        msg += f"Write Data Command (Ops: {self.ops.label}, Bytes: {self.num_bytes})\n"
        for cmd in self._data:
            msg += f"- Address: 0x{cmd[0]:08X}, Value: 0x{cmd[1]:08X}\n"
        msg += "-" * 60 + "\n"
        return msg

    def append(self, address: int, value: int) -> None:
        """Append of Write data command."""
        if address < 0 or address > 0xFFFFFFFF:
            raise SPSDKError("Address out of range")
        if value < 0 or value > 0xFFFFFFFF:
            raise SPSDKError("Value out of range")
        self._data.append([address, value])
        self._header.length += 8

    def pop(self, index: int) -> list[int]:
        """Pop of Write data command."""
        if index < 0 or index >= len(self._data):
            raise SPSDKError("Length of data is incorrect")
        cmd = self._data.pop(index)
        self._header.length -= 8
        return cmd

    def clear(self) -> None:
        """Clear of Write data command."""
        self._data.clear()
        self._header.length = self._header.size

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: binary representation of the command
        """
        raw_data = super().export()
        for cmd in self._data:
            raw_data += pack(">LL", cmd[0], cmd[1])
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: parse command
        """
        header = CmdHeader.parse(data, required_tag=CmdTag.WRT_DAT.tag)
        obj = cls(header.param & 0x7, EnumWriteOps.from_tag((header.param >> 3) & 0x3))
        index = header.size
        while index < header.length:
            (address, value) = unpack_from(">LL", data, index)
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
        if value not in (1, 2, 4):
            raise SPSDKError("Incorrect number of bytes")
        self._header.param &= ~0x7
        self._header.param |= int(value)

    @property
    def ops(self) -> EnumCheckOps:
        """Operation of Check data command."""
        return EnumCheckOps.from_tag((self._header.param >> 3) & 0x3)

    @ops.setter
    def ops(self, value: EnumCheckOps) -> None:
        """Operation of Check data command.

        :raises SPSDKError: If incorrect operation
        """
        if value not in EnumCheckOps:
            raise SPSDKError("Incorrect operation")
        self._header.param &= ~(0x3 << 3)
        self._header.param |= int(value.tag) << 3

    def __init__(
        self,
        numbytes: int = 4,
        ops: EnumCheckOps = EnumCheckOps.ALL_SET,
        address: int = 0,
        mask: int = 0,
        count: Optional[int] = None,
    ) -> None:
        """Initialize the check data command.

        :param numbytes: number of bytes
        :param ops: type of  operation
        :param address: list of tuples: address and value
        :param mask: mask value
        :param count: count value
        :raises SPSDKError: If incorrect number of bytes
        :raises SPSDKError: If incorrect operation
        """
        if numbytes not in (1, 2, 4):
            raise SPSDKError("Incorrect number of bytes")
        if ops not in EnumCheckOps:
            raise SPSDKError("Incorrect operation")
        super().__init__(CmdTag.CHK_DAT, ((int(ops.tag) & 0x3) << 3) | (numbytes & 0x7))
        self.address = address
        self.mask = mask
        self.count = count
        # the length of 'address'(4B), 'mask'(4B) and count(0 or 4B)  need to be added into Header.length
        self._header.length += 4 + 4 + (4 if count else 0)

    def __repr__(self) -> str:
        return (
            f"CmdCheckData <{self.ops.label}/{self.num_bytes}, "
            f"ADDR=0x{self.address:X}, MASK=0x{self.mask:X}>"
        )

    def __str__(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().__str__()
        msg += f"Check Data Command (Ops: {self.ops.label}, Bytes: {self.num_bytes})\n"

        msg += f"- Address: 0x{self.address:08X}, Mask: 0x{self.mask:08X}"
        if self.count:
            msg += f", Count: {self.count}"
        msg += "\n"
        msg += "-" * 60 + "\n"
        return msg

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: binary representation of the command
        """
        raw_data = super().export()
        raw_data += pack(">LL", self.address, self.mask)
        if self.count is not None:
            raw_data += pack(">L", self.count)
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: parse command
        """
        header = CmdHeader.parse(data, CmdTag.CHK_DAT.tag)
        numbytes = header.param & 0x7
        ops = (header.param >> 3) & 0x3
        address, mask = unpack_from(">LL", data, header.size)
        count = None
        if (header.length - header.size) > 8:
            count = unpack_from(">L", data, header.size + 8)[0]
        return cls(numbytes, EnumCheckOps.from_tag(ops), address, mask, count)


class CmdNop(CmdBase):
    """Nop command."""

    def __init__(self, param: int = 0):
        """Initialize the nop command."""
        super().__init__(CmdTag.NOP, param)

    def __repr__(self) -> str:
        return "CmdNop"

    def __str__(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().__str__()
        msg += "-" * 60 + "\n"
        return msg

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: parse command
        """
        header = CmdHeader.parse(data, CmdTag.NOP.tag)
        if header.length != header.size:
            pass
        return cls(header.param)


class CmdSet(CmdBase):
    """Set command."""

    @property
    def itm(self) -> EnumItm:
        """Item of Set command."""
        return EnumItm.from_tag(self._header.param)

    @itm.setter
    def itm(self, value: EnumItm) -> None:
        if value not in EnumItm:
            raise SPSDKError("Incorrect item of set command")
        self._header.param = value.tag

    @property
    def hash_algorithm(self) -> EnumAlgorithm:
        """Type of hash algorithm."""
        return self._hash_alg

    @hash_algorithm.setter
    def hash_algorithm(self, value: EnumAlgorithm) -> None:
        if value not in EnumAlgorithm:
            raise SPSDKError("Incorrect type of algorithm")
        self._hash_alg = value

    @property
    def engine(self) -> EnumEngine:
        """Engine plugin tags."""
        return self._engine

    @engine.setter
    def engine(self, value: EnumEngine) -> None:
        if value not in EnumEngine:
            raise SPSDKError("Incorrect type of engine plugin")
        self._engine = value

    def __init__(
        self,
        itm: EnumItm = EnumItm.ENG,
        hash_alg: EnumAlgorithm = EnumAlgorithm.ANY,
        engine: EnumEngine = EnumEngine.ANY,
        engine_cfg: int = 0,
    ):
        """Initialize the set command."""
        if itm not in EnumItm:
            raise SPSDKError("Incorrect engine configuration flag")
        super().__init__(CmdTag.SET, itm.tag)
        self.hash_algorithm: EnumAlgorithm = hash_alg
        self.engine = engine
        self.engine_cfg = engine_cfg
        self._header.length = CmdHeader.SIZE + 4

    def __repr__(self) -> str:
        return (
            f"CmdSet <{self.itm.label}, {self.hash_algorithm.label},"
            f" {self.engine.label}, eng_cfg=0x{self.engine_cfg:X}>"
        )

    def __str__(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().__str__()
        msg += "Set Command ITM : {EnumItm.name(self.itm)}\n"
        msg += f"HASH Algo      : {self.hash_algorithm} ({self.hash_algorithm.description})\n"
        msg += f"Engine         : {self.engine} ({self.engine.description})\n"
        msg += f"Engine Conf    : {hex(self.engine_cfg)})\n"
        msg += "-" * 60 + "\n"
        return msg

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: binary representation of the command
        """
        raw_data = super().export()
        raw_data += pack("4B", 0x00, self.hash_algorithm.tag, self.engine.tag, self.engine_cfg)
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: parse command
        """
        header = CmdHeader.parse(data, CmdTag.SET.tag)
        (_, alg, eng, cfg) = unpack_from("4B", data, CmdHeader.SIZE)
        return cls(
            EnumItm.from_tag(header.param),
            EnumAlgorithm.from_tag(alg),
            EnumEngine.from_tag(eng),
            cfg,
        )


class CmdInitialize(CmdBase):
    """Initialize command."""

    @property
    def engine(self) -> EnumEngine:
        """Engine."""
        return EnumEngine.from_tag(self._header.param)

    @engine.setter
    def engine(self, value: EnumEngine) -> None:
        if value not in EnumEngine:
            raise SPSDKError("Incorrect value of engine")
        self._header.param = value.tag

    def __init__(
        self, engine: EnumEngine = EnumEngine.ANY, data: Optional[list[int]] = None
    ) -> None:
        """Initialize the initialize command."""
        if engine not in EnumEngine:
            raise SPSDKError("Incorrect value of engine")
        super().__init__(CmdTag.INIT, engine.tag)
        self._data = data if data else []

    def __repr__(self) -> str:
        return f"CmdInitialize <{self.engine.label}, {len(self._data)}>"

    def __len__(self) -> int:
        return len(self._data)

    def __getitem__(self, key: int) -> int:
        return self._data[key]

    def __setitem__(self, key: int, value: int) -> None:
        self._data[key] = value

    def __iter__(self) -> Iterator[int]:
        return self._data.__iter__()

    def __str__(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().__str__()
        msg += f"Initialize Command (Engine: {self.engine.description})\n"
        cnt = 0
        for val in self._data:
            msg += f" {cnt:02d}) Value: 0x{val:08X}\n"
            cnt += 1
        msg += "-" * 60 + "\n"
        return msg

    def append(self, value: int) -> None:
        """Appending of Initialize command.

        :raises SPSDKError: If value out of range
        """
        assert isinstance(value, int), "value must be INT type"
        if value < 0 or value >= 0xFFFFFFFF:
            raise SPSDKError("Value out of range")
        self._data.append(value)
        self._header.length += 4

    def pop(self, index: int) -> int:
        """Pop of Initialize command.

        :return: value from the index
        :raises SPSDKError: If incorrect length of data
        """
        if index < 0 or index >= len(self._data):
            raise SPSDKError("Incorrect length of data")
        val = self._data.pop(index)
        self._header.length -= 4
        return val

    def clear(self) -> None:
        """Clear of Initialize command."""
        self._data.clear()
        self._header.length = self._header.size

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: binary representation of the command
        """
        raw_data = super().export()
        for val in self._data:
            raw_data += pack(">L", val)
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: parse command
        :raises SPSDKError: If incorrect length of data
        """
        header = CmdHeader.parse(data, CmdTag.INIT.tag)
        obj = cls(EnumEngine.from_tag(header.param))
        index = header.size
        while index < header.length:
            if index >= len(data):
                raise SPSDKError("Incorrect length of data")
            val = unpack_from(">L", data, index)
            obj.append(val[0])
            index += 4
        return obj


class CmdUnlockAbstract(CmdBase, ABC):
    """Abstract unlock engine command; the command depends on engine type."""

    def __init__(
        self, engine: EnumEngine = EnumEngine.ANY, features: Union[int, SpsdkEnum] = 0, uid: int = 0
    ):
        """Constructor.

        :param engine: to be unlocked
        :param features: engine specific features
        :param uid: Unique ID required by some engine/feature combinations
        """
        super().__init__(CmdTag.UNLK, engine.tag, length=8)
        self.features = features if isinstance(features, int) else features.tag
        self.uid = uid
        if self._need_uid:
            self._header.length += 8

    def __iter__(self) -> Iterator[int]:
        return self.__iter__()

    def __repr__(self) -> str:
        return f"{self.__class__.__name__} <{self.engine.description}, {self.features}, {self.uid}>"

    @property
    def engine(self) -> EnumEngine:
        """Engine to be unlocked.

        The term `engine` denotes a peripheral involved in one or more of the following functions:
        - cryptographic computation
        - security state management
        - security alarm handling
        - access control
        """
        return EnumEngine.from_tag(self._header.param)

    def __str__(self) -> str:
        """Text description of the command."""
        msg = super().__str__()
        msg += f"Unlock Command ({self.__class__.__name__})\n"
        msg += f"Engine : {self.engine.description}\n"
        return msg

    @property
    def _need_uid(self) -> bool:
        """Return True if given Engine and Feature requires UID."""
        return self.need_uid(self.engine, self.features)

    @staticmethod
    def need_uid(engine: EnumEngine, features: int) -> bool:
        """Return True if given Engine and Feature requires UID."""
        overall_condition = False
        ocotp_condition = engine == EnumEngine.OCOTP and bool(features & 0b1101)
        overall_condition |= ocotp_condition
        return overall_condition

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: Unlock command
        """
        header = CmdHeader.parse(data, CmdTag.UNLK.tag)
        features = unpack_from(">L", data, header.size)[0]
        engine = EnumEngine.from_tag(header.param)
        uid = 0
        if cls.need_uid(engine, features):
            uid = unpack_from(">Q", data, header.size + 4)[0]

        if engine == EnumEngine.SNVS:
            return CmdUnlockSNVS(features)  # type: ignore
        if engine == EnumEngine.CAAM:
            return CmdUnlockCAAM(features)  # type: ignore
        if engine == EnumEngine.OCOTP:
            return CmdUnlockOCOTP(features, uid)  # type: ignore
        return cls(engine, features, uid)

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: binary representation of the command
        """
        # assert self.size == CmdHeader.SIZE + 4
        raw_data = super().export()
        data = pack(">L", self.features)
        raw_data += data
        if self._need_uid:
            raw_data += pack(">Q", self.uid)
        return raw_data


class UnlockSNVSFeatures(SpsdkEnum):
    """Enum definition for Unlock SNVS features."""

    LP_SWR = (1, "LP SWR", "Leaves LP SW reset unlocked")
    ZMK_WRITE = (2, "ZMK WRITE", "Leaves Zero-able Master Key write unlocked.")


class CmdUnlockSNVS(CmdUnlockAbstract):
    """Command Unlock Secure Non-Volatile Storage (SNVS) Engine."""

    FEATURES = UnlockSNVSFeatures

    def __init__(self, features: Union[int, UnlockSNVSFeatures] = 0) -> None:
        """Constructor.

        :param features: mask of FEATURE_UNLOCK_* constants
        """
        super().__init__(EnumEngine.SNVS, features)

    @property
    def unlock_lp_swr(self) -> bool:
        """Leave LP SW reset unlocked."""
        return self.features & UnlockSNVSFeatures.LP_SWR.tag != 0

    @property
    def unlock_zmk_write(self) -> bool:
        """Leave Zero is able Master Key write unlocked."""
        return self.features & UnlockSNVSFeatures.ZMK_WRITE.tag != 0

    def __str__(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().__str__()
        msg += f"Unlock LP SWR    : {self.unlock_lp_swr}\n"
        msg += f"Unlock ZMK Write : {self.unlock_zmk_write}\n"
        msg += "-" * 60 + "\n"
        return msg


class UnlockCAAMFeatures(SpsdkEnum):
    """Enum definition for Unlock SNVS features."""

    MID = (1, "MID", "Leaves Job Ring and DECO master ID registers unlocked")
    RNG = (2, "RNG", "Leave RNG uninitialized.")
    MFG = (4, "MFG", "Keep manufacturing protection private key in CAAM internal memory.")


class CmdUnlockCAAM(CmdUnlockAbstract):
    """Command Unlock for Cryptographic Acceleration and Assurance Module ."""

    FEATURES = UnlockCAAMFeatures

    def __init__(self, features: Union[int, UnlockCAAMFeatures] = 0):
        """Initialize.

        :param features: mask of FEATURE_UNLOCK_x constants, defaults to 0
        """
        super().__init__(EnumEngine.CAAM, features)

    @property
    def unlock_mid(self) -> bool:
        """Leave Job Ring and DECO master ID registers unlocked."""
        return self.features & UnlockCAAMFeatures.MID.tag != 0

    @property
    def unlock_rng(self) -> bool:
        """Leave RNG un-instantiated."""
        return self.features & UnlockCAAMFeatures.RNG.tag != 0

    @property
    def unlock_mfg(self) -> bool:
        """Leave Zero is able Master Key write unlocked."""
        return self.features & UnlockCAAMFeatures.MFG.tag != 0

    def __str__(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().__str__()
        msg += f"MID : {self.unlock_mid}\n"
        msg += f"RNG : {self.unlock_rng}\n"
        msg += f"MFG : {self.unlock_mfg}\n"
        msg += "-" * 60 + "\n"
        return msg


class UnlockOCOTPFeatures(SpsdkEnum):
    """Enum definition for Unlock SNVS features."""

    FIELD_RETURN = (1, "FIELD RETURN", "Leave Field Return activation unlocked.")
    SRK_REVOKE = (2, "SRK REVOKE", "Leave SRK revocation unlocked.")
    SCS = (4, "SCS", "Leave SCS register unlocked.")
    JTAG = (8, "JTAG", "Unlock JTAG using SCS HAB_JDE bit.")


class CmdUnlockOCOTP(CmdUnlockAbstract):
    """Command Unlock for On-Chip One-time programmable memory (fuses)."""

    FEATURES = UnlockOCOTPFeatures

    def __init__(self, features: Union[int, UnlockOCOTPFeatures] = 0, uid: int = 0):
        """Initialize.

        :param features: mask of FEATURE_UNLOCK_x constants, defaults to 0
        :param uid: Unique ID required by some engine/feature combinations
        """
        super().__init__(EnumEngine.OCOTP, features, uid=uid)

    @property
    def _need_uid(self) -> bool:
        """Return True if given Engine and Feature requires UID."""
        return self.unlock_fld_rtn or self.unlock_csc or self.unlock_jtag

    @property
    def unlock_fld_rtn(self) -> bool:
        """Leave Field Return activation unlocked."""
        return self.features & UnlockOCOTPFeatures.FIELD_RETURN.tag != 0

    @property
    def unlock_srk_rvk(self) -> bool:
        """Leave SRK revocation unlocked."""
        return self.features & UnlockOCOTPFeatures.SRK_REVOKE.tag != 0

    @property
    def unlock_csc(self) -> bool:
        """Leave SCS register unlocked."""
        return self.features & UnlockOCOTPFeatures.SCS.tag != 0

    @property
    def unlock_jtag(self) -> bool:
        """Unlock JTAG using SCS HAB_JDE bit."""
        return self.features & UnlockOCOTPFeatures.JTAG.tag != 0

    def __str__(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().__str__()
        msg += f"FLD_RTN : {self.unlock_fld_rtn}\n"
        msg += f"SRK_RVK : {self.unlock_srk_rvk}\n"
        msg += f"CSC     : {self.unlock_csc}\n"
        msg += f"JTAG    : {self.unlock_jtag}\n"
        if self.uid:
            msg += f"UID : {hex(self.uid)}\n"
        msg += "-" * 60 + "\n"
        return msg


class CmdUnlock(CmdUnlockAbstract):
    """Generic unlock engine command."""

    def __init__(self, engine: EnumEngine = EnumEngine.ANY, features: int = 0, uid: int = 0):
        """Constructor.

        :param engine: to be unlocked
        :param features: mask of features to use by the engine
        :param uid: Unique ID (if needed)
        """
        super().__init__(engine, features, uid=uid)

    def __str__(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().__str__()
        msg += f"Features: {self.features}\n"
        msg += f"UID:      {self.uid}\n"
        msg += "-" * 60 + "\n"
        return msg


UNLOCK_COMMANDS_MAPPING: Mapping[
    EnumEngine, Type[Union[CmdUnlockCAAM, CmdUnlockSNVS, CmdUnlockOCOTP]]
] = {
    EnumEngine.CAAM: CmdUnlockCAAM,
    EnumEngine.SNVS: CmdUnlockSNVS,
    EnumEngine.OCOTP: CmdUnlockOCOTP,
}


class CmdInstallKey(CmdBase):
    """Install key command."""

    def __init__(
        self,
        flags: EnumInsKey = EnumInsKey.CLR,
        cert_fmt: EnumCertFormat = EnumCertFormat.SRK,
        hash_alg: EnumAlgorithm = EnumAlgorithm.ANY,
        src_index: int = 0,
        tgt_index: int = 0,
        location: int = 0,
    ) -> None:
        """Constructor.

        :param flags: from EnumInsKey
        :param cert_fmt: format of the certificate; key authentication protocol
        :param hash_alg: hash algorithm
        :param src_index: source key (verification key, KEK) index
        :param tgt_index: target key index
        :param location: start address of an additional data such as KEY to be installed;
                Typically it is relative to CSF start; Might be absolute for DEK key
        """
        super().__init__(CmdTag.INS_KEY, flags.tag)
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
        return EnumInsKey.from_tag(self._header.param)

    @flags.setter
    def flags(self, value: EnumInsKey) -> None:
        """Flags.

        :raises SPSDKError: If incorrect flag"
        """
        if value not in EnumInsKey:
            raise SPSDKError("Incorrect flag")
        self._header.param = value.tag

    @property
    def certificate_format(self) -> EnumCertFormat:
        """Certificate format."""
        return self._cert_fmt

    @certificate_format.setter
    def certificate_format(self, value: EnumCertFormat) -> None:
        """Setter.

        :param value: certificate format
        :raises SPSDKError: If incorrect certificate format
        """
        if value not in EnumCertFormat:
            raise SPSDKError("Incorrect certificate format")
        self._cert_fmt = value

    @property
    def hash_algorithm(self) -> EnumAlgorithm:
        """Hash algorithm."""
        return self._hash_alg

    @hash_algorithm.setter
    def hash_algorithm(self, value: EnumAlgorithm) -> None:
        """Setter.

        :param value: hash algorithm
        :raises SPSDKError: If incorrect hash algorithm
        """
        if value not in EnumAlgorithm:
            raise SPSDKError("Incorrect hash algorithm")
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
        :raises SPSDKError: If incorrect keys
        :raises SPSDKError: If incorrect keys
        """
        if self._cert_fmt == EnumCertFormat.SRK:
            # This might need update for devices with different count of keys
            if value not in (
                0,
                1,
                2,
                3,
            ):
                raise SPSDKError("Incorrect keys")
        else:
            if value not in (0, 2, 3, 4, 5):
                raise SPSDKError("Incorrect keys")
        self._src_index = value

    @property
    def target_index(self) -> int:
        """Target key index."""
        return self._tgt_index

    @target_index.setter
    def target_index(self, value: int) -> None:
        """Setter.

        :param value: target key index
        :raises SPSDKError: If incorrect key index
        """
        if value not in (0, 1, 2, 3, 4, 5):
            raise SPSDKError("Incorrect key index")
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
        if (
            self.flags == EnumInsKey.ABS
        ):  # reference is an absolute address; instance not assigned; used for DEK key
            if self._certificate_ref is not None:
                raise SPSDKError("Reference is not none")
            return False
        return True

    @property  # type: ignore
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
        """
        assert isinstance(value, (CertificateImg, SrkTable))
        self._certificate_ref = value

    def parse_cmd_data(self, data: bytes) -> Union[CertificateImg, SrkTable, None]:
        """Parse additional command data from binary data.

        :param data: to be parsed
        :return: parsed data object; command-specific: certificate or SrkTable to be installed
        """
        if self.certificate_format == EnumCertFormat.SRK:
            result: Union[CertificateImg, SrkTable] = SrkTable.parse(data)
        else:
            result = CertificateImg.parse(data)
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
        return (
            f"CmdInstallKey <{self.flags.label}, {self.certificate_format.label},"
            f" {self.hash_algorithm.label}, {self.source_index}, "
            f"{self.target_index}, 0x{self.cmd_data_location:X}>"
        )

    def __str__(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().__str__()
        msg += f" Flag      : {self.flags} ({self.flags.description})\n"
        msg += f" CertFormat: {self.certificate_format}"
        msg += f"({self.certificate_format.description})\n"
        msg += f" Algorithm : {self.hash_algorithm} ({self.hash_algorithm.description})\n"
        msg += f" SrcKeyIdx : {self.source_index} (Source key index) \n"
        msg += f" TgtKeyIdx : {self.target_index} (Target key index) \n"
        msg += f" Location  : 0x{self.cmd_data_location:08X} (Start address of certificate(s) to install) \n"
        if self.certificate_ref:
            msg += "[related-certificate]\n"
            msg += str(self.certificate_ref)
        msg += "-" * 60 + "\n"
        return msg

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: binary representation of the command
        """
        raw_data = super().export()
        data = pack(
            ">4BL",
            self.certificate_format.tag,
            self.hash_algorithm.tag,
            self.source_index,
            self.target_index,
            self.cmd_data_location,
        )
        raw_data += data
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: parse command
        """
        header = CmdHeader.parse(data, CmdTag.INS_KEY.tag)
        protocol, algorithm, src_index, tgt_index, location = unpack_from(">4BL", data, header.size)
        return cls(
            EnumInsKey.from_tag(header.param),
            EnumCertFormat.from_tag(protocol),
            EnumAlgorithm.from_tag(algorithm),
            src_index,
            tgt_index,
            location,
        )


# the type represents referenced command data: either Signature or MAC
SignatureOrMAC = Union[MAC, Signature]


class ExpectedSignatureOrMACError(SPSDKError):
    """CmdAuthData additional data block: expected Signature or MAC object."""


class CmdAuthData(CmdBase):
    """Authenticate data command."""

    @property
    def flags(self) -> EnumAuthDat:
        """Flag of Authenticate data command."""
        return EnumAuthDat.from_tag(self._header.param)

    @flags.setter
    def flags(self, value: EnumAuthDat) -> None:
        if value not in EnumAuthDat:
            raise SPSDKError("Incorrect flag")
        self._header.param = value.tag

    @property
    def key_index(self) -> int:
        """Key index."""
        return self._key_index

    @key_index.setter
    def key_index(self, value: int) -> None:
        if value not in (0, 1, 2, 3, 4, 5):
            raise SPSDKError("Incorrect key index")
        self._key_index = value

    @property
    def engine(self) -> EnumEngine:
        """Engine."""
        return self._engine

    @engine.setter
    def engine(self, value: EnumEngine) -> None:
        if value not in EnumEngine:
            raise SPSDKError("Incorrect engine")
        self._engine = value

    def __init__(
        self,
        flags: EnumAuthDat = EnumAuthDat.CLR,
        key_index: int = 1,
        sig_format: EnumCertFormat = EnumCertFormat.CMS,
        engine: EnumEngine = EnumEngine.ANY,
        engine_cfg: int = 0,
        location: int = 0,
        certificate: Optional[Certificate] = None,
        private_key: Optional[PrivateKey] = None,
        signature_provider: Optional[SignatureProvider] = None,
    ):
        """Initialize the Authenticate data command."""
        super().__init__(CmdTag.AUT_DAT, flags.tag)
        self.key_index = key_index
        self.sig_format = sig_format
        self.engine = engine
        self.engine_cfg = engine_cfg
        self.location = location
        self.certificate = certificate
        self.private_key = private_key
        self.signature_provider = signature_provider
        self._header.length = CmdHeader.SIZE + 8
        self._blocks: list[tuple[int, int]] = []  # list of (start-address, size)
        self._signature: Optional[SignatureOrMAC] = None
        if private_key and signature_provider:
            raise SPSDKValueError(
                "Only one of private key and signature provider must be specified"
            )
        if certificate and (private_key or signature_provider):
            public_key = certificate.get_public_key()
            if signature_provider:
                signature_provider.try_to_verify_public_key(public_key)
            else:
                assert isinstance(private_key, PrivateKey)
                if not private_key.verify_public_key(public_key):
                    raise SPSDKError("Given private key does not match the public certificate")

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

    @property  # type: ignore
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
        :raises ExpectedSignatureOrMACError: if unsupported data object is provided
        """
        if self.sig_format == EnumCertFormat.AEAD:
            assert isinstance(value, MAC)
        elif self.sig_format == EnumCertFormat.CMS:
            assert isinstance(value, Signature)
        else:
            raise ExpectedSignatureOrMACError("Unsupported data object is provided")
        self._signature = value

    def parse_cmd_data(self, data: bytes) -> SignatureOrMAC:
        """Parse additional command data from binary data.

        :param data: to be parsed
        :return: parsed data object; command-specific: Signature or MAC
        :raises ExpectedSignatureOrMACError: if unsupported data object is provided
        """
        header = Header.parse(data)
        if header.tag == SegTag.MAC:
            self._signature = MAC.parse(data)
            return self._signature
        if header.tag == SegTag.SIG:
            self._signature = Signature.parse(data)
            return self._signature
        raise ExpectedSignatureOrMACError(f"TAG = {header.tag}")

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
        return (
            f"CmdAuthData <{self.flags.label}, {self.engine.label},"
            f" {self.engine_cfg}, key:{self.key_index}, 0x{self.location:X}>"
        )

    def __len__(self) -> int:
        return len(self._blocks)

    def __getitem__(self, key: int) -> tuple[int, int]:
        return self._blocks[key]

    def __setitem__(self, key: int, value: tuple[int, int]) -> None:
        assert isinstance(value, (list, tuple))
        if len(value) != 2:
            raise SPSDKError("Incorrect length")
        self._blocks[key] = value

    def __iter__(self) -> Iterator[Union[tuple[Any, ...], list[Any]]]:
        return self._blocks.__iter__()

    def __str__(self) -> str:
        """Text description of the command."""
        msg = "-" * 60 + "\n"
        msg += super().__str__()
        msg += f" Flag:        {self.flags} ({self.flags.description})\n"
        msg += f" Key index:   {self.key_index}\n"
        msg += f" Engine:      {self.engine} ({self.engine.description})\n"
        msg += f" Engine Conf: {self.engine_cfg}\n"
        msg += f" Location:    0x{self.location:08X} (Start address of authentication data) \n"
        if self.signature:
            msg += "[related signature]\n"
            msg += str(self.signature)
        msg += "-" * 60 + "\n"
        for blk in self._blocks:
            msg += f"- Start: 0x{blk[0]:08X}, Length: {blk[1]} Bytes\n"
        return msg

    def append(self, start_address: int, size: int) -> None:
        """Append of Authenticate data command."""
        self._blocks.append(
            (start_address, size),
        )
        self._header.length += 8

    def pop(self, index: int) -> tuple[int, int]:
        """Pop of Authenticate data command."""
        if index < 0 or index >= len(self._blocks):
            raise SPSDKError("Incorrect length of blocks")
        value = self._blocks.pop(index)
        self._header.length -= 8
        return value

    def clear(self) -> None:
        """Clear of Authenticate data command."""
        self._blocks.clear()
        self._header.length = self._header.size + 8

    def update_signature(
        self, zulu: datetime, data: bytes, base_data_addr: int = 0xFFFFFFFF
    ) -> bool:
        """Update signature.

        This method must be called from parent to provide data to be signed

        :param zulu: current UTC time+date
        :param data: currently generated binary data
        :param base_data_addr: base address of the generated data
        :raises ValueError: When certificate or private key are not assigned
        :raises ValueError: When signatures not assigned explicitly
        :raises SPSDKError: If incorrect start address
        :raises SPSDKError: If incorrect end address
        :raises SPSDKError: If incorrect length
        :return: True if length of the signature was unchanged, as this may affect content of the CSF section (pointer
                        to data);
        """
        if not self.certificate:
            raise SPSDKAttributeError("Certificate not assigned, cannot update signature")
        if not (self.private_key or self.signature_provider):
            raise SPSDKAttributeError(
                "Private key or signature provider not assigned, cannot update signature"
            )
        if self.signature is None:
            raise SPSDKError(
                "signature must be assigned explicitly, so its version matches to CST version"
            )

        if self._blocks:
            sign_data = b""
            if data:  # if not data specified, create "fake" signature to update length
                total_len = 0
                for blk in self._blocks:
                    start = blk[0] - base_data_addr
                    end = blk[0] + blk[1] - base_data_addr
                    if start < 0:
                        raise SPSDKError("Incorrect start address")
                    if end > len(data):
                        raise SPSDKError("Incorrect end address")
                    sign_data += data[start:end]
                    total_len += blk[1]
                if len(sign_data) != total_len:
                    raise SPSDKError("Incorrect length")
        else:
            sign_data = data  # if no blocks defined, sign complete data; used for CSF
        if isinstance(self.signature, Signature):
            new_signature = cms_sign(
                zulu=zulu,
                data=sign_data,
                certificate=self.certificate,
                signing_key=self.private_key,
                signature_provider=self.signature_provider,
            )
            result = len(self.signature.data) == len(new_signature)
            self.signature.data = new_signature
        else:
            assert isinstance(self.signature, MAC)
            result = True
        return result

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: binary representation of the command
        """
        self._header.length = self.size
        raw_data = super().export()
        raw_data += pack(
            ">4BL",
            self.key_index,
            self.sig_format.tag,
            self.engine.tag,
            self.engine_cfg,
            self.location,
        )
        for blk in self._blocks:
            raw_data += pack(">2L", blk[0], blk[1])
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: parse command
        """
        header = CmdHeader.parse(data, CmdTag.AUT_DAT.tag)
        key, sig_format, eng, cfg, location = unpack_from(">4BL", data, header.size)
        obj = cls(
            EnumAuthDat.from_tag(header.param),
            key,
            EnumCertFormat.from_tag(sig_format),
            EnumEngine.from_tag(eng),
            cfg,
            location,
        )
        index = header.size + 8
        while index < header.length:
            start_address, size = unpack_from(">2L", data, index)
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
    CmdTag.AUT_DAT: CmdAuthData,
}


def parse_command(data: bytes) -> CmdBase:
    """Parse CSF/DCD command.

    :param data: binary data to be parsed
    :return: instance of the command
    :raises SPSDKError: If the command is not valid
    """
    try:
        cmd_tag = CmdTag.from_tag(data[0])
    except SPSDKKeyError as exc:
        raise SPSDKError("Unknown command to parse") from exc
    cmd_class = _CMD_TO_CLASS[cmd_tag]
    return cmd_class.parse(data)
