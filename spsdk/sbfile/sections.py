#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Sections within SBfile."""

from struct import unpack_from
from typing import Iterator, List, Optional

from spsdk import SPSDKError
from spsdk.utils.crypto import CertBlockV2, Counter
from spsdk.utils.crypto.abstract import BaseClass
from spsdk.utils.crypto.common import calc_cypher_block_count, crypto_backend

from .commands import CmdBaseClass, CmdHeader, EnumCmdTag, EnumSectionFlag, parse_command

########################################################################################################################
# Boot Image Sections
########################################################################################################################


class BootSectionV2(BaseClass):
    """Boot Section V2."""

    HMAC_SIZE = 32

    @property
    def uid(self) -> int:
        """Boot Section UID."""
        return self._header.address

    @uid.setter
    def uid(self, value: int) -> None:
        self._header.address = value

    @property
    def is_last(self) -> bool:
        """Check whether the section is the last one."""
        return self._header.flags & EnumSectionFlag.LAST_SECT != 0

    @is_last.setter
    def is_last(self, value: bool) -> None:
        assert isinstance(value, bool)
        self._header.flags = EnumSectionFlag.BOOTABLE
        if value:
            self._header.flags |= EnumSectionFlag.LAST_SECT

    @property
    def hmac_count(self) -> int:
        """Number of HMACs."""
        raw_size = 0
        hmac_count = 0
        for cmd in self._commands:
            raw_size += cmd.raw_size
        if raw_size > 0:
            block_count = (raw_size + 15) // 16
            hmac_count = self._hmac_count if block_count >= self._hmac_count else block_count
        return hmac_count

    @property
    def raw_size(self) -> int:
        """Raw size of section."""
        size = CmdHeader.SIZE + self.HMAC_SIZE
        size += self.hmac_count * self.HMAC_SIZE
        for cmd in self._commands:
            size += cmd.raw_size
        if size % 16:
            size += 16 - (size % 16)
        return size

    def __init__(self, uid: int, *commands: CmdBaseClass, hmac_count: int = 1) -> None:
        """Initialize BootSectionV2.

        :param uid: section unique identification
        :param commands: List of commands
        :param hmac_count: The number of HMAC entries
        """
        self._header = CmdHeader(EnumCmdTag.TAG, EnumSectionFlag.BOOTABLE)
        self._commands: List[CmdBaseClass] = []
        self._hmac_count = hmac_count
        for cmd in commands:
            self.append(cmd)
        # Initialize HMAC count
        if not isinstance(self._hmac_count, int) or self._hmac_count == 0:
            self._hmac_count = 1
        # section UID
        self.uid = uid

    def __str__(self) -> str:
        pass

    def __len__(self) -> int:
        return len(self._commands)

    def __getitem__(self, key: int) -> CmdBaseClass:
        return self._commands[key]

    def __setitem__(self, key: int, value: CmdBaseClass) -> None:
        self._commands[key] = value

    def __iter__(self) -> Iterator[CmdBaseClass]:
        return self._commands.__iter__()

    def append(self, cmd: CmdBaseClass) -> None:
        """Add command to section."""
        assert isinstance(cmd, CmdBaseClass)
        self._commands.append(cmd)

    def info(self) -> str:
        """Get object info."""
        nfo = ""
        for index, cmd in enumerate(self._commands):
            nfo += f" {index}) {cmd.info()}\n"
        return nfo

    # pylint: disable=too-many-locals
    def export(
        self,
        dek: bytes = b"",
        mac: bytes = b"",
        counter: Optional[Counter] = None,
        dbg_info: Optional[List[str]] = None,
    ) -> bytes:
        """Serialize Boot Section object.

        :param dek: The DEK value in bytes (required)
        :param mac: The MAC value in bytes (required)
        :param counter: The counter object (required)
        :param dbg_info: Optional[List[str]] optional list to export debug information about content in text format
        :return: exported bytes
        :raise Exception: raised when dek, mac, counter have invalid format
        """
        cmd_dbg_info: Optional[List[str]] = None
        if dbg_info is not None:
            dbg_info.append("[bootable_section]")
            cmd_dbg_info = list()
            cmd_dbg_info.append("[commands]")
        if not isinstance(dek, bytes):
            raise Exception()
        if not isinstance(mac, bytes):
            raise Exception()
        if not isinstance(counter, Counter):
            raise Exception()
        # Export commands
        commands_data = b""
        for cmd in self._commands:
            cmd_data = cmd.export()
            commands_data += cmd_data
            if cmd_dbg_info is not None:
                cmd_dbg_info.append(f"[command:{type(cmd).__name__}]")
                cmd_dbg_info.append(cmd_data.hex())
        if len(commands_data) % 16:
            commands_data += b"\x00" * (16 - (len(commands_data) % 16))
        # Encrypt header
        self._header.data = self.hmac_count
        self._header.count = len(commands_data) // 16
        encrypted_header = crypto_backend().aes_ctr_encrypt(
            dek, self._header.export(), counter.value
        )
        hmac_data = crypto_backend().hmac(mac, encrypted_header)
        counter.increment(1 + (self.hmac_count + 1) * 2)
        if dbg_info:
            dbg_info.append("[header]")
            dbg_info.append(self._header.export().hex())
            dbg_info.append("[encrypted_header]")
            dbg_info.append(encrypted_header.hex())
            dbg_info.append("[hmac]")
            dbg_info.append(hmac_data.hex())
            if cmd_dbg_info:
                dbg_info.extend(cmd_dbg_info)
        # Encrypt commands
        encrypted_commands = b""
        for index in range(0, len(commands_data), 16):
            encrypted_block = crypto_backend().aes_ctr_encrypt(
                dek, commands_data[index : index + 16], counter.value
            )
            encrypted_commands += encrypted_block
            counter.increment()
        # Calculate HMAC of commands
        index = 0
        hmac_count = self._header.data
        block_size = (self._header.count // hmac_count) * 16
        while hmac_count > 0:
            enc_block = (
                encrypted_commands[index:]
                if hmac_count == 1
                else encrypted_commands[index : index + block_size]
            )
            hmac_data += crypto_backend().hmac(mac, enc_block)
            hmac_count -= 1
            index += len(enc_block)
        return encrypted_header + hmac_data + encrypted_commands

    # pylint: disable=too-many-locals
    @classmethod
    def parse(
        cls,
        data: bytes,
        offset: int = 0,
        plain_sect: bool = False,
        dek: bytes = b"",
        mac: bytes = b"",
        counter: Optional[Counter] = None,
    ) -> "BootSectionV2":
        """Parse Boot Section from bytes.

        :param data: Raw data of parsed image
        :param offset: The offset of input data
        :param plain_sect: If the sections are not encrypted; It is used for debugging only, not supported by ROM code
        :param dek: The DEK value in bytes (required)
        :param mac: The MAC value in bytes (required)
        :param counter: The counter object (required)
        :return: exported bytes
        :raise Exception: raised when dek, mac, counter have invalid format
        """
        if not isinstance(dek, bytes):
            raise Exception()
        if not isinstance(mac, bytes):
            raise Exception()
        if not isinstance(counter, Counter):
            raise Exception()
        # Get Header specific data
        header_encrypted = data[offset : offset + CmdHeader.SIZE]
        header_hmac_data = data[offset + CmdHeader.SIZE : offset + CmdHeader.SIZE + cls.HMAC_SIZE]
        offset += CmdHeader.SIZE + cls.HMAC_SIZE
        # Check header HMAC
        if header_hmac_data != crypto_backend().hmac(mac, header_encrypted):
            raise Exception()
        # Decrypt header
        header_decrypted = crypto_backend().aes_ctr_decrypt(dek, header_encrypted, counter.value)
        counter.increment()
        # Parse header
        header = CmdHeader.parse(header_decrypted)
        counter.increment((header.data + 1) * 2)
        # Get HMAC data
        hmac_data = data[offset : offset + (cls.HMAC_SIZE * header.data)]
        offset += cls.HMAC_SIZE * header.data
        encrypted_commands = data[offset : offset + (header.count * 16)]
        # Check HMAC
        hmac_index = 0
        hmac_count = header.data
        block_size = (header.count // hmac_count) * 16
        section_size = header.count * 16
        while hmac_count > 0:
            if hmac_count == 1:
                block_size = section_size
            hmac_block = crypto_backend().hmac(mac, data[offset : offset + block_size])
            if hmac_block != hmac_data[hmac_index : hmac_index + cls.HMAC_SIZE]:
                raise Exception()
            hmac_count -= 1
            hmac_index += cls.HMAC_SIZE
            section_size -= block_size
            offset += block_size
        # Decrypt commands
        decrypted_commands = b""
        for hmac_index in range(0, len(encrypted_commands), 16):
            encr_block = encrypted_commands[hmac_index : hmac_index + 16]
            decrypted_block = (
                encr_block
                if plain_sect
                else crypto_backend().aes_ctr_decrypt(dek, encr_block, counter.value)
            )
            decrypted_commands += decrypted_block
            counter.increment()
        # ...
        cmd_offset = 0
        obj = cls(header.address, hmac_count=header.data)
        while cmd_offset < len(decrypted_commands):
            cmd_obj = parse_command(decrypted_commands, cmd_offset)
            cmd_offset += cmd_obj.raw_size
            obj.append(cmd_obj)
        return obj


class CertSectionV2(BaseClass):
    """Certificate Section V2 class."""

    HMAC_SIZE = 32
    SECT_MARK = unpack_from("<L", b"sign")[0]

    @property
    def cert_block(self) -> CertBlockV2:
        """Return certification block."""
        return self._cert_block

    @property
    def raw_size(self) -> int:
        """Calculate raw size of section."""
        # Section header size
        size = CmdHeader.SIZE
        # Header HMAC 32 bytes + Certificate block HMAC 32 bytes
        size += self.HMAC_SIZE * 2
        # Certificate block size in bytes
        size += self.cert_block.raw_size
        return size

    def __init__(self, cert_block: CertBlockV2):
        """Initialize CertBlockV2."""
        assert isinstance(cert_block, CertBlockV2)
        self._header = CmdHeader(
            EnumCmdTag.TAG, EnumSectionFlag.CLEARTEXT | EnumSectionFlag.LAST_SECT
        )
        self._header.address = self.SECT_MARK
        self._header.count = cert_block.raw_size // 16
        self._header.data = 1
        self._cert_block = cert_block

    def __str__(self) -> str:
        return f"CertSectionV2: Length={self._header.count * 16}"

    def info(self) -> str:
        """Get object info."""
        return self.cert_block.info()

    def export(
        self, dek: bytes = b"", mac: bytes = b"", counter: Optional[Counter] = None
    ) -> bytes:
        """Serialize Certificate Section object.

        :param dek: The DEK value in bytes (required)
        :param mac: The MAC value in bytes (required)
        :param counter: The counter object (required)
        :return: exported bytes
        :raise Exception: raised when dek, mac, counter have invalid format
        :raises SPSDKError: Raised size of exported bytes is invalid
        """
        if not isinstance(dek, bytes):
            raise Exception()
        if not isinstance(mac, bytes):
            raise Exception()
        if not isinstance(counter, Counter):
            raise Exception()
        # Prepare Header data
        header_data = self._header.export()
        header_encrypted = crypto_backend().aes_ctr_encrypt(dek, header_data, counter.value)
        # counter.increment()
        # Prepare Certificate Block data
        body_data = self.cert_block.export()
        # Prepare HMAC data
        hmac_data = crypto_backend().hmac(mac, header_encrypted)
        hmac_data += crypto_backend().hmac(mac, body_data)
        result = header_encrypted + hmac_data + body_data
        if len(result) != self.raw_size:
            raise SPSDKError("Invalid size")
        return result

    @classmethod
    def parse(
        cls,
        data: bytes,
        offset: int = 0,
        dek: bytes = b"",
        mac: bytes = b"",
        counter: Optional[Counter] = None,
    ) -> "CertSectionV2":
        """Parse Certificate Section from bytes array.

        :param data: Raw data of parsed image
        :param offset: The offset of input data
        :param dek: The DEK value in bytes (required)
        :param mac: The MAC value in bytes (required)
        :param counter: The counter object (required)
        :return: parsed cert section v2 object
        :raises SPSDKError: Raised when dek, mac, counter are not valid
        :raises SPSDKError: Raised when there is invalid header HMAC, TAG, FLAGS, Mark
        :raises SPSDKError: Raised when there is invalid certificate block HMAC
        """
        if not isinstance(dek, bytes):
            raise SPSDKError("DEK value has invalid format")
        if not isinstance(mac, bytes):
            raise SPSDKError("MAC value has invalid format")
        if not isinstance(counter, Counter):
            raise SPSDKError("Counter value has invalid format")
        index = offset
        header_encrypted = data[index : index + CmdHeader.SIZE]
        index += CmdHeader.SIZE
        header_hmac = data[index : index + cls.HMAC_SIZE]
        index += cls.HMAC_SIZE
        cert_block_hmac = data[index : index + cls.HMAC_SIZE]
        index += cls.HMAC_SIZE
        if header_hmac != crypto_backend().hmac(mac, header_encrypted):
            raise SPSDKError("Invalid Header HMAC")
        header_encrypted = crypto_backend().aes_ctr_decrypt(dek, header_encrypted, counter.value)
        header = CmdHeader.parse(header_encrypted)
        if header.tag != EnumCmdTag.TAG:
            raise SPSDKError(f"Invalid Header TAG: 0x{header.tag:02X}")
        if header.flags != (EnumSectionFlag.CLEARTEXT | EnumSectionFlag.LAST_SECT):
            raise SPSDKError(f"Invalid Header FLAGS: 0x{header.flags:02X}")
        if header.address != cls.SECT_MARK:
            raise SPSDKError(f"Invalid Section Mark: 0x{header.address:08X}")
        # Parse Certificate Block
        cert_block = CertBlockV2.parse(data, index)
        if cert_block_hmac != crypto_backend().hmac(mac, data[index : index + cert_block.raw_size]):
            raise SPSDKError("Invalid Certificate Block HMAC")
        index += cert_block.raw_size
        cert_section_obj = cls(cert_block)
        counter.increment(calc_cypher_block_count(index - offset))
        return cert_section_obj
