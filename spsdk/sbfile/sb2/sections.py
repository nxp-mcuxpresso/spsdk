#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB2 file sections implementation.

This module provides section classes for SB2 (Secure Binary version 2) file format,
including boot sections and certificate sections with encryption and authentication
capabilities.
"""

from struct import unpack_from
from typing import Iterator, Optional

from spsdk.crypto.spsdk_hmac import hmac
from spsdk.crypto.symmetric import Counter, aes_ctr_decrypt, aes_ctr_encrypt
from spsdk.exceptions import SPSDKError
from spsdk.image.cert_block.cert_blocks import CertBlockV1
from spsdk.sbfile.misc import SecBootBlckSize
from spsdk.sbfile.sb2.commands import (
    CmdBaseClass,
    CmdHeader,
    EnumCmdTag,
    EnumSectionFlag,
    parse_command,
)
from spsdk.utils.abstract import BaseClass

########################################################################################################################
# Boot Image Sections
########################################################################################################################


class BootSectionV2(BaseClass):
    """Boot Section V2 for Secure Binary file format.

    This class represents a boot section in the SB2.x file format, managing
    commands, HMAC authentication data, and section metadata. It provides
    functionality for building bootable sections with cryptographic integrity
    protection.

    :cvar HMAC_SIZE: Size of HMAC in bytes (32).
    """

    HMAC_SIZE = 32

    @property
    def uid(self) -> int:
        """Get Boot Section UID.

        :return: The unique identifier of the boot section.
        """
        return self._header.address

    @uid.setter
    def uid(self, value: int) -> None:
        """Set the unique identifier for the section.

        The UID is stored in the header address field and is used to identify
        this specific section within the SB2 file structure.

        :param value: The unique identifier value to assign to this section.
        """
        self._header.address = value

    @property
    def is_last(self) -> bool:
        """Check whether the section is the last one.

        This method examines the section header flags to determine if the current
        section is marked as the last section in the sequence.

        :return: True if this is the last section, False otherwise.
        """
        return self._header.flags & EnumSectionFlag.LAST_SECT.tag != 0

    @is_last.setter
    def is_last(self, value: bool) -> None:
        """Set the last section flag for this section.

        This method configures the section header flags to mark whether this section
        is the last section in the SB2 file. The bootable flag is always set, and
        the last section flag is conditionally added based on the input parameter.

        :param value: True if this is the last section, False otherwise.
        """
        assert isinstance(value, bool)
        self._header.flags = EnumSectionFlag.BOOTABLE.tag
        if value:
            self._header.flags |= EnumSectionFlag.LAST_SECT.tag

    @property
    def hmac_count(self) -> int:
        """Calculate the number of HMACs required for the section.

        The method determines the HMAC count based on the total raw size of all commands
        in the section. It calculates the number of 16-byte blocks needed and returns
        the minimum between the configured HMAC count and the actual block count.

        :return: Number of HMACs required for this section.
        """
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
        """Get the raw size of the section in bytes.

        Calculates the total size including command header, HMAC data, all commands,
        and padding to ensure 16-byte alignment.

        :return: Total raw size of the section in bytes.
        """
        size = CmdHeader.SIZE + self.HMAC_SIZE
        size += self.hmac_count * self.HMAC_SIZE
        for cmd in self._commands:
            size += cmd.raw_size
        if size % 16:
            size += 16 - (size % 16)
        return size

    def __init__(
        self,
        uid: int,
        *commands: CmdBaseClass,
        hmac_count: int = 1,
        zero_filling: bool = False,
    ) -> None:
        """Initialize BootSectionV2.

        :param uid: Section unique identification number.
        :param commands: Variable number of command objects to include in the section.
        :param hmac_count: The number of HMAC entries, defaults to 1.
        :param zero_filling: If True, the section will be zero-filled, defaults to False.
        """
        self._header = CmdHeader(
            EnumCmdTag.TAG.tag, EnumSectionFlag.BOOTABLE.tag, zero_filling=zero_filling
        )
        self._commands: list[CmdBaseClass] = []
        self._hmac_count = hmac_count
        for cmd in commands:
            self.append(cmd)
        # Initialize HMAC count
        if not isinstance(self._hmac_count, int) or self._hmac_count == 0:
            self._hmac_count = 1
        # section UID
        self.uid = uid

    def __len__(self) -> int:
        """Get the number of commands in the section.

        :return: Number of commands stored in this section.
        """
        return len(self._commands)

    def __getitem__(self, key: int) -> CmdBaseClass:
        """Get command at specified index.

        :param key: Index of the command to retrieve.
        :return: Command object at the specified index.
        """
        return self._commands[key]

    def __setitem__(self, key: int, value: CmdBaseClass) -> None:
        """Set command at specified index in the commands list.

        :param key: Index position where to set the command.
        :param value: Command object to be set at the specified index.
        """
        self._commands[key] = value

    def __iter__(self) -> Iterator[CmdBaseClass]:
        """Return iterator over commands in the section.

        :return: Iterator yielding command objects from the internal commands collection.
        """
        return self._commands.__iter__()

    def append(self, cmd: CmdBaseClass) -> None:
        """Add command to section.

        :param cmd: Command object to be added to the section.
        :raises AssertionError: If cmd is not an instance of CmdBaseClass.
        """
        assert isinstance(cmd, CmdBaseClass)
        self._commands.append(cmd)

    def __repr__(self) -> str:
        """Return string representation of BootSectionV2 object.

        Provides a human-readable string showing the class name and number of commands
        contained in this boot section.

        :return: String representation in format "BootSectionV2: X commands."
        """
        return f"BootSectionV2: {len(self)} commands."

    def __str__(self) -> str:
        """Get string representation of the section with all commands.

        The method iterates through all commands in the section and formats them
        as a numbered list for display purposes.

        :return: Formatted string containing indexed list of all commands in the section.
        """
        nfo = ""
        for index, cmd in enumerate(self._commands):
            nfo += f" {index}) {str(cmd)}\n"
        return nfo

    # pylint: disable=too-many-locals
    def export(
        self,
        dek: bytes = b"",
        mac: bytes = b"",
        counter: Optional[Counter] = None,
    ) -> bytes:
        """Export Boot Section object to encrypted binary format.

        The method encrypts the section header and commands using AES-CTR encryption,
        calculates HMAC for integrity protection, and returns the complete encrypted
        section data ready for secure boot file generation.

        :param dek: Data Encryption Key used for AES-CTR encryption of header and commands
        :param mac: Message Authentication Code key for HMAC calculation
        :param counter: Counter object for AES-CTR mode encryption, gets incremented during process
        :return: Encrypted section data containing header, HMAC data, and encrypted commands
        :raises SPSDKError: Invalid parameter types or missing commands in section
        """
        if not isinstance(dek, bytes):
            raise SPSDKError("Invalid type of dek, should be bytes")
        if not isinstance(mac, bytes):
            raise SPSDKError("Invalid type of mac, should be bytes")
        if not isinstance(counter, Counter):
            raise SPSDKError("Invalid type of counter")
        if not self._commands:
            raise SPSDKError("SB2 must contain commands")
        # Export commands
        commands_data = b""
        for cmd in self._commands:
            cmd_data = cmd.export()
            commands_data += cmd_data
        if len(commands_data) % 16:
            commands_data += b"\x00" * (16 - (len(commands_data) % 16))
        # Encrypt header
        self._header.data = self.hmac_count
        self._header.count = len(commands_data) // 16
        encrypted_header = aes_ctr_encrypt(dek, self._header.export(), counter.value)
        hmac_data = hmac(mac, encrypted_header)
        counter.increment(1 + (self.hmac_count + 1) * 2)

        # Encrypt commands
        encrypted_commands = b""
        for index in range(0, len(commands_data), 16):
            encrypted_block = aes_ctr_encrypt(dek, commands_data[index : index + 16], counter.value)
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
            hmac_data += hmac(mac, enc_block)
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

        Decrypts and parses a boot section from raw binary data, validating HMAC integrity
        and extracting commands. The method handles encrypted sections with proper counter
        management and HMAC verification.

        :param data: Raw binary data containing the boot section to parse.
        :param offset: Starting offset within the data buffer for parsing.
        :param plain_sect: Whether sections are unencrypted (debugging only, not ROM supported).
        :param dek: Data Encryption Key as bytes for decryption.
        :param mac: Message Authentication Code as bytes for HMAC verification.
        :param counter: Counter object for AES-CTR decryption state management.
        :return: Parsed BootSectionV2 object containing the extracted commands.
        :raises SPSDKError: Invalid parameter types or HMAC verification failure.
        """
        if not isinstance(dek, bytes):
            raise SPSDKError("Invalid type of dek, should be bytes")
        if not isinstance(mac, bytes):
            raise SPSDKError("Invalid type of mac, should be bytes")
        if not isinstance(counter, Counter):
            raise SPSDKError("Invalid type of counter")
        # Get Header specific data
        header_encrypted = data[offset : offset + CmdHeader.SIZE]
        header_hmac_data = data[offset + CmdHeader.SIZE : offset + CmdHeader.SIZE + cls.HMAC_SIZE]
        offset += CmdHeader.SIZE + cls.HMAC_SIZE
        # Check header HMAC
        if header_hmac_data != hmac(mac, header_encrypted):
            raise SPSDKError("Invalid header HMAC")
        # Decrypt header
        header_decrypted = aes_ctr_decrypt(dek, header_encrypted, counter.value)
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
            hmac_block = hmac(mac, data[offset : offset + block_size])
            if hmac_block != hmac_data[hmac_index : hmac_index + cls.HMAC_SIZE]:
                raise SPSDKError("HMAC failed")
            hmac_count -= 1
            hmac_index += cls.HMAC_SIZE
            section_size -= block_size
            offset += block_size
        # Decrypt commands
        decrypted_commands = b""
        for hmac_index in range(0, len(encrypted_commands), 16):
            encr_block = encrypted_commands[hmac_index : hmac_index + 16]
            decrypted_block = (
                encr_block if plain_sect else aes_ctr_decrypt(dek, encr_block, counter.value)
            )
            decrypted_commands += decrypted_block
            counter.increment()
        # ...
        cmd_offset = 0
        obj = cls(header.address, hmac_count=header.data)
        while cmd_offset < len(decrypted_commands):
            cmd_obj = parse_command(decrypted_commands[cmd_offset:])
            cmd_offset += cmd_obj.raw_size
            obj.append(cmd_obj)
        return obj


class CertSectionV2(BaseClass):
    """SB2 Certificate Section V2 representation.

    This class manages certificate sections in Secure Binary 2.0 files, handling
    certificate block data with proper HMAC validation and section formatting.

    :cvar HMAC_SIZE: Size of HMAC in bytes (32).
    :cvar SECT_MARK: Section marker identifier for certificate sections.
    """

    HMAC_SIZE = 32
    SECT_MARK = unpack_from("<L", b"sign")[0]

    @property
    def cert_block(self) -> CertBlockV1:
        """Get certification block.

        :return: Certification block instance.
        """
        return self._cert_block

    @property
    def raw_size(self) -> int:
        """Calculate raw size of section in bytes.

        The method calculates the total size including section header, HMAC values
        for both header and certificate block, and the certificate block itself.

        :return: Total raw size of the section in bytes.
        """
        # Section header size
        size = CmdHeader.SIZE
        # Header HMAC 32 bytes + Certificate block HMAC 32 bytes
        size += self.HMAC_SIZE * 2
        # Certificate block size in bytes
        size += self.cert_block.raw_size
        return size

    def __init__(self, cert_block: CertBlockV1):
        """Initialize certificate block section.

        Creates a new certificate block section with proper header configuration
        including section flags and address marking.

        :param cert_block: Certificate block to be wrapped in this section.
        :raises AssertionError: If cert_block is not an instance of CertBlockV1.
        """
        assert isinstance(cert_block, CertBlockV1)
        self._header = CmdHeader(
            EnumCmdTag.TAG.tag, EnumSectionFlag.CLEARTEXT.tag | EnumSectionFlag.LAST_SECT.tag
        )
        self._header.address = self.SECT_MARK
        self._header.count = cert_block.raw_size // 16
        self._header.data = 1
        self._cert_block = cert_block

    def __repr__(self) -> str:
        """Return string representation of CertSectionV2 object.

        :return: String containing class name and length information.
        """
        return f"CertSectionV2: Length={self._header.count * 16}"

    def __str__(self) -> str:
        """Get string representation of the object.

        :return: String representation of the certificate block.
        """
        return str(self.cert_block)

    def export(
        self, dek: bytes = b"", mac: bytes = b"", counter: Optional[Counter] = None
    ) -> bytes:
        """Export Certificate Section object to binary format.

        The method encrypts the header using AES-CTR, generates HMAC for authentication,
        and combines all components into the final binary representation.

        :param dek: Data Encryption Key in bytes format for AES-CTR encryption.
        :param mac: Message Authentication Code key in bytes for HMAC generation.
        :param counter: Counter object used for AES-CTR encryption mode.
        :return: Binary representation of the certificate section.
        :raises SPSDKError: Invalid parameter type for dek, mac, or counter.
        :raises SPSDKError: Exported data size doesn't match expected raw size.
        """
        if not isinstance(dek, bytes):
            raise SPSDKError("DEK value is not in bytes")
        if not isinstance(mac, bytes):
            raise SPSDKError("MAC value is not in bytes")
        if not isinstance(counter, Counter):
            raise SPSDKError("Counter value is not incorrect")
        # Prepare Header data
        header_data = self._header.export()
        header_encrypted = aes_ctr_encrypt(dek, header_data, counter.value)
        # counter.increment()
        # Prepare Certificate Block data
        body_data = self.cert_block.export()
        # Prepare HMAC data
        hmac_data = hmac(mac, header_encrypted)
        hmac_data += hmac(mac, body_data)
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

        Parses and validates an encrypted certificate section with HMAC verification,
        decrypts the header, and extracts the certificate block.

        :param data: Raw data of parsed image.
        :param offset: The offset of input data.
        :param dek: The DEK value in bytes (required).
        :param mac: The MAC value in bytes (required).
        :param counter: The counter object (required).
        :return: Parsed cert section v2 object.
        :raises SPSDKError: Raised when dek, mac, counter are not valid.
        :raises SPSDKError: Raised when there is invalid header HMAC, TAG, FLAGS, Mark.
        :raises SPSDKError: Raised when there is invalid certificate block HMAC.
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
        if header_hmac != hmac(mac, header_encrypted):
            raise SPSDKError("Invalid Header HMAC")
        header_encrypted = aes_ctr_decrypt(dek, header_encrypted, counter.value)
        header = CmdHeader.parse(header_encrypted)
        if header.tag != EnumCmdTag.TAG:
            raise SPSDKError(f"Invalid Header TAG: 0x{header.tag:02X}")
        if header.flags != (EnumSectionFlag.CLEARTEXT.tag | EnumSectionFlag.LAST_SECT.tag):
            raise SPSDKError(f"Invalid Header FLAGS: 0x{header.flags:02X}")
        if header.address != cls.SECT_MARK:
            raise SPSDKError(f"Invalid Section Mark: 0x{header.address:08X}")
        # Parse Certificate Block
        cert_block = CertBlockV1.parse(data[index:])
        if cert_block_hmac != hmac(mac, data[index : index + cert_block.raw_size]):
            raise SPSDKError("Invalid Certificate Block HMAC")
        index += cert_block.raw_size
        cert_section_obj = cls(cert_block)
        counter.increment(SecBootBlckSize.to_num_blocks(index - offset))
        return cert_section_obj
