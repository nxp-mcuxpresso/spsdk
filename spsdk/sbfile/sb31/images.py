#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module used for generation SecureBinary V3.1."""
from datetime import datetime
from typing import List, Sequence
from struct import pack, unpack_from, calcsize

from spsdk import SPSDKError
from spsdk.sbfile.sb31.functions import KeyDerivator
from spsdk.utils.misc import align_block
from spsdk.utils.crypto.abstract import BaseClass
from spsdk.sbfile.sb31.commands import BaseCmd, CmdSectionHeader
from spsdk.utils.crypto.backend_internal import internal_backend


########################################################################################################################
# Secure Boot Image Class (Version 3.1)
########################################################################################################################
class SecureBinary31Header(BaseClass):
    """Header of the SecureBinary V3.1."""

    HEADER_FORMAT = "<4s2H3LQ4L16s"
    HEADER_SIZE = calcsize(HEADER_FORMAT)
    MAGIC = b"sbv3"
    FORMAT_VERSION = "3.1"
    DESCRIPTION_LENGTH = 16

    def __init__(
        self,
        firmware_version: int,
        curve_name: str,
        description: str = None,
        timestamp: int = None,
        is_nxp_container: bool = False,
        flags: int = 0,
    ) -> None:
        """Initialize the SecureBinary V3.1 Header.

        :param firmware_version: Firmaware version (must be bigger than current CMPA record)
        :param curve_name: Name of the ECC curve used for Secure binary (secp256r1/secp384r1)
        :param description: Custom description up to 16 characters long, defaults to None
        :param timestamp: Timestap (number of seconds since Jan 1st, 200), if None use current time
        :param is_nxp_container: NXP provisioning SB file, defaults to False
        :param flags: Flags for SB file (currently un-used), defaults to 0
        """
        self.flags = flags
        self.block_count = 0
        self.curve_name = curve_name
        self.block_size = self.calculate_block_size()
        self.image_type = 7 if is_nxp_container else 6
        self.firmware_version = firmware_version
        self.timestamp = timestamp or int(datetime.now().timestamp())
        self.image_total_length = self.HEADER_SIZE
        self.cert_block_offset = self.calculate_cert_block_offset()
        self.description = self._adjust_description(description)

    def _adjust_description(self, description: str = None) -> bytes:
        """Format the description."""
        if not description:
            return bytes(self.DESCRIPTION_LENGTH)
        desc = bytes(description, encoding="ascii")
        desc = desc[: self.DESCRIPTION_LENGTH]
        desc += bytes(self.DESCRIPTION_LENGTH - len(desc))
        return desc

    def calculate_cert_block_offset(self) -> int:
        """Calculate the offset to the Certification block."""
        fixed_offset = 1 * 8 + 9 * 4 + 16
        if self.curve_name == "secp256r1":
            return fixed_offset + 32
        if self.curve_name == "secp384r1":
            return fixed_offset + 48
        raise SPSDKError(f"Invalid curve name: {self.curve_name}")

    def calculate_block_size(self) -> int:
        """Calculate the the data block size."""
        fixed_block_size = 4 + 256
        if self.curve_name == "secp256r1":
            return fixed_block_size + 32
        if self.curve_name == "secp384r1":
            return fixed_block_size + 48
        raise SPSDKError(f"Invalid curve name: {self.curve_name}")

    def info(self) -> str:
        """Get info of SB v31 as a string."""
        info = str()
        info += f" Magic:                       {self.MAGIC.decode('ascii')}\n"
        info += f" Version:                     {self.FORMAT_VERSION}\n"
        info += f" Flags:                       0x{self.flags:04X}\n"
        info += f" Block count:                 {self.block_count}\n"
        info += f" Block size:                  {self.block_size}\n"
        info += f" Firmware version:            {self.firmware_version}\n"
        info += f" Image type:                  {self.image_type}\n"
        info += f" Timestamp:                   {self.timestamp}\n"
        info += f" Total length of image:       {self.image_total_length}\n"
        info += f" Certificate block offset:    {self.cert_block_offset}\n"
        info += f" Description:                 {self.description.decode('ascii')}\n"
        return info

    def export(self) -> bytes:
        """Serialize the SB file to bytes."""
        major_format_version, minor_format_version = [
            int(v) for v in self.FORMAT_VERSION.split(".")
        ]
        return pack(
            self.HEADER_FORMAT,
            self.MAGIC,
            minor_format_version,
            major_format_version,
            self.flags,
            self.block_count,
            self.block_size,
            self.timestamp,
            self.firmware_version,
            self.image_total_length,
            self.image_type,
            self.cert_block_offset,
            self.description,
        )

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "SecureBinary31Header":
        """Parse binary data into SecureBinary31Header.

        :raises NotImplementedError: Not yet implemented
        """
        raise NotImplementedError()


class SecureBinary31Commands(BaseClass):
    """Blob containing SB3.1 commands."""

    DATA_CHUNK_LENGTH = 256

    def __init__(
        self,
        curve_name: str,
        is_encrypted: bool = True,
        pck: bytes = None,
        timestamp: int = None,
        kdk_access_rights: int = None,
    ) -> None:
        """Initialize container for SB3.1 commands.

        :param curve_name: Name of the ECC curve used for Secure binary (secp256r1/secp384r1)
        :param is_encrypted: Indicate whether commands should be encrypted or not, defaults to True
        :param pck: Part Common Key (needed if `is_encrypted` is True), defaults to None
        :param timestamp: Timestamp used for encryption (needed if `is_encrypted` is True), defaults to None
        :param kdk_access_rights: Key Derivation Key access rights (needed if `is_encrypted` is True), defaults to None
        :raises SPSDKError: Key derivation arguments are not provided if `is_encrypted` is True
        """
        super().__init__()
        self.curve_name = curve_name
        self.hash_type = self._get_hash_type(curve_name)
        self.is_encrypted = is_encrypted
        self.block_count = 0
        self.final_hash = bytes(self._get_hash_length(curve_name))
        self.commands: List[BaseCmd] = []
        self.key_derivator = None
        if is_encrypted:
            if not (pck and timestamp and kdk_access_rights):
                raise SPSDKError("PCK, timeout or kdk_access_rights are not defined.")
            self.key_derivator = KeyDerivator(
                pck=pck,
                timestamp=timestamp,
                key_length=self._get_key_length(curve_name),
                kdk_access_rights=kdk_access_rights,
            )

    def _get_hash_length(self, curve_name: str) -> int:
        return {"secp256r1": 32, "secp384r1": 48}[curve_name]

    def _get_key_length(self, curve_name: str) -> int:
        return {"secp256r1": 128, "secp384r1": 256}[curve_name]

    def _get_hash_type(self, curve_name: str) -> str:
        return {"secp256r1": "sha256", "secp384r1": "sha384"}[curve_name]

    def add_command(self, command: BaseCmd) -> None:
        """Add SB3.1 command."""
        self.commands.append(command)

    def set_commands(self, commands: List[BaseCmd]) -> None:
        """Set all SB3.1 commands at once."""
        self.commands = commands.copy()

    def export(self) -> bytes:
        """Export commands as bytes."""
        commands_bytes = b"".join([command.export() for command in self.commands])
        section_header = CmdSectionHeader(length=len(commands_bytes))
        total = section_header.export() + commands_bytes

        data_blocks = [
            total[i : i + self.DATA_CHUNK_LENGTH]
            for i in range(0, len(total), self.DATA_CHUNK_LENGTH)
        ]
        data_blocks[-1] = align_block(data_blocks[-1], alignment=self.DATA_CHUNK_LENGTH)
        self.block_count = len(data_blocks)

        processed_blocks = [
            self._process_block(block_number, block_data)
            for block_number, block_data in reversed(list(enumerate(data_blocks, start=1)))
        ]
        final_data = b"".join(reversed(processed_blocks))
        return final_data

    def _process_block(self, block_number: int, block_data: bytes) -> bytes:
        """Process single block."""
        if self.is_encrypted:
            assert self.key_derivator
            block_key = self.key_derivator.get_block_key(block_number)
            encrypted_block = internal_backend.aes_cbc_encrypt(block_key, block_data)
        else:
            encrypted_block = block_data

        full_block = pack(
            f"<L{len(self.final_hash)}s{len(encrypted_block)}s",
            block_number,
            self.final_hash,
            encrypted_block,
        )
        block_hash = internal_backend.hash(full_block, self.hash_type)
        self.final_hash = block_hash
        return full_block

    def info(self) -> str:
        """Get string information for commands in the container."""
        info = str()
        info += f"COMMANDS:\n"
        info += f"Number of commands: {len(self.commands)}\n"
        for command in self.commands:
            info += f"  {command.info()}\n"
        return info

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "SecureBinary31Commands":
        """Parse binary data into SecureBinary31Commands.

        :raises NotImplementedError: Not yet implemented
        """
        raise NotImplementedError()
