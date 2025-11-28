#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SecureBinary V3.1 image generation and management.

This module provides functionality for creating, parsing, and managing
SecureBinary V3.1 format images used in NXP MCU secure boot process.
"""

import logging
import os
from datetime import datetime
from struct import calcsize, pack, unpack, unpack_from
from typing import Any, Optional, Union

from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash, get_hash_length
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.crypto.symmetric import aes_cbc_decrypt
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.cert_block.cert_blocks import CertBlockV21
from spsdk.sbfile.sb31.commands import CFG_NAME_TO_CLASS, BaseCmd, CmdSectionHeader
from spsdk.sbfile.sb31.commands_validator import CommandsValidator
from spsdk.sbfile.utils.encryption_provider import (
    EncryptionProvider,
    NoEncryption,
    SB31EncryptionProvider,
    get_encryption_provider,
)
from spsdk.sbfile.utils.key_derivator import LocalKeyDerivator
from spsdk.utils.abstract import BaseClass
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import align_block, load_hex_string, write_file

logger = logging.getLogger(__name__)


########################################################################################################################
# Secure Binary Image Class (Version 3.1)
########################################################################################################################
class SecureBinary31Header(BaseClass):
    """SecureBinary V3.1 header representation for NXP MCU secure boot files.

    This class manages the header structure (Block 0) of SecureBinary format version 3.1,
    including metadata such as firmware version, hash algorithms, certificate blocks,
    and container properties for secure provisioning operations.

    :cvar MAGIC: Magic bytes identifier for SB v3.1 format.
    :cvar FORMAT_VERSION: Version string for this SecureBinary format.
    :cvar HEADER_SIZE: Size of the header structure in bytes.
    :cvar DESCRIPTION_LENGTH: Maximum length for description field.
    """

    HEADER_FORMAT = "<4s2H3LQ4L16s"
    HEADER_SIZE = calcsize(HEADER_FORMAT)
    MAGIC = b"sbv3"
    FORMAT_VERSION = "3.1"
    DESCRIPTION_LENGTH = 16

    def __init__(
        self,
        firmware_version: int,
        hash_type: EnumHashAlgorithm,
        cert_block: Optional[CertBlockV21] = None,
        description: Optional[str] = None,
        timestamp: Optional[int] = None,
        is_nxp_container: bool = False,
        flags: int = 0,
    ) -> None:
        """Initialize the SecureBinary V3.1 Header.

        :param firmware_version: Firmware version (must be bigger than current CMPA record)
        :param hash_type: Hash type used in commands binary block
        :param cert_block: Certificate block v2.1 for the Block 0, defaults to None
        :param description: Custom description up to 16 characters long, defaults to None
        :param timestamp: Timestamp (number of seconds since Jan 1st, 2000), if None use current time
        :param is_nxp_container: NXP provisioning SB file, defaults to False
        :param flags: Flags for SB file, defaults to 0
        :raises SPSDKValueError: Invalid hash type provided
        """
        self.flags = flags
        if hash_type not in [EnumHashAlgorithm.SHA256, EnumHashAlgorithm.SHA384]:
            raise SPSDKValueError(f"Invalid hash type: {hash_type.label}")
        self.hash_type = hash_type
        self.block_count = 0
        self.image_type = 7 if is_nxp_container else 6
        self.firmware_version = firmware_version
        self.timestamp = timestamp or SecureBinary31.get_current_timestamp()
        self.image_total_length = self.HEADER_SIZE
        self.description = self._adjust_description(description)

        # Add fields for the complete Block 0 representation
        self.next_block_hash: bytes = bytes(get_hash_length(self.hash_type))
        self.cert_block: Optional[CertBlockV21] = cert_block

    def _adjust_description(self, description: Optional[str] = None) -> bytes:
        """Format the description to fixed-length byte array.

        Converts string description to ASCII bytes and pads or truncates to DESCRIPTION_LENGTH.
        If no description provided, returns zero-filled byte array.

        :param description: Optional description string to format.
        :return: Fixed-length byte array of DESCRIPTION_LENGTH size.
        """
        if not description:
            return bytes(self.DESCRIPTION_LENGTH)
        desc = bytes(description, encoding="ascii")
        desc = desc[: self.DESCRIPTION_LENGTH]
        desc += bytes(self.DESCRIPTION_LENGTH - len(desc))
        return desc

    @property
    def cert_block_offset(self) -> int:
        """Calculate the offset to the Certification block.

        The offset is computed based on the fixed structure layout: 1 field of 8 bytes,
        9 fields of 4 bytes each, 16 bytes of additional data, plus the hash length
        determined by the hash type.

        :return: Offset in bytes to the Certification block.
        """
        return 1 * 8 + 9 * 4 + 16 + get_hash_length(self.hash_type)

    @property
    def block_size(self) -> int:
        """Calculate the data block size.

        The method computes the total size of a data block by adding the fixed overhead
        (4 bytes) plus signature size (256 bytes) plus the hash length based on the
        configured hash type.

        :return: Total data block size in bytes.
        """
        return 4 + 256 + get_hash_length(self.hash_type)

    def __repr__(self) -> str:
        """Return string representation of SB3.1 Header.

        Provides a human-readable string representation showing the header type and timestamp.

        :return: String representation containing header type and timestamp.
        """
        return f"SB3.1 Header, Timestamp: {self.timestamp}"

    def __str__(self) -> str:
        """Get string representation of SB v31 image information.

        Provides a formatted string containing all key properties of the SB v31 image
        including magic number, version, flags, block information, firmware version,
        timestamps, and certificate block status.

        :return: Formatted string with detailed SB v31 image information.
        """
        info = str()
        info += f" Magic:                       {self.MAGIC.decode('ascii')}\n"
        info += f" Version:                     {self.FORMAT_VERSION}\n"
        info += f" Flags:                       0x{self.flags:04X}\n"
        info += f" Block count:                 {self.block_count}\n"
        info += f" Block size:                  {self.block_size}\n"
        info += f" Firmware version:            {self.firmware_version}\n"
        info += f" Image type:                  {self.image_type}\n"
        info += f" Timestamp:                   {self.timestamp}\n"
        info += f" Total length of Block#0:     {self.image_total_length}\n"
        info += f" Certificate block offset:    {self.cert_block_offset}\n"
        info += f" Description:                 {self.description.decode('ascii')}\n"
        if self.next_block_hash:
            info += f" Hash of next block:         {self.next_block_hash.hex()}\n"
        if self.cert_block:
            info += " Certificate block:          Present\n"
        else:
            info += " Certificate block:          Not present\n"
        return info

    def update(self, commands: "SecureBinary31Commands") -> None:
        """Update the volatile fields in header by real commands and certification block data.

        The method calculates and sets the block count and total image length based on the
        provided commands and existing certification block. It accounts for header size,
        hash size, optional certification block size, and signature size.

        :param commands: SB3.1 Commands block containing the command data.
        """
        hash_size = get_hash_length(self.hash_type)
        self.block_count = commands.block_count

        # Calculate total length, accounting for optional cert_block
        self.image_total_length = self.HEADER_SIZE + hash_size
        if self.cert_block:
            self.image_total_length += self.cert_block.expected_size

        # Add space for signature
        signature_size = 64 if self.hash_type == EnumHashAlgorithm.SHA256 else 96
        self.image_total_length += signature_size

    def export(self) -> bytes:
        """Export the SB 3.1 file to binary format.

        Converts the SB 3.1 header structure into its packed binary representation using the
        predefined header format. The method processes the format version string and packs all
        header fields according to the SB 3.1 specification.

        :return: Packed binary representation of the SB 3.1 header.
        """
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

    def export_full_block0(self) -> bytes:
        """Export the complete Block 0 data including header, hash, and certificate block.

        This data is used for signature calculation and contains all necessary components
        of Block 0 except the signature itself.

        :return: Binary data of Block 0 without signature.
        :raises SPSDKError: If cert_block is required but not set.
        """
        data = self.export()  # Export header
        data += self.next_block_hash  # Add hash of next block

        # Add certificate block if available
        if self.cert_block:
            data += self.cert_block.export()

        return data

    def set_next_block_hash(self, hash_value: bytes) -> None:
        """Set the hash of the next block.

        :param hash_value: Hash value of the next block
        :raises SPSDKError: If hash length doesn't match the configured hash type
        """
        expected_length = get_hash_length(self.hash_type)
        if len(hash_value) != expected_length:
            raise SPSDKError(
                f"Hash length mismatch: expected {expected_length}, got {len(hash_value)}"
            )
        self.next_block_hash = hash_value

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data into SecureBinary31Header.

        Parses the provided binary data and creates a SecureBinary31Header instance with
        validated header fields including magic number, version, block configuration,
        and hash type determination.

        :param data: Binary data containing the SB31 header to parse.
        :raises SPSDKError: Invalid input size, magic mismatch, unsupported version,
                           invalid block size, or header validation failure.
        :return: Parsed SecureBinary31Header instance.
        """
        if len(data) < cls.HEADER_SIZE:
            raise SPSDKError("Invalid input header binary size.")
        (
            magic,
            minor_version,
            major_version,
            flags,
            block_count,
            block_size,
            timestamp,
            firmware_version,
            image_total_length,
            image_type,
            cert_block_offset,
            description,
        ) = unpack_from(cls.HEADER_FORMAT, data)
        if magic != cls.MAGIC:
            raise SPSDKError("Magic doesn't match")
        if major_version != 3 and minor_version != 1:
            raise SPSDKError(f"Unable to parse SB version {major_version}.{minor_version}")
        if block_size not in [292, 308]:
            raise SPSDKError(f"Unable to determine hash type from block size: {block_size}")

        hash_type = EnumHashAlgorithm.SHA256 if block_size == 292 else EnumHashAlgorithm.SHA384
        obj = cls(
            firmware_version=firmware_version,
            hash_type=hash_type,
            description=description.decode("utf-8"),
            timestamp=timestamp,
            is_nxp_container=image_type == 7,
            flags=flags,
        )
        obj.block_count = block_count

        if obj.block_size != block_size:
            raise SPSDKError(f"Invalid SB3.1 parsed block size: {obj.block_size} != {block_size}")
        if obj.cert_block_offset != cert_block_offset:
            raise SPSDKError(
                f"Invalid SB3.1 parsed certificate block offset: {obj.cert_block_offset} != {cert_block_offset}"
            )
        obj.image_total_length = image_total_length
        # Extract the hash of the next block
        hash_length = get_hash_length(hash_type)
        next_block_hash_offset = cls.HEADER_SIZE
        if next_block_hash_offset + hash_length <= len(data):
            next_block_hash = data[next_block_hash_offset : next_block_hash_offset + hash_length]
            obj.next_block_hash = next_block_hash
        return obj

    def validate(self) -> None:
        """Validate the settings of SB3.1 header blob class members.

        Performs comprehensive validation of all required class members including flags, block count,
        hash type, block size, image type, firmware version, timestamp, image total length,
        certification block offset, description, and next block hash. Optionally validates the
        certificate block if present.

        :raises SPSDKError: Invalid configuration of SB3.1 header blob class members.
        """
        if self.flags is None:
            raise SPSDKError("Invalid SB3.1 header flags.")
        if self.block_count is None or self.block_count < 0:
            raise SPSDKError("Invalid SB3.1 header block count.")
        if self.hash_type is None or self.hash_type not in [
            EnumHashAlgorithm.SHA256,
            EnumHashAlgorithm.SHA384,
        ]:
            raise SPSDKError("Invalid SB3.1 header hash type.")
        if self.block_size is None or self.block_size not in [292, 308]:
            raise SPSDKError("Invalid SB3.1 header block size.")
        if self.image_type is None or self.image_type not in [6, 7]:
            raise SPSDKError("Invalid SB3.1 header image type.")
        if self.firmware_version is None:
            raise SPSDKError("Invalid SB3.1 header firmware version.")
        if self.timestamp is None:
            raise SPSDKError("Invalid SB3.1 header timestamp.")
        if self.image_total_length is None or self.image_total_length < self.HEADER_SIZE:
            raise SPSDKError("Invalid SB3.1 header image total length.")
        if self.cert_block_offset is None:
            raise SPSDKError("Invalid SB3.1 header certification block offset.")
        if self.description is None or len(self.description) != 16:
            raise SPSDKError("Invalid SB3.1 header image description.")

        # Validate next_block_hash
        if not self.next_block_hash or len(self.next_block_hash) != get_hash_length(self.hash_type):
            raise SPSDKError("Invalid SB3.1 header next block hash.")

        # Certificate block validation is optional
        if self.cert_block:
            self.cert_block.validate()


class SecureBinary31Commands(BaseClass):
    """SB3.1 Commands Container.

    This class manages a collection of SB3.1 (Secure Binary 3.1) commands that form
    the executable payload of a secure binary file. It handles command organization,
    encryption, hashing, and serialization for NXP MCU secure boot operations.

    :cvar FEATURE: Database feature identifier for SB3.1.
    :cvar SB_COMMANDS_NAME: Human-readable name for SB3.1 commands.
    :cvar SUPPORTED_HASHES: List of supported hash algorithms.
    :cvar PCK_SIZES: Supported Part Common Key sizes in bits.
    """

    FEATURE = DatabaseManager.SB31
    SB_COMMANDS_NAME = "SB3.1"
    SUPPORTED_HASHES = [EnumHashAlgorithm.SHA256, EnumHashAlgorithm.SHA384]
    PCK_SIZES = [256, 128]

    def __init__(
        self,
        family: FamilyRevision,
        hash_type: EnumHashAlgorithm,
        timestamp: Optional[int] = None,
        encryption_provider: EncryptionProvider = NoEncryption(),
    ) -> None:
        """Initialize container for SB3.1 commands.

        :param family: Device family and revision information.
        :param hash_type: Hash algorithm type used in commands binary block.
        :param timestamp: Timestamp used for encryption, defaults to current timestamp if None.
        :param encryption_provider: Encryption provider instance, defaults to NoEncryption.
        :raises SPSDKValueError: Invalid hash type not supported by the family.
        """
        super().__init__()
        self.family = family
        if hash_type.label.lower() not in [x.label.lower() for x in self.SUPPORTED_HASHES]:
            raise SPSDKValueError(f"Invalid hash type: {hash_type}")
        self.hash_type = hash_type
        self.block_count = 0
        self.final_hash = bytes(get_hash_length(hash_type))
        self.block1_size = 0
        self.commands: list[BaseCmd] = []
        self.timestamp = timestamp or SecureBinary31.get_current_timestamp()
        self.encryption_provider = encryption_provider
        db = get_db(family=family)
        self.data_chunk_length = db.get_int(self.FEATURE, "commands_block_length")
        self.variable_block_length = db.get_bool(self.FEATURE, "variable_block_length")

    @staticmethod
    def _get_key_length(hash_type: EnumHashAlgorithm) -> int:
        """Get the key length in bits for the specified hash algorithm.

        Returns the appropriate key length based on the hash algorithm type.
        SHA256 uses 128-bit keys, while SHA384 and SHA512 use 256-bit keys.

        :param hash_type: Hash algorithm enumeration value.
        :raises KeyError: Unsupported hash algorithm type.
        :return: Key length in bits for the specified hash algorithm.
        """
        return {
            EnumHashAlgorithm.SHA256.label.lower(): 128,
            EnumHashAlgorithm.SHA384.label.lower(): 256,
            EnumHashAlgorithm.SHA512.label.lower(): 256,
        }[hash_type.label.lower()]

    @property
    def is_encrypted(self) -> bool:
        """Check if commands are encrypted.

        :return: True if commands are encrypted, False otherwise.
        """
        return self.encryption_provider.is_encrypted

    def add_command(self, command: Union[BaseCmd, list[BaseCmd]]) -> None:
        """Add Secure Binary command to the image.

        The method accepts either a single command or a list of commands and adds them
        to the internal commands collection.

        :param command: Single command or list of commands to be added to the image.
        """
        if isinstance(command, list):
            logger.info(f"Adding list ({len(command)}): {command}")
            self.commands.extend(command)
        else:
            self.commands.append(command)

    def insert_command(self, index: int, command: BaseCmd) -> None:
        """Insert Secure Binary command at specified index.

        :param index: Position where to insert the command. Use -1 to append at the end.
        :param command: The Secure Binary command to insert.
        """
        if index == -1:
            self.commands.append(command)
        else:
            self.commands.insert(index, command)

    def set_commands(self, commands: list[BaseCmd]) -> None:
        """Set all Secure Binary commands at once.

        :param commands: List of BaseCmd objects to be set as the commands for this instance.
        """
        self.commands = commands.copy()

    @classmethod
    def load_pck(cls, pck_src: str, search_paths: Optional[list[str]] = None) -> bytes:
        """Load Part Common Key from source.

        The method tries to load PCK with different supported sizes and returns the first
        successfully parsed key bytes.

        :param pck_src: Path to file or hex string containing the Part Common Key.
        :param search_paths: List of additional directories to search for PCK file.
        :return: Parsed PCK as bytes.
        :raises SPSDKError: If PCK cannot be loaded with any supported size.
        """
        pck = None
        for size in cls.PCK_SIZES:
            try:
                pck = load_hex_string(pck_src, size // 8, search_paths=search_paths, name="PCK")
            except SPSDKError:
                logger.debug(f"Failed loading PCK as key with {size}")
        if not pck:
            raise SPSDKError("Cannot load PCK from source")
        return pck

    @classmethod
    def load_from_config(
        cls,
        config: Config,
        hash_type: EnumHashAlgorithm = EnumHashAlgorithm.SHA256,
        timestamp: Optional[int] = None,
        load_just_commands: bool = False,
    ) -> Self:
        """Load SecureBinary commands from configuration.

        Creates a SecureBinary31Commands instance from configuration data, including encryption
        setup and command loading. Handles timestamp resolution and encryption provider
        configuration based on the provided settings.

        :param config: Configuration object containing SecureBinary settings and commands.
        :param hash_type: Hash algorithm for command block hashing, defaults to SHA256.
        :param timestamp: Timestamp for commands, defaults to None (uses current time).
        :param load_just_commands: If True, loads only commands without encryption setup,
            defaults to False.
        :return: Configured SecureBinary31Commands instance with loaded commands.
        """
        family = FamilyRevision.load_from_config(config)
        cfg_timestamp = timestamp
        if "timestamp" in config:
            cfg_timestamp = config.get_int("timestamp")
        if cfg_timestamp is None:
            cfg_timestamp = SecureBinary31.get_current_timestamp()

        if load_just_commands:
            kdk_access_rights = 0
            is_encrypted = False
        else:
            kdk_access_rights = config.get_int("kdkAccessRights", 0)
            is_encrypted = config.get("isEncrypted", True)

        encryption_provider = get_encryption_provider(
            is_encrypted=is_encrypted,
            # in this case the config file may contain path to a file or service config string
            service_config=config.get("containerKeyBlobEncryptionKey"),
            search_paths=config.search_paths,
        )
        encryption_provider.configure(
            timestamp=cfg_timestamp,
            kdk_access_rights=kdk_access_rights,
            key_length=SecureBinary31Commands._get_key_length(hash_type=hash_type),
        )

        ret = cls(
            family=family,
            hash_type=hash_type,
            timestamp=cfg_timestamp,
            encryption_provider=encryption_provider,
        )

        for cfg_cmd in config.get_list_of_configs("commands", []):
            cfg_cmd_key = list(cfg_cmd.keys())[0]
            cfg_cmd_value = cfg_cmd.get_config(cfg_cmd_key)
            cfg_cmd_value["family"] = family.name
            cfg_cmd_value["revision"] = family.revision
            ret.add_command(CFG_NAME_TO_CLASS[cfg_cmd_key].load_from_config(cfg_cmd_value))
        return ret

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the SecureBinary4 feature.

        Generates a configuration object representing the current state of the SecureBinary4 instance.
        If encryption is enabled, writes the key derivation key to a file in the specified data path.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration object with current SecureBinary4 settings.
        """
        ret = Config()
        ret["isEncrypted"] = self.is_encrypted
        ret["timestamp"] = self.timestamp

        if self.is_encrypted:
            assert isinstance(self.encryption_provider, SB31EncryptionProvider)
            ret["kdkAccessRights"] = self.encryption_provider.key_derivator.kdk_access_rights
            if isinstance(self.encryption_provider, LocalKeyDerivator):
                pck_filename = "pck.txt"
                write_file(
                    self.encryption_provider.key_derivator.kdk.hex(),
                    os.path.join(data_path, pck_filename),
                )
            else:
                pck_filename = "N/A"
            ret["containerKeyBlobEncryptionKey"] = pck_filename

        if len(self.commands):
            cfg_commands = []
            for cmd in self.commands:
                cfg_commands.append(cmd.get_config(data_path))

            ret["commands"] = cfg_commands

        return ret

    def get_cmd_blocks_to_export(self) -> list[bytes]:
        """Export command blocks as byte chunks for SB3.1 file generation.

        This method processes all commands in the section, creates a section header,
        and splits the combined data into appropriately sized blocks. The last block
        is aligned if fixed block length is required.

        :return: List of byte blocks containing the exported command section data.
        """
        commands_bytes = b"".join([command.export() for command in self.commands])
        section_header = CmdSectionHeader(length=len(commands_bytes))
        total = section_header.export() + commands_bytes
        data_blocks = [
            total[i : i + self.data_chunk_length]
            for i in range(0, len(total), self.data_chunk_length)
        ]
        if not self.variable_block_length:
            data_blocks[-1] = align_block(data_blocks[-1], alignment=self.data_chunk_length)

        self.block_count = len(data_blocks)
        self.block1_size = len(data_blocks[0]) if data_blocks else 0
        return data_blocks

    def _encrypt_block(self, block_number: int, block_data: bytes) -> bytes:
        """Encrypt single block using the configured encryption provider.

        :param block_number: Sequential number of the block to encrypt.
        :param block_data: Raw data bytes to be encrypted.
        :return: Encrypted block data as bytes.
        """
        encrypted_block = self.encryption_provider.encrypt_block(
            block_number=block_number, data=block_data
        )
        return encrypted_block

    def process_cmd_blocks_to_export(self, data_blocks: list[bytes]) -> bytes:
        """Process given data blocks for export to SB3.1 format.

        This method takes a list of data blocks and processes them for export by encrypting each block,
        adding block numbers and hash chains, and combining them into the final exportable format.
        The blocks are processed in reverse order to build the hash chain correctly.

        :param data_blocks: List of byte arrays representing the data blocks to be processed.
        :return: Final processed data ready for export as bytes.
        """
        self.block_count = len(data_blocks)
        next_block_hash = bytes(get_hash_length(self.hash_type))

        processed_blocks = []
        for block_number, block_data in reversed(list(enumerate(data_blocks, start=1))):
            encrypted_block = self._encrypt_block(block_number, block_data)

            full_block = pack(
                f"<L{len(next_block_hash)}s{len(encrypted_block)}s",
                block_number,
                next_block_hash,
                encrypted_block,
            )

            next_block_hash = get_hash(full_block, self.hash_type)
            processed_blocks.append(full_block)

        self.final_hash = next_block_hash
        self.block1_size = len(processed_blocks[0]) if processed_blocks else 0
        final_data = b"".join(reversed(processed_blocks))
        return final_data

    def export(self) -> bytes:
        """Export commands as bytes.

        The method retrieves command blocks to export and processes them into a byte representation
        suitable for serialization or transmission.

        :return: Serialized command data as bytes.
        """
        data_blocks = self.get_cmd_blocks_to_export()
        return self.process_cmd_blocks_to_export(data_blocks)

    def __repr__(self) -> str:
        """Return string representation of the commands collection.

        Provides a formatted string showing the command type name and the total number
        of commands in the collection.

        :return: String representation in format "{COMMAND_NAME} Commands[#{count}]".
        """
        return f"{self.SB_COMMANDS_NAME} Commands[#{len(self.commands)}]"

    def __str__(self) -> str:
        """Get string information for commands in the container.

        Returns a formatted string containing the number of commands and details
        about each command in the container.

        :return: Formatted string with commands information.
        """
        info = str()
        info += "COMMANDS:\n"
        info += f"Number of commands: {len(self.commands)}\n"
        for command in self.commands:
            info += f"  {str(command)}\n"
        return info

    @classmethod
    def parse_block_header(
        cls,
        block_data: bytes,
        offset: int,
        block_size: int,
        block_hash: bytes,
        hash_type: EnumHashAlgorithm,
    ) -> tuple[int, int, bytes, bytes]:
        """Parse the block header from the input data and verify its integrity.

        The method extracts block information including block number, next block hash, and encrypted
        data from the binary block data. It also performs hash verification to ensure block integrity.

        :param block_data: Binary data of the block
        :param offset: Offset in the data where the header begins
        :param block_size: Size of the block in bytes
        :param block_hash: Expected hash of the block for verification
        :param hash_type: Hash algorithm used for block hashing
        :return: Tuple containing block number, block size, next block hash, and encrypted block data
        :raises SPSDKError: When the block hash verification fails
        """
        hash_length = get_hash_length(hash_type)

        # Extract block header information
        block_number, next_block_hash, encrypted_block = unpack(
            f"<L{hash_length}s{block_size - hash_length - 4}s",
            block_data[offset : offset + block_size],
        )

        # Verify block integrity by checking hash
        full_block = block_data[offset : offset + block_size]

        calculated_hash = get_hash(full_block, hash_type)
        if calculated_hash != block_hash:
            raise SPSDKError(
                f"Block hash verification failed for block {block_number}. "
                f"Expected: {block_hash.hex()}, Got: {calculated_hash.hex()}"
            )

        return block_number, block_size, next_block_hash, encrypted_block

    @classmethod
    def parse(
        cls,
        data: bytes,
        family: Optional[FamilyRevision] = None,
        block_size: int = 256,
        pck: Optional[str] = None,
        block1_hash: Optional[bytes] = None,
        hash_type: Optional[EnumHashAlgorithm] = None,
        kdk_access_rights: int = 0,
        timestamp: Optional[int] = None,
    ) -> Self:
        """Parse binary data into SecureBinary31Commands.

        This method reconstructs SecureBinary31Commands from binary SB31 format by parsing blocks,
        decrypting if needed, and extracting individual commands. Blocks are processed in reverse
        order and commands are parsed according to their specific types.

        :param data: Binary data containing SB31 commands.
        :param family: FamilyRevision instance with device family information.
        :param block_size: Size of each command block in bytes, defaults to 256.
        :param pck: Part Common Key string required for decryption of encrypted data.
        :param block1_hash: Hash bytes of the first block for validation.
        :param hash_type: EnumHashAlgorithm specifying hash algorithm used in binary data.
        :param kdk_access_rights: Key Derivation Key access rights, defaults to 0.
        :param timestamp: Timestamp integer used for decryption (required for encrypted commands).
        :return: Initialized SecureBinary31Commands object with parsed commands.
        :raises SPSDKError: When parsing fails, data is invalid, or required parameters missing.
        :raises SPSDKValueError: When an invalid hash type is provided.
        """
        if not (family and block1_hash and hash_type and timestamp):
            raise SPSDKError("Missing required parameters for parsing encrypted commands")

        # Validate hash type
        if hash_type not in cls.SUPPORTED_HASHES:
            raise SPSDKValueError(f"Invalid hash type: {hash_type}")

        # Get hash size for the specified hash algorithm
        hash_size = get_hash_length(hash_type)

        # Extract first block number to check format
        if len(data) < 4 + hash_size:  # Minimum size needed for basic header
            raise SPSDKError(f"Invalid {cls.SB_COMMANDS_NAME} commands data: too small")

        block_number = unpack_from("<L", data)[0]

        encryption_provider = get_encryption_provider(
            is_encrypted=bool(pck),
            service_config=pck,
        )
        encryption_provider.configure(
            timestamp=timestamp,
            kdk_access_rights=kdk_access_rights,
            key_length=SecureBinary31Commands._get_key_length(hash_type=hash_type),
        )

        # Create commands object
        obj = cls(
            family=family,
            hash_type=hash_type,
            timestamp=timestamp,
            encryption_provider=encryption_provider,
        )

        # Process blocks in reverse order (last to first)
        offset = 0
        next_block_size = block_size
        next_block_hash = block1_hash
        blocks = []
        block_hashes = {}

        while offset < len(data):
            next_offset = offset + next_block_size
            # Extract block number and next block hash
            block_number, next_block_size, next_block_hash, encrypted_block = (
                cls.parse_block_header(
                    block_data=data,
                    offset=offset,
                    block_size=next_block_size,
                    block_hash=next_block_hash,
                    hash_type=hash_type,
                )
            )

            # Decrypt the block if needed
            if obj.is_encrypted:
                assert isinstance(obj.encryption_provider, SB31EncryptionProvider)
                block_key = obj.encryption_provider.key_derivator.get_block_key(block_number)
                decrypted_block = aes_cbc_decrypt(block_key, encrypted_block)
            else:
                decrypted_block = encrypted_block

            # Store block data and hash for later processing
            blocks.append((block_number, decrypted_block))
            block_hashes[block_number] = next_block_hash

            # Move to next block
            offset = next_offset

        # Sort blocks by number
        blocks.sort(key=lambda x: x[0])

        # Combine all decrypted blocks
        commands_data = b"".join([block[1] for block in blocks])

        # Parse section header and commands
        section_header = CmdSectionHeader.parse(commands_data)
        commands_data = commands_data[section_header.SIZE :]

        # Now parse the individual commands
        obj.commands = []
        cmd_offset = 0

        while cmd_offset < section_header.length:
            # Each command starts with a tag and length
            _, _, cmd_tag = BaseCmd.header_parse_raw(
                commands_data[cmd_offset : cmd_offset + BaseCmd.SIZE]
            )

            # Find appropriate command class based on tag
            cmd_class = None
            for cmd_cls in CFG_NAME_TO_CLASS.values():
                if hasattr(cmd_cls, "TAG") and cmd_cls.CMD_TAG == cmd_tag:
                    cmd_class = cmd_cls
                    break

            if cmd_class is None:
                raise SPSDKError(f"Unknown command tag: {cmd_tag}")

            # Parse command
            cmd_data = commands_data[cmd_offset:]  # Include header
            cmd = cmd_class.parse(cmd_data)
            obj.add_command(cmd)

            # Move to next command
            cmd_offset += cmd.export_length

        # Set block count and hash
        obj.block_count = len(blocks)
        if blocks:
            obj.final_hash = get_hash(blocks[0][1], hash_type)

        return obj

    def validate(self) -> None:
        """Validate the settings of class members.

        :raises SPSDKError: Invalid configuration of SB3.1 commands blob class members.
        """
        self.validate_command_rules()

    def validate_command_rules(self) -> None:
        """Validate commands against device-specific rules.

        This method retrieves command validation rules from the device database and
        applies them to verify that all commands in the image comply with the
        device-specific requirements and constraints.

        :raises SPSDKError: When command validation rules are violated.
        """
        command_rules: list[dict] = get_db(family=self.family).get_list(
            self.FEATURE, "command_rules", []
        )
        validator = CommandsValidator(self.family, command_rules)
        validator.validate_commands(self.commands)


class SecureBinary31(FeatureBaseClass):
    """Secure Binary v3.1 container for NXP MCU secure provisioning.

    This class represents a complete SB3.1 secure binary file that contains
    encrypted commands and data for secure device provisioning. It manages
    the creation, validation, and export of SB3.1 containers with proper
    certification blocks, signatures, and command sequences.

    :cvar FEATURE: Database feature identifier for SB3.1 support.
    """

    FEATURE = DatabaseManager.SB31

    def __init__(
        self,
        family: FamilyRevision,
        cert_block: CertBlockV21,
        firmware_version: int,
        sb_commands: SecureBinary31Commands,
        description: Optional[str] = None,
        is_nxp_container: bool = False,
        flags: int = 0,
        signature_provider: Optional[SignatureProvider] = None,
        signature: Optional[bytes] = None,
    ) -> None:
        """Constructor for Secure Binary v3.1 data container.

        Initializes a new Secure Binary v3.1 container with the provided configuration,
        commands, and signing information. The container requires either a signature
        provider or a pre-computed signature for authentication.

        :param family: Device family revision information.
        :param cert_block: Certificate block for authentication.
        :param firmware_version: Firmware version (must be greater than current CMPA record).
        :param sb_commands: SecureBinary31Commands object containing the commands to execute.
        :param description: Custom description up to 16 characters long, defaults to None.
        :param is_nxp_container: Whether this is an NXP provisioning SB file, defaults to False.
        :param flags: Additional flags for the SB file, defaults to 0.
        :param signature_provider: Signature provider for signing the SB3.1 image, defaults to None.
        :param signature: Pre-computed signature bytes if signature_provider not used, defaults to None.
        :raises SPSDKError: If neither signature_provider nor signature is provided.
        """
        self.family = family
        self.signature_provider = signature_provider
        self.signature = signature
        self.sb_commands = sb_commands

        if signature_provider is None and signature is None:
            raise SPSDKError("Either signature_provider or signature must be provided")

        # Determine hash type from signature provider or signature length
        if signature_provider:
            hash_type = {64: EnumHashAlgorithm.SHA256, 96: EnumHashAlgorithm.SHA384}[
                signature_provider.signature_length
            ]
        else:
            assert (
                signature is not None
            ), "Signature must be provided, when signature_provider is not set"
            hash_type = {64: EnumHashAlgorithm.SHA256, 96: EnumHashAlgorithm.SHA384}.get(
                len(signature), EnumHashAlgorithm.SHA256
            )

        self.sb_commands.hash_type = hash_type

        # Create header with all the necessary information
        self.sb_header = SecureBinary31Header(
            hash_type=hash_type,
            firmware_version=firmware_version,
            cert_block=cert_block,
            description=description,
            timestamp=sb_commands.timestamp,
            is_nxp_container=is_nxp_container,
            flags=flags,
        )

    @staticmethod
    def get_current_timestamp() -> int:
        """Get current timestamp as seconds since January 1, 2000.

        :return: Integer representing seconds elapsed since January 1, 2000.
        """
        return int((datetime.now() - datetime(2000, 1, 1)).total_seconds())

    def get_rkth(self) -> bytes:
        """Get the Root Key Table Hash (RKTH) from the certificate block.

        :return: RKTH as bytes if available, empty bytes otherwise.
        """
        if not self.sb_header.cert_block:
            return b""

        return self.sb_header.cert_block.rkth

    @classmethod
    def get_commands_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas for SB3.1 commands.

        The method retrieves the base SB3.1 schema and customizes it based on the target family's
        capabilities. It filters out unsupported commands and adjusts compression-related properties
        if the family doesn't support compression features.

        :param family: Family description containing device-specific configuration.
        :return: List of validation schemas customized for the specified family.
        """
        sb3_sch_cfg = get_schema_file(DatabaseManager.SB31)
        db = get_db(family)
        schemas: list[dict[str, Any]] = [sb3_sch_cfg["sb3_commands"]]
        # remove unused command for current family
        supported_commands = db.get_list(DatabaseManager.SB31, "supported_commands")
        list_of_commands: list[dict] = schemas[0]["properties"]["commands"]["items"]["oneOf"]
        schemas[0]["properties"]["commands"]["items"]["oneOf"] = [
            command
            for command in list_of_commands
            if list(command["properties"].keys())[0] in supported_commands
        ]
        supports_compression = db.get_bool(DatabaseManager.SB31, "supports_compression")
        if not supports_compression:
            load_cmd = schemas[0]["properties"]["commands"]["items"]["oneOf"][1]
            load_cmd["properties"]["load"]["properties"]["compress"]["skip_in_template"] = True
            load_cmd["properties"]["load"]["properties"]["sectorSize"]["skip_in_template"] = True

        return schemas

    @classmethod
    def get_devhsm_commands_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas for DevHSM commands.

        The method retrieves the base SB3 schema and filters commands based on what's
        supported by the specific device family. It also makes the 'commands' field
        optional for device HSM configurations.

        :param family: Family description containing device-specific information.
        :return: List of validation schemas with filtered commands for the family.
        """
        sb3_sch_cfg = get_schema_file(DatabaseManager.SB31)
        db = get_db(family)
        schemas: list[dict[str, Any]] = [sb3_sch_cfg["sb3_commands"]]
        # remove unused command for current family
        supported_commands = db.get_list(DatabaseManager.DEVHSM, "supported_commands")
        list_of_commands: list[dict] = schemas[0]["properties"]["commands"]["items"]["oneOf"]
        schemas[0]["properties"]["commands"]["items"]["oneOf"] = [
            command
            for command in list_of_commands
            if list(command["properties"].keys())[0] in supported_commands
        ]
        # The 'commands' are optional for device HSM
        required: list[str] = schemas[0]["required"]
        required.remove("commands")
        return schemas

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas for SB3.1 image configuration.

        The method retrieves and combines validation schemas from multiple sources including
        MBI, SB3.1, and general configuration schemas, along with command-specific schemas
        for the specified family.

        :param family: Family description containing chip family and revision information.
        :return: List of validation schema dictionaries for configuration validation.
        """
        mbi_sch_cfg = get_schema_file(DatabaseManager.MBI)
        sb3_sch_cfg = get_schema_file(DatabaseManager.SB31)
        sch_cfg = get_schema_file("general")["family"]
        update_validation_schema_family(sch_cfg["properties"], cls.get_supported_families(), family)

        schemas: list[dict[str, Any]] = [sch_cfg]
        schemas.extend([mbi_sch_cfg[x] for x in ["firmware_version", "signer", "cert_block_v21"]])
        schemas.extend(
            [sb3_sch_cfg[x] for x in ["sb3", "sb3_description", "sb3_test", "sb3_output"]]
        )
        schemas.extend(cls.get_commands_validation_schemas(family))

        return schemas

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Creates an instance of SecureBinary31 from configuration.

        The method parses the configuration to extract all necessary parameters including
        family revision, certificate block, commands, and signature provider to create
        a complete Secure Binary V3.1 instance.

        :param config: Input standard configuration containing SB3.1 parameters.
        :return: Instance of Secure Binary V3.1 class.
        """
        family = FamilyRevision.load_from_config(config)
        is_nxp_container = config.get("isNxpContainer", False)
        description = config.get_str("description") if "description" in config else None

        container_configuration_word = config.get_int("containerConfigurationWord", 0)
        firmware_version = config.get_int("firmwareVersion", 1)

        cert_block = CertBlockV21.load_from_config(config)

        signature_provider = get_signature_provider(config)

        assert isinstance(signature_provider, SignatureProvider)
        hash_type = {64: EnumHashAlgorithm.SHA256, 96: EnumHashAlgorithm.SHA384}[
            signature_provider.signature_length
        ]
        sb_commands = SecureBinary31Commands.load_from_config(config, hash_type=hash_type)

        # Create SB3 object
        sb3 = cls(
            family=family,
            cert_block=cert_block,
            sb_commands=sb_commands,
            firmware_version=firmware_version,
            description=description,
            is_nxp_container=is_nxp_container,
            flags=container_configuration_word,
            signature_provider=signature_provider,
        )

        return sb3

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the SB3.1 image.

        The method generates a complete configuration dictionary containing all SB3.1 image
        properties including header information, certificate block, and commands configuration.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration object with SB3.1 image settings.
        """
        # Create a base configuration object
        ret = Config()

        # Add family and revision information
        ret["family"] = self.family.name
        ret["revision"] = self.family.revision

        # Add SB3.1 specific configuration
        ret["description"] = self.sb_header.description.decode("ascii").rstrip("\x00")
        ret["isNxpContainer"] = self.sb_header.image_type == 7
        ret["containerConfigurationWord"] = self.sb_header.flags
        ret["firmwareVersion"] = self.sb_header.firmware_version
        ret["timestamp"] = self.sb_commands.timestamp

        # Add output file configuration
        ret["containerOutputFile"] = "sb3.bin"

        # Add certificate block configuration if available
        if self.sb_header.cert_block:
            cert_block_config = self.sb_header.cert_block.get_config(data_path)
            ret.update(cert_block_config)

        # Add SB commands configuration
        sb_commands_config = self.sb_commands.get_config(data_path)
        ret.update(sb_commands_config)

        return ret

    def validate(self) -> None:
        """Validate the settings of class members.

        This method performs comprehensive validation of SB3.1 configuration including
        signature provider verification, raw signature length validation, and validation
        of header and commands components.

        :raises SPSDKError: Invalid configuration of SB3.1 class members, invalid
            signature provider, missing certificate block for public key verification,
            invalid signature length, or missing signature configuration.
        """
        # If we have a signature provider, validate it
        if self.signature_provider is not None:
            if not isinstance(self.signature_provider, SignatureProvider):
                raise SPSDKError(f"SB3.1 signature provider is invalid: {self.signature_provider}")

            if self.sb_header.cert_block:
                public_key = (
                    self.sb_header.cert_block.isk_certificate.isk_cert.export()
                    if self.sb_header.cert_block.isk_certificate
                    and self.sb_header.cert_block.isk_certificate.isk_cert
                    else self.sb_header.cert_block.root_key_record.root_public_key
                )
                self.signature_provider.try_to_verify_public_key(public_key)
            else:
                raise SPSDKError("Unable to verify public key for signature provider")
        # If we have a raw signature, validate its length
        elif self.signature is not None:
            if len(self.signature) not in [64, 96]:
                raise SPSDKError(f"Invalid signature length: {len(self.signature)}")
        else:
            raise SPSDKError("Either signature_provider or signature must be provided")

        self.sb_header.validate()
        self.sb_commands.validate()

    def export(self) -> bytes:
        """Generate binary output of SB3.1 file.

        The method validates the file structure, exports commands to get their hash, updates the header
        with block count and total length, sets the next block hash, and assembles the final binary
        data including header, certificate block, signature, and command blocks.

        :raises AssertionError: When signature is not provided and signature provider is not used.
        :return: Content of SB3.1 file in bytes.
        """
        self.validate()

        # Generate commands as first to get hash
        sb_commands = self.sb_commands.export()

        # Update header with block count and total length
        self.sb_header.update(self.sb_commands)

        # Set the hash of next block
        self.sb_header.set_next_block_hash(self.sb_commands.final_hash)

        # Get the Block 0 data for signature calculation (header + hash + cert block)
        block0_data = self.sb_header.export_full_block0()

        # Use either signature provider or raw signature
        if self.signature_provider:
            signature = self.signature_provider.get_signature(block0_data)
        else:
            assert (
                self.signature is not None
            ), "Signature must be provided, when signature provider is not used"
            signature = self.signature

        # Assemble the final data
        final_data = block0_data  # Header + hash + cert block
        final_data += signature  # Add signature
        final_data += sb_commands  # Add command blocks

        return final_data

    def __repr__(self) -> str:
        """Return string representation of the SB3.1 image.

        Provides a human-readable string containing the SB version and timestamp
        information for debugging and logging purposes.

        :return: String representation showing SB version and timestamp.
        """
        return f"SB3.1, TimeStamp: {self.sb_commands.timestamp}"

    def __str__(self) -> str:
        """Create string representation of SB3.1 loaded file.

        The method validates the file structure and returns formatted information
        about the SB3.1 header and commands blob.

        :return: Text information about SB3.1 file structure.
        """
        self.validate()
        ret = ""

        ret += "SB3.1 header:\n"
        ret += str(self.sb_header)

        ret += "SB3.1 commands blob :\n"
        ret += str(self.sb_commands)

        return ret

    @classmethod
    def parse(
        cls,
        data: bytes,
        family: Optional[FamilyRevision] = None,
        pck: Optional[str] = None,
        kdk_access_rights: int = 0,
    ) -> Self:
        """Parse SecureBinary31 object from binary data.

        This method reconstructs a complete SecureBinary31 object by parsing the binary
        representation, including header, certificate block, signature, and commands sections.

        :param data: Binary data containing the complete SB3.1 file to parse
        :param family: Family revision information required for proper parsing
        :param pck: Part Common Key needed for decrypting encrypted sections
        :param kdk_access_rights: Key Derivation Key access rights for key derivation
        :return: Constructed SecureBinary31 object with all parsed components
        :raises SPSDKError: When parsing fails or data is invalid
        """
        if not family:
            raise SPSDKError("Family information must be provided for parsing SB3.1")

        # Parse SB3.1 header first
        sb_header = SecureBinary31Header.parse(data)

        # Determine the hash type from the header
        hash_type = sb_header.hash_type

        # Calculate signature size based on hash type
        signature_size = 64 if hash_type == EnumHashAlgorithm.SHA256 else 96

        # Extract certificate block
        cert_block_offset = sb_header.cert_block_offset
        cert_block_end = sb_header.image_total_length - signature_size
        cert_block_data = data[cert_block_offset:cert_block_end]
        cert_block = CertBlockV21.parse(cert_block_data)

        # Extract signature
        signature_offset = sb_header.image_total_length - signature_size
        signature = data[signature_offset : sb_header.image_total_length]

        # Extract commands data - starts after Block 0
        commands_offset = sb_header.image_total_length
        commands_data = data[commands_offset:]

        # Parse the commands section
        sb_commands = SecureBinary31Commands.parse(
            data=commands_data,
            family=family,
            block_size=sb_header.block_size,
            pck=pck,
            block1_hash=sb_header.next_block_hash,
            hash_type=hash_type,
            kdk_access_rights=kdk_access_rights,
            timestamp=sb_header.timestamp,
        )

        # Create and return the SecureBinary31 object
        return cls(
            family=family,
            cert_block=cert_block,
            firmware_version=sb_header.firmware_version,
            signature_provider=None,
            sb_commands=sb_commands,
            description=sb_header.description.decode("ascii").rstrip("\x00"),
            is_nxp_container=(sb_header.image_type == 7),
            flags=sb_header.flags,
            signature=signature,
        )

    @staticmethod
    def validate_header(binary: bytes) -> None:
        """Validate SB3.1 header in binary data.

        This method parses the SB3.1 header from the provided binary data and validates
        its structure and content to ensure it conforms to the SB3.1 specification.

        :param binary: Binary data containing the SB3.1 header to be validated.
        :raises SPSDKError: Invalid header of SB3.1 data.
        """
        sb31_header = SecureBinary31Header.parse(binary)
        sb31_header.validate()
