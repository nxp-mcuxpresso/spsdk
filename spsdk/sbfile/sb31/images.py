#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module used for generation SecureBinary V3.1."""
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
# Secure Boot Image Class (Version 3.1)
########################################################################################################################
class SecureBinary31Header(BaseClass):
    """Header of the SecureBinary V3.1 (Block 0)."""

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

        :param hash_type: Hash type used in commands binary block
        :param firmware_version: Firmware version (must be bigger than current CMPA record)
        :param cert_block: Certificate block v2.1 for the Block 0, defaults to None
        :param description: Custom description up to 16 characters long, defaults to None
        :param timestamp: Timestamp (number of seconds since Jan 1st, 200), if None use current time
        :param is_nxp_container: NXP provisioning SB file, defaults to False
        :param flags: Flags for SB file, defaults to 0
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
        """Format the description."""
        if not description:
            return bytes(self.DESCRIPTION_LENGTH)
        desc = bytes(description, encoding="ascii")
        desc = desc[: self.DESCRIPTION_LENGTH]
        desc += bytes(self.DESCRIPTION_LENGTH - len(desc))
        return desc

    @property
    def cert_block_offset(self) -> int:
        """Calculate the offset to the Certification block."""
        return 1 * 8 + 9 * 4 + 16 + get_hash_length(self.hash_type)

    @property
    def block_size(self) -> int:
        """Calculate the the data block size."""
        return 4 + 256 + get_hash_length(self.hash_type)

    def __repr__(self) -> str:
        return f"SB3.1 Header, Timestamp: {self.timestamp}"

    def __str__(self) -> str:
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
        """Updates the volatile fields in header by real commands and certification block data.

        :param commands: SB3.1 Commands block
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
        """Export the SB file to bytes.

        :return: Packed binary representation of the SB 3.1 header
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
        """Export the complete Block 0 data (header + hash + cert block).

        This data is used for signature calculation.

        :return: Binary data of Block 0 (without signature)
        :raises SPSDKError: If cert_block is required but not set
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

        :raises SPSDKError: Unable to parse SB31 Header.
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
        """Validate the settings of class members.

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
    """Blob containing SB3.1 commands."""

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

        :param family: Device family
        :param hash_type: Hash type used in commands binary block
        :param is_encrypted: Indicate whether commands should be encrypted or not, defaults to True
        :param pck: Part Common Key (needed if `is_encrypted` is True), defaults to None
        :param timestamp: Timestamp used for encryption (needed if `is_encrypted` is True), defaults to None
        :param kdk_access_rights: Key Derivation Key access rights (needed if `is_encrypted` is True), defaults to None
        :raises SPSDKError: Key derivation arguments are not provided if `is_encrypted` is True
        :raises SPSDKValueError: Invalid hash type
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
        return {
            EnumHashAlgorithm.SHA256.label.lower(): 128,
            EnumHashAlgorithm.SHA384.label.lower(): 256,
            EnumHashAlgorithm.SHA512.label.lower(): 256,
        }[hash_type.label.lower()]

    @property
    def is_encrypted(self) -> bool:
        """Check if commands are encrypted."""
        return self.encryption_provider.is_encrypted

    def add_command(self, command: Union[BaseCmd, list[BaseCmd]]) -> None:
        """Add Secure Binary command."""
        if isinstance(command, list):
            logger.info(f"Adding list ({len(command)}): {command}")
            self.commands.extend(command)
        else:
            self.commands.append(command)

    def insert_command(self, index: int, command: BaseCmd) -> None:
        """Insert Secure Binary command."""
        if index == -1:
            self.commands.append(command)
        else:
            self.commands.insert(index, command)

    def set_commands(self, commands: list[BaseCmd]) -> None:
        """Set all Secure Binary commands at once."""
        self.commands = commands.copy()

    @classmethod
    def load_pck(cls, pck_src: str, search_paths: Optional[list[str]] = None) -> bytes:
        """Load Part Common Key from source.

        :param pck_src: Path or string containing PCK
        :param search_paths: Optional list of additional search paths
        :return: Parsed PCK bytes
        :raises SPSDKError: If PCK cannot be loaded
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

        :param config: Config object with configuration fields.
        :param hash_type: Hash algorithm to use for command block hashing, defaults to SHA256.
        :param timestamp: Timestamp value to use in commands, defaults to None (automatic).
        :param load_just_commands: Flag to control whether to load only commands or full configuration,
            defaults to False.
        :return: Instance of the SecureBinary commands class.
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

        :param data_path: Path to store the data files of configuration.
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
        """Export commands as bytes."""
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
        """Encrypt single block."""
        encrypted_block = self.encryption_provider.encrypt_block(
            block_number=block_number, data=block_data
        )
        return encrypted_block

    def process_cmd_blocks_to_export(self, data_blocks: list[bytes]) -> bytes:
        """Process given data blocks for export."""
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
        """Export commands as bytes."""
        data_blocks = self.get_cmd_blocks_to_export()
        return self.process_cmd_blocks_to_export(data_blocks)

    def __repr__(self) -> str:
        return f"{self.SB_COMMANDS_NAME} Commands[#{len(self.commands)}]"

    def __str__(self) -> str:
        """Get string information for commands in the container."""
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

        :param data: Binary data containing SB31 commands.
        :param family: FamilyRevision instance with device family information.
        :param block_size: Size of each command block in bytes.
        :param pck: Part Common Key (bytes) required for decryption.
        :param block1_hash: Hash of the first block (bytes).
        :param hash_type: EnumHashAlgorithm specifying the hash algorithm used in the binary data.
        :param kdk_access_rights: Key Derivation Key access rights, defaults to 0.
        :param timestamp: Optional timestamp used for decryption (required for encrypted commands).
        :return: Initialized SecureBinary31Commands object.
        :raises SPSDKError: When parsing fails or data is invalid.
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

        :raises SPSDKError: When command validation rules are violated
        """
        command_rules: list[dict] = get_db(family=self.family).get_list(
            self.FEATURE, "command_rules", []
        )
        validator = CommandsValidator(self.family, command_rules)
        validator.validate_commands(self.commands)


class SecureBinary31(FeatureBaseClass):
    """Secure Binary SB3.1 class."""

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

        :param family: Device family
        :param cert_block: Certification block.
        :param firmware_version: Firmware version (must be bigger than current CMPA record).
        :param sb_commands: SecureBinary31Commands object containing commands
        :param description: Custom description up to 16 characters long, defaults to None
        :param is_nxp_container: NXP provisioning SB file, defaults to False
        :param flags: Flags for SB file, defaults to 0
        :param signature_provider: Signature provider for final sign of SB3.1 image, defaults to None
        :param signature: Raw signature bytes (if signature_provider is not provided), defaults to None
        :raises SPSDKError: If neither signature_provider nor signature is provided
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

        :return: RKTH as bytes if available, None otherwise
        """
        if not self.sb_header.cert_block:
            return b""

        return self.sb_header.cert_block.rkth

    @classmethod
    def get_commands_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas.

        :param family: Family description.
        :return: List of validation schemas.
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
        """Create the list of validation schemas.

        :param family: Family description.
        :return: List of validation schemas.
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
        """Create the list of validation schemas.

        :param family: Family description.
        :return: List of validation schemas.
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

        :param config: Input standard configuration.
        :return: Instance of Secure Binary V3.1 class
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
        """Create configuration of the Feature.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
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

        :raises SPSDKError: Invalid configuration of SB3.1 class members.
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
        return f"SB3.1, TimeStamp: {self.sb_commands.timestamp}"

    def __str__(self) -> str:
        """Create string information about SB3.1 loaded file.

        :return: Text information about SB3.1.
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
        """Parse object from bytes array.

        :param data: Binary data to parse
        :param family: Family revision information, defaults to None
        :param pck: Part Common Key needed for decryption, defaults to None
        :param kdk_access_rights: Key Derivation Key access rights, defaults to 0
        :return: Constructed SecureBinary31 object
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

        :param binary: Binary data to be validate
        :raises SPSDKError: Invalid header of SB3.1 data
        """
        sb31_header = SecureBinary31Header.parse(binary)
        sb31_header.validate()
