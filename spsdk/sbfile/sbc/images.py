#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module used for generation SecureBinary X."""
import logging
from struct import calcsize, pack, unpack_from
from typing import Any, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError
from spsdk.sbfile.sb31.images import SecureBinary31, SecureBinary31Commands
from spsdk.utils.abstract import BaseClass
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, update_validation_schema_family

logger = logging.getLogger(__name__)


########################################################################################################################
# Secure Boot Image Class (Version C)
########################################################################################################################
class SecureBinaryCHeader(BaseClass):
    """Header of the SecureBinary X."""

    HEADER_FORMAT = "<4s2H3LQ4L16s"
    HEADER_SIZE = calcsize(HEADER_FORMAT) + 32
    MAGIC = b"sbv3"
    FORMAT_VERSION = "3.1"
    DESCRIPTION_LENGTH = 16
    BLOCK_SIZE = 292
    CERT_OFFSET = 0x5C

    def __init__(
        self,
        firmware_version: int = 1,
        description: Optional[str] = None,
        timestamp: Optional[int] = None,
        image_type: int = 6,
        flags: int = 1,
    ) -> None:
        """Initialize the SecureBinary C Header.

        :param firmware_version: Firmware version
        :param description: Custom description up to 16 characters long, defaults to None
        :param timestamp: Timestamp (number of seconds since Jan 1st, 2000), if None use current time
        :param image_type: type of the SB file, defaults to OEM_PROVISIONING
        :param flags: Flags for SBc file, defaults to 0
        """
        self.flags = flags
        self.block_count = 1
        self.image_type = image_type
        self.firmware_version = firmware_version
        self.timestamp = timestamp or SecureBinary31.get_current_timestamp()
        manifest_size = 0xAC
        self.sbc_block0_total_length = manifest_size
        self.description = self._adjust_description(description)
        self.block_size = self.BLOCK_SIZE
        self.cert_offset = self.CERT_OFFSET

    def _adjust_description(self, description: Optional[str] = None) -> bytes:
        """Format the description."""
        if not description:
            return bytes(self.DESCRIPTION_LENGTH)
        desc = bytes(description, encoding="ascii")
        desc = desc[: self.DESCRIPTION_LENGTH]
        desc += bytes(self.DESCRIPTION_LENGTH - len(desc))
        return desc

    def __repr__(self) -> str:
        return "Secure Binary C header"

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
        info += f" Total length of Block#0:     {self.sbc_block0_total_length}\n"
        info += f" Description:                 {self.description.decode('ascii')}\n"
        return info

    def update(self, commands: "SecureBinaryCCommands") -> None:
        """Updates the volatile fields in header by real commands.

        :param commands: SBc Commands block
        """
        self.block_count = commands.block_count

    def export(self) -> bytes:
        """Export the SB file to bytes.

        :return: Exported header bytes
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
            self.sbc_block0_total_length,
            self.image_type,
            self.cert_offset,
            self.description,
        )

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> Self:
        """Parse binary data into SecureBinaryC Header.

        :raises SPSDKError: Unable to parse SBc Header.
        """
        (
            magic,
            minor_version,
            major_version,
            flags,
            block_count,
            block_size,
            timestamp,
            firmware_version,
            sbc_block0_total_length,
            image_type,
            description,
        ) = unpack_from(cls.HEADER_FORMAT, data, offset=offset)
        if magic != cls.MAGIC:
            raise SPSDKError("Magic doesn't match")
        if major_version != 1 and minor_version != 0:
            raise SPSDKError(f"Unable to parse SB version {major_version}.{minor_version}")
        if block_size not in [292, 308]:
            raise SPSDKError(f"Wrong block size: {block_size}")

        obj = cls(
            firmware_version=firmware_version,
            description=description.decode("utf-8"),
            timestamp=timestamp,
            image_type=image_type,
            flags=flags,
        )
        obj.block_count = block_count
        obj.block_size = block_size
        obj.sbc_block0_total_length = sbc_block0_total_length
        return obj

    def validate(self) -> None:
        """Validate the settings of class members.

        :raises SPSDKError: Invalid configuration of SBc header blob class members.
        """
        if self.flags is None:
            raise SPSDKError("Invalid SBc header flags.")
        if self.block_count is None or self.block_count < 0:
            raise SPSDKError("Invalid SBc header block count.")
        if self.block_size is None or self.block_size != self.BLOCK_SIZE:
            raise SPSDKError("Invalid SBc header block size.")
        if self.firmware_version is None:
            raise SPSDKError("Invalid SBc header firmware version.")
        if self.timestamp is None:
            raise SPSDKError("Invalid SBc header timestamp.")
        if self.sbc_block0_total_length is None or self.sbc_block0_total_length < self.HEADER_SIZE:
            raise SPSDKError("Invalid SBc block 0 total length.")
        if self.description is None or len(self.description) != 16:
            raise SPSDKError("Invalid SBc header image description.")


class SecureBinaryCCommands(SecureBinary31Commands):
    """Blob containing SBC commands."""

    FEATURE = DatabaseManager.SBC
    SB_COMMANDS_NAME = "SBc"


class SecureBinaryC(FeatureBaseClass):
    """Secure Binary SBC class."""

    FEATURE = DatabaseManager.SBC

    def __init__(
        self,
        family: FamilyRevision,
        firmware_version: int,
        commands: SecureBinaryCCommands,
        description: Optional[str] = None,
        image_type: int = 6,
        flags: int = 1,
    ) -> None:
        """Constructor for Secure Binary vC data container.

        :param family: The CPU family
        :param firmware_version: Firmware version
        :param description: Custom description up to 16 characters long, defaults to None
        :param image_type: SecureBinaryCType
        :param signature_provider: signature provider to final sign of SBC image
            in case of OEM and NXP_PROVISIONING types
        :param flags: Flags for SB file, defaults to 0
        """
        # in our case, timestamp is the number of seconds since "Jan 1, 2000"
        self.family = family
        self.firmware_version = firmware_version
        self.image_type = image_type
        self.description = description
        self.flags = flags

        self.sb_header = SecureBinaryCHeader(
            firmware_version=self.firmware_version,
            description=self.description,
            timestamp=commands.timestamp,
            image_type=image_type,
            flags=self.flags,
        )

        self.sb_commands = commands

    @classmethod
    def get_validation_schemas(
        cls, family: FamilyRevision, include_test_configuration: bool = False
    ) -> list[dict[str, Any]]:
        """Create the list of validation schemas.

        :param family: Family description.
        :param include_test_configuration: Add also testing configuration schemas.
        :return: List of validation schemas.
        """
        mbi_sch_cfg = get_schema_file(DatabaseManager.MBI)
        sbc_sch_cfg = get_schema_file(DatabaseManager.SBC)
        family_sch = get_schema_file("general")["family"]
        update_validation_schema_family(
            family_sch["properties"], cls.get_supported_families(), family
        )
        ret: list[dict[str, Any]] = [family_sch]
        ret.extend(
            [
                mbi_sch_cfg[x]
                for x in [
                    "firmware_version",
                ]
            ]
        )
        ret.extend(
            [
                sbc_sch_cfg[x]
                for x in [
                    "sbc_output",
                    "sbc",
                    "sbc_description",
                    "sbc_commands",
                ]
            ]
        )
        if include_test_configuration:
            ret.append(sbc_sch_cfg["sbc_test"])

        return ret

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Creates an instance of SecureBinaryC from configuration.

        :param config: Input standard configuration.
        :return: Instance of Secure Binary C class
        """
        description = config.get_str("description", "SBC file")
        firmware_version = config.get_int("firmwareVersion", 1)
        family = FamilyRevision.load_from_config(config)

        sb_commands = SecureBinaryCCommands.load_from_config(config, load_just_commands=True)
        # Create SBC object
        return cls(
            family=family,
            commands=sb_commands,
            firmware_version=firmware_version,
            description=description,
        )

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature."""
        raise SPSDKNotImplementedError()

    def validate(self) -> None:
        """Validate the settings of class members.

        :raises SPSDKError: Invalid configuration of SBc class members.
        """
        self.sb_header.validate()

    def update_header(self) -> None:
        """Update SBc header."""
        self.sb_header.update(self.sb_commands)

    def export_header(self, final_hash: bytes = bytes(32)) -> bytes:
        """Export SBc header without signature for encryption on device.

        :return: plain header without signature in bytes
        """
        final_data = bytes()
        final_data += self.sb_header.export()
        # add hash of next block
        final_data += final_hash

        return final_data

    def export(self) -> bytes:
        """Generate binary output of SBc file.

        :return: Content of SBc file in bytes.
        """
        self.validate()

        sbc_commands_data = self.sb_commands.export()

        final_data = bytes()
        # HEADER OF SB C FILE
        self.sb_header.update(self.sb_commands)
        final_data += self.sb_header.export()

        # HASH OF PREVIOUS BLOCK
        final_data += self.sb_commands.final_hash
        # # SIGNATURE (keep it blank)
        final_data += bytes(32)

        # # COMMANDS BLOBS DATA
        final_data += sbc_commands_data

        return final_data

    def __repr__(self) -> str:
        return "SBc Container"

    def __str__(self) -> str:
        """Create string information about SBc loaded file."""
        self.validate()
        ret = ""

        ret += "SBc header:\n"
        ret += str(self.sb_header)

        ret += "SBc commands blob :\n"
        ret += str(self.sb_commands)

        return ret

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> Self:
        """Parse object from bytes array.

        :raises NotImplementedError: Not yet implemented
        """
        raise NotImplementedError("Not yet implemented.")
