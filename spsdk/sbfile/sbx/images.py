#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK SecureBinary X image generation and management utilities.

This module provides functionality for creating and handling SecureBinary X (SBX) images,
including TPM HSM blob management, secure binary headers, commands, and complete SBX image
construction for NXP MCU secure provisioning.
"""

import logging
from enum import Enum
from struct import calcsize, pack, unpack_from
from typing import Any, Optional, Union

from typing_extensions import Self

from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.crypto.spsdk_hmac import hmac
from spsdk.exceptions import SPSDKError, SPSDKNotImplementedError, SPSDKParsingError
from spsdk.sbfile.sb31.images import SecureBinary31, SecureBinary31Commands
from spsdk.utils.abstract import BaseClass
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, update_validation_schema_family

logger = logging.getLogger(__name__)


########################################################################################################################
# Secure Binary Image Class (Version X)
########################################################################################################################
class TpHsmBlobHeader(BaseClass):
    """TP HSM blob header for secure provisioning operations.

    This class represents and manages the header structure for
    TP HSM (TrustProvisioning Hardware Security Module) blobs, providing
    functionality to create, parse, and export binary header data with
    version control and OEM encryption support.

    :cvar FORMAT: Binary format string for header structure.
    :cvar SIZE: Total size of the header in bytes.
    :cvar SIGNATURE: Expected signature for header validation.
    """

    FORMAT = "<2BH16s"
    SIZE = calcsize(FORMAT)
    SIGNATURE = b"cert"

    def __init__(
        self, version: int = 1, blob_type: int = 0, oem_enc_data: bytes = bytes(16)
    ) -> None:
        """Initialize TpHsmBlob instance.

        :param version: Blob version number.
        :param blob_type: Type of the HSM blob.
        :param oem_enc_data: OEM encryption data, defaults to 16 zero bytes.
        :raises SPSDKError: When there is invalid version.
        """
        self.version = version
        self.blob_type = blob_type
        self.blob_size = TpHsmBlob.SIZE  # header size + signature size
        self.oem_enc_data = oem_enc_data

    def __str__(self) -> str:
        """Get string representation of TP HSM Blob header.

        Creates a formatted string containing the version, blob type, and blob size
        information of the TP HSM Blob header.

        :return: Formatted string with header information including version, type, and size.
        """
        nfo = f"TP HSM Blob header: V={self.version}, T={self.blob_type}, BS={self.blob_size},"
        return nfo

    def __repr__(self) -> str:
        """Get string representation of the TP HSM blob header.

        :return: String representation of the header.
        """
        return "TP HSM blob header"

    def export(self) -> bytes:
        """Export TP HSM block header in binary form.

        Serializes the TP HSM block header into its binary representation using the
        defined format structure.

        :return: Binary representation of the TP HSM block header.
        """
        return pack(self.FORMAT, self.version, self.blob_type, self.blob_size, self.oem_enc_data)

    @classmethod
    def parse(cls, header_data: bytes, offset: int = 0) -> "TpHsmBlobHeader":
        """Parse TpHsmBlobHeader object from bytes array.

        :param header_data: Input data as bytes to parse the header from.
        :param offset: The offset of input data (default: 0).
        :return: TpHsmBlobHeader instance.
        :raises SPSDKParsingError: Unexpected size or signature of data.
        """
        if cls.SIZE > len(header_data) - offset:
            raise SPSDKParsingError("Unexpected size or signature of data")
        (
            version,
            blob_type,
            blob_size,
            oem_enc_data,
        ) = unpack_from(cls.FORMAT, header_data, offset)
        obj = cls(
            version=version,
            blob_type=blob_type,
            oem_enc_data=oem_enc_data,
        )
        obj.blob_size = blob_size

        return obj


class TpHsmBlob(BaseClass):
    """TP HSM (Trusted Provisioning Hardware Security Module) blob container.

    This class represents a cryptographically secured blob used in trusted provisioning
    operations. It combines a TP HSM header with HMAC-based authentication to ensure
    data integrity and authenticity during secure provisioning workflows.

    :cvar FORMAT: Binary format string for blob structure.
    :cvar SIZE: Total size of the blob in bytes.
    """

    FORMAT = "<20s32s"
    SIZE = calcsize(FORMAT)

    def __init__(
        self,
        tphsm_header: Union[TpHsmBlobHeader, bytes],
        signature: Optional[bytes] = None,
        hmac_key: Optional[str] = None,
    ) -> None:
        """Initialize TPHSM blob with header and authentication.

        Creates a new TPHSM blob instance with the provided header and either a signature
        or HMAC key for authentication. If HMAC key is provided, it will be used to generate
        the signature from the header data.

        :param tphsm_header: TPHSM header object or raw header bytes.
        :param signature: Pre-computed blob signature bytes, optional.
        :param hmac_key: Hexadecimal string representation of HMAC key for signature
            generation, optional.
        :raises SPSDKError: When neither signature nor HMAC key is provided.
        """
        self.header = tphsm_header
        if not hmac_key and not signature:
            raise SPSDKError("One of signature or HMAC key must be provided")
        if hmac_key:
            self.hmac_key = bytes.fromhex(hmac_key)
        if signature:
            self.signature = signature
        else:
            header = self.header if isinstance(self.header, bytes) else self.header.export()
            self.signature = hmac(self.hmac_key, header)

    def __repr__(self) -> str:
        """Return string representation of TP HSM Blob header.

        :return: String representation of the TP HSM Blob header.
        """
        return "TP HSM Blob header"

    def __str__(self) -> str:
        """Get string representation of TP HSM blob.

        Returns formatted information about the TP HSM blob including HMAC key and signature
        in human-readable text format.

        :return: Formatted string containing HMAC key and signature information.
        """
        msg = f"HMAC Key: {self.hmac_key.decode('ascii')}"
        msg += f"Signature: {self.signature.decode('ascii')}"
        return msg

    def export(self) -> bytes:
        """Export TP HSM blob in binary form.

        Converts the TP HSM blob object into its binary representation by combining
        the header and signature components.

        :return: Binary representation of the TP HSM blob.
        """
        if isinstance(self.header, TpHsmBlobHeader):
            return self.header.export() + self.signature
        return self.header + self.signature

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "TpHsmBlob":
        """Parse TpHsmBlob object from bytes array.

        :param data: Input data as bytes to parse the TpHsmBlob from.
        :param offset: The offset of input data (default: 0).
        :return: TpHsmBlob instance parsed from the data.
        :raises SPSDKParsingError: Unexpected size or signature of data.
        """
        if cls.SIZE > len(data) - offset:
            raise SPSDKParsingError("Unexpected size or signature of data")
        (
            tphsm_header,
            signature,
        ) = unpack_from(cls.FORMAT, data, offset)
        obj = cls(
            tphsm_header=tphsm_header,
            signature=signature,
        )

        return obj


class SecureBinaryXType(Enum):
    """Secure Binary X container type enumeration.

    This enumeration defines the different types of Secure Binary X containers
    used in SPSDK for various provisioning and deployment scenarios.
    """

    NXP_PROVISIONING = 1
    OEM_PROVISIONING = 2
    OEM = 3


class SecureBinaryXHeader(BaseClass):
    """SecureBinary X file header representation.

    This class manages the header structure for SecureBinary X (SBx) files, handling
    metadata such as firmware version, timestamps, image types, and descriptions.
    It provides functionality for creating, validating, and serializing SBx headers
    according to the NXP secure binary format specification.

    :cvar HEADER_FORMAT: Binary format string for header structure.
    :cvar HEADER_SIZE: Total size of the header in bytes.
    :cvar MAGIC: Magic bytes identifier for SBx files.
    :cvar FORMAT_VERSION: Version of the SBx format.
    :cvar DESCRIPTION_LENGTH: Maximum length for description field.
    :cvar BLOCK_SIZE: Size of data blocks in the SBx file.
    """

    HEADER_FORMAT = "<4s2H3LQ3L16s"
    HEADER_SIZE = calcsize(HEADER_FORMAT) + 84
    MAGIC = b"sbvx"
    FORMAT_VERSION = "1.0"
    DESCRIPTION_LENGTH = 16
    BLOCK_SIZE = 4 + 256 + 32

    def __init__(
        self,
        firmware_version: int,
        description: Optional[str] = None,
        timestamp: Optional[int] = None,
        image_type: SecureBinaryXType = SecureBinaryXType.OEM_PROVISIONING,
        flags: int = 0,
    ) -> None:
        """Initialize the SecureBinary X Header.

        :param firmware_version: Firmware version number.
        :param description: Custom description up to 16 characters long, defaults to None.
        :param timestamp: Timestamp (number of seconds since Jan 1st, 2000), if None use current time.
        :param image_type: Type of the SB file, defaults to OEM_PROVISIONING.
        :param flags: Flags for SBx file, defaults to 0.
        """
        self.flags = flags
        self.block_count = 1
        self.image_type = image_type
        self.firmware_version = firmware_version
        self.timestamp = timestamp or SecureBinary31.get_current_timestamp()
        manifest_size = self.HEADER_SIZE
        manifest_size += 32 if image_type == SecureBinaryXType.OEM_PROVISIONING else 64
        self.sbx_block0_total_length = manifest_size
        self.description = self._adjust_description(description)
        self.block_size = self.BLOCK_SIZE

    def _adjust_description(self, description: Optional[str] = None) -> bytes:
        """Format the description to fixed-length byte array.

        Converts string description to ASCII bytes and pads or truncates to match
        the required DESCRIPTION_LENGTH. If no description is provided, returns
        a zero-filled byte array.

        :param description: Optional description string to format.
        :return: Fixed-length byte array of DESCRIPTION_LENGTH size.
        """
        if not description:
            return bytes(self.DESCRIPTION_LENGTH)
        desc = bytes(description, encoding="ascii")
        desc = desc[: self.DESCRIPTION_LENGTH]
        desc += bytes(self.DESCRIPTION_LENGTH - len(desc))
        return desc

    def __repr__(self) -> str:
        """Return string representation of Secure Binary X header.

        :return: String representation of the header.
        """
        return "Secure Binary X header"

    def __str__(self) -> str:
        """Get string representation of SB v3.1 image information.

        Returns formatted string containing all SB v3.1 image properties including magic,
        version, flags, block information, firmware version, image type, timestamp,
        and description.

        :return: Formatted string with SB v3.1 image details.
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
        info += f" Total length of Block#0:     {self.sbx_block0_total_length}\n"
        info += f" Description:                 {self.description.decode('ascii')}\n"
        return info

    def update(self, commands: "SecureBinaryXCommands") -> None:
        """Updates the volatile fields in header by real commands.

        :param commands: SBx Commands block to extract data from.
        """
        self.block_count = commands.block_count

    def export(self) -> bytes:
        """Export the SB file to bytes.

        Converts the SBX image header structure into a binary representation using the defined
        header format and packing all header fields according to the specification.

        :return: Exported header bytes containing the complete SBX image header structure.
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
            self.sbx_block0_total_length,
            self.image_type.value,
            self.description,
        )

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> Self:
        """Parse binary data into SecureBinaryXHeader.

        This method deserializes binary data according to the SBX header format and creates
        a SecureBinaryXHeader instance with the parsed values.

        :param data: Binary data containing the SBX header.
        :param offset: Offset in the data where parsing should start.
        :raises SPSDKError: Unable to parse SBX Header due to invalid magic, version, or block size.
        :return: Parsed SecureBinaryXHeader instance.
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
            sbx_block0_total_length,
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
        obj.sbx_block0_total_length = sbx_block0_total_length
        return obj

    def validate(self) -> None:
        """Validate the settings of SBx header class members.

        Performs comprehensive validation of all required SBx header attributes including flags,
        block count, block size, image type, firmware version, timestamp, block 0 total length,
        and image description to ensure they meet the SBx format requirements.

        :raises SPSDKError: Invalid configuration of SBx header blob class members.
        """
        if self.flags is None:
            raise SPSDKError("Invalid SBx header flags.")
        if self.block_count is None or self.block_count < 0:
            raise SPSDKError("Invalid SBx header block count.")
        if self.block_size is None or self.block_size != self.BLOCK_SIZE:
            raise SPSDKError("Invalid SBx header block size.")
        if self.image_type is None or not isinstance(self.image_type, SecureBinaryXType):
            raise SPSDKError("Invalid SBx header image type.")
        if self.firmware_version is None:
            raise SPSDKError("Invalid SBx header firmware version.")
        if self.timestamp is None:
            raise SPSDKError("Invalid SBx header timestamp.")
        if self.sbx_block0_total_length is None or self.sbx_block0_total_length < self.HEADER_SIZE:
            raise SPSDKError("Invalid SBx block 0 total length.")
        if self.description is None or len(self.description) != 16:
            raise SPSDKError("Invalid SBx header image description.")


class SecureBinaryXCommands(SecureBinary31Commands):
    """SBX (Secure Binary X) commands container for NXP MCU provisioning.

    This class manages and processes SBX format commands used in secure provisioning
    operations for NXP microcontrollers, extending the SB3.1 command functionality.

    :cvar FEATURE: Database feature identifier for SBX operations.
    :cvar SB_COMMANDS_NAME: Human-readable name for SBX command format.
    """

    FEATURE = DatabaseManager.SBX
    SB_COMMANDS_NAME = "SBX"


class SecureBinaryX(FeatureBaseClass):
    """Secure Binary X (SBX) container for NXP MCU secure provisioning.

    This class manages the creation, validation, and export of Secure Binary X format
    files used for secure provisioning and firmware updates on NXP MCUs. It handles
    SBX headers, command sequences, cryptographic signatures, and TP-HSM integration.

    :cvar FEATURE: Database manager feature identifier for SBX support.
    """

    FEATURE = DatabaseManager.SBX

    def __init__(
        self,
        family: FamilyRevision,
        firmware_version: int,
        tphsm_blob: Optional[TpHsmBlob],
        commands: SecureBinaryXCommands,
        description: Optional[str] = None,
        image_type: SecureBinaryXType = SecureBinaryXType.OEM_PROVISIONING,
        signature_provider: Optional[SignatureProvider] = None,
        flags: int = 0,
    ) -> None:
        """Constructor for Secure Binary vX data container.

        :param family: The MCU/MPU family.
        :param firmware_version: Firmware version.
        :param tphsm_blob: TP HSM blob, optional.
        :param commands: SecureBinaryX commands container.
        :param description: Custom description up to 16 characters long, defaults to None.
        :param image_type: SecureBinaryXType, defaults to OEM_PROVISIONING.
        :param signature_provider: Signature provider to final sign of SBX image in case of OEM
            and NXP_PROVISIONING types, defaults to None.
        :param flags: Flags for SB file, defaults to 0.
        :raises SPSDKError: If signature provider is not provided for OEM and NXP_PROVISIONING
            images.
        """
        # in our case, timestamp is the number of seconds since "Jan 1, 2000"
        self.family = family
        self.tphsm_blob = tphsm_blob
        self.firmware_version = firmware_version
        self.image_type = image_type
        self.description = description
        self.flags = flags
        self.signature_provider = signature_provider

        if self.isk_signed and not signature_provider:
            raise SPSDKError(
                "Signature provider needs to be provided in case of OEM and NXP_PROVISIONING images"
            )

        self.sb_header = SecureBinaryXHeader(
            firmware_version=self.firmware_version,
            description=self.description,
            timestamp=commands.timestamp,
            image_type=image_type,
            flags=self.flags,
        )

        self.sb_commands = commands

    @property
    def isk_signed(self) -> bool:
        """Check if SBx image is signed by ISK certificate.

        This method determines whether the secure binary image uses ISK (Intermediate Signing Key)
        certificate for signing by checking if the image type is OEM or NXP_PROVISIONING.

        :return: True if the image is signed by ISK certificate, False otherwise.
        """
        return self.image_type in [SecureBinaryXType.OEM, SecureBinaryXType.NXP_PROVISIONING]

    @classmethod
    def get_validation_schemas(
        cls, family: FamilyRevision, include_test_configuration: bool = False
    ) -> list[dict[str, Any]]:
        """Create the list of validation schemas for SBX image configuration.

        The method retrieves and combines validation schemas from MBI and SBX schema files,
        including family-specific schemas and optional test configuration schemas.

        :param family: Family description specifying the target MCU family.
        :param include_test_configuration: Add also testing configuration schemas.
        :return: List of validation schemas for SBX image configuration.
        """
        mbi_sch_cfg = get_schema_file(DatabaseManager.MBI)
        sbx_sch_cfg = get_schema_file(DatabaseManager.SBX)
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
                sbx_sch_cfg[x]
                for x in [
                    "sbx_output",
                    "sbx",
                    "sbx_description",
                    "signer",
                    "sbx_commands",
                ]
            ]
        )
        if include_test_configuration:
            ret.append(sbx_sch_cfg["sbx_test"])

        return ret

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Creates an instance of SecureBinaryX from configuration.

        The method parses the configuration to extract all necessary parameters for creating
        a SecureBinaryX instance, including family revision, image type, signature provider,
        and commands.

        :param config: Input standard configuration containing SBX parameters.
        :return: Instance of Secure Binary X class.
        """
        description = config.get_str("description", "SBX file")
        firmware_version = config.get_int("firmwareVersion", 1)
        family = FamilyRevision.load_from_config(config)
        image_type = SecureBinaryXType[config["image_type"]]

        # signature provider only necessary for OEM and NXP provisioning types
        if image_type in [SecureBinaryXType.OEM, SecureBinaryXType.NXP_PROVISIONING]:
            signature_provider = get_signature_provider(config)
        else:
            signature_provider = None

        sb_commands = SecureBinaryXCommands.load_from_config(config, load_just_commands=True)

        # Create SBX object
        return cls(
            family=family,
            tphsm_blob=None,
            commands=sb_commands,
            firmware_version=firmware_version,
            description=description,
            image_type=image_type,
            signature_provider=signature_provider,
        )

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature.

        :param data_path: Path to directory containing configuration data files.
        :raises SPSDKNotImplementedError: Method is not implemented in base class.
        """
        raise SPSDKNotImplementedError()

    def validate(self) -> None:
        """Validate the settings of class members.

        :raises SPSDKError: Invalid configuration of SBx class members.
        """
        self.sb_header.validate()

    def load_tphsm(self, tphsm: bytes, offset: int = 0) -> None:
        """Load TPHSM blob from binary data.

        This method parses the provided TPHSM binary data and stores it as a TpHsmBlob object
        in the instance.

        :param tphsm: TPHSM binary data to be parsed.
        :param offset: Starting offset in the binary data, defaults to 0.
        """
        self.tphsm_blob = TpHsmBlob.parse(tphsm, offset)

    def update_header(self) -> None:
        """Update SBx header.

        Updates the SB header with current command information from sb_commands.
        This method synchronizes the header metadata to reflect the current state
        of the command sequence.
        """
        self.sb_header.update(self.sb_commands)

    def export_header(self, final_hash: bytes = bytes(32)) -> bytes:
        """Export SBx header without signature for encryption on device.

        The method exports the SB header combined with TPHSM blob and final hash
        for device-side encryption processing.

        :param final_hash: Hash of the next block to be included in header.
        :raises SPSDKError: TPHSM blob must be loaded first.
        :return: Plain header without signature in bytes.
        """
        if not isinstance(self.tphsm_blob, TpHsmBlob):
            raise SPSDKError("TPHSM blob must be loaded first")

        final_data = bytes()
        final_data += self.sb_header.export()
        final_data += self.tphsm_blob.export()
        # add hash of next block
        final_data += final_hash

        return final_data

    def export(self) -> bytes:
        """Generate binary output of SBx file.

        The method exports the complete SBx file structure including header, TPHSM blob,
        hash of previous block, signature placeholder, and commands data.

        :raises SPSDKError: TPHSM blob must be loaded first
        :return: Content of SBx file in bytes.
        """
        if not isinstance(self.tphsm_blob, TpHsmBlob):
            raise SPSDKError("TPHSM blob must be loaded first")
        self.validate()

        sbx_commands_data = self.sb_commands.export()
        tphsm_blob = self.tphsm_blob.export()

        final_data = bytes()
        # HEADER OF SB X FILE
        self.sb_header.update(self.sb_commands)
        final_data += self.sb_header.export()

        # TPHSM BLOB
        final_data += tphsm_blob

        # HASH OF PREVIOUS BLOCK
        final_data += self.sb_commands.final_hash
        # # SIGNATURE (keep it blank)
        final_data += bytes(32)

        # # COMMANDS BLOBS DATA
        final_data += sbx_commands_data

        return final_data

    def __repr__(self) -> str:
        """Return string representation of SBx Container.

        :return: String representation of the SBx Container object.
        """
        return "SBx Container"

    def __str__(self) -> str:
        """Create string representation of SBx loaded file.

        The method validates the SBx file and returns a formatted string containing
        information about the SBx header and commands blob.

        :raises SPSDKError: If validation fails.
        :return: Formatted string with SBx header and commands information.
        """
        self.validate()
        ret = ""

        ret += "SBx header:\n"
        ret += str(self.sb_header)

        ret += "SBx commands blob :\n"
        ret += str(self.sb_commands)

        return ret

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> Self:
        """Parse object from bytes array.

        :param data: Input bytes array to parse the object from.
        :param offset: Starting offset in the bytes array, defaults to 0.
        :raises NotImplementedError: Not yet implemented.
        :return: Parsed object instance.
        """
        raise NotImplementedError("Not yet implemented.")
