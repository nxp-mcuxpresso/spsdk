#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module used for generation SecureBinary X."""
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
# Secure Boot Image Class (Version X)
########################################################################################################################
class TpHsmBlobHeader(BaseClass):
    """TP HSM blob header."""

    FORMAT = "<2BH16s"
    SIZE = calcsize(FORMAT)
    SIGNATURE = b"cert"

    def __init__(
        self, version: int = 1, blob_type: int = 0, oem_enc_data: bytes = bytes(16)
    ) -> None:
        """Constructor.

        :param version: blob version
        :param blob_type: type of the HSM blob
        :param build_number: of the certificate
        :raises SPSDKError: When there is invalid version
        """
        self.version = version
        self.blob_type = blob_type
        self.blob_size = TpHsmBlob.SIZE  # header size + signature size
        self.oem_enc_data = oem_enc_data

    def __str__(self) -> str:
        nfo = f"TP HSM Blob header: V={self.version}, T={self.blob_type}, BS={self.blob_size},"
        return nfo

    def __repr__(self) -> str:
        """Info of the certificate header in text form."""
        return "TP HSM blob header"

    def export(self) -> bytes:
        """TP HSM block header in binary form."""
        return pack(self.FORMAT, self.version, self.blob_type, self.blob_size, self.oem_enc_data)

    @classmethod
    def parse(cls, header_data: bytes, offset: int = 0) -> "TpHsmBlobHeader":
        """Parse object from bytes array.

        :param header_data: Input data as bytes
        :param offset: The offset of input data (default: 0)
        :return: Certificate Header instance
        :raises SPSDKParsingError: Unexpected size or signature of data
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
    """TP HSM blob."""

    FORMAT = "<20s32s"
    SIZE = calcsize(FORMAT)

    def __init__(
        self,
        tphsm_header: Union[TpHsmBlobHeader, bytes],
        signature: Optional[bytes] = None,
        hmac_key: Optional[str] = None,
    ) -> None:
        """Constructor.

        :param tphsm_header: TPHSM header
        :param signature: blob signature
        :param hmac_key: of the certificate
        :raises SPSDKError: When there is invalid version
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
        return "TP HSM Blob header"

    def __str__(self) -> str:
        """Info about TP HSM blob in text form."""
        msg = f"HMAC Key: {self.hmac_key.decode('ascii')}"
        msg += f"Signature: {self.signature.decode('ascii')}"
        return msg

    def export(self) -> bytes:
        """TP HSM blob in binary form."""
        if isinstance(self.header, TpHsmBlobHeader):
            return self.header.export() + self.signature
        return self.header + self.signature

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "TpHsmBlob":
        """Parse object from bytes array.

        :param data: Input data as bytes
        :param offset: The offset of input data (default: 0)
        :return: Certificate Header instance
        :raises SPSDKParsingError: Unexpected size or signature of data
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
    """Type of the Secure Binary X container."""

    NXP_PROVISIONING = 1
    OEM_PROVISIONING = 2
    OEM = 3


class SecureBinaryXHeader(BaseClass):
    """Header of the SecureBinary X."""

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

        :param firmware_version: Firmware version
        :param description: Custom description up to 16 characters long, defaults to None
        :param timestamp: Timestamp (number of seconds since Jan 1st, 2000), if None use current time
        :param image_type: type of the SB file, defaults to OEM_PROVISIONING
        :param flags: Flags for SBx file, defaults to 0
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
        """Format the description."""
        if not description:
            return bytes(self.DESCRIPTION_LENGTH)
        desc = bytes(description, encoding="ascii")
        desc = desc[: self.DESCRIPTION_LENGTH]
        desc += bytes(self.DESCRIPTION_LENGTH - len(desc))
        return desc

    def __repr__(self) -> str:
        return "Secure Binary X header"

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
        info += f" Total length of Block#0:     {self.sbx_block0_total_length}\n"
        info += f" Description:                 {self.description.decode('ascii')}\n"
        return info

    def update(self, commands: "SecureBinaryXCommands") -> None:
        """Updates the volatile fields in header by real commands.

        :param commands: SBx Commands block
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
            self.sbx_block0_total_length,
            self.image_type.value,
            self.description,
        )

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> Self:
        """Parse binary data into SecureBinaryXHeader.

        :raises SPSDKError: Unable to parse SBX Header.
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
        """Validate the settings of class members.

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
    """Blob containing SBX commands."""

    FEATURE = DatabaseManager.SBX
    SB_COMMANDS_NAME = "SBX"


class SecureBinaryX(FeatureBaseClass):
    """Secure Binary SBX class."""

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

        :param family: The CPU family
        :param tphsm_blob: TP HSM blob
        :param firmware_version: Firmware version.
        :param description: Custom description up to 16 characters long, defaults to None
        :param image_type: SecureBinaryXType
        :param signature_provider: signature provider to final sign of SBX image
            in case of OEM and NXP_PROVISIONING types
        :param flags: Flags for SB file, defaults to 0
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
        """Return true if SBx is signed by ISK certificate."""
        return self.image_type in [SecureBinaryXType.OEM, SecureBinaryXType.NXP_PROVISIONING]

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

        :param config: Input standard configuration.
        :return: Instance of Secure Binary X class
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
        """Create configuration of the Feature."""
        raise SPSDKNotImplementedError()

    def validate(self) -> None:
        """Validate the settings of class members.

        :raises SPSDKError: Invalid configuration of SBx class members.
        """
        self.sb_header.validate()

    def load_tphsm(self, tphsm: bytes, offset: int = 0) -> None:
        """Load TPHSM blob from binary data.

        :param tphsm: TPHSM binary data
        :param offset: offset, defaults to 0
        """
        self.tphsm_blob = TpHsmBlob.parse(tphsm, offset)

    def update_header(self) -> None:
        """Update SBx header."""
        self.sb_header.update(self.sb_commands)

    def export_header(self, final_hash: bytes = bytes(32)) -> bytes:
        """Export SBx header without signature for encryption on device.

        :raises SPSDKError: TPHSM blob must be loaded first
        :return: plain header without signature in bytes
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
        return "SBx Container"

    def __str__(self) -> str:
        """Create string information about SBx loaded file."""
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

        :raises NotImplementedError: Not yet implemented
        """
        raise NotImplementedError("Not yet implemented.")
