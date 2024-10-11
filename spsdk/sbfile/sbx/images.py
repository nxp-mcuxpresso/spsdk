#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module used for generation SecureBinary X."""
import logging
from datetime import datetime
from enum import Enum
from struct import calcsize, pack, unpack_from
from typing import Any, Optional, Union

from spsdk.crypto.hash import get_hash
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.crypto.spsdk_hmac import hmac
from spsdk.exceptions import SPSDKError, SPSDKParsingError
from spsdk.sbfile.sb31.commands import CFG_NAME_TO_CLASS, CmdSectionHeader, MainCmd
from spsdk.utils.abstract import BaseClass
from spsdk.utils.database import DatabaseManager, get_db, get_families, get_schema_file
from spsdk.utils.misc import align_block, value_to_int
from spsdk.utils.schema_validator import CommentedConfig, update_validation_schema_family

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
        """Deserialize object from bytes array.

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
        """Deserialize object from bytes array.

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
        self.timestamp = timestamp or int(datetime.now().timestamp())
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
            self.sbx_block0_total_length,
            self.image_type.value,
            self.description,
        )

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "SecureBinaryXHeader":
        """Parse binary data into SecureBinary31Header.

        :raises SPSDKError: Unable to parse SB31 Header.
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

        obj = SecureBinaryXHeader(
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


class SecureBinaryXCommands(BaseClass):
    """Blob containing SBX commands."""

    DATA_CHUNK_LENGTH = 256

    def __init__(
        self,
    ) -> None:
        """Initialize container for SBx commands.

        :raises SPSDKError: Key derivation arguments are not provided if `is_encrypted` is True
        """
        super().__init__()
        self.block_count = 0
        self.final_hash = bytes(32)
        self.commands: list[MainCmd] = []

    def add_command(self, command: MainCmd) -> None:
        """Add SBx command."""
        self.commands.append(command)

    def insert_command(self, index: int, command: MainCmd) -> None:
        """Insert SBx command."""
        if index == -1:
            self.commands.append(command)
        else:
            self.commands.insert(index, command)

    def set_commands(self, commands: list[MainCmd]) -> None:
        """Set all SBx commands at once."""
        self.commands = commands.copy()

    def load_from_config(
        self, config: list[dict[str, Any]], search_paths: Optional[list[str]] = None
    ) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        for cfg_cmd in config:
            cfg_cmd_key = list(cfg_cmd.keys())[0]
            cfg_cmd_value = cfg_cmd[cfg_cmd_key]
            self.add_command(
                CFG_NAME_TO_CLASS[cfg_cmd_key].load_from_config(
                    cfg_cmd_value, search_paths=search_paths
                )
            )

    def get_cmd_blocks_to_export(self) -> list[bytes]:
        """Export commands as bytes."""
        commands_bytes = b"".join([command.export() for command in self.commands])
        section_header = CmdSectionHeader(length=len(commands_bytes))
        total = section_header.export() + commands_bytes

        data_blocks = [
            total[i : i + self.DATA_CHUNK_LENGTH]
            for i in range(0, len(total), self.DATA_CHUNK_LENGTH)
        ]
        data_blocks[-1] = align_block(data_blocks[-1], alignment=self.DATA_CHUNK_LENGTH)

        return data_blocks

    def process_cmd_blocks_to_export(self, data_blocks: list[bytes]) -> bytes:
        """Process given data blocks for export."""
        self.block_count = len(data_blocks)

        processed_blocks = [
            self._process_block(block_number, block_data)
            for block_number, block_data in reversed(list(enumerate(data_blocks, start=1)))
        ]
        final_data = b"".join(reversed(processed_blocks))
        return final_data

    def export(self) -> bytes:
        """Export commands as bytes."""
        data_blocks = self.get_cmd_blocks_to_export()
        return self.process_cmd_blocks_to_export(data_blocks)

    def _process_block(self, block_number: int, block_data: bytes) -> bytes:
        """Process single block."""
        full_block = pack(
            f"<L{len(self.final_hash)}s{len(block_data)}s",
            block_number,
            self.final_hash,
            block_data,
        )
        block_hash = get_hash(full_block)
        self.final_hash = block_hash
        return full_block

    def __repr__(self) -> str:
        return f"SBx Commands count {len(self.commands)}"

    def __str__(self) -> str:
        """Get string information for commands in the container."""
        info = str()
        info += "COMMANDS:\n"
        info += f"Number of commands: {len(self.commands)}\n"
        for command in self.commands:
            info += f"  {str(command)}\n"
        return info

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "SecureBinaryXCommands":
        """Parse binary data into SecureBinary31Commands.

        :raises NotImplementedError: Not yet implemented
        """
        raise NotImplementedError("Not yet implemented.")


class SecureBinaryX(BaseClass):
    """Secure Binary SBX class."""

    def __init__(
        self,
        firmware_version: int,
        tphsm_blob: Optional[TpHsmBlob],
        description: Optional[str] = None,
        image_type: SecureBinaryXType = SecureBinaryXType.OEM_PROVISIONING,
        signature_provider: Optional[SignatureProvider] = None,
        flags: int = 0,
        timestamp: Optional[int] = None,
    ) -> None:
        """Constructor for Secure Binary vX data container.

        :param tphsm_blob: TP HSM blob
        :param firmware_version: Firmware version.
        :param description: Custom description up to 16 characters long, defaults to None
        :param image_type: SecureBinaryXType
        :param signature_provider: signature provider to final sign of SBX image
            in case of OEM and NXP_PROVISIONING types
        :param flags: Flags for SB file, defaults to 0
        :param timestamp: Timestamp used for encryption (needed if `is_encrypted` is True), defaults to None
        """
        # in our case, timestamp is the number of seconds since "Jan 1, 2000"
        self.timestamp = timestamp or int((datetime.now() - datetime(2000, 1, 1)).total_seconds())
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
            timestamp=self.timestamp,
            image_type=image_type,
            flags=self.flags,
        )

        self.sb_commands = SecureBinaryXCommands()

    @property
    def isk_signed(self) -> bool:
        """Return true if SBx is signed by ISK certificate."""
        return self.image_type in [SecureBinaryXType.OEM, SecureBinaryXType.NXP_PROVISIONING]

    @classmethod
    def get_validation_schemas(
        cls, family: str, include_test_configuration: bool = False
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
                    "signing_cert_prv_key",
                    "signature_provider",
                    "sbx_commands",
                ]
            ]
        )
        if include_test_configuration:
            ret.append(sbx_sch_cfg["sbx_test"])

        return ret

    @classmethod
    def load_from_config(
        cls, config: dict[str, Any], search_paths: Optional[list[str]] = None
    ) -> "SecureBinaryX":
        """Creates an instance of SecureBinaryX from configuration.

        :param config: Input standard configuration.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Instance of Secure Binary X class
        """
        description = config.get("description")
        firmware_version = value_to_int(config.get("firmwareVersion", 1))
        image_type = SecureBinaryXType[config["image_type"]]
        commands = config["commands"]
        timestamp = config.get("timestamp")
        if timestamp:  # re-format it
            timestamp = value_to_int(timestamp)
        # signature provider only necessary for OEM and NXP provisioning types
        if image_type in [SecureBinaryXType.OEM, SecureBinaryXType.NXP_PROVISIONING]:
            signature_provider = get_signature_provider(
                sp_cfg=config.get("signProvider"),
                local_file_key=config.get("signingCertificatePrivateKeyFile"),
                search_paths=search_paths,
            )
        else:
            signature_provider = None

        # Create SBX object
        sbx = SecureBinaryX(
            tphsm_blob=None,
            firmware_version=firmware_version,
            description=description,
            image_type=image_type,
            timestamp=timestamp,
            signature_provider=signature_provider,
        )

        # Add commands into the SBX object
        sbx.sb_commands.load_from_config(commands, search_paths=search_paths)

        return sbx

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

    @staticmethod
    def get_supported_families() -> list[str]:
        """Get the list of supported families by Device HSM.

        :return: List of supported families.
        """
        families = get_families(DatabaseManager.DEVHSM)
        families = [
            family
            for family in families
            if get_db(family, "latest").get_str(DatabaseManager.DEVHSM, "devhsm_class")
            == "DevHsmSBx"
        ]
        return families

    @classmethod
    def generate_config_template(cls, family: str) -> str:
        """Generate configuration for selected family.

        :param family: Family description.
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        if family not in cls.get_supported_families():
            raise SPSDKError(f"SBx does not support family {family}")
        schemas = cls.get_validation_schemas(family)
        schemas.append(get_schema_file(DatabaseManager.SBX)["sbx_output"])

        yaml_data = CommentedConfig(
            f"Secure Binary X Configuration template for {family}.", schemas
        ).get_template()

        return yaml_data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "SecureBinaryX":
        """Deserialize object from bytes array.

        :raises NotImplementedError: Not yet implemented
        """
        raise NotImplementedError("Not yet implemented.")
