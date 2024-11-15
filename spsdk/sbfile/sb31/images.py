#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module used for generation SecureBinary V3.1."""
import logging
from datetime import datetime
from struct import calcsize, pack, unpack_from
from typing import Any, Optional

from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash, get_hash_length
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.crypto.symmetric import aes_cbc_encrypt
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.sbfile.sb31.commands import CFG_NAME_TO_CLASS, CmdSectionHeader, MainCmd
from spsdk.sbfile.sb31.functions import KeyDerivator
from spsdk.utils.abstract import BaseClass
from spsdk.utils.crypto.cert_blocks import CertBlockV21
from spsdk.utils.database import DatabaseManager, get_db, get_families, get_schema_file
from spsdk.utils.misc import align_block, load_hex_string, value_to_int
from spsdk.utils.schema_validator import CommentedConfig, update_validation_schema_family

logger = logging.getLogger(__name__)


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
        hash_type: EnumHashAlgorithm,
        description: Optional[str] = None,
        timestamp: Optional[int] = None,
        is_nxp_container: bool = False,
        flags: int = 0,
    ) -> None:
        """Initialize the SecureBinary V3.1 Header.

        :param hash_type: Hash type used in commands binary block
        :param firmware_version: Firmware version (must be bigger than current CMPA record)
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
        self.timestamp = timestamp or int(datetime.now().timestamp())
        self.image_total_length = self.HEADER_SIZE
        self.description = self._adjust_description(description)

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
        return info

    def update(self, commands: "SecureBinary31Commands", cert_block: CertBlockV21) -> None:
        """Updates the volatile fields in header by real commands and certification block data.

        :param commands: SB3.1 Commands block
        :param cert_block: SB3.1 Certification block.
        """
        hash_size = get_hash_length(self.hash_type)
        self.block_count = commands.block_count
        self.image_total_length += hash_size + cert_block.expected_size
        self.image_total_length += 2 * hash_size

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


class SecureBinary31Commands(BaseClass):
    """Blob containing SB3.1 commands."""

    DATA_CHUNK_LENGTH = 256

    def __init__(
        self,
        family: str,
        hash_type: EnumHashAlgorithm,
        is_encrypted: bool = True,
        pck: Optional[bytes] = None,
        timestamp: Optional[int] = None,
        kdk_access_rights: Optional[int] = None,
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
        if hash_type not in [EnumHashAlgorithm.SHA256, EnumHashAlgorithm.SHA384]:
            raise SPSDKValueError(f"Invalid hash type: {hash_type}")
        self.hash_type = hash_type
        self.is_encrypted = is_encrypted
        self.block_count = 0
        self.final_hash = bytes(get_hash_length(hash_type))
        self.commands: list[MainCmd] = []
        self.key_derivator = None
        if is_encrypted:
            if pck is None or timestamp is None or kdk_access_rights is None:
                raise SPSDKError("PCK, timestamp or kdk_access_rights are not defined.")
            self.key_derivator = KeyDerivator(
                pck=pck,
                timestamp=timestamp,
                key_length=self._get_key_length(self.hash_type),
                kdk_access_rights=kdk_access_rights,
            )

    @staticmethod
    def _get_key_length(hash_type: EnumHashAlgorithm) -> int:
        return {EnumHashAlgorithm.SHA256: 128, EnumHashAlgorithm.SHA384: 256}[hash_type]

    def add_command(self, command: MainCmd) -> None:
        """Add SB3.1 command."""
        self.commands.append(command)

    def insert_command(self, index: int, command: MainCmd) -> None:
        """Insert SB3.1 command."""
        if index == -1:
            self.commands.append(command)
        else:
            self.commands.insert(index, command)

    def set_commands(self, commands: list[MainCmd]) -> None:
        """Set all SB3.1 commands at once."""
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
            cfg_cmd_value["family"] = self.family
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
        if self.is_encrypted:
            if not self.key_derivator:
                raise SPSDKError("No key derivator")
            block_key = self.key_derivator.get_block_key(block_number)
            encrypted_block = aes_cbc_encrypt(block_key, block_data)
        else:
            encrypted_block = block_data

        full_block = pack(
            f"<L{len(self.final_hash)}s{len(encrypted_block)}s",
            block_number,
            self.final_hash,
            encrypted_block,
        )
        block_hash = get_hash(full_block, self.hash_type)
        self.final_hash = block_hash
        return full_block

    def __repr__(self) -> str:
        return f"SB3.1 Commands[#{len(self.commands)}]"

    def __str__(self) -> str:
        """Get string information for commands in the container."""
        info = str()
        info += "COMMANDS:\n"
        info += f"Number of commands: {len(self.commands)}\n"
        for command in self.commands:
            info += f"  {str(command)}\n"
        return info

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data into SecureBinary31Commands.

        :raises NotImplementedError: Not yet implemented
        """
        raise NotImplementedError("Not yet implemented.")

    def validate(self) -> None:
        """Validate the settings of class members.

        :raises SPSDKError: Invalid configuration of SB3.1 commands blob class members.
        """
        if self.is_encrypted and not self.key_derivator:
            raise SPSDKError("Invalid key derivator")


class SecureBinary31(BaseClass):
    """Secure Binary SB3.1 class."""

    PCK_SIZES = [256, 128]

    def __init__(
        self,
        family: str,
        cert_block: CertBlockV21,
        firmware_version: int,
        signature_provider: SignatureProvider,
        pck: Optional[bytes] = None,
        kdk_access_rights: Optional[int] = None,
        description: Optional[str] = None,
        is_nxp_container: bool = False,
        flags: int = 0,
        timestamp: Optional[int] = None,
        is_encrypted: bool = True,
    ) -> None:
        """Constructor for Secure Binary v3.1 data container.

        :param cert_block: Certification block.
        :param firmware_version: Firmware version (must be bigger than current CMPA record).
        :param signature_provider: Signature provider for final sign of SB3.1 image.
        :param pck: Part Common Key (needed if `is_encrypted` is True), defaults to None
        :param kdk_access_rights: Key Derivation Key access rights (needed if `is_encrypted` is True), defaults to None
        :param description: Custom description up to 16 characters long, defaults to None
        :param is_nxp_container: NXP provisioning SB file, defaults to False
        :param flags: Flags for SB file, defaults to 0
        :param timestamp: Timestamp used for encryption (needed if `is_encrypted` is True), defaults to None
        :param is_encrypted: Indicate whether commands should be encrypted or not, defaults to True
        """
        # in our case, timestamp is the number of seconds since "Jan 1, 2000"
        self.family = family
        self.timestamp = timestamp or int((datetime.now() - datetime(2000, 1, 1)).total_seconds())
        self.pck = pck
        self.cert_block: CertBlockV21 = cert_block
        self.is_encrypted = is_encrypted
        self.kdk_access_rights = kdk_access_rights
        self.firmware_version = firmware_version
        self.description = description
        self.is_nxp_container = is_nxp_container
        self.flags = flags
        self.signature_provider = signature_provider
        hash_type = {64: EnumHashAlgorithm.SHA256, 96: EnumHashAlgorithm.SHA384}[
            signature_provider.signature_length
        ]

        self.sb_header = SecureBinary31Header(
            hash_type=hash_type,
            firmware_version=self.firmware_version,
            description=self.description,
            timestamp=self.timestamp,
            is_nxp_container=self.is_nxp_container,
            flags=self.flags,
        )
        self.sb_commands = SecureBinary31Commands(
            family=self.family,
            hash_type=hash_type,
            is_encrypted=self.is_encrypted,
            pck=pck,
            timestamp=self.timestamp,
            kdk_access_rights=self.kdk_access_rights,
        )
        if self.pck:
            logger.info(f"SB3KDK: {self.pck.hex()}")

    @classmethod
    def get_validation_schemas_family(cls) -> list[dict[str, Any]]:
        """Create the validation schema just for supported families.

        :return: List of validation schemas for SB31 supported families.
        """
        sch_cfg = get_schema_file("general")["family"]
        update_validation_schema_family(sch_cfg["properties"], cls.get_supported_families())
        return [sch_cfg]

    @classmethod
    def get_commands_validation_schemas(cls, family: str) -> list[dict[str, Any]]:
        """Create the list of validation schemas.

        :param family: Family description.
        :return: List of validation schemas.
        """
        sb3_sch_cfg = get_schema_file(DatabaseManager.SB31)
        db = get_db(family, "latest")
        schemas: list[dict[str, Any]] = [sb3_sch_cfg["sb3_commands"]]
        # remove unused command for current family
        supported_commands = db.get_list(DatabaseManager.SB31, "supported_commands")
        list_of_commands: list[dict] = schemas[0]["properties"]["commands"]["items"]["oneOf"]
        schemas[0]["properties"]["commands"]["items"]["oneOf"] = [
            command
            for command in list_of_commands
            if list(command["properties"].keys())[0] in supported_commands
        ]

        return schemas

    @classmethod
    def get_devhsm_commands_validation_schemas(cls, family: str) -> list[dict[str, Any]]:
        """Create the list of validation schemas.

        :param family: Family description.
        :return: List of validation schemas.
        """
        sb3_sch_cfg = get_schema_file(DatabaseManager.SB31)
        db = get_db(family, "latest")
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
    def get_validation_schemas(cls, family: str) -> list[dict[str, Any]]:
        """Create the list of validation schemas.

        :param family: Family description.
        :return: List of validation schemas.
        """
        mbi_sch_cfg = get_schema_file(DatabaseManager.MBI)
        sb3_sch_cfg = get_schema_file(DatabaseManager.SB31)
        sch_cfg = get_schema_file("general")["family"]
        update_validation_schema_family(sch_cfg["properties"], cls.get_supported_families(), family)

        schemas: list[dict[str, Any]] = [sch_cfg]
        schemas.extend(
            [mbi_sch_cfg[x] for x in ["firmware_version", "signature_provider", "cert_block_v21"]]
        )
        schemas.extend(
            [sb3_sch_cfg[x] for x in ["sb3", "sb3_description", "sb3_test", "sb3_output"]]
        )
        schemas.extend(cls.get_commands_validation_schemas(family))

        # find family
        for schema in schemas:
            if "properties" in schema and "family" in schema["properties"]:
                update_validation_schema_family(
                    schema["properties"], cls.get_supported_families(), family
                )
                break
        return schemas

    @classmethod
    def load_from_config(
        cls, config: dict[str, Any], search_paths: Optional[list[str]] = None
    ) -> "SecureBinary31":
        """Creates an instance of SecureBinary31 from configuration.

        :param config: Input standard configuration.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Instance of Secure Binary V3.1 class
        """
        family = config["family"]
        container_keyblob_enc_key = config.get("containerKeyBlobEncryptionKey")
        is_nxp_container = config.get("isNxpContainer", False)
        description = config.get("description")
        kdk_access_rights = value_to_int(config.get("kdkAccessRights", 0))
        container_configuration_word = value_to_int(config.get("containerConfigurationWord", 0))
        firmware_version = value_to_int(config.get("firmwareVersion", 1))

        commands = config["commands"]
        is_encrypted = config.get("isEncrypted", True)
        timestamp = config.get("timestamp")
        if timestamp:  # re-format it
            timestamp = value_to_int(timestamp)

        cert_block = CertBlockV21.from_config(config, search_paths=search_paths)

        # if use_isk is set, we use for signing the ISK certificate instead of root
        # signing_key_path = (
        #     config.get("signingCertificatePrivateKeyFile")
        #     if cert_block.isk_certificate
        #     else config.get("mainRootCertPrivateKeyFile")
        # )
        signing_key_path = config.get("signPrivateKey", config.get("mainRootCertPrivateKeyFile"))

        signature_provider = get_signature_provider(
            sp_cfg=config.get("signProvider"),
            local_file_key=signing_key_path,
            search_paths=search_paths,
        )
        assert isinstance(signature_provider, SignatureProvider)

        pck = None
        if is_encrypted:
            if not isinstance(container_keyblob_enc_key, str):
                raise SPSDKError("Invalid value for containerKeyBlobEncryptionKey")
            for size in cls.PCK_SIZES:
                try:
                    pck = load_hex_string(container_keyblob_enc_key, size // 8, search_paths)
                except SPSDKError:
                    logger.debug(
                        f"Failed loading PCK {container_keyblob_enc_key} as key with {size}"
                    )
            if not pck:
                raise SPSDKError(f"Cannot load PCK from {container_keyblob_enc_key}")
        # Create SB3 object
        sb3 = SecureBinary31(
            family=family,
            pck=pck,
            cert_block=cert_block,
            kdk_access_rights=kdk_access_rights,
            firmware_version=firmware_version,
            description=description,
            is_nxp_container=is_nxp_container,
            flags=container_configuration_word,
            signature_provider=signature_provider,
            timestamp=timestamp,
            is_encrypted=is_encrypted,
        )

        # Add commands into the SB3 object
        sb3.sb_commands.load_from_config(commands, search_paths=search_paths)

        return sb3

    def validate(self) -> None:
        """Validate the settings of class members.

        :raises SPSDKError: Invalid configuration of SB3.1 class members.
        """
        if self.signature_provider is None or not isinstance(
            self.signature_provider, SignatureProvider
        ):
            raise SPSDKError(f"SB3.1 signature provider is invalid: {self.signature_provider}")
        public_key = (
            self.cert_block.isk_certificate.isk_cert.export()
            if self.cert_block.isk_certificate and self.cert_block.isk_certificate.isk_cert
            else self.cert_block.root_key_record.root_public_key
        )
        self.signature_provider.try_to_verify_public_key(public_key)

        self.cert_block.validate()
        self.sb_header.validate()
        self.sb_commands.validate()

    def export(self, cert_block: Optional[bytes] = None) -> bytes:
        """Generate binary output of SB3.1 file.

        :return: Content of SB3.1 file in bytes.
        """
        self.validate()

        if cert_block:
            cert_block_data = cert_block
        else:
            cert_block_data = self.cert_block.export()
        sb3_commands_data = self.sb_commands.export()

        final_data = bytes()
        # HEADER OF SB 3.1 FILE
        self.sb_header.update(self.sb_commands, self.cert_block)
        final_data += self.sb_header.export()

        # HASH OF PREVIOUS BLOCK
        final_data += self.sb_commands.final_hash
        final_data += cert_block_data

        # SIGNATURE
        final_data += self.signature_provider.get_signature(final_data)

        # COMMANDS BLOBS DATA
        final_data += sb3_commands_data

        return final_data

    def __repr__(self) -> str:
        return f"SB3.1, TimeStamp: {self.timestamp}"

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

    @staticmethod
    def get_supported_families() -> list[str]:
        """Return list of supported families.

        :return: List of supported families.
        """
        return get_families(DatabaseManager.SB31)

    @classmethod
    def generate_config_template(cls, family: str) -> dict[str, str]:
        """Generate configuration for selected family.

        :param family: Device family.
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        ret: dict[str, str] = {}

        if family in cls.get_supported_families():
            schemas = cls.get_validation_schemas(family)
            schemas.append(get_schema_file(DatabaseManager.SB31)["sb3_output"])

            yaml_data = CommentedConfig(
                f"Secure Binary v3.1 Configuration template for {family}.", schemas
            ).get_template()

            ret[f"{family}_sb31"] = yaml_data

        return ret

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Deserialize object from bytes array.

        :raises NotImplementedError: Not yet implemented
        """
        raise NotImplementedError("Not yet implemented.")

    @staticmethod
    def validate_header(binary: bytes) -> None:
        """Validate SB3.1 header in binary data.

        :param binary: Binary data to be validate
        :raises SPSDKError: Invalid header of SB3.1 data
        """
        sb31_header = SecureBinary31Header.parse(binary)
        sb31_header.validate()
