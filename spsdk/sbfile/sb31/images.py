#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module used for generation SecureBinary V3.1."""
from datetime import datetime
from struct import calcsize, pack
from typing import Any, Dict, List

from spsdk import SPSDKError
from spsdk.image import MBIMG_SCH_FILE, SB3_SCH_FILE
from spsdk.sbfile.sb31.commands import CFG_NAME_TO_CLASS, CmdSectionHeader, MainCmd
from spsdk.sbfile.sb31.functions import KeyDerivator
from spsdk.utils.crypto import CRYPTO_SCH_FILE
from spsdk.utils.crypto.abstract import BaseClass
from spsdk.utils.crypto.backend_internal import internal_backend
from spsdk.utils.crypto.cert_blocks import CertBlockV31
from spsdk.utils.misc import align_block, load_binary, load_text, value_to_int
from spsdk.utils.schema_validator import ConfigTemplate, ValidationSchemas


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
        :param flags: Flags for SB file, defaults to 0
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
        raise NotImplementedError("Not yet implemented.")

    def validate(self) -> None:
        """Validate the settings of class members.

        :raises SPSDKError: Invalid configuration of SB3.1 header blob class members.
        """
        if self.flags is None:
            raise SPSDKError("Invalid SB3.1 header flags.")
        if self.block_count is None or self.block_count < 0:
            raise SPSDKError("Invalid SB3.1 header block count.")
        if self.curve_name is None or self.curve_name not in ["secp256r1", "secp384r1"]:
            raise SPSDKError("Invalid SB3.1 header curve name.")
        if self.block_size is None or self.block_size != self.calculate_block_size():
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
        self.commands: List[MainCmd] = []
        self.key_derivator = None
        if is_encrypted:
            if pck is None or timestamp is None or kdk_access_rights is None:
                raise SPSDKError("PCK, timestamp or kdk_access_rights are not defined.")
            self.key_derivator = KeyDerivator(
                pck=pck,
                timestamp=timestamp,
                key_length=self._get_key_length(curve_name),
                kdk_access_rights=kdk_access_rights,
            )

    @staticmethod
    def _get_hash_length(curve_name: str) -> int:
        return {"secp256r1": 32, "secp384r1": 48}[curve_name]

    @staticmethod
    def _get_key_length(curve_name: str) -> int:
        return {"secp256r1": 128, "secp384r1": 256}[curve_name]

    @staticmethod
    def _get_hash_type(curve_name: str) -> str:
        return {"secp256r1": "sha256", "secp384r1": "sha384"}[curve_name]

    def add_command(self, command: MainCmd) -> None:
        """Add SB3.1 command."""
        self.commands.append(command)

    def set_commands(self, commands: List[MainCmd]) -> None:
        """Set all SB3.1 commands at once."""
        self.commands = commands.copy()

    def load_from_config(self, config: List[Dict[str, Any]]) -> None:
        """Load configuration from dictionary.

        :param config: Dictionary with configuration fields.
        """
        for cfg_cmd in config:
            cfg_cmd_key = list(cfg_cmd.keys())[0]
            cfg_cmd_value = cfg_cmd[cfg_cmd_key]
            self.add_command(CFG_NAME_TO_CLASS[cfg_cmd_key].load_from_config(cfg_cmd_value))

    def get_cmd_blocks_to_export(self) -> List[bytes]:
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

    def process_cmd_blocks_to_export(self, data_blocks: List[bytes]) -> bytes:
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
        info += "COMMANDS:\n"
        info += f"Number of commands: {len(self.commands)}\n"
        for command in self.commands:
            info += f"  {command.info()}\n"
        return info

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "SecureBinary31Commands":
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

    def __init__(
        self,
        curve_name: str,
        cert_block: CertBlockV31,
        firmware_version: int,
        signing_key: bytes,
        pck: bytes = None,
        kdk_access_rights: int = None,
        description: str = None,
        is_nxp_container: bool = False,
        flags: int = 0,
        timestamp: int = None,
        is_encrypted: bool = True,
    ) -> None:
        """Constructor for Secure Binary v3.1 data container.

        :param curve_name: Name of the ECC curve used for Secure binary (secp256r1/secp384r1).
        :param cert_block: Certification block.
        :param firmware_version: Firmaware version (must be bigger than current CMPA record).
        :param signing_key: Key to final sign of SB3.1 image.
        :param pck: Part Common Key (needed if `is_encrypted` is True), defaults to None
        :param kdk_access_rights: Key Derivation Key access rights (needed if `is_encrypted` is True), defaults to None
        :param description: Custom description up to 16 characters long, defaults to None
        :param is_nxp_container: NXP provisioning SB file, defaults to False
        :param flags: Flags for SB file, defaults to 0
        :param timestamp: Timestamp used for encryption (needed if `is_encrypted` is True), defaults to None
        :param is_encrypted: Indicate whether commands should be encrypted or not, defaults to True
        """
        # in our case, timestamp is the number of seconds since "Jan 1, 2000"
        self.timestamp = timestamp or int((datetime.now() - datetime(2000, 1, 1)).total_seconds())
        self.pck = pck
        self.cert_block: CertBlockV31 = cert_block
        self.curve_name = curve_name
        self.is_encrypted = is_encrypted
        self.kdk_access_rights = kdk_access_rights
        self.firmware_version = firmware_version
        self.description = description
        self.is_nxp_container = is_nxp_container
        self.flags = flags
        self.signing_key = signing_key

        self.sb_header = SecureBinary31Header(
            firmware_version=self.firmware_version,
            curve_name=self.curve_name,
            description=self.description,
            timestamp=self.timestamp,
            is_nxp_container=self.is_nxp_container,
            flags=self.flags,
        )
        self.sb_commands = SecureBinary31Commands(
            curve_name=curve_name,
            is_encrypted=self.is_encrypted,
            pck=pck,
            timestamp=self.timestamp,
            kdk_access_rights=self.kdk_access_rights,
        )

    @classmethod
    def get_validation_schemas(
        cls, include_test_configuration: bool = False
    ) -> List[Dict[str, Any]]:
        """Create the list of validation schemas.

        :param include_test_configuration: Add also testing configuration schemas.
        :return: List of validation schemas.
        """
        mbi_sch_cfg = ValidationSchemas().get_schema_file(MBIMG_SCH_FILE)
        crypto_sch_cfg = ValidationSchemas().get_schema_file(CRYPTO_SCH_FILE)
        sb3_sch_cfg = ValidationSchemas().get_schema_file(SB3_SCH_FILE)

        ret: List[Dict[str, Any]] = []
        ret.extend(
            [
                mbi_sch_cfg[x]
                for x in [
                    "firmware_version",
                    "use_isk",
                    "signing_cert_prv_key",
                    "signing_root_prv_key",
                    "signing_prv_key_lpc55s3x",
                    "elliptic_curves",
                ]
            ]
        )
        ret.extend([crypto_sch_cfg[x] for x in ["certificate_v31", "certificate_root_keys"]])
        ret.extend([sb3_sch_cfg[x] for x in ["sb3_family", "sb3", "sb3_commands"]])
        if include_test_configuration:
            ret.append(sb3_sch_cfg["sb3_test"])
        return ret

    @classmethod
    def load_from_config(cls, config: Dict[str, Any]) -> "SecureBinary31":
        """Creates instantion of SecureBinary31 from configuration.

        :param config: Input standard configuration.
        :return: Instantion of Secure Binary V3.1 class
        """
        container_keyblob_enc_key_path = config.get("containerKeyBlobEncryptionKey")
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

        cert_block = CertBlockV31.from_config(config)

        # if use_isk is set, we use for signing the ISK certificate instead of root
        signing_key_path = (
            config.get("signingCertificatePrivateKeyFile")
            if cert_block.isk_certificate
            else config.get("mainRootCertPrivateKeyFile")
        )
        curve_name = (
            config.get("iskCertificateEllipticCurve")
            if cert_block.isk_certificate
            else config.get("rootCertificateEllipticCurve")
        )
        assert curve_name and isinstance(curve_name, str)
        assert signing_key_path
        signing_key = load_binary(signing_key_path) if signing_key_path else None
        assert signing_key

        pck = None
        if is_encrypted:
            assert container_keyblob_enc_key_path
            pck = bytes.fromhex(load_text(container_keyblob_enc_key_path))

        # Create SB3 object
        sb3 = SecureBinary31(
            pck=pck,
            cert_block=cert_block,
            curve_name=curve_name,
            kdk_access_rights=kdk_access_rights,
            firmware_version=firmware_version,
            description=description,
            is_nxp_container=is_nxp_container,
            flags=container_configuration_word,
            signing_key=signing_key,
            timestamp=timestamp,
            is_encrypted=is_encrypted,
        )

        # Add commands into the SB3 object
        sb3.sb_commands.load_from_config(commands)

        return sb3

    def validate(self) -> None:
        """Validate the settings of class members.

        :raises SPSDKError: Invalid configuration of SB3.1 class members.
        """
        # TODO add checking length of signing key
        if self.signing_key is None or not isinstance(self.signing_key, bytes):
            raise SPSDKError(f"SB3.1 Signing Key is invalid: {self.signing_key}")

        self.cert_block.validate()
        self.sb_header.validate()
        self.sb_commands.validate()

    def export(self) -> bytes:
        """Generate binary output of SB3.1 file.

        :return: Content of SB3.1 file in bytes.
        """
        self.validate()

        cert_block_data = self.cert_block.export()
        sb3_commands_data = self.sb_commands.export()
        self.sb_header.block_count = self.sb_commands.block_count
        self.sb_header.image_total_length += len(self.sb_commands.final_hash) + len(cert_block_data)
        # TODO: use proper signature len calculation
        self.sb_header.image_total_length += 2 * len(self.sb_commands.final_hash)

        final_data = bytes()
        # HEADER OF SB 3.1 FILE
        final_data += self.sb_header.export()

        # HASH OF PREVIOUS BLOCK
        final_data += self.sb_commands.final_hash
        final_data += cert_block_data

        # SIGNATURE
        final_data += internal_backend.ecc_sign(self.signing_key, final_data)

        # COMMANDS BLOBS DATA
        final_data += sb3_commands_data

        return final_data

    def info(self) -> str:
        """Create string information about SB3.1 loaded file.

        :return: Text information about SB3.1.
        """
        self.validate()
        ret = ""

        ret += "SB3.1 header:\n"
        ret += self.sb_header.info()

        ret += "SB3.1 commands blob :\n"
        ret += self.sb_commands.info()

        return ret

    @staticmethod
    def get_supported_families() -> List[str]:
        """Return list of supported families.

        :return: List of supported families.
        """
        sb3_sch_cfg = ValidationSchemas().get_schema_file(SB3_SCH_FILE)
        sb3_families = sb3_sch_cfg["sb3_family"]

        return sb3_families["properties"]["family"]["enum"]

    @classmethod
    def generate_config_template(cls, family: str) -> Dict[str, str]:
        """Generate configuration for selected family.

        :param family: Family description.
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        ret: Dict[str, str] = {}

        if family in cls.get_supported_families():
            schemas = cls.get_validation_schemas()
            schemas.append(ValidationSchemas.get_schema_file(SB3_SCH_FILE)["sb3_output"])
            override = {}
            override["family"] = family

            yaml_data = ConfigTemplate(
                f"Secure Binary v3.1 Configuration template for {family}.",
                schemas,
                override,
            ).export_to_yaml()

            ret[f"{family}_sb31"] = yaml_data

        return ret

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "SecureBinary31":
        """Deserialize object from bytes array.

        :raises NotImplementedError: Not yet implemented
        """
        raise NotImplementedError("Not yet implemented.")
