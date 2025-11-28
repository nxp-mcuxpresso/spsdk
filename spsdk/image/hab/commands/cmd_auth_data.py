#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""HAB authentication data commands implementation.

This module provides HAB (High Assurance Boot) commands for handling authentication
data operations in the secure boot process. It includes commands for authenticating
CSF data, decrypting data, and managing authentication signatures and MACs.
"""

from datetime import datetime
from struct import pack, unpack_from
from typing import Any, Iterator, Optional, Union

from typing_extensions import Self

from spsdk.crypto.cms import cms_sign
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.keys import PrivateKey, PrivateKeyEcc
from spsdk.crypto.rng import random_bytes
from spsdk.crypto.signature_provider import PlainFileSP, SignatureProvider, get_signature_provider
from spsdk.exceptions import SPSDKAttributeError, SPSDKError, SPSDKValueError
from spsdk.image.hab.commands.cmd_install_key import CmdInstallCsfk, CmdInstallKey, CmdInstallNOCAK
from spsdk.image.hab.commands.commands import CmdBase, SPSDKCommandNotDefined
from spsdk.image.hab.constants import CertFormatEnum, CmdName, CmdTag, EngineEnum
from spsdk.image.hab.hab_certificate import HabCertificate
from spsdk.image.hab.hab_header import CmdHeader, Header, SegmentTag
from spsdk.image.hab.hab_mac import MAC
from spsdk.image.hab.hab_signature import Signature
from spsdk.image.hab.hab_srk import SrkTable
from spsdk.image.hab.utils import aead_nonce_len, get_header_version
from spsdk.utils.config import Config
from spsdk.utils.misc import load_binary
from spsdk.utils.spsdk_enum import SpsdkEnum


class AuthDataFlagsEnum(SpsdkEnum):
    """Flags enumeration for HAB Authenticate Data commands.

    This enumeration defines the available flags that can be used with
    HAB (High Assurance Boot) Authenticate Data commands to control
    signature verification behavior.

    :cvar CLR: No flags set, default behavior.
    :cvar ABS: Absolute signature address flag.
    """

    CLR = (0, "CLR", "No flags set")
    ABS = (1, "ABS", "Absolute signature address")


class SPSDKExpectedSignatureOrMACError(SPSDKError):
    """SPSDK exception for invalid authentication data format in HAB commands.

    This exception is raised when CmdAuthData encounters an additional data block
    that should contain a Signature or MAC object but contains invalid or
    unexpected data instead.
    """


SignatureOrMAC = Union[MAC, Signature]


class CmdAuthData(CmdBase):
    """HAB Authenticate Data command for verifying pre-loaded data authenticity.

    This command verifies the authenticity of pre-loaded data using a pre-installed key.
    The data may include executable SW instructions and can be spread across multiple
    non-contiguous blocks in memory. The command structure includes authentication
    parameters and block definitions for the data to be verified.

        Authentication data command format::

        +--------------+---------------+--------------+
        |     tag      |      len      |    flags     |
        +-----------+--+-------+-------+-+------------+
        | key_index | sig_fmt  | engine  | engine_cfg |
        +-----------+----------+---------+------------+
        |                  aut_start                  |
        +---------------------------------------------+
        |                 [blk_start]                 |
        +---------------------------------------------+
        |                 [blk_bytes]                 |
        +---------------------------------------------+
        |                      .                      |
        +---------------------------------------------+
        |                 [blk_start]                 |
        +---------------------------------------------+
        |                 [blk_bytes]                 |
        +---------------------------------------------+

    :cvar CMD_TAG: Command tag identifier for authenticate data operations.
    """

    CMD_TAG = CmdTag.AUT_DAT

    def __init__(
        self,
        flags: AuthDataFlagsEnum = AuthDataFlagsEnum.CLR,
        key_index: int = 1,
        sig_fmt: CertFormatEnum = CertFormatEnum.CMS,
        engine: EngineEnum = EngineEnum.ANY,
        engine_cfg: int = 0,
        location: int = 0,
        certificate: Optional[HabCertificate] = None,
        private_key: Optional[PrivateKey] = None,
        signature_provider: Optional[SignatureProvider] = None,
    ):
        """Initialize the Authenticate data command.

        Creates a new HAB authenticate data command with specified cryptographic parameters
        and validation settings.

        :param flags: Authentication data flags controlling command behavior.
        :param key_index: Index of the key to be used for authentication.
        :param sig_fmt: Certificate format for signature verification.
        :param engine: Cryptographic engine to be used for operations.
        :param engine_cfg: Engine-specific configuration value.
        :param location: Memory location for the authentication data.
        :param certificate: HAB certificate for authentication (optional).
        :param private_key: Private key for signing operations (optional).
        :param signature_provider: External signature provider (optional).
        :raises SPSDKValueError: When both private key and signature provider are specified.
        :raises SPSDKError: When private key doesn't match the certificate's public key.
        """
        super().__init__(flags.tag)
        self.key_index = key_index
        self.sig_format = sig_fmt
        self.engine = engine
        self.engine_cfg = engine_cfg
        self.location = location
        self.certificate = certificate
        self.private_key = private_key
        self.signature_provider = signature_provider
        self._header.length = CmdHeader.SIZE + 8
        self._blocks: list[tuple[int, int]] = []  # list of (start-address, size)
        self._signature: Optional[SignatureOrMAC] = None
        if private_key and signature_provider:
            raise SPSDKValueError(
                "Only one of private key and signature provider must be specified"
            )
        if certificate and (private_key or signature_provider):
            public_key = certificate.cert.get_public_key()
            if signature_provider:
                signature_provider.try_to_verify_public_key(public_key)
            else:
                assert isinstance(private_key, PrivateKey)
                if not private_key.verify_public_key(public_key):
                    raise SPSDKError("Given private key does not match the public certificate")

    @property
    def flags(self) -> AuthDataFlagsEnum:
        """Get the flags of Authenticate data command.

        :return: Authentication data command flags extracted from header parameter.
        """
        return AuthDataFlagsEnum.from_tag(self._header.param)

    @flags.setter
    def flags(self, value: AuthDataFlagsEnum) -> None:
        """Set authentication data flags.

        This method validates and sets the authentication data flags by updating
        the header parameter with the provided flag value.

        :param value: Authentication data flag to be set.
        :raises SPSDKError: If the provided flag value is not valid.
        """
        if value not in AuthDataFlagsEnum:
            raise SPSDKError("Incorrect flag")
        self._header.param = value.tag

    @property
    def key_index(self) -> int:
        """Get the key index value.

        :return: The key index as an integer value.
        """
        return self._key_index

    @key_index.setter
    def key_index(self, value: int) -> None:
        """Set the key index value.

        :param value: Key index value, must be in range 0-5.
        :raises SPSDKError: If the key index value is not in the valid range (0-5).
        """
        if value not in (0, 1, 2, 3, 4, 5):
            raise SPSDKError("Incorrect key index")
        self._key_index = value

    @property
    def engine(self) -> EngineEnum:
        """Get the engine type used for authentication.

        :return: The engine enumeration value specifying the cryptographic engine.
        """
        return self._engine

    @engine.setter
    def engine(self, value: EngineEnum) -> None:
        """Set the engine type for the command.

        :param value: Engine type to be set for the command.
        :raises SPSDKError: If the provided engine value is not a valid EngineEnum member.
        """
        if value not in EngineEnum:
            raise SPSDKError("Incorrect engine")
        self._engine = value

    @property
    def needs_cmd_data_reference(self) -> bool:
        """Check if the command contains a reference to additional data.

        This method indicates whether the authentication data command requires
        a reference to external data that needs to be processed separately.

        :return: True if the command needs additional data reference, False otherwise.
        """
        return True

    @property
    def cmd_data_offset(self) -> int:
        """Get offset of additional data in binary image.

        The method returns the location offset for additional data such as signature or MAC
        in the binary image.

        :return: Offset value in bytes.
        """
        return self.location

    @cmd_data_offset.setter
    def cmd_data_offset(self, value: int) -> None:
        """Set command data offset value.

        :param value: Offset value to be assigned to the location attribute.
        """
        self.location = value

    @property  # type: ignore
    def cmd_data_reference(self) -> Optional[SignatureOrMAC]:
        """Get reference to additional data such as certificate or signature.

        Returns the signature or MAC reference if one was assigned to this command,
        otherwise returns None. The specific type of the returned value depends on
        the command implementation.

        :return: Signature or MAC reference if assigned, None otherwise.
        """
        return self._signature

    @cmd_data_reference.setter
    def cmd_data_reference(self, value: Union[HabCertificate, Signature, MAC, SrkTable]) -> None:
        """Set command data reference for authentication.

        Sets the signature or MAC object based on the certificate format. For AEAD format,
        a MAC object is required. For CMS format, a Signature object is required.

        :param value: Authentication data object (MAC for AEAD, Signature for CMS)
        :raises SPSDKExpectedSignatureOrMACError: If unsupported data object is provided for the format
        """
        if self.sig_format == CertFormatEnum.AEAD:
            if not isinstance(value, MAC):
                raise SPSDKExpectedSignatureOrMACError("Expected MAC object for AEAD format")
        elif self.sig_format == CertFormatEnum.CMS:
            if not isinstance(value, Signature):
                raise SPSDKExpectedSignatureOrMACError("Expected Signature object for CMS format")
        else:
            raise SPSDKExpectedSignatureOrMACError("Unsupported data object is provided")
        self._signature = value

    def parse_cmd_data(self, data: bytes) -> SignatureOrMAC:
        """Parse additional command data from binary data.

        The method parses HAB command data and creates appropriate signature or MAC object
        based on the header tag found in the binary data.

        :param data: Binary data to be parsed containing signature or MAC information.
        :return: Parsed data object, either Signature or MAC instance.
        :raises SPSDKExpectedSignatureOrMACError: If unsupported data object is provided.
        """
        header = Header.parse(data)
        if header.tag == SegmentTag.MAC:
            self._signature = MAC.parse(data)
            return self._signature
        if header.tag == SegmentTag.SIG:
            self._signature = Signature.parse(data)
            return self._signature
        raise SPSDKExpectedSignatureOrMACError(f"TAG = {header.tag}")

    @property
    def signature(self) -> Optional[SignatureOrMAC]:
        """Get signature referenced by location attribute.

        :return: Signature or MAC object if available, None otherwise.
        """
        return self._signature

    @signature.setter
    def signature(self, value: SignatureOrMAC) -> None:
        """Set signature for the authentication data command.

        :param value: Signature to be installed by the command.
        """
        self.cmd_data_reference = value

    def __repr__(self) -> str:
        """Return string representation of the HAB Authenticate Data command.

        The representation includes class name, flags, engine configuration, key index,
        and memory location in a readable format.

        :return: String representation of the command with key configuration details.
        """
        return (
            f"{self.__class__.__name__} <{self.flags.label}, {self.engine.label},"
            f" {self.engine_cfg}, key:{self.key_index}, 0x{self.location:X}>"
        )

    def __len__(self) -> int:
        """Get the number of blocks in the authentication data.

        :return: Number of blocks contained in this authentication data object.
        """
        return len(self._blocks)

    def __getitem__(self, key: int) -> tuple[int, int]:
        """Get block tuple at specified index.

        Retrieves a tuple containing block information from the internal blocks list
        at the given index position.

        :param key: Index position of the block to retrieve.
        :return: Tuple containing two integers representing block information.
        """
        return self._blocks[key]

    def __setitem__(self, key: int, value: tuple[int, int]) -> None:
        """Set a block entry at the specified index.

        Assigns a tuple containing start address and length to the blocks list at the given index.

        :param key: Index position in the blocks list.
        :param value: Tuple containing (start_address, length) for the block.
        :raises SPSDKError: If the value tuple doesn't contain exactly 2 elements.
        """
        assert isinstance(value, (list, tuple))
        if len(value) != 2:
            raise SPSDKError("Incorrect length")
        self._blocks[key] = value

    def __iter__(self) -> Iterator[Union[tuple[Any, ...], list[Any]]]:
        """Iterate over authentication data blocks.

        Provides an iterator interface to access the internal blocks collection,
        allowing for standard Python iteration patterns over the authentication data.

        :return: Iterator yielding tuples or lists containing block data elements.
        """
        return self._blocks.__iter__()

    def __str__(self) -> str:
        """Get string representation of the authentication data command.

        Provides a detailed text description including command flags, key index, engine
        configuration, memory location, associated signature, and all authenticated
        memory blocks with their start addresses and lengths.

        :return: Formatted string containing complete command information.
        """
        msg = super().__str__()
        msg += f" Flag:        {self.flags} ({self.flags.description})\n"
        msg += f" Key index:   {self.key_index}\n"
        msg += f" Engine:      {self.engine} ({self.engine.description})\n"
        msg += f" Engine Conf: {self.engine_cfg}\n"
        msg += f" Location:    0x{self.location:08X} (Start address of authentication data) \n"
        if self.signature:
            msg += "[related signature]\n"
            msg += str(self.signature)
        for blk in self._blocks:
            msg += f"- Start: 0x{blk[0]:08X}, Length: {blk[1]} Bytes\n"
        return msg

    def append(self, start_address: int, size: int) -> None:
        """Append authentication data block to the command.

        Adds a new memory block defined by start address and size to the list of blocks
        that will be authenticated. Updates the command header length accordingly.

        :param start_address: Starting memory address of the block to authenticate.
        :param size: Size in bytes of the memory block to authenticate.
        """
        self._blocks.append(
            (start_address, size),
        )
        self._header.length += 8

    def pop(self, index: int) -> tuple[int, int]:
        """Remove authentication data block from the command.

        Removes a block at the specified index from the list of authentication data blocks
        and updates the command header length accordingly.

        :param index: Index of the block to remove from the blocks list.
        :raises SPSDKError: If the index is out of range for the blocks list.
        :return: Tuple containing the start address and length of the removed block.
        """
        if index < 0 or index >= len(self._blocks):
            raise SPSDKError("Incorrect length of blocks")
        value = self._blocks.pop(index)
        self._header.length -= 8
        return value

    def clear(self) -> None:
        """Clear the authenticate data command.

        Resets the command by clearing all data blocks and resetting the header
        length to its base size plus 8 bytes.
        """
        self._blocks.clear()
        self._header.length = self._header.size + 8

    def update_signature(
        self, zulu: datetime, data: bytes, base_data_addr: int = 0xFFFFFFFF
    ) -> bool:
        """Update signature with provided data and timestamp.

        This method must be called from parent to provide data to be signed. It processes
        the data according to defined blocks or signs the complete data if no blocks are
        specified.

        :param zulu: Current UTC time and date for signature timestamp.
        :param data: Binary data to be signed.
        :param base_data_addr: Base address of the generated data.
        :raises SPSDKAttributeError: When certificate is not assigned.
        :raises SPSDKAttributeError: When private key or signature provider not assigned.
        :raises SPSDKError: When signature not assigned explicitly.
        :raises SPSDKError: If incorrect start address.
        :raises SPSDKError: If incorrect end address.
        :raises SPSDKError: If incorrect length.
        :return: True if signature length unchanged, False otherwise.
        """
        if not self.certificate:
            raise SPSDKAttributeError("Certificate not assigned, cannot update signature")
        if not (self.private_key or self.signature_provider):
            raise SPSDKAttributeError(
                "Private key or signature provider not assigned, cannot update signature"
            )
        if self.signature is None:
            raise SPSDKError(
                "signature must be assigned explicitly, so its version matches to CST version"
            )

        if self._blocks:
            sign_data = b""
            if data:  # if not data specified, create "fake" signature to update length
                total_len = 0
                for blk in self._blocks:
                    start = blk[0] - base_data_addr
                    end = blk[0] + blk[1] - base_data_addr
                    if start < 0:
                        raise SPSDKError("Incorrect start address")
                    if end > len(data):
                        raise SPSDKError("Incorrect end address")
                    sign_data += data[start:end]
                    total_len += blk[1]
                if len(sign_data) != total_len:
                    raise SPSDKError("Incorrect length")
        else:
            sign_data = data  # if no blocks defined, sign complete data; used for CSF
        if isinstance(self.signature, Signature):
            new_signature = cms_sign(
                zulu=zulu,
                data=sign_data,
                certificate=self.certificate.cert,
                signing_key=self.private_key,
                signature_provider=self.signature_provider,
            )
            result = len(self.signature.data) == len(new_signature)
            self.signature.data = new_signature
        else:
            assert isinstance(self.signature, MAC)
            result = True
        return result

    def export(self) -> bytes:
        """Export command to binary representation for HAB processing.

        Serializes the authentication data command including header, key index, signature format,
        engine configuration, location, and all associated data blocks into packed binary format
        suitable for HAB (High Assurance Boot) consumption.

        :return: Binary representation of the complete authentication data command.
        """
        self._header.length = self.size
        raw_data = super().export()
        raw_data += pack(
            ">4BL",
            self.key_index,
            self.sig_format.tag,
            self.engine.tag,
            self.engine_cfg,
            self.location,
        )
        for blk in self._blocks:
            raw_data += pack(">2L", blk[0], blk[1])
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data into AuthData command object.

        Deserializes binary representation of HAB Authenticate Data command into
        a structured command object with all parameters and data blocks.

        :param data: Binary data to be parsed into command structure.
        :return: Parsed AuthData command object.
        """
        header = CmdHeader.parse(data, CmdTag.AUT_DAT.tag)
        key, sig_format, eng, cfg, location = unpack_from(">4BL", data, header.size)
        obj = cls(
            AuthDataFlagsEnum.from_tag(header.param),
            key,
            CertFormatEnum.from_tag(sig_format),
            EngineEnum.from_tag(eng),
            cfg,
            location,
        )
        index = header.size + 8
        while index < header.length:
            start_address, size = unpack_from(">2L", data, index)
            obj.append(start_address, size)
            index += 8
        return obj


def get_hab_signature_provider(config: Config) -> SignatureProvider:
    """Get the HAB signature provider from configuration.

    This method retrieves and configures a signature provider for HAB (High Assurance Boot)
    operations. For PlainFileSP providers using ECC private keys, it automatically sets
    the hash algorithm to SHA256.

    :param config: Configuration object containing signature provider settings.
    :return: Configured signature provider instance for HAB operations.
    """
    signature_provider = get_signature_provider(config, "Signer")
    if isinstance(signature_provider, PlainFileSP):
        if isinstance(signature_provider.private_key, PrivateKeyEcc):
            signature_provider.hash_alg = EnumHashAlgorithm.SHA256
    return signature_provider


class CmdAuthenticateCsf(CmdAuthData):
    """HAB Authenticate CSF command implementation.

    This class represents the HAB (High Assurance Boot) Authenticate CSF (Command Sequence File)
    command used for authenticating the CSF itself during the secure boot process. It handles
    the creation and configuration of authentication commands that verify the integrity and
    authenticity of the command sequence file.

    :cvar SIGNED_DATA_SIZE: Size of the signed data block in bytes (768).
    :cvar CMD_IDENTIFIER: Command identifier for authenticate CSF operations.
    """

    SIGNED_DATA_SIZE = 768
    CMD_IDENTIFIER = CmdName.AUTHENTICATE_CSF

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the command.

        This method creates a command instance from HAB image configuration by determining the
        authentication mode (normal or fast) and setting up the appropriate signature provider
        and certificate reference.

        :param config: HAB image configuration containing command settings and certificates
        :param cmd_index: Optional index of the command in the configuration in case multiple
            same commands are present
        :raises SPSDKError: When neither InstallCSFK nor InstallNOCAK commands are defined
        :return: Configured command instance with certificate and signature provider
        """
        cmd_cfg = cls._get_cmd_config(config, cmd_index)
        # determine the key path, depending on if HAB is configured in normal or fast authentication mode
        install_key: Union[CmdInstallCsfk, CmdInstallNOCAK]
        try:
            install_key = CmdInstallCsfk.load_from_config(config)
        except SPSDKCommandNotDefined:
            try:
                install_key = CmdInstallNOCAK.load_from_config(config)
            except SPSDKCommandNotDefined as exc:
                raise SPSDKError("Either InstallCSFK or InstallNOCAK must be defined.") from exc

        signature_provider = get_hab_signature_provider(cmd_cfg)
        assert isinstance(install_key.certificate_ref, HabCertificate)
        cmd = cls(certificate=install_key.certificate_ref)
        engine = config.get_config("sections/0/Header").get_str("Header_Engine")
        if engine is not None:
            cmd.engine = EngineEnum.from_label(engine)

        cmd.signature_provider = signature_provider
        cmd.signature = Signature(version=get_header_version(config))
        return cmd


class CmdDecryptData(CmdAuthData):
    """HAB decrypt data command for secure data decryption operations.

    This command handles decryption of data blocks in HAB (High Assurance Boot) images,
    providing cryptographic decryption capabilities with configurable encryption engines,
    nonce handling, and MAC (Message Authentication Code) validation.

    :cvar CMD_IDENTIFIER: Command identifier for decrypt data operations.
    """

    CMD_IDENTIFIER = CmdName.DECRYPT_DATA

    def __init__(
        self,
        flags: AuthDataFlagsEnum = AuthDataFlagsEnum.CLR,
        key_index: int = 1,
        sig_fmt: CertFormatEnum = CertFormatEnum.CMS,
        engine: EngineEnum = EngineEnum.ANY,
        engine_cfg: int = 0,
        location: int = 0,
        certificate: Optional[HabCertificate] = None,
        private_key: Optional[PrivateKey] = None,
        signature_provider: Optional[SignatureProvider] = None,
        nonce: Optional[bytes] = None,
        mac_len: int = 16,
    ):
        """Initialize HAB Authenticate Data command.

        Initializes the command with authentication parameters including flags, key information,
        signature format, engine configuration, and optional nonce data for MAC operations.

        :param flags: Authentication data flags controlling command behavior.
        :param key_index: Index of the key to use for authentication.
        :param sig_fmt: Certificate format for signature verification.
        :param engine: Cryptographic engine to use for operations.
        :param engine_cfg: Engine-specific configuration value.
        :param location: Memory location for the authentication operation.
        :param certificate: HAB certificate for authentication.
        :param private_key: Private key for signing operations.
        :param signature_provider: External signature provider for signing.
        :param nonce: Nonce data for MAC calculation.
        :param mac_len: Length of the MAC in bytes.
        """
        super().__init__(
            flags,
            key_index,
            sig_fmt,
            engine,
            engine_cfg,
            location,
            certificate,
            private_key,
            signature_provider,
        )
        self.nonce = nonce
        self.mac_len = mac_len

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the authenticate data command.

        Creates an authenticate data command instance from HAB image configuration with proper
        validation of engine settings and verification parameters.

        :param config: HAB image configuration containing decrypt settings
        :param cmd_index: Optional index of the command in the configuration in case multiple
            same commands are present
        :raises SPSDKValueError: Invalid engine configuration combination or verification index
            out of range
        :return: Configured authenticate data command instance
        """
        cmd_cfg = cls._get_cmd_config(config, cmd_index)
        engine = cmd_cfg.get("Decrypt_Engine", "ANY")
        engine = EngineEnum.from_label(engine)

        engine_cfg = int(cmd_cfg.get("Decrypt_EngineConfiguration", 0))

        if engine == EngineEnum.ANY and engine_cfg != 0:
            raise SPSDKValueError(f"Invalid argument combination:{engine}: {engine_cfg}")

        verification_index = int(cmd_cfg["Decrypt_VerifyIndex"])
        if verification_index >= 6:
            raise SPSDKValueError("Verification index must be lower than 6.")
        nonce = cmd_cfg.get("Decrypt_Nonce")
        if nonce is not None:
            nonce = load_binary(nonce, search_paths=cmd_cfg.search_paths)
        cmd = cls(
            flags=AuthDataFlagsEnum.CLR,
            sig_fmt=CertFormatEnum.AEAD,
            nonce=nonce,
            mac_len=int(cmd_cfg.get("Decrypt_MacBytes", 16)),
        )
        cmd.engine = engine
        cmd.engine_cfg = engine_cfg
        cmd.key_index = verification_index
        return cmd

    def generate_nonce(self, data: bytes) -> None:
        """Generate a random nonce for the decrypt data command.

        The nonce length is determined based on the length of the data to be decrypted.

        :param data: The data that will be decrypted, used to calculate appropriate nonce length.
        """
        nonce_len = aead_nonce_len(len(data))
        self.nonce = random_bytes(nonce_len)


class SecCsfAuthenticateData(CmdAuthData):
    """HAB Authenticate Data command for secure boot verification.

    This command is used in HAB (High Assurance Boot) to authenticate data blocks
    during the secure boot process. It manages cryptographic verification of data
    using certificates and signatures, supporting both normal and fast authentication
    modes.

    :cvar KEY_IDX_AUT_DAT_FAST_AUTH: Key index for fast authentication mode.
    :cvar KEY_IDX_AUT_DAT_MIN: Minimum allowed key index for normal authentication.
    :cvar KEY_IDX_AUT_DAT_MAX: Maximum allowed key index for normal authentication.
    :cvar CMD_IDENTIFIER: Command identifier for authenticate data operations.
    """

    KEY_IDX_AUT_DAT_FAST_AUTH = 0
    KEY_IDX_AUT_DAT_MIN = 2
    KEY_IDX_AUT_DAT_MAX = 5
    CMD_IDENTIFIER = CmdName.AUTHENTICATE_DATA

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the authenticate data command.

        Creates an authenticate data command instance from HAB configuration, determining the
        appropriate key installation method (InstallCSFK or InstallNOCAK) and validating
        engine and verification index parameters.

        :param config: HAB image configuration containing command parameters
        :param cmd_index: Optional index of the command in the configuration in case multiple
            same commands are present
        :raises SPSDKError: When neither InstallCSFK nor InstallNOCAK is defined
        :raises SPSDKValueError: When engine configuration or key index has invalid value
        :return: Configured authenticate data command instance
        """
        cmd_cfg = cls._get_cmd_config(config, cmd_index)
        # determine the key path, depending on if HAB is configured in normal or fast authentication mode
        install_key: Union[CmdInstallKey, CmdInstallNOCAK]
        try:
            install_key = CmdInstallKey.load_from_config(config)
        except SPSDKCommandNotDefined:
            try:
                install_key = CmdInstallNOCAK.load_from_config(config)
            except SPSDKCommandNotDefined as exc:
                raise SPSDKError("Either InstallCSFK or InstallNOCAK must be defined.") from exc

        engine = EngineEnum.from_label(cmd_cfg["AuthenticateData_Engine"])
        engine_config = int(cmd_cfg["AuthenticateData_EngineConfiguration"])
        if engine == EngineEnum.ANY and engine_config != 0:
            raise SPSDKValueError(f"Invalid argument combination:{engine}: {engine_config}")

        verification_index = int(cmd_cfg["AuthenticateData_VerificationIndex"])
        if verification_index != cls.KEY_IDX_AUT_DAT_FAST_AUTH and (
            verification_index < cls.KEY_IDX_AUT_DAT_MIN
            or verification_index > cls.KEY_IDX_AUT_DAT_MAX
        ):
            raise SPSDKValueError("Key index does not have valid value.")

        signature_provider = get_hab_signature_provider(cmd_cfg)
        cmd = cls(
            engine=engine,
            engine_cfg=engine_config,
            key_index=verification_index,
            signature_provider=signature_provider,
        )
        assert isinstance(install_key.certificate_ref, HabCertificate)
        cmd.certificate = install_key.certificate_ref
        cmd.signature = Signature(version=get_header_version(config))
        return cmd
