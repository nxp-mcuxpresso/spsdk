#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK HAB Install Key command implementations.

This module provides classes for different types of key installation commands
used in High Assurance Boot (HAB) protocol, including SRK, CSFK, and various
secret key installation operations.
"""

from struct import pack, unpack_from
from typing import Optional, Union

from typing_extensions import Self

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.rng import random_bytes
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.hab.commands.commands import CmdBase
from spsdk.image.hab.constants import CertFormatEnum, CmdName, CmdTag, EnumAlgorithm
from spsdk.image.hab.hab_certificate import HabCertificate
from spsdk.image.hab.hab_header import CmdHeader
from spsdk.image.hab.hab_mac import MAC
from spsdk.image.hab.hab_signature import Signature
from spsdk.image.hab.hab_srk import SrkTable
from spsdk.image.hab.utils import get_app_image, get_header_version, get_initial_load_size
from spsdk.utils.config import Config
from spsdk.utils.misc import get_abs_path, load_binary, write_file
from spsdk.utils.spsdk_enum import SpsdkEnum


class InstallKeyFlagsEnum(SpsdkEnum):
    """HAB Install Key command flags enumeration.

    This enumeration defines the available flags for HAB (High Assurance Boot) Install Key
    commands, including certificate addressing modes, key binding options, and hash presence
    indicators.
    """

    CLR = (0, "CLR", "No flags set")
    ABS = (1, "ABS", "Absolute certificate address")
    CSF = (2, "CSF", "Install CSF key")
    DAT = (4, "DAT", "Key binds to Data Type")
    CFG = (8, "CFG", "Key binds to Configuration")
    FID = (16, "FID", "Key binds to Fabrication UID")
    MID = (32, "MID", "Key binds to Manufacturing ID")
    CID = (64, "CID", "Key binds to Caller ID")
    HSH = (128, "HSH", "Certificate hash present")


class SecCmdInstallKey(CmdBase):
    """HAB Install Key command for secure key installation operations.

    This command installs public keys or secret keys that will be used in subsequent
    AuthenticateData commands. It manages key installation parameters including
    certificate format, hash algorithm, source and target indices, and memory location.
    The command structure follows the HAB specification format::

    +-------------+--------------+--------------+
    |     tag     |      len     |    flags     |
    +----------+--+-------+------+---+----------+
    | cert_fmt | hash_alg |   src    |   tgt    |
    +----------+----------+----------+----------+
    |                 location                  |
    +-------------------------------------------+
    |                 [crt_hash]                |
    +-------------------------------------------+
    |                      .                    |
    +-------------------------------------------+
    |                 [crt_hash]                |
    +-------------------------------------------+

    :cvar CMD_TAG: Command tag identifier for Install Key operations.
    """

    CMD_TAG = CmdTag.INS_KEY

    def __init__(
        self,
        flags: InstallKeyFlagsEnum = InstallKeyFlagsEnum.CLR,
        cert_fmt: CertFormatEnum = CertFormatEnum.SRK,
        hash_alg: EnumAlgorithm = EnumAlgorithm.ANY,
        src_index: int = 0,
        tgt_index: int = 0,
        location: int = 0,
    ) -> None:
        """Initialize Install Key command for HAB (High Assurance Boot).

        Creates a command to install cryptographic keys in the target device during
        the secure boot process.

        :param flags: Installation flags controlling key installation behavior.
        :param cert_fmt: Certificate format specifying key authentication protocol.
        :param hash_alg: Hash algorithm used for key verification.
        :param src_index: Source key index for verification (KEK index).
        :param tgt_index: Target key index where the key will be installed.
        :param location: Start address for additional key data installation, typically
            relative to CSF start or absolute for DEK keys.
        """
        super().__init__(flags.tag)
        self._cert_fmt: CertFormatEnum = cert_fmt
        self.hash_algorithm: EnumAlgorithm = hash_alg
        self.source_index = src_index
        self.target_index = tgt_index
        self.cmd_data_location = location
        self._header.length = CmdHeader.SIZE + 8
        self._certificate_ref: Optional[Union[HabCertificate, SrkTable]] = None

    @property
    def flags(self) -> InstallKeyFlagsEnum:
        """Get the flags value for the install key command.

        :return: Flags enumeration value extracted from the header parameter.
        """
        return InstallKeyFlagsEnum.from_tag(self._header.param)

    @flags.setter
    def flags(self, value: InstallKeyFlagsEnum) -> None:
        """Set installation key flags for the HAB command.

        This method validates and sets the flags that control the behavior of the
        install key command in the HAB (High Assurance Boot) context.

        :param value: The flag value to set for the install key command.
        :raises SPSDKError: If the provided flag value is not valid.
        """
        if value not in InstallKeyFlagsEnum:
            raise SPSDKError("Incorrect flag")
        self._header.param = value.tag

    @property
    def certificate_format(self) -> CertFormatEnum:
        """Get certificate format.

        :return: Certificate format enumeration value.
        """
        return self._cert_fmt

    @certificate_format.setter
    def certificate_format(self, value: CertFormatEnum) -> None:
        """Set certificate format for the command.

        :param value: Certificate format to be set.
        :raises SPSDKError: If incorrect certificate format is provided.
        """
        if value not in CertFormatEnum:
            raise SPSDKError("Incorrect certificate format")
        self._cert_fmt = value

    @property
    def hash_algorithm(self) -> EnumAlgorithm:
        """Get hash algorithm used by the command.

        :return: Hash algorithm enumeration value.
        """
        return self._hash_alg

    @hash_algorithm.setter
    def hash_algorithm(self, value: EnumAlgorithm) -> None:
        """Set hash algorithm for the command.

        Validates that the provided algorithm is supported and updates the internal hash algorithm setting.

        :param value: Hash algorithm to be set for the command
        :raises SPSDKError: If incorrect hash algorithm is provided
        """
        if value not in EnumAlgorithm:
            raise SPSDKError("Incorrect hash algorithm")
        self._hash_alg = value

    @property
    def source_index(self) -> int:
        """Get source key index for verification.

        Returns the index of the source key (verification key, KEK) used for authentication.
        For SRK keys, this is the index of the SRK key (0-3). For other keys, this is the
        index of previously installed target key, typically 0.

        :return: Source key index value.
        """
        return self._src_index

    @source_index.setter
    def source_index(self, value: int) -> None:
        """Set source key index for certificate format validation.

        Validates and sets the source index based on the certificate format type.
        For SRK format, accepts indices 0-3. For other formats, accepts indices 0, 2-5.

        :param value: Source key (verification key, KEK) index to set
        :raises SPSDKError: If the provided index value is not valid for the current certificate format
        """
        if self._cert_fmt == CertFormatEnum.SRK:
            # This might need update for devices with different count of keys
            if value not in (
                0,
                1,
                2,
                3,
            ):
                raise SPSDKError(f"Incorrect source index value: {value}")
        else:
            if value not in (0, 2, 3, 4, 5):
                raise SPSDKError(f"Incorrect source index value: {value}")
        self._src_index = value

    @property
    def target_index(self) -> int:
        """Get target key index.

        :return: Target key index value.
        """
        return self._tgt_index

    @target_index.setter
    def target_index(self, value: int) -> None:
        """Set target key index for the install key command.

        :param value: Target key index, must be between 0 and 5 inclusive
        :raises SPSDKError: If incorrect key index provided
        """
        if value not in (0, 1, 2, 3, 4, 5):
            raise SPSDKError(f"Incorrect key index: {value}")
        self._tgt_index = value

    @property
    def cmd_data_offset(self) -> int:
        """Get offset of additional data in binary image.

        The method returns the offset where additional data such as certificate,
        signature, or other supplementary information is located within the binary image.

        :return: Offset position of additional data in the binary image.
        """
        return self.cmd_data_location

    @cmd_data_offset.setter
    def cmd_data_offset(self, value: int) -> None:
        """Set the command data offset value.

        :param value: The offset value to set for command data location.
        """
        self.cmd_data_location = value

    @property
    def needs_cmd_data_reference(self) -> bool:
        """Check if the command contains a reference to additional data.

        This method determines whether the Install Key command needs to reference
        additional data based on the flags configuration. When flags are set to ABS
        (absolute), the command uses an absolute address reference and doesn't need
        additional data assignment.

        :raises SPSDKError: When reference is unexpectedly not None for ABS flag.
        :return: True if command needs additional data reference, False otherwise.
        """
        if (
            self.flags == InstallKeyFlagsEnum.ABS
        ):  # reference is an absolute address; instance not assigned; used for DEK key
            if self._certificate_ref is not None:
                raise SPSDKError("Reference is not none")
            return False
        return True

    @property  # type: ignore
    def cmd_data_reference(self) -> Optional[Union[HabCertificate, SrkTable]]:
        """Get reference to additional data such as certificate or signature.

        Returns the certificate reference if one was assigned to this command,
        otherwise returns None. The actual type of the returned value depends
        on the specific command implementation.

        :return: Certificate reference or SRK table if assigned, None otherwise.
        """
        return self._certificate_ref

    @cmd_data_reference.setter
    def cmd_data_reference(self, value: Union[HabCertificate, Signature, MAC, SrkTable]) -> None:
        """Set command data reference for certificate or SRK table.

        This method assigns a certificate or SRK table reference to the install key command.
        Only HabCertificate and SrkTable types are supported for this command.

        :param value: Certificate or SRK table to be referenced by the command.
        :raises SPSDKError: If value is not HabCertificate or SrkTable type.
        """
        if not isinstance(value, (HabCertificate, SrkTable)):
            raise SPSDKError(f"Expected HabCertificate or SrkTable, got {type(value).__name__}")
        self._certificate_ref = value

    def parse_cmd_data(self, data: bytes) -> Union[HabCertificate, SrkTable, None]:
        """Parse additional command data from binary data.

        The method parses binary data into either a HAB certificate or SRK table based on the
        certificate format configuration. The parsed object is stored as command data reference.

        :param data: Binary data to be parsed into certificate or SRK table format.
        :return: Parsed data object - either HabCertificate or SrkTable depending on format.
        """
        if self.certificate_format == CertFormatEnum.SRK:
            result: Union[HabCertificate, SrkTable] = SrkTable.parse(data)
        else:
            result = HabCertificate.parse(data)
        self.cmd_data_reference = result
        return result

    @property
    def certificate_ref(self) -> Union[HabCertificate, SrkTable, None]:
        """Get corresponding certificate referenced by key-location.

        :return: Certificate object (HabCertificate or SrkTable) if available, None otherwise.
        """
        return self._certificate_ref

    @certificate_ref.setter
    def certificate_ref(self, value: Union[HabCertificate, SrkTable]) -> None:
        """Set the certificate reference for the install key command.

        :param value: Certificate to be installed by the command, either a HAB certificate or SRK table.
        """
        self._certificate_ref = value

    def __repr__(self) -> str:
        """Return string representation of the Install Key command.

        Provides a formatted string containing the command class name and key properties
        including flags, certificate format, hash algorithm, source/target indices,
        and command data location.

        :return: Formatted string representation of the Install Key command.
        """
        return (
            f"{self.__class__.__name__} <{self.flags.label}, {self.certificate_format.label},"
            f" {self.hash_algorithm.label}, {self.source_index}, "
            f"{self.target_index}, 0x{self.cmd_data_location:X}>"
        )

    def __str__(self) -> str:
        """Get text description of the install key command.

        Returns a formatted string containing detailed information about the install key command
        including flags, certificate format, hash algorithm, source and target key indices,
        memory location, and related certificate if present.

        :return: Formatted string representation of the install key command.
        """
        msg = super().__str__()
        msg += f" Flag      : {self.flags} ({self.flags.description})\n"
        msg += f" CertFormat: {self.certificate_format}"
        msg += f"({self.certificate_format.description})\n"
        msg += f" Algorithm : {self.hash_algorithm} ({self.hash_algorithm.description})\n"
        msg += f" SrcKeyIdx : {self.source_index} (Source key index) \n"
        msg += f" TgtKeyIdx : {self.target_index} (Target key index) \n"
        msg += f" Location  : 0x{self.cmd_data_location:08X} (Start address of certificate(s) to install) \n"
        if self.certificate_ref:
            msg += "[related-certificate]\n"
            msg += str(self.certificate_ref)
        return msg

    def export(self) -> bytes:
        """Export command to binary representation for HAB processing.

        Serializes the install key command into binary format by packing the certificate format,
        hash algorithm, source and target indices, and command data location into the proper
        byte structure required by the HAB (High Assurance Boot) system.

        :return: Binary representation of the install key command ready for HAB processing.
        """
        raw_data = super().export()
        data = pack(
            ">4BL",
            self.certificate_format.tag,
            self.hash_algorithm.tag,
            self.source_index,
            self.target_index,
            self.cmd_data_location,
        )
        raw_data += data
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data into InstallKey command object.

        Deserializes binary representation of an InstallKey command back into a structured
        command object with all parameters extracted and validated.

        :param data: Binary data containing the serialized InstallKey command.
        :return: InstallKey command object with parsed parameters.
        """
        header = CmdHeader.parse(data, CmdTag.INS_KEY.tag)
        protocol, algorithm, src_index, tgt_index, location = unpack_from(">4BL", data, header.size)
        return cls(
            InstallKeyFlagsEnum.from_tag(header.param),
            CertFormatEnum.from_tag(protocol),
            EnumAlgorithm.from_tag(algorithm),
            src_index,
            tgt_index,
            location,
        )


class CmdInstallSrk(SecCmdInstallKey):
    """HAB Install SRK command implementation.

    This class represents the HAB (High Assurance Boot) Install SRK (Super Root Key)
    command used for installing cryptographic keys during the secure boot process.
    It handles SRK table parsing and configuration loading for key installation
    operations in NXP MCU secure provisioning.

    :cvar CMD_IDENTIFIER: Command identifier for Install SRK operations.
    """

    CMD_IDENTIFIER = CmdName.INSTALL_SRK

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the install key command.

        Creates an InstallKey command instance from HAB image configuration data, parsing the SRK
        table and source index parameters.

        :param config: HAB image configuration containing command parameters.
        :param cmd_index: Optional index of the command in the configuration in case multiple
            same commands are present.
        :return: Configured InstallKey command instance.
        """
        cmd_cfg = cls._get_cmd_config(config, cmd_index)
        cmd = cls(flags=InstallKeyFlagsEnum.CLR, hash_alg=EnumAlgorithm.SHA256, tgt_index=0)
        cmd.certificate_ref = SrkTable.parse(
            load_binary(cmd_cfg["InstallSRK_Table"], search_paths=cmd_cfg.search_paths)
        )
        cmd.source_index = int(cmd_cfg["InstallSRK_SourceIndex"])
        return cmd


class CmdInstallCsfk(SecCmdInstallKey):
    """HAB Install CSFK command implementation.

    This class represents the HAB (High Assurance Boot) Install CSFK (Command Sequence File Key)
    command used for installing cryptographic keys during the secure boot process. It handles
    loading and processing of CSFK certificates from configuration data.

    :cvar CMD_IDENTIFIER: Command identifier for Install CSFK operations.
    """

    CMD_IDENTIFIER = CmdName.INSTALL_CSFK

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the install key command.

        Creates an InstallKey command instance from HAB image configuration data. The method loads
        the CSFK certificate file, validates the certificate format, and initializes the command
        with appropriate flags and parameters.

        :param config: HAB image configuration containing command settings
        :param cmd_index: Optional index of the command in the configuration in case multiple
            same commands are present
        :raises SPSDKValueError: Invalid certificate format (SRK format not supported)
        :return: Configured InstallKey command instance
        """
        cmd_cfg = cls._get_cmd_config(config, cmd_index)
        csfk_certificate_bin = load_binary(
            cmd_cfg["InstallCSFK_File"], search_paths=cmd_cfg.search_paths
        )
        cert_format = CertFormatEnum.from_label(
            cmd_cfg.get("InstallCSFK_CertificateFormat", "X509")
        )
        if cert_format == CertFormatEnum.SRK:
            raise SPSDKValueError(f"Invalid certificate format: {CertFormatEnum.SRK}")

        cmd = cls(flags=InstallKeyFlagsEnum.CSF, tgt_index=1, cert_fmt=cert_format)

        cmd.certificate_ref = HabCertificate(
            version=get_header_version(config), certificate=Certificate.parse(csfk_certificate_bin)
        )
        return cmd


class CmdInstallKey(SecCmdInstallKey):
    """HAB Install Key command for secure boot operations.

    This command handles the installation of cryptographic keys during the HAB
    (High Assurance Boot) process, managing key verification and target indices
    for secure key provisioning in NXP MCU devices.

    :cvar CMD_IDENTIFIER: Command identifier for HAB install key operations.
    """

    CMD_IDENTIFIER = CmdName.INSTALL_KEY

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the install key command.

        Creates an InstallKey command instance from HAB image configuration data, including
        certificate format, verification index, target index, and certificate reference.

        :param config: HAB image configuration containing command parameters
        :param cmd_index: Optional index of the command in configuration when multiple
            same commands are present
        :return: Configured InstallKey command instance
        """
        cmd_cfg = cls._get_cmd_config(config, cmd_index)
        cmd = cls(
            cert_fmt=CertFormatEnum.X509,
            src_index=int(cmd_cfg["InstallKey_VerificationIndex"]),
            tgt_index=int(cmd_cfg["InstallKey_TargetIndex"]),
        )
        cmd.certificate_ref = HabCertificate(
            version=get_header_version(config),
            certificate=Certificate.parse(
                load_binary(cmd_cfg["InstallKey_File"], config.search_paths)
            ),
        )

        return cmd


class CmdInstallSecretKey(SecCmdInstallKey):
    """HAB Install Secret Key command for secure key provisioning.

    This command handles the installation of secret keys in HAB (High Assurance Boot)
    operations, providing functionality to load, validate, and manage cryptographic
    keys used in secure boot processes.

    :cvar CMD_IDENTIFIER: Command identifier for install secret key operations.
    """

    CMD_IDENTIFIER = CmdName.INSTALL_SECRET_KEY

    def __init__(
        self,
        flags: InstallKeyFlagsEnum = InstallKeyFlagsEnum.CLR,
        cert_fmt: CertFormatEnum = CertFormatEnum.SRK,
        hash_alg: EnumAlgorithm = EnumAlgorithm.ANY,
        src_index: int = 0,
        tgt_index: int = 0,
        location: int = 0,
        secret_len: int = 128,
        secret_key_path: Optional[str] = None,
    ) -> None:
        """Initialize Install Key command.

        Initializes the Install Key HAB command with specified parameters for key installation,
        including flags, certificate format, hash algorithm, and key location settings.

        :param flags: Installation flags controlling key installation behavior.
        :param cert_fmt: Certificate format specification for the key.
        :param hash_alg: Hash algorithm to be used with the key.
        :param src_index: Source index for key location.
        :param tgt_index: Target index for key location.
        :param location: Memory location for key installation.
        :param secret_len: Length of the secret key in bits.
        :param secret_key_path: Optional path to the secret key file.
        """
        super().__init__(flags, cert_fmt, hash_alg, src_index, tgt_index, location)
        self._secret_key: Optional[bytes] = None
        self.secret_key_path = secret_key_path
        self.secret_len = secret_len

    @property
    def secret_key(self) -> Optional[bytes]:
        """Get secret key bytes.

        :return: Secret key bytes if available, None otherwise.
        """
        return self._secret_key

    @secret_key.setter
    def secret_key(self, value: bytes) -> None:
        """Set secret key value.

        The method validates that the provided secret key has the correct length
        before setting it.

        :param value: Secret key bytes that must match the expected length
        :raises SPSDKError: If the secret key length doesn't match expected length
        """
        if len(value) != self.secret_len // 8:
            raise SPSDKError(
                f"Loaded secret key length does not match the expected length: {self.secret_len}"
            )
        self._secret_key = value

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the install key command.

        Creates an InstallKeyCommand instance from HAB image configuration data, including secret key
        parameters, indices, and key generation or loading based on configuration settings.

        :param config: HAB image configuration containing command parameters
        :param cmd_index: Optional index of the command in the configuration in case multiple same
            commands are present
        :raises SPSDKValueError: Invalid source index (greater than 3) or invalid secret key length
            (not 128, 192, or 256)
        :return: Configured InstallKeyCommand instance
        """
        cmd_cfg = cls._get_cmd_config(config, cmd_index)
        location = cls.calculate_location(config)
        source_index = int(cmd_cfg.get("SecretKey_VerifyIndex", 0))
        if source_index > 3:
            raise SPSDKValueError("Source index must be equal or lower than 3")
        target_index = int(cmd_cfg["SecretKey_TargetIndex"])

        cmd = cls(
            flags=InstallKeyFlagsEnum.ABS,
            cert_fmt=CertFormatEnum.BLOB,
            hash_alg=EnumAlgorithm.ANY,
            location=location,
        )
        cmd.source_index = source_index
        cmd.target_index = target_index

        secret_len = int(cmd_cfg.get("SecretKey_Length", 128))
        if secret_len not in [128, 192, 256]:
            raise SPSDKValueError(f"Invalid secret key length {secret_len}")
        cmd.secret_len = secret_len
        cmd.secret_key_path = get_abs_path(cmd_cfg["SecretKey_Name"], config.config_dir)
        if bool(cmd_cfg.get("SecretKey_ReuseDek", False)):
            cmd.secret_key = load_binary(cmd.secret_key_path, search_paths=config.search_paths)
        else:
            cmd.secret_key = cmd.generate_secret_key()
        return cmd

    def generate_secret_key(self) -> bytes:
        """Generate a random secret key.

        Creates a random secret key with length defined by the secret_len attribute (in bits)
        divided by 8 to get the byte length. The key is generated using the random_bytes
        function from the crypto module.

        :return: Randomly generated secret key as bytes.
        """
        return random_bytes(self.secret_len // 8)

    def save_secret_key(self) -> str:
        """Save secret key to the file specified in secret_key_path.

        :raises SPSDKValueError: If secret key path is not specified or secret key is not defined.
        :return: Path to the saved secret key file.
        """
        if not self.secret_key_path:
            raise SPSDKValueError("Secret key path is not specified")
        if not self.secret_key:
            raise SPSDKValueError("Secret key is not defined")
        write_file(self.secret_key, self.secret_key_path, "wb")
        return self.secret_key_path

    @staticmethod
    def calculate_location(config: Config) -> int:
        """Get CSF segment location.

        Calculates the location where the CSF (Command Sequence File) segment should be placed
        in memory. The calculation considers the initial load size, application image size,
        applies proper alignment (16-byte and 4KB), and adds the configured start address
        with an additional 8KB offset.

        :param config: Configuration object containing image and address settings.
        :return: Memory location for CSF segment placement.
        """
        image_len = get_initial_load_size(config) + len(get_app_image(config))
        # align to 0x1000
        csf_offset = image_len + (16 - (image_len % 16))
        csf_offset = ((csf_offset + 0x1000 - 1) // 0x1000) * 0x1000

        location = config.get_config("options")["startAddress"] + csf_offset + 0x2000
        return location


class CmdInstallNOCAK(SecCmdInstallKey):
    """HAB Install NOCAK command for CSF key installation.

    This command handles the installation of Code Signing Framework (CSF) keys
    in HAB (High Assurance Boot) images using NOCAK (NXP Online Certificate
    Authority Key) certificates.

    :cvar CMD_IDENTIFIER: Command identifier for INSTALL_NOCAK operations.
    """

    CMD_IDENTIFIER = CmdName.INSTALL_NOCAK

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the install key command.

        Creates an InstallKey command instance from HAB image configuration data. The method
        loads the certificate file, parses it, and sets up the command with appropriate flags
        and format settings.

        :param config: HAB image configuration containing command settings
        :param cmd_index: Optional index of the command in the configuration in case multiple
            same commands are present
        :return: Configured InstallKey command instance
        :raises SPSDKError: Invalid configuration or certificate loading failure
        """
        cmd_cfg = cls._get_cmd_config(config, cmd_index)
        cert_bin = load_binary(cmd_cfg["InstallNOCAK_File"], search_paths=cmd_cfg.search_paths)
        cert = Certificate.parse(cert_bin)

        cert_format = CertFormatEnum.from_label(
            cmd_cfg.get("InstallNOCAK_CertificateFormat", "X509")
        )

        cmd = cls(flags=InstallKeyFlagsEnum.CSF, tgt_index=1, cert_fmt=cert_format)

        cmd.certificate_ref = HabCertificate(
            version=get_header_version(config),
            certificate=cert,
        )
        return cmd
