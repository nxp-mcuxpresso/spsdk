#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module implementing HAB Install Key commands.

This module provides classes for different types of key installation commands
used in High Assurance Boot (HAB) protocol.
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
from spsdk.image.hab.hab_srk import SrkTable
from spsdk.image.hab.utils import get_app_image, get_header_version, get_initial_load_size
from spsdk.utils.config import Config
from spsdk.utils.misc import get_abs_path, load_binary, write_file
from spsdk.utils.spsdk_enum import SpsdkEnum


class InstallKeyFlagsEnum(SpsdkEnum):
    """Flags for Install Key commands."""

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
    """Install a public key or secret key to use in subsequent AuthenticateData command.

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
        """Constructor.

        :param flags: from InstallKeyFlagsEnum
        :param cert_fmt: format of the certificate; key authentication protocol
        :param hash_alg: hash algorithm
        :param src_index: source key (verification key, KEK) index
        :param tgt_index: target key index
        :param location: start address of an additional data such as KEY to be installed;
                Typically it is relative to CSF start; Might be absolute for DEK key
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
        """Flags."""
        return InstallKeyFlagsEnum.from_tag(self._header.param)

    @flags.setter
    def flags(self, value: InstallKeyFlagsEnum) -> None:
        """Flags.

        :raises SPSDKError: If incorrect flag"
        """
        if value not in InstallKeyFlagsEnum:
            raise SPSDKError("Incorrect flag")
        self._header.param = value.tag

    @property
    def certificate_format(self) -> CertFormatEnum:
        """Certificate format."""
        return self._cert_fmt

    @certificate_format.setter
    def certificate_format(self, value: CertFormatEnum) -> None:
        """Setter.

        :param value: certificate format
        :raises SPSDKError: If incorrect certificate format
        """
        if value not in CertFormatEnum:
            raise SPSDKError("Incorrect certificate format")
        self._cert_fmt = value

    @property
    def hash_algorithm(self) -> EnumAlgorithm:
        """Hash algorithm."""
        return self._hash_alg

    @hash_algorithm.setter
    def hash_algorithm(self, value: EnumAlgorithm) -> None:
        """Setter.

        :param value: hash algorithm
        :raises SPSDKError: If incorrect hash algorithm
        """
        if value not in EnumAlgorithm:
            raise SPSDKError("Incorrect hash algorithm")
        self._hash_alg = value

    @property
    def source_index(self) -> int:
        """Source key (verification key, KEK) index.

        - For SRK, it is index of the SRK key (0-3)
        - For other keys it is index of previously installed target key, typically 0
        """
        return self._src_index

    @source_index.setter
    def source_index(self, value: int) -> None:
        """Setter.

        :param value: source key (verification key, KEK) index
        :raises SPSDKError: If incorrect keys
        :raises SPSDKError: If incorrect keys
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
        """Target key index."""
        return self._tgt_index

    @target_index.setter
    def target_index(self, value: int) -> None:
        """Setter.

        :param value: target key index
        :raises SPSDKError: If incorrect key index
        """
        if value not in (0, 1, 2, 3, 4, 5):
            raise SPSDKError(f"Incorrect key index: {value}")
        self._tgt_index = value

    @property
    def cmd_data_offset(self) -> int:
        """Offset of an additional data (such as certificate, signature, etc) in binary image."""
        return self.cmd_data_location

    @cmd_data_offset.setter
    def cmd_data_offset(self, value: int) -> None:
        """Setter.

        :param value: offset to set
        """
        self.cmd_data_location = value

    @property
    def needs_cmd_data_reference(self) -> bool:
        """Whether the command contains a reference to an additional data."""
        if (
            self.flags == InstallKeyFlagsEnum.ABS
        ):  # reference is an absolute address; instance not assigned; used for DEK key
            if self._certificate_ref is not None:
                raise SPSDKError("Reference is not none")
            return False
        return True

    @property  # type: ignore
    def cmd_data_reference(self) -> Optional[Union[HabCertificate, SrkTable]]:
        """Reference to an additional data (such as certificate, signature, etc).

        None if no reference was assigned;
        Value type is command-specific
        """
        return self._certificate_ref

    @cmd_data_reference.setter
    def cmd_data_reference(self, value: Union[HabCertificate, SrkTable]) -> None:
        """Setter.

        By default, the command does not support cmd_data_reference

        :param value: to be set
        """
        assert isinstance(value, (HabCertificate, SrkTable))
        self._certificate_ref = value

    def parse_cmd_data(self, data: bytes) -> Union[HabCertificate, SrkTable, None]:
        """Parse additional command data from binary data.

        :param data: to be parsed
        :return: parsed data object; command-specific: certificate or SrkTable to be installed
        """
        if self.certificate_format == CertFormatEnum.SRK:
            result: Union[HabCertificate, SrkTable] = SrkTable.parse(data)
        else:
            result = HabCertificate.parse(data)
        self.cmd_data_reference = result
        return result

    @property
    def certificate_ref(self) -> Union[HabCertificate, SrkTable, None]:
        """Corresponding certificate referenced by key-location."""
        return self._certificate_ref

    @certificate_ref.setter
    def certificate_ref(self, value: Union[HabCertificate, SrkTable]) -> None:
        """Setter.

        :param value: certificate to be installed by the command
        """
        self._certificate_ref = value

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__} <{self.flags.label}, {self.certificate_format.label},"
            f" {self.hash_algorithm.label}, {self.source_index}, "
            f"{self.target_index}, 0x{self.cmd_data_location:X}>"
        )

    def __str__(self) -> str:
        """Text description of the command."""
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
        """Export to binary form (serialization).

        :return: binary representation of the command
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
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: parse command
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
    """Install SRK command."""

    CMD_IDENTIFIER = CmdName.INSTALL_SRK

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the command.

        :param config: HAB image configuration
        :param cmd_index: Optional index of the command in the configuration in case multiple same commands are present
        """
        cmd_cfg = cls._get_cmd_config(config, cmd_index)
        cmd = cls(flags=InstallKeyFlagsEnum.CLR, hash_alg=EnumAlgorithm.SHA256, tgt_index=0)
        cmd.certificate_ref = SrkTable.parse(
            load_binary(cmd_cfg["InstallSRK_Table"], search_paths=cmd_cfg.search_paths)
        )
        cmd.source_index = int(cmd_cfg["InstallSRK_SourceIndex"])
        return cmd


class CmdInstallCsfk(SecCmdInstallKey):
    """Install CSFK command."""

    CMD_IDENTIFIER = CmdName.INSTALL_CSFK

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the command.

        :param config: HAB image configuration
        :param cmd_index: Optional index of the command in the configuration in case multiple same commands are present
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
    """Install key command."""

    CMD_IDENTIFIER = CmdName.INSTALL_KEY

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the command.

        :param config: HAB image configuration
        :param cmd_index: Optional index of the command in the configuration in case multiple same commands are present
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
    """Install secret key command."""

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
        """Command initialization."""
        super().__init__(flags, cert_fmt, hash_alg, src_index, tgt_index, location)
        self._secret_key: Optional[bytes] = None
        self.secret_key_path = secret_key_path
        self.secret_len = secret_len

    @property
    def secret_key(self) -> Optional[bytes]:
        """Load secret key from file or use provided bytes.

        :return: Secret key bytes
        :raises SPSDKValueError: If secret key cannot be loaded
        """
        return self._secret_key

    @secret_key.setter
    def secret_key(self, value: bytes) -> None:
        """Set secret key value.

        :param value: Secret key bytes or None
        """
        if len(value) != self.secret_len // 8:
            raise SPSDKError(
                f"Loaded secret key length does not match the expected length: {self.secret_len}"
            )
        self._secret_key = value

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the command.

        :param config: HAB image configuration
        :param cmd_index: Optional index of the command in the configuration in case multiple same commands are present
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

        :return: Randomly generated secret key as bytes
        """
        return random_bytes(self.secret_len // 8)

    def save_secret_key(self) -> str:
        """Save secret key to the file specified in secret_key_path.

        :raises SPSDKValueError: If secret key is not available
        """
        if not self.secret_key_path:
            raise SPSDKValueError("Secret key path is not specified")
        if not self.secret_key:
            raise SPSDKValueError("Secret key is not defined")
        write_file(self.secret_key, self.secret_key_path, "wb")
        return self.secret_key_path

    @staticmethod
    def calculate_location(config: Config) -> int:
        """Get CSF segment location."""
        image_len = get_initial_load_size(config) + len(get_app_image(config))
        # align to 0x1000
        csf_offset = image_len + (16 - (image_len % 16))
        csf_offset = ((csf_offset + 0x1000 - 1) // 0x1000) * 0x1000

        location = config.get_config("options")["startAddress"] + csf_offset + 0x2000
        return location


class CmdInstallNOCAK(SecCmdInstallKey):
    """Install CSFK command."""

    CMD_IDENTIFIER = CmdName.INSTALL_NOCAK

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the command.

        :param config: HAB image configuration
        :param cmd_index: Optional index of the command in the configuration in case multiple same commands are present
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
