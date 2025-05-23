#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""HAB commands module for handling authentication data operations.

This module implements the Authenticate Data commands used in the HAB secure boot
process.
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
from spsdk.image.hab.utils import aead_nonce_len, get_header_version
from spsdk.utils.config import Config
from spsdk.utils.misc import load_binary
from spsdk.utils.spsdk_enum import SpsdkEnum


class AuthDataFlagsEnum(SpsdkEnum):
    """Flags for Authenticate Data commands."""

    CLR = (0, "CLR", "No flags set")
    ABS = (1, "ABS", "Absolute signature address")


class SPSDKExpectedSignatureOrMACError(SPSDKError):
    """CmdAuthData additional data block: expected Signature or MAC object."""


SignatureOrMAC = Union[MAC, Signature]


class CmdAuthData(CmdBase):
    """Verify the authenticity of pre-loaded data using a pre-installed key.

    The data may include executable SW instructions and may be spread across multiple non-contiguous blocks in memory.
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
        """Initialize the Authenticate data command."""
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
        """Flag of Authenticate data command."""
        return AuthDataFlagsEnum.from_tag(self._header.param)

    @flags.setter
    def flags(self, value: AuthDataFlagsEnum) -> None:
        if value not in AuthDataFlagsEnum:
            raise SPSDKError("Incorrect flag")
        self._header.param = value.tag

    @property
    def key_index(self) -> int:
        """Key index."""
        return self._key_index

    @key_index.setter
    def key_index(self, value: int) -> None:
        """Key index setter."""
        if value not in (0, 1, 2, 3, 4, 5):
            raise SPSDKError("Incorrect key index")
        self._key_index = value

    @property
    def engine(self) -> EngineEnum:
        """Engine."""
        return self._engine

    @engine.setter
    def engine(self, value: EngineEnum) -> None:
        """Engine setter."""
        if value not in EngineEnum:
            raise SPSDKError("Incorrect engine")
        self._engine = value

    @property
    def needs_cmd_data_reference(self) -> bool:
        """Whether the command contains a reference to an additional data."""
        return True

    @property
    def cmd_data_offset(self) -> int:
        """Offset of an additional data (such as signature or MAC, etc) in binary image."""
        return self.location

    @cmd_data_offset.setter
    def cmd_data_offset(self, value: int) -> None:
        """Setter.

        :param value: offset to set
        """
        self.location = value

    @property  # type: ignore
    def cmd_data_reference(self) -> Optional[SignatureOrMAC]:
        """Reference to an additional data (such as certificate, signature, etc).

        -   None if no reference was assigned;
        -   Value type is command-specific
        """
        return self._signature

    @cmd_data_reference.setter
    def cmd_data_reference(self, value: SignatureOrMAC) -> None:
        """Setter.

        By default, the command does not support cmd_data_reference

        :param value: to be set
        :raises SPSDKExpectedSignatureOrMACError: if unsupported data object is provided
        """
        if self.sig_format == CertFormatEnum.AEAD:
            assert isinstance(value, MAC)
        elif self.sig_format == CertFormatEnum.CMS:
            assert isinstance(value, Signature)
        else:
            raise SPSDKExpectedSignatureOrMACError("Unsupported data object is provided")
        self._signature = value

    def parse_cmd_data(self, data: bytes) -> SignatureOrMAC:
        """Parse additional command data from binary data.

        :param data: to be parsed
        :return: parsed data object; command-specific: Signature or MAC
        :raises SPSDKExpectedSignatureOrMACError: if unsupported data object is provided
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
        """Signature referenced by `location` attribute."""
        return self._signature

    @signature.setter
    def signature(self, value: SignatureOrMAC) -> None:
        """Setter.

        :param value: signature to be installed by the command
        """
        self.cmd_data_reference = value

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__} <{self.flags.label}, {self.engine.label},"
            f" {self.engine_cfg}, key:{self.key_index}, 0x{self.location:X}>"
        )

    def __len__(self) -> int:
        return len(self._blocks)

    def __getitem__(self, key: int) -> tuple[int, int]:
        return self._blocks[key]

    def __setitem__(self, key: int, value: tuple[int, int]) -> None:
        assert isinstance(value, (list, tuple))
        if len(value) != 2:
            raise SPSDKError("Incorrect length")
        self._blocks[key] = value

    def __iter__(self) -> Iterator[Union[tuple[Any, ...], list[Any]]]:
        return self._blocks.__iter__()

    def __str__(self) -> str:
        """Text description of the command."""
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
        """Append of Authenticate data command."""
        self._blocks.append(
            (start_address, size),
        )
        self._header.length += 8

    def pop(self, index: int) -> tuple[int, int]:
        """Pop of Authenticate data command."""
        if index < 0 or index >= len(self._blocks):
            raise SPSDKError("Incorrect length of blocks")
        value = self._blocks.pop(index)
        self._header.length -= 8
        return value

    def clear(self) -> None:
        """Clear of Authenticate data command."""
        self._blocks.clear()
        self._header.length = self._header.size + 8

    def update_signature(
        self, zulu: datetime, data: bytes, base_data_addr: int = 0xFFFFFFFF
    ) -> bool:
        """Update signature.

        This method must be called from parent to provide data to be signed

        :param zulu: current UTC time+date
        :param data: currently generated binary data
        :param base_data_addr: base address of the generated data
        :raises ValueError: When certificate or private key are not assigned
        :raises ValueError: When signatures not assigned explicitly
        :raises SPSDKError: If incorrect start address
        :raises SPSDKError: If incorrect end address
        :raises SPSDKError: If incorrect length
        :return: True if length of the signature was unchanged, as this may affect content of the CSF section (pointer
                        to data);
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
        """Export to binary form (serialization).

        :return: binary representation of the command
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
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: parse command
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
    """Get the HAB signature provider from configuration."""
    signature_provider = get_signature_provider(config, "Signer")
    if isinstance(signature_provider, PlainFileSP):
        if isinstance(signature_provider.private_key, PrivateKeyEcc):
            signature_provider.hash_alg = EnumHashAlgorithm.SHA256
    return signature_provider


class CmdAuthenticateCsf(CmdAuthData):
    """Authenticate CSFK command."""

    SIGNED_DATA_SIZE = 768
    CMD_IDENTIFIER = CmdName.AUTHENTICATE_CSF

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the command.

        :param config: HAB image configuration
        :param cmd_index: Optional index of the command in the configuration in case multiple same commands are present
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
    """Set decrypt data command."""

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
        """Command initialization.

        :param nonce: Nonce data
        :param mac_len: MAC length
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
        """Load configuration into the command.

        :param config: HAB image configuration
        :param cmd_index: Optional index of the command in the configuration in case multiple same commands are present
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

        :param data: The data that will be decrypted, used to calculate appropriate nonce length
        """
        nonce_len = aead_nonce_len(len(data))
        self.nonce = random_bytes(nonce_len)


class SecCsfAuthenticateData(CmdAuthData):
    """Authenticate data command."""

    KEY_IDX_AUT_DAT_FAST_AUTH = 0
    KEY_IDX_AUT_DAT_MIN = 2
    KEY_IDX_AUT_DAT_MAX = 5
    CMD_IDENTIFIER = CmdName.AUTHENTICATE_DATA

    @classmethod
    def load_from_config(cls, config: Config, cmd_index: Optional[int] = None) -> Self:
        """Load configuration into the command.

        :param config: HAB image configuration
        :param cmd_index: Optional index of the command in the configuration in case multiple same commands are present
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
