#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""Builder of CST segments."""

import logging
import os
from abc import ABC, abstractmethod
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.serialization import Encoding

from spsdk.crypto import Certificate
from spsdk.crypto.loaders import load_certificate_from_data, load_private_key_from_data
from spsdk.exceptions import (
    SPSDKAttributeError,
    SPSDKError,
    SPSDKFileNotFoundError,
    SPSDKKeyError,
    SPSDKTypeError,
    SPSDKValueError,
)
from spsdk.image import segments
from spsdk.image.commands import (
    CmdAuthData,
    CmdBase,
    CmdInstallKey,
    CmdSet,
    CmdUnlockAbstract,
    CmdUnlockCAAM,
    CmdUnlockSNVS,
    EnumAuthDat,
    EnumCertFormat,
    EnumEngine,
    EnumInsKey,
)
from spsdk.image.hab.config_parser import ImageConfig, SectionConfig
from spsdk.image.hab.hab_binary_image import HabBinaryImage, HabSegment
from spsdk.image.header import Header, SegTag
from spsdk.image.images import BootImgRT
from spsdk.image.secret import MAC, CertificateImg, EnumAlgorithm, Signature, SrkTable
from spsdk.utils.crypto.common import crypto_backend
from spsdk.utils.misc import (
    BinaryPattern,
    align_block,
    find_file,
    find_first,
    get_abs_path,
    load_binary,
    write_file,
)

logger = logging.getLogger(__name__)


@dataclass
class ImageBlock:
    """Single image block."""

    base_address: int
    start: int
    size: int


class SecCommand(ABC):
    """Sec command abstract class."""

    CMD_INDEX: int
    CONFIGURATION_PARAMS: Dict[str, Any]

    def __init__(self) -> None:
        """Command abstract class constructor."""
        self._cmd: Optional[Union[CmdBase, Header]] = None

    @property
    def cmd(self) -> Union[CmdBase, Header]:
        """Command property.

        :raises SPSDKAttributeError: If command is not set
        """
        if self._cmd is None:
            raise SPSDKAttributeError("Command is not set")
        return self._cmd

    @cmd.setter
    def cmd(self, value: Union[CmdBase, Header]) -> None:
        """Command setter."""
        self._cmd = value

    @classmethod
    def check_config_section_params(cls, section_data: SectionConfig) -> None:
        """Check if options contains only accepted arguments.

        :param section_data: Section data to be checked
        :raises SPSDKError: If mandatory parameter is not present
        :raises SPSDKError: If unexpected key is present
        """
        for param, is_mandatory in cls.CONFIGURATION_PARAMS.items():
            if is_mandatory and section_data.options.get(param) is None:
                raise SPSDKError("Mandatory parameter is not defined")

        additional_params = list(
            set(key.lower() for key in section_data.options.keys())
            - set(key.lower() for key in cls.CONFIGURATION_PARAMS.keys())
        )
        if additional_params:
            raise SPSDKError(f"Unexpected arguments {additional_params}")

    @staticmethod
    @abstractmethod
    def parse(config: SectionConfig, search_paths: Optional[List[str]] = None) -> "SecCommand":
        """Parse configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Parsed command instance
        """

    @abstractmethod
    def build_command(self) -> None:
        """Build command with given properties."""

    @staticmethod
    def generate_random_bytes(length: int) -> bytes:
        """Generate random bytes.

        :param length: Length of random bytes
        :raises SPSDKError: If length of bytes is not as expected
        :return: Generated random bytes
        """
        secret_key = crypto_backend().random_bytes(length)
        if length != len(secret_key):
            raise SPSDKError(f"Invalid sectet key bytes length: {len(secret_key)}")
        return secret_key


class SecCsfHeader(SecCommand):
    """CSF header command."""

    CMD_INDEX = 20
    CONFIGURATION_PARAMS = {
        "Header_Version": True,
        "Header_HashAlgorithm": False,
        "Header_Engine": True,
        "Header_EngineConfiguration": True,
        "Header_CertificateFormat": False,
        "Header_SignatureFormat": True,
    }

    def __init__(
        self,
        version: Union[int, str],
        engine: EnumEngine,
        engine_config: int,
        hash_algorithm: Optional[EnumAlgorithm] = None,
        certificate_format: Optional[EnumCertFormat] = None,
        signature_format: Optional[str] = None,
    ) -> None:
        """CSF header class constructor.

        :param version: Header version
        :param engine: Engine plugin tag
        :param engine_config: Engine configuration index
        :param hash_algorithm: Hash algorithm type
        :param certificate_format: Certificate format tag
        :param signature_format: Signature format
        :raises SPSDKValueError: Invalid combination of input parameters.
        :raises SPSDKValueError: Invalid signature format.
        """
        super().__init__()
        self.version = self._parse_version(version)
        if engine == EnumEngine.ANY and engine_config != 0:
            raise SPSDKValueError(f"Invalid combination:{engine}: {engine_config}")
        self.engine: EnumEngine = engine
        self.engine_config: int = engine_config
        if not signature_format:
            signature_format = "CMS"
        if signature_format and signature_format.lower() != "cms":
            raise SPSDKValueError(f"Invalid signature format: {signature_format}")
        self.signature_format: str = signature_format
        self.certificate_format: Optional[EnumCertFormat] = certificate_format
        self.hash_algorithm: Optional[EnumAlgorithm] = hash_algorithm

    @staticmethod
    def parse(config: SectionConfig, search_paths: Optional[List[str]] = None) -> "SecCsfHeader":
        """Parse configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        SecCsfHeader.check_config_section_params(config)
        version = config.options["Header_Version"]
        assert version

        hash_algorithm = config.options.get("Header_HashAlgorithm")
        if hash_algorithm is not None:
            hash_algorithm = EnumAlgorithm[hash_algorithm]

        engine = EnumEngine[config.options["Header_Engine"]]
        engine_config = int(config.options["Header_EngineConfiguration"])

        cert_format = config.options.get("Header_CertificateFormat")
        if cert_format is not None:
            cert_format = EnumCertFormat[cert_format]

        signature_format = config.options.get("Header_SignatureFormat")
        return SecCsfHeader(
            version=version,
            engine=engine,
            engine_config=engine_config,
            hash_algorithm=hash_algorithm,
            certificate_format=cert_format,
            signature_format=signature_format,
        )

    def build_command(self) -> None:
        """Build command with given properties."""
        self.cmd: Header = Header(SegTag.CSF, param=self.version)
        self.cmd.length = 4

    @staticmethod
    def _parse_version(version: Union[str, int]) -> int:
        """Parse version from string to actiual integer.

        An example: "4.2" -> 0x42 -> 64

        :param version: Version as string or int
        :raises SPSDKTypeError: Input version if wrong type.
        :return: Version as int value
        """
        if not isinstance(version, (str, int)):
            raise SPSDKTypeError("Version can be either int or string")
        if isinstance(version, str):
            int_version = int(version.replace(".", ""), 16)
        else:
            int_version = version
        return int_version


class SecCsfInstallSrk(SecCommand):
    """Install SRK command."""

    CMD_INDEX = 21
    CONFIGURATION_PARAMS = {"InstallSRK_Table": True, "InstallSRK_SourceIndex": True}

    def __init__(self, srk_table: bytes, source_index: int) -> None:
        """Install SRK class constructor.

        :param srk_table: SRK table
        :param source_index: Source index
        :raises SPSDKError: Srk table is not defined .
        :raises SPSDKError: Source index is not defined .
        """
        super().__init__()
        if not srk_table:
            raise SPSDKError("SRK table must be defined.")
        self.srk_table = srk_table
        if source_index is None:
            raise SPSDKError("Source index must be defined.")
        self.source_index = source_index

    @staticmethod
    def parse(
        config: SectionConfig, search_paths: Optional[List[str]] = None
    ) -> "SecCsfInstallSrk":
        """Parse configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        SecCsfInstallSrk.check_config_section_params(config)

        source_index = int(config.options["InstallSRK_SourceIndex"])
        srk_table = load_binary(config.options["InstallSRK_Table"], search_paths=search_paths)

        return SecCsfInstallSrk(srk_table=srk_table, source_index=source_index)

    def build_command(self) -> None:
        """Build command with given properties."""
        self.cmd = CmdInstallKey(flags=EnumInsKey.CLR, hash_alg=EnumAlgorithm.SHA256, tgt_index=0)

        self.cmd.certificate_ref = SrkTable.parse(self.srk_table)
        self.cmd.source_index = self.source_index


class SecCsfInstallCsfk(SecCommand):
    """Install CSFK command."""

    CMD_INDEX = 22
    CONFIGURATION_PARAMS = {"InstallCSFK_File": True, "InstallCSFK_CertificateFormat": False}

    def __init__(
        self,
        csfk_file_path: str,
        certificate_format: Optional[EnumCertFormat] = None,
    ) -> None:
        """Install CSF class constructor.

        :param csfk_file_path: Path to CSFK file
        :param version: Header version
        :param certificate_format: Certificate format
        :raises SPSDKValueError: Invalid combination of input parameters.
        """
        super().__init__()
        self._version: Optional[int] = None
        self.csfk_file_path = csfk_file_path
        if certificate_format == EnumCertFormat.SRK:
            raise SPSDKValueError(f"Invalid certificate format: {EnumCertFormat.SRK}")
        if certificate_format is None:
            certificate_format = EnumCertFormat.X509
        self.certificate_format = certificate_format

    @staticmethod
    def parse(
        config: SectionConfig, search_paths: Optional[List[str]] = None
    ) -> "SecCsfInstallCsfk":
        """Parse configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        SecCsfInstallCsfk.check_config_section_params(config)

        csfk_file_path = find_file(config.options["InstallCSFK_File"], search_paths=search_paths)
        cert_format = config.options.get("InstallCSFK_CertificateFormat")
        cert_format = EnumCertFormat[cert_format] if cert_format is not None else None

        return SecCsfInstallCsfk(
            csfk_file_path=csfk_file_path,
            certificate_format=cert_format,
        )

    @property
    def version(self) -> int:
        """Image version."""
        assert self._version is not None
        return self._version

    @version.setter
    def version(self, value: int) -> None:
        """Image version setter."""
        if not isinstance(value, int):
            raise SPSDKTypeError("Version must be int type")
        self._version = value

    def build_command(self) -> None:
        """Build command with given properties."""
        self.cmd: CmdInstallKey = CmdInstallKey(
            flags=EnumInsKey.CSF,
            tgt_index=1,
        )
        self.cmd.certificate_format = self.certificate_format  # type: ignore
        certificate_bin = load_binary(self.csfk_file_path)
        certificate = load_certificate_from_data(certificate_bin)
        self.cmd.certificate_ref = CertificateImg(
            version=self.version, data=certificate.public_bytes(Encoding.DER)
        )


class SecCsfAuthenticateCsf(SecCommand):
    """Authenticate CSFK command."""

    CMD_INDEX = 24
    CONFIGURATION_PARAMS = {
        "AuthenticateCsf_PrivateKeyFile": False,
        "AuthenticateCsf_KeyPass": False,
    }
    SIGNED_DATA_SIZE = 768

    def __init__(
        self,
        private_key: Optional[bytes],
        key_pass: Optional[str] = None,
    ) -> None:
        """Authenticate CSFK class constructor.

        :param version: Header version
        :param certificate: Certificate
        :param private_key: Private key used for authentication
        :param data: Command data to be signed
        :param key_pass: Key for decryption of private key
        """
        super().__init__()
        self.private_key = private_key
        self.key_pass = key_pass
        self._version: Optional[int] = None
        self._certificate: Optional[Certificate] = None
        self._engine: Optional[EnumEngine] = None

    @staticmethod
    def parse(
        config: SectionConfig, search_paths: Optional[List[str]] = None
    ) -> "SecCsfAuthenticateCsf":
        """Parse configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        SecCsfAuthenticateCsf.check_config_section_params(config)
        private_key_path = config.options.get("AuthenticateCsf_PrivateKeyFile")
        private_key = None
        if private_key_path is not None:
            private_key = load_binary(private_key_path, search_paths=search_paths)

        key_pass = None
        private_key_pass_path = config.options.get("AuthenticateCsf_KeyPass")
        if private_key_pass_path is not None:
            private_key_pass_file = find_file(private_key_pass_path, search_paths=search_paths)
            with open(private_key_pass_file) as file:
                key_pass = file.readline().strip()
        return SecCsfAuthenticateCsf(private_key=private_key, key_pass=key_pass)

    @property
    def certificate(self) -> Certificate:
        """Certificate."""
        assert self._certificate is not None
        return self._certificate

    @certificate.setter
    def certificate(self, value: Certificate) -> None:
        """Certificate setter."""
        if not isinstance(value, Certificate):
            raise SPSDKTypeError("Certificate is of incorrect type")
        self._certificate = value

    @property
    def engine(self) -> Optional[EnumEngine]:
        """Engine."""
        return self._engine

    @engine.setter
    def engine(self, value: Optional[EnumEngine]) -> None:
        """Engine setter."""
        if not (isinstance(value, EnumEngine) or isinstance(value, int)):
            raise SPSDKTypeError("Engine is of incorrect type")
        self._engine = value

    @property
    def version(self) -> int:
        """Image version."""
        assert self._version is not None
        return self._version

    @version.setter
    def version(self, value: int) -> None:
        """Image version setter."""
        if not isinstance(value, int):
            raise SPSDKTypeError("Version must be int type")
        self._version = value

    def build_command(self) -> None:
        """Build command with given properties."""
        self.cmd: CmdAuthData = CmdAuthData(certificate=self.certificate)
        if self.engine is not None:
            self.cmd.engine = self.engine

        assert self.private_key is not None
        pem_private_key = load_private_key_from_data(
            self.private_key, password=str.encode(self.key_pass) if self.key_pass else None
        )
        self.cmd.private_key_pem_data = pem_private_key  # type: ignore

        signature = Signature(version=self.version)
        self.cmd.signature = signature

    def sign(self, data: bytes, timestamp: datetime) -> None:
        """Sign data and update command signature.

        :param data: Data to be signed
        :param timestamp: Signature timestamp
        """
        data = align_block(data, alignment=self.SIGNED_DATA_SIZE, padding=BinaryPattern("zeros"))
        self.cmd.update_signature(zulu=timestamp, data=data)


class SecCsfInstallKey(SecCommand):
    """Install key command."""

    CMD_INDEX = 25
    CONFIGURATION_PARAMS = {
        "InstallKey_File": True,
        "InstallKey_VerificationIndex": True,
        "InstallKey_TargetIndex": True,
    }

    def __init__(
        self,
        certificate_path: str,
        source_index: int,
        target_index: int,
    ) -> None:
        """Install key class constructor.

        :param certificate_path: Path to certificate
        :param version: Header version
        :param source_index: Source index
        :param target_index: Target index
        """
        super().__init__()
        self.certificate_path = certificate_path
        self.certificate = load_certificate_from_data(load_binary(certificate_path))
        self.source_index = source_index
        self.target_index = target_index
        self._version: Optional[int] = None

    @staticmethod
    def parse(
        config: SectionConfig, search_paths: Optional[List[str]] = None
    ) -> "SecCsfInstallKey":
        """Parse configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        SecCsfInstallKey.check_config_section_params(config)

        install_key_path = config.options["InstallKey_File"]
        certificate_path = find_file(install_key_path, search_paths=search_paths)

        source_index = int(config.options["InstallKey_VerificationIndex"])

        target_index = int(config.options["InstallKey_TargetIndex"])
        return SecCsfInstallKey(
            certificate_path=certificate_path, source_index=source_index, target_index=target_index
        )

    @property
    def version(self) -> int:
        """Image version."""
        assert self._version is not None
        return self._version

    @version.setter
    def version(self, value: int) -> None:
        """Image version setter."""
        if not isinstance(value, int):
            raise SPSDKTypeError("Version must be int type")
        self._version = value

    def build_command(self) -> None:
        """Build command with given properties."""
        self.cmd: CmdInstallKey = CmdInstallKey(cert_fmt=EnumCertFormat.X509)
        self.cmd.certificate_ref = CertificateImg(
            version=self.version, data=self.certificate.public_bytes(Encoding.DER)
        )
        self.cmd.source_index = self.source_index
        self.cmd.target_index = self.target_index


class SecCsfAuthenticateData(SecCommand):
    """Authenticate data command."""

    CMD_INDEX = 26
    KEY_IDX_AUT_DAT_FAST_AUTH = 0
    KEY_IDX_AUT_DAT_MIN = 2
    KEY_IDX_AUT_DAT_MAX = 5
    CONFIGURATION_PARAMS = {
        "AuthenticateData_VerificationIndex": True,
        "AuthenticateData_Engine": True,
        "AuthenticateData_EngineConfiguration": True,
        "AuthenticateData_PrivateKeyFile": False,
        "AuthenticateData_KeyPass": False,
    }

    def __init__(
        self,
        engine: EnumEngine,
        engine_config: int,
        verification_index: int,
        private_key: Optional[bytes],
        key_pass: Optional[str] = None,
    ) -> None:
        """Authenticate data class constructor.

        :param engine: Engine plugin tag
        :param engine_config: Engine configuration index
        :param verification_index: Target index
        :raises SPSDKValueError: Invalid combination of input parameters.
        :raises SPSDKValueError: Verification index is not defined.
        :raises SPSDKValueError: Key index is not a valid value.
        """
        super().__init__()
        if engine == EnumEngine.ANY and engine_config != 0:
            raise SPSDKValueError(f"Invalid argument combination:{engine}: {engine_config}")
        self.engine = engine
        self.engine_config = engine_config
        if verification_index is None:
            raise SPSDKValueError("Verification index must be defined.")
        if verification_index != self.KEY_IDX_AUT_DAT_FAST_AUTH and (
            verification_index < self.KEY_IDX_AUT_DAT_MIN
            or verification_index > self.KEY_IDX_AUT_DAT_MAX
        ):
            raise SPSDKValueError("Key index must have valid value.")
        self.verification_index = verification_index
        self.private_key = private_key
        self.key_pass = key_pass
        self._certificate: Optional[Certificate] = None
        self._blocks: List[ImageBlock] = []

    @property
    def blocks(self) -> List[ImageBlock]:
        """Blocks to be signed property."""
        return self._blocks

    @blocks.setter
    def blocks(self, value: List[ImageBlock]) -> None:
        """Blocks to be signed property setter."""
        if not isinstance(value, List):
            raise SPSDKTypeError("Blocks must be a list type")
        self._blocks = value

    def sign(
        self,
        data: bytes,
        base_data_address: int,
        timestamp: Optional[datetime] = None,
    ) -> None:
        """Sign data and update command signature.

        :param data: Data to be signed
        :param base_data_address: Base address of the generated data
        :param timestamp: Signature timestamp
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        self.cmd.update_signature(
            zulu=timestamp,
            data=data,
            base_data_addr=base_data_address,
        )

    @staticmethod
    def parse(
        config: SectionConfig, search_paths: Optional[List[str]] = None
    ) -> "SecCsfAuthenticateData":
        """Parse configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        SecCsfAuthenticateData.check_config_section_params(config)
        verification_index = int(config.options["AuthenticateData_VerificationIndex"])
        engine = EnumEngine[config.options["AuthenticateData_Engine"]]
        engine_cfg = int(config.options["AuthenticateData_EngineConfiguration"])

        private_key_path = config.options.get("AuthenticateData_PrivateKeyFile")
        private_key = None
        if private_key_path is not None:
            private_key = load_binary(private_key_path, search_paths=search_paths)

        key_pass = None
        private_key_pass_path = config.options.get("AuthenticateData_KeyPass")
        if private_key_pass_path is not None:
            private_key_pass_file = find_file(private_key_pass_path, search_paths=search_paths)
            with open(private_key_pass_file) as file:
                key_pass = file.readline().strip()
        return SecCsfAuthenticateData(
            verification_index=verification_index,
            engine=engine,
            engine_config=engine_cfg,
            private_key=private_key,
            key_pass=key_pass,
        )

    @property
    def certificate(self) -> Certificate:
        """Certificate."""
        assert self._certificate is not None
        return self._certificate

    @certificate.setter
    def certificate(self, value: Certificate) -> None:
        """Certificate setter."""
        if not isinstance(value, Certificate):
            raise SPSDKTypeError("Certificate is of incorrect type")
        self._certificate = value

    @property
    def version(self) -> int:
        """Image version."""
        assert self._version is not None
        return self._version

    @version.setter
    def version(self, value: int) -> None:
        """Image version setter."""
        if not isinstance(value, int):
            raise SPSDKTypeError("Version must be int type")
        self._version = value

    def build_command(self) -> None:
        """Build command with given properties."""
        self.cmd: CmdAuthData = CmdAuthData(
            certificate=self.certificate,
        )
        self.cmd.engine = self.engine
        self.cmd.engine_cfg = self.engine_config
        self.cmd.key_index = self.verification_index

        assert self.private_key is not None
        pem_private_key = load_private_key_from_data(
            self.private_key, password=str.encode(self.key_pass) if self.key_pass else None
        )
        self.cmd.private_key_pem_data = pem_private_key  # type: ignore

        signature = Signature(version=self.version)
        self.cmd.signature = signature

        if self.blocks:
            for block in self.blocks:
                self.cmd.append(block.base_address, block.size)

    @staticmethod
    def _get_image_blocks(
        image_config: ImageConfig,
        app_length: int,
        is_encrypted: bool,
        search_paths: Optional[List[str]] = None,
    ) -> List[ImageBlock]:
        """Get image blocks from image binary.

        :param image_config: Loaded image configuration
        :param app_length: App length
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        blocks = []
        # IVT + BDT
        blocks.append(
            ImageBlock(
                base_address=image_config.options.start_address + image_config.options.ivt_offset,
                start=image_config.options.ivt_offset,
                size=segments.SegIVT2.SIZE + BootImgRT.BDT_SIZE,
            )
        )
        if image_config.options.dcd_file_path is not None:
            dcd_bin = load_binary(image_config.options.dcd_file_path, search_paths=search_paths)
            blocks.append(
                ImageBlock(
                    base_address=image_config.options.start_address
                    + image_config.options.ivt_offset
                    + segments.SegIVT2.SIZE
                    + BootImgRT.BDT_SIZE,
                    start=image_config.options.ivt_offset
                    + segments.SegIVT2.SIZE
                    + BootImgRT.BDT_SIZE,
                    size=len(dcd_bin),
                )
            )
        if image_config.options.xmcd_file_path is not None:
            xmcd_bin = load_binary(image_config.options.xmcd_file_path, search_paths=search_paths)

            blocks.append(
                ImageBlock(
                    base_address=image_config.options.start_address
                    + image_config.options.ivt_offset
                    + BootImgRT.XMCD_IVT_OFFSET,
                    start=image_config.options.ivt_offset + BootImgRT.XMCD_IVT_OFFSET,
                    size=len(xmcd_bin),
                )
            )
        if not is_encrypted:
            blocks.append(
                ImageBlock(
                    base_address=image_config.options.start_address
                    + image_config.options.initial_load_size,
                    start=image_config.options.initial_load_size,
                    size=app_length,
                )
            )
        return blocks


class SecSetEngine(SecCommand):
    """Set engine command."""

    CMD_INDEX = 31
    CONFIGURATION_PARAMS = {
        "SetEngine_HashAlgorithm": False,
        "SetEngine_Engine": False,
        "SetEngine_EngineConfiguration": False,
    }

    def __init__(
        self,
        hash_algorithm: Optional[EnumAlgorithm] = None,
        engine: Optional[EnumEngine] = None,
        engine_cfg: Optional[int] = None,
    ) -> None:
        """Set engine class constructor.

        :param hash_algorithm: Hash algorithm type
        :param engine: Engine plugin tag
        :param engine_config: Engine configuration index
        """
        super().__init__()
        self.hash_algorithm = hash_algorithm
        self.engine = engine
        self.engine_cfg = engine_cfg

    @staticmethod
    def parse(config: SectionConfig, search_paths: Optional[List[str]] = None) -> "SecSetEngine":
        """Parse configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        SecSetEngine.check_config_section_params(config)
        hash_algorithm = config.options.get("SetEngine_HashAlgorithm")
        hash_algorithm = EnumAlgorithm[hash_algorithm] if hash_algorithm is not None else None

        engine = config.options.get("SetEngine_Engine")
        engine = EnumEngine[engine] if engine is not None else None

        engine_cfg = config.options.get("SetEngine_EngineConfiguration")
        engine_cfg = int(engine_cfg) if engine_cfg is not None else None
        return SecSetEngine(hash_algorithm=hash_algorithm, engine=engine, engine_cfg=engine_cfg)

    def build_command(self) -> None:
        """Build command with given properties."""
        self.cmd = CmdSet()
        if self.hash_algorithm is not None:
            self.cmd.hash_algorithm = self.hash_algorithm

        if self.engine is not None:
            self.cmd.engine = self.engine

        if self.engine_cfg is not None:
            self.cmd.engine_cfg = self.engine_cfg


class SecUnlock(SecCommand):
    """Unlock engine command."""

    CMD_INDEX = 33
    ENGINE_CLASSES = {"SNVS": CmdUnlockSNVS, "CAAM": CmdUnlockCAAM}
    UNLOCK_FEARTURES = {"LP SWR": 1, "ZMK WRITE": 2}
    CONFIGURATION_PARAMS = {"Unlock_Engine": True, "Unlock_Features": False}

    def __init__(self, unlock_engine: str, features: Optional[int]) -> None:
        """Unlock class constructor.

        :param unlock_engine: Unlock engine type: can be aither SNVS or CAAM
        :param features: Features
        :raises SPSDKKeyError: Unknown engine.
        """
        super().__init__()
        if unlock_engine not in self.ENGINE_CLASSES:
            raise SPSDKKeyError(f"Unknown engine {unlock_engine}")
        self.unlock_engine = unlock_engine
        self.features = features

    @staticmethod
    def parse(config: SectionConfig, search_paths: Optional[List[str]] = None) -> SecCommand:
        """Parse configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKKeyError: Unknown features.
        """
        SecUnlock.check_config_section_params(config)
        unlock_engine = config.options["Unlock_Engine"]
        unlock_features = config.options.get("Unlock_Features")
        if unlock_features is not None:
            if unlock_features not in SecUnlock.UNLOCK_FEARTURES:
                raise SPSDKKeyError(f"Unknown features {unlock_features}")
            unlock_features = SecUnlock.UNLOCK_FEARTURES[unlock_features]
        return SecUnlock(unlock_engine=unlock_engine, features=unlock_features)

    def build_command(self) -> None:
        """Build command with given properties."""
        self.cmd: CmdUnlockAbstract = self.ENGINE_CLASSES[self.unlock_engine]()
        if self.features is not None:
            self.cmd.features = self.features


class SecInstallSecretKey(SecCommand):
    """Set engine command."""

    CMD_INDEX = 27
    CONFIGURATION_PARAMS = {
        "SecretKey_Name": True,
        "SecretKey_Length": False,
        "SecretKey_VerifyIndex": False,
        "SecretKey_TargetIndex": True,
        "SecretKey_ReuseDek": False,
    }

    def __init__(
        self,
        secret_key: bytes,
        source_index: int,
        target_index: int,
    ) -> None:
        """Set install secret key class constructor.

        :param hash_algorithm: Hash algorithm type
        :param engine: Engine plugin tag
        :param engine_config: Engine configuration index
        :raises SPSDKValueError: Source index not specified.
        :raises SPSDKValueError: Source index is not lower or equal to 3.
        :raises SPSDKValueError: Target index not specified.
        """
        super().__init__()
        self.secret_key: bytes = secret_key
        if source_index is None:
            raise SPSDKValueError("Source index must be specified")
        if source_index > 3:
            raise SPSDKValueError("Source index must be equal or lower than 3")
        self.source_index = source_index
        if target_index is None:
            raise SPSDKValueError("Target index must be specified")
        self.target_index = target_index
        self._location: Optional[int] = None

    @staticmethod
    def parse(
        config: SectionConfig, search_paths: Optional[List[str]] = None
    ) -> "SecInstallSecretKey":
        """Parse configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        SecInstallSecretKey.check_config_section_params(config)
        reuse_dek = True if config.options.get("SecretKey_ReuseDek", 0) == 1 else False
        length = int(config.options.get("SecretKey_Length", 128))  # type: ignore
        if length not in [128, 192, 256]:
            raise SPSDKValueError(f"Invalid sectet key length {length}")
        key_length = length // 8
        if reuse_dek:
            secret_key_path = find_file(config.options["SecretKey_Name"], search_paths=search_paths)
            secret_key = load_binary(secret_key_path)
        else:
            base_dir = search_paths[0] if search_paths is not None else None
            secret_key_path = get_abs_path(config.options["SecretKey_Name"], base_dir)
            secret_key = SecInstallSecretKey.generate_random_bytes(length // 8)
            SecInstallSecretKey.save_secret_key(secret_key_path, secret_key)
        if len(secret_key) != key_length:
            raise SPSDKError(
                f"Loaded secret key lenght does not match the expected length: {length}"
            )
        source_index = int(config.options.get("SecretKey_VerifyIndex", 0))  # type: ignore
        target_index = int(config.options["SecretKey_TargetIndex"])
        return SecInstallSecretKey(
            secret_key=secret_key, source_index=source_index, target_index=target_index
        )

    @staticmethod
    def save_secret_key(secret_key_path: str, secret_key: bytes) -> None:
        """Save given sectret key into file.

        :param secret_key_path: Path to file with secret key
        :param secret_key: Secret key to be saved
        """
        exists = os.path.isfile(secret_key_path)
        if exists:
            os.remove(secret_key_path)
        write_file(secret_key, secret_key_path, "wb")

    @property
    def location(self) -> int:
        """Start address of DEK key."""
        assert self._location is not None
        return self._location

    @location.setter
    def location(self, value: int) -> None:
        """Setter for start address of DEK key."""
        if not isinstance(value, int):
            raise SPSDKTypeError("Location must be int type")
        self._location = value

    def build_command(self) -> None:
        """Build command with given properties."""
        assert self.location is not None
        self.cmd: CmdInstallKey = CmdInstallKey(
            flags=EnumInsKey.ABS,
            cert_fmt=EnumCertFormat.BLOB,
            hash_alg=EnumAlgorithm.ANY,
            location=self.location,
        )
        self.cmd.source_index = self.source_index
        self.cmd.target_index = self.target_index


class SecDecryptData(SecCommand):
    """Set engine command."""

    CMD_INDEX = 28
    CONFIGURATION_PARAMS = {
        "Decrypt_Engine": False,
        "Decrypt_EngineConfiguration": False,
        "Decrypt_VerifyIndex": True,
        "Decrypt_MacBytes": False,
        "Decrypt_Nonce": False,
    }

    def __init__(
        self,
        verification_index: int,
        mac_len: Optional[int],
        nonce: Optional[bytes] = None,
        engine: Optional[EnumEngine] = None,
        engine_config: Optional[int] = None,
    ) -> None:
        """Decrypt data class constructor.

        :param verification_index: Target index
        :param mac_len: Number of mac bytes
        :param nonce: Nonce binary
        :param engine: Engine plugin tag
        :param engine_config: Engine configuration index
        :raises SPSDKValueError: Invalid combination of input parameters.
        """
        super().__init__()
        if verification_index is None:
            raise SPSDKValueError("Verification index must be defined.")
        if verification_index >= 6:
            raise SPSDKValueError("Verification index must be lower than 6.")
        self.verification_index = verification_index
        self.engine = engine if engine is not None else EnumEngine.ANY
        self.engine_config = engine_config if engine_config is not None else 0
        if engine == EnumEngine.ANY and engine_config != 0:
            raise SPSDKValueError(f"Invalid argument combination:{engine}: {engine_config}")
        self.mac_len = mac_len if mac_len is not None else 16
        if self.mac_len < 4 or self.mac_len > 16 or self.mac_len % 2:
            raise SPSDKValueError(
                "Invalid mac length. Valid options are 4, 6, 8, 10, 12, 14 and 16."
            )
        self.nonce = nonce
        self._dek: Optional[bytes] = None
        self._blocks: Optional[List[ImageBlock]] = None

    def encrypt(self, data: bytes) -> Tuple[bytes, bytes]:
        """Encrypt data and return mac and encrypted data.

        :raises SPSDKError: Invalid length of encrypted data.
        """
        assert self.dek is not None
        data_to_encrypt: bytes = b""
        if self.blocks:
            for block in self.blocks:
                data_to_encrypt += data[block.start : block.start + block.size]
        else:
            data_to_encrypt = data
        if self.nonce is None:
            nonce_len = BootImgRT.aead_nonce_len(len(data_to_encrypt))
            self.nonce = SecDecryptData.generate_random_bytes(nonce_len)
        aesccm = AESCCM(self.dek, tag_length=self.mac_len)
        encr = aesccm.encrypt(self.nonce, data_to_encrypt, None)  # type: ignore
        if len(encr) != len(data_to_encrypt) + self.mac_len:
            raise SPSDKError("Invalid length of encrypted data")
        mac = encr[-self.mac_len :]
        data = encr[: -self.mac_len]
        return mac, data

    @property
    def dek(self) -> bytes:
        """Data encryption key."""
        assert self._dek is not None
        return self._dek

    @dek.setter
    def dek(self, value: bytes) -> None:
        """Data encryption key setter."""
        if not isinstance(value, bytes):
            raise SPSDKTypeError("Dek must be bytes type")
        self._dek = value

    @property
    def blocks(self) -> Optional[List[ImageBlock]]:
        """Blocks to be encrypted property."""
        return self._blocks

    @blocks.setter
    def blocks(self, value: List[ImageBlock]) -> None:
        """Blocks to be encrypted property setter."""
        if not isinstance(value, List):
            raise SPSDKTypeError("Blocks must be a list type")
        self._blocks = value

    @staticmethod
    def parse(config: SectionConfig, search_paths: Optional[List[str]] = None) -> "SecDecryptData":
        """Parse configuration into the command.

        :param config: Section config
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        SecDecryptData.check_config_section_params(config)
        engine = config.options.get("Decrypt_Engine")
        if engine is not None:
            engine = EnumEngine[engine]

        engine_cfg = config.options.get("Decrypt_EngineConfiguration")
        if engine_cfg is not None:
            engine_cfg = int(engine_cfg)

        verification_index = int(config.options["Decrypt_VerifyIndex"])

        mac_len = config.options.get("Decrypt_MacBytes")
        if mac_len is not None:
            mac_len = int(mac_len)

        nonce = config.options.get("Decrypt_Nonce")
        if nonce is not None:
            nonce = load_binary(nonce, search_paths=search_paths)
        return SecDecryptData(
            verification_index=verification_index,
            mac_len=mac_len,
            nonce=nonce,
            engine=engine,
            engine_config=engine_cfg,
        )

    def build_command(self) -> None:
        """Build command with given properties."""
        self.cmd: CmdAuthData = CmdAuthData(flags=EnumAuthDat.CLR, sig_format=EnumCertFormat.AEAD)

        self.cmd.engine = self.engine
        self.cmd.engine_cfg = self.engine_config
        self.cmd.key_index = self.verification_index
        if self.blocks:
            for block in self.blocks:
                self.cmd.append(block.base_address, block.size)

    @staticmethod
    def _get_image_blocks(
        image_config: ImageConfig,
        app_length: int,
    ) -> List[ImageBlock]:
        blocks = []
        blocks.append(
            ImageBlock(
                base_address=image_config.options.start_address
                + image_config.options.initial_load_size,
                start=image_config.options.initial_load_size,
                size=app_length,
            )
        )
        return blocks


class CsfBuilder:
    """Csf command builder."""

    def __init__(
        self,
        bd_config: ImageConfig,
        csf_offset: int,
        hab_image: HabBinaryImage,
        search_paths: Optional[List[str]] = None,
        timestamp: Optional[datetime] = None,
    ) -> None:
        """CSF builder class constructor.

        :param bd_config: Loaded image configuration
        :param csf_offset: CSF segment offset
        :param hab_image: Hab binary image
        :param search_paths: List of paths where to search for the file, defaults to None
        :param timestamp: Signature timestamp
        """
        self.header: Optional[SecCsfHeader] = None
        self.commands: List[SecCommand] = []
        self.bd_config = bd_config
        self.is_encrypted = self.bd_config.options.flags == 0x0C
        self.is_authenticated = self.bd_config.options.flags == 0x08
        self.csf_offset = csf_offset
        self.search_paths = search_paths
        self.timestamp = timestamp if timestamp is not None else datetime.now(timezone.utc)
        if self.is_authenticated or self.is_encrypted:
            hab_image.align_segment(HabSegment.APP, 16)
        self.hab_image = hab_image

    def reset(self) -> None:
        """Reset builder into its initial state."""
        self.header = None
        self.commands = []

    def get_command(self, command_id: int, raise_exc: bool = True) -> Optional[SecCommand]:
        """Get command by command id.

        :param command_id: Command ID to be retrieved
        :param raise_exc: If set and section is not found, the error is raised
        :raises SPSDKKeyError: If command does not exist
        """
        command = find_first(self.commands, lambda cmd: cmd.CMD_INDEX == command_id)
        if raise_exc and command is None:
            raise SPSDKKeyError(f"Section with id {command_id} does not exist.")
        return command

    def append_command(self, command: SecCommand) -> None:
        """Append command to list of commands and update header length.

        :param command: Command to be appended
        """
        assert self.header
        assert self.header.cmd
        header = self.header.cmd
        header.length += len(command.cmd.export())
        self.commands.append(command)

    def get_padding_hab_image(self) -> HabBinaryImage:
        """Get HAB image with initial padding."""
        image = deepcopy(self.hab_image)
        for sub_img in image.sub_images:
            sub_img.offset += self.bd_config.options.ivt_offset
        return image

    @property
    def keyblob_address(self) -> int:
        """Keyblob address property."""
        return (
            self.bd_config.options.start_address
            + self.csf_offset
            + self.bd_config.options.ivt_offset
            + self.hab_image.CSF_SIZE
        )

    def build_csf_header(self) -> None:
        """Build CSF header command."""
        bd_section = self.bd_config.get_section(SecCsfHeader.CMD_INDEX)
        if not bd_section:
            return
        command = SecCsfHeader.parse(bd_section, search_paths=self.search_paths)
        command.build_command()
        self.header = command

    def build_csf_install_srk(self) -> None:
        """Build CSF install SRK command."""
        bd_section = self.bd_config.get_section(SecCsfInstallSrk.CMD_INDEX)
        if not bd_section:
            return
        command = SecCsfInstallSrk.parse(bd_section, search_paths=self.search_paths)
        command.build_command()
        self.append_command(command)

    def build_csf_install_csfk(self) -> None:
        """Build CSF install CSFK command."""
        bd_section = self.bd_config.get_section(SecCsfInstallCsfk.CMD_INDEX)
        if not bd_section:
            return

        assert self.header is not None
        command = SecCsfInstallCsfk.parse(bd_section, search_paths=self.search_paths)
        command.version = self.header.version
        command.build_command()

        self.append_command(command)

    def build_authenticate_csfk(self) -> None:
        """Build authenticate CSFK command."""
        bd_section = self.bd_config.get_section(SecCsfAuthenticateCsf.CMD_INDEX)
        if not bd_section:
            return

        assert self.header is not None
        install_csfk: SecCsfInstallCsfk = self.get_command(SecCsfInstallCsfk.CMD_INDEX)  # type: ignore

        command = SecCsfAuthenticateCsf.parse(bd_section, search_paths=self.search_paths)
        if command.private_key is None:
            private_key_path = self._determine_private_key_path(install_csfk.csfk_file_path)
            if not private_key_path:
                raise SPSDKFileNotFoundError("Private key could not be found.")
            private_key = load_binary(private_key_path, search_paths=self.search_paths)
            command.private_key = private_key

        if command.key_pass is None:
            key_pass_file = self._determine_key_pass_path(install_csfk.csfk_file_path)
            if key_pass_file:
                with open(key_pass_file) as file:
                    command.key_pass = file.readline().strip()

        command.certificate = load_certificate_from_data(
            load_binary(install_csfk.csfk_file_path, search_paths=self.search_paths)
        )
        command.version = self.header.version
        command.engine = self.header.engine
        command.build_command()

        # This is just temporary signature.
        # It will be recreated in the finish method
        data_to_sign = self.header.cmd.export()
        for section in self.commands:
            data_to_sign += section.cmd.export()
        data_to_sign += command.cmd.export()

        command.sign(data_to_sign, self.timestamp)
        self.append_command(command)

    def build_install_key_csfk(self) -> None:
        """Build install key CSFK command."""
        bd_section = self.bd_config.get_section(SecCsfInstallKey.CMD_INDEX)
        if not bd_section:
            return

        assert self.header is not None
        command = SecCsfInstallKey.parse(bd_section, search_paths=self.search_paths)
        command.version = self.header.version
        command.build_command()
        self.append_command(command)

    def build_authenticate_data(self) -> None:
        """Build authenticate data command."""
        bd_section = self.bd_config.get_section(SecCsfAuthenticateData.CMD_INDEX)
        if not bd_section:
            return

        assert self.header is not None
        install_key: SecCsfInstallKey = self.get_command(SecCsfInstallKey.CMD_INDEX)  # type: ignore

        command = SecCsfAuthenticateData.parse(bd_section, search_paths=self.search_paths)
        if command.private_key is None:
            private_key_path = self._determine_private_key_path(install_key.certificate_path)
            if not private_key_path:
                raise SPSDKFileNotFoundError("Private key could not be found.")
            command.private_key = load_binary(private_key_path, search_paths=self.search_paths)

        if command.key_pass is None:
            key_pass_file = self._determine_key_pass_path(install_key.certificate_path)
            if key_pass_file:
                with open(key_pass_file) as file:
                    command.key_pass = file.readline().strip()

        app = self.hab_image.get_hab_segment(HabSegment.APP)
        blocks = SecCsfAuthenticateData._get_image_blocks(
            self.bd_config,
            app_length=len(app),
            is_encrypted=self.is_encrypted,
            search_paths=self.search_paths,
        )

        command.certificate = install_key.certificate
        command.version = self.header.version
        command.blocks = blocks
        command.build_command()

        padding_image = self.get_padding_hab_image()
        command.sign(
            data=padding_image.export(),
            base_data_address=self.bd_config.options.start_address,
            timestamp=self.timestamp,
        )
        self.append_command(command)

    def build_set_engine(self) -> None:
        """Build set engine command."""
        bd_section = self.bd_config.get_section(SecSetEngine.CMD_INDEX)
        if not bd_section:
            return
        command = SecSetEngine.parse(bd_section, search_paths=self.search_paths)
        command.build_command()
        self.append_command(command)

    def build_unlock_engine(self) -> None:
        """Build unlock engine command."""
        bd_section = self.bd_config.get_section(SecUnlock.CMD_INDEX)
        if not bd_section:
            return
        command = SecUnlock.parse(bd_section, search_paths=self.search_paths)
        command.build_command()
        self.append_command(command)

    def build_install_secret_key(self) -> None:
        """Build install Secret key command.

        :raises SPSDKError: Incorrect version is used
        """
        bd_section = self.bd_config.get_section(SecInstallSecretKey.CMD_INDEX)
        if not bd_section:
            return

        assert self.header is not None

        if self.header.version <= 0x40:
            raise SPSDKError("The command is supported from version 0x41 onwards")

        command = SecInstallSecretKey.parse(bd_section, search_paths=self.search_paths)
        command.location = self.keyblob_address
        command.build_command()
        self.append_command(command)

    def build_decrypt_data(self) -> None:
        """Build install Secret key command."""
        bd_section = self.bd_config.get_section(SecDecryptData.CMD_INDEX)
        if not bd_section:
            return

        install_secret_key: SecInstallSecretKey = self.get_command(SecInstallSecretKey.CMD_INDEX)  # type: ignore

        command = SecDecryptData.parse(bd_section, search_paths=self.search_paths)
        command.dek = install_secret_key.secret_key
        app = self.hab_image.get_hab_segment(HabSegment.APP)
        blocks = SecDecryptData._get_image_blocks(
            self.bd_config,
            app_length=app.aligned_length(16),
        )
        command.blocks = blocks
        command.build_command()
        self.append_command(command)

    def finish(self) -> None:
        """Finish command creation."""
        if not self.commands:
            return None
        assert self.header is not None
        # Encrypt data if needed
        if self.is_encrypted:
            encrypt_data_cmd: SecDecryptData = self.get_command(SecDecryptData.CMD_INDEX)  # type: ignore
            app = self.hab_image.get_hab_segment(HabSegment.APP)
            assert app is not None

            padding_image = self.get_padding_hab_image()
            mac, data = encrypt_data_cmd.encrypt(padding_image.export())

            app.binary = data
            # Update signature
            decrypt: SecDecryptData = self.get_command(SecDecryptData.CMD_INDEX)  # type: ignore
            assert decrypt.nonce is not None
            decrypt.cmd.signature = MAC(
                version=self.header.version,
                nonce_len=len(decrypt.nonce),
                mac_len=decrypt.mac_len,
                data=decrypt.nonce + mac,
            )

        auth_command: SecCsfAuthenticateCsf = self.get_command(SecCsfAuthenticateCsf.CMD_INDEX)  # type: ignore
        # Sign all command's data at the end of whole process
        if auth_command is not None:
            csf = self._build_csf_segment()
            data_to_sign = self.header.cmd.export()
            for section in csf.commands:
                data_to_sign += section.export()
            auth_command.cmd.update_signature(zulu=self.timestamp, data=data_to_sign)
        self.hab_image.add_hab_segment(
            HabSegment.CSF, self._build_csf_segment().export(), offset_override=self.csf_offset
        )

    def _build_csf_segment(self) -> segments.SegCSF:
        """Build whole CSF segment from individual commands."""
        assert self.header is not None
        csf = segments.SegCSF(version=self.header.version, enabled=True)
        for section in self.commands:
            csf.append_command(section.cmd)  # type: ignore
        csf.update(True)
        return csf

    def _determine_private_key_path(self, cert_file_path: str) -> Optional[str]:
        """Determine private key path the same was as legacy CST tool does.

        :param cert_file_path: Path to certificate file
        :return: Path to private key file
        """
        logger.debug("Trying to determine the private key path.")
        keys_dir = self._get_keys_dir(cert_file_path)
        cert_file_name = os.path.basename(cert_file_path)
        cert_file, cert_extension = os.path.splitext(cert_file_name)
        if cert_file.endswith("crt"):
            key_file = cert_file[:-3] + "key"
            key_file_name = key_file + cert_extension
        else:
            return None
        private_key_file = os.path.join(keys_dir, key_file_name)
        if not os.path.isfile(private_key_file):
            return None
        return private_key_file

    def _determine_key_pass_path(self, cert_file_path: str) -> Optional[str]:
        """Determine key pass path the same was as legacy CST tool does.

        :param cert_file_path: Path to certificate file
        :return: Path to key pass file
        """
        logger.debug("Trying to determine the key pass path.")
        keys_dir = self._get_keys_dir(cert_file_path)
        key_pass_file = os.path.join(keys_dir, "key_pass.txt")
        if not os.path.isfile(key_pass_file):
            return None
        return key_pass_file

    @staticmethod
    def _get_keys_dir(cert_file_path: str) -> str:
        """Get keys directory from certificate file path.

        :param cert_file_path: Path to certificate file
        :return: Keys directory path
        """
        directory, _ = os.path.split(cert_file_path)
        if directory.endswith("crts"):
            return directory[:-4] + "keys"
        return cert_file_path


class CsfBuildDirector:
    """CSF command build director."""

    def __init__(self, builder: CsfBuilder) -> None:
        """CSF build director class constructor.

        :param builder: CSF builder
        """
        self._builder: CsfBuilder = builder

    @property
    def builder(self) -> CsfBuilder:
        """CSF builder property."""
        return self._builder

    def build_csf(self) -> None:
        """Build individual CSF commands."""
        self._builder.build_csf_header()
        self._builder.build_csf_install_srk()
        self._builder.build_csf_install_csfk()
        self._builder.build_authenticate_csfk()
        self._builder.build_install_key_csfk()
        self._builder.build_authenticate_data()
        self._builder.build_set_engine()
        self._builder.build_unlock_engine()
        self._builder.build_install_secret_key()
        self._builder.build_decrypt_data()
        self._builder.finish()
